//! `kutup ssh-agent` and `kutup ssh-add` (docs/plans/pass.md, K3b): the SSH
//! keys kept in the vaults of a folder `kutup sync` keeps, served by an
//! opt-in agent or pushed into the system's own.

use std::path::PathBuf;

use clap::Args;

#[derive(Args)]
pub struct AgentArgs {
    /// The local folder `kutup sync` keeps (its .kdbx files are read).
    pub local_dir: PathBuf,
    /// The Drive folder it syncs with (for the vault keys kept in your account).
    pub collection_id: String,
    /// The socket to serve (default: $XDG_RUNTIME_DIR/kutup/ssh-agent.sock).
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Forget decrypted keys and approvals after this many minutes unused.
    #[arg(long, default_value_t = 15)]
    pub idle: u64,
    /// Never ask before a key is used (forwarded requests still ask).
    #[arg(long)]
    pub no_confirm: bool,
}

#[derive(Args)]
pub struct AddArgs {
    /// The local folder `kutup sync` keeps.
    pub local_dir: PathBuf,
    /// The Drive folder it syncs with.
    pub collection_id: String,
    /// The entry: its title or UUID.
    pub entry: String,
    /// Remove the key from the agent after this many seconds (default: the entry's KeeAgent setting).
    #[arg(long)]
    pub lifetime: Option<u32>,
    /// Have the agent ask before each use (default: the entry's KeeAgent setting).
    #[arg(long)]
    pub confirm: bool,
}

#[cfg(not(unix))]
pub fn agent(_profile: &str, _args: &AgentArgs) -> anyhow::Result<()> {
    Err(
        crate::errors::UsageError("the kutup SSH agent runs on Linux and macOS for now".into())
            .into(),
    )
}

#[cfg(not(unix))]
pub fn add(_profile: &str, _json: bool, _args: &AddArgs) -> anyhow::Result<()> {
    Err(crate::errors::UsageError("kutup ssh-add runs on Linux and macOS for now".into()).into())
}

#[cfg(unix)]
pub use unix::{add, agent};

#[cfg(unix)]
mod unix {
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use anyhow::{anyhow, bail, Context, Result};
    use kutup_pass::ssh::{agent_identity_blob, ssh_keys};

    use super::{AddArgs, AgentArgs};
    use crate::api::Client;
    use crate::session::{sync_pair_id, Store};
    use crate::sshagent::approval::TerminalApprover;
    use crate::sshagent::{proto, server, LoadedKey, Policy, State};
    use crate::vaultsync::{is_vault, VaultKeys};

    /// Where vaults come from, and how to open them.
    struct Source {
        root: PathBuf,
        /// Drive file id by path in the folder (from the sync state).
        file_ids: HashMap<String, String>,
        server: Option<(String, String)>,
    }

    impl Source {
        fn open(
            profile: &str,
            root: &Path,
            collection: &str,
            keys: &mut VaultKeys,
        ) -> Result<Self> {
            let canonical = std::fs::canonicalize(root)
                .with_context(|| format!("{} is not a folder", root.display()))?;
            let (store, server) = match crate::context::require_session(profile) {
                Ok(ctx) => {
                    keys.sign_in(&ctx.session)?;
                    let server =
                        Some((ctx.session.server.clone(), ctx.session.access_token.clone()));
                    (ctx.store, server)
                }
                // Signed out: the vaults open with KUTUP_VAULT_PASSWORD or a prompt.
                Err(_) => (Store::open(profile)?, None),
            };
            let pair = sync_pair_id(collection, &canonical.to_string_lossy());
            let file_ids = store
                .list_sync_files(&pair)?
                .into_iter()
                .map(|(rel, state)| (rel, state.file_id))
                .collect();
            Ok(Self {
                root: canonical,
                file_ids,
                server,
            })
        }

        fn client(&self) -> Client {
            match &self.server {
                Some((server, token)) => Client::new(server, token),
                None => Client::new("http://127.0.0.1:9", ""),
            }
        }

        /// Every vault file under the folder (not hidden ones), by path in it.
        fn vault_files(&self) -> Vec<(String, PathBuf)> {
            let mut out = Vec::new();
            let mut stack = vec![(String::new(), self.root.clone())];
            while let Some((rel, dir)) = stack.pop() {
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with('.') {
                        continue;
                    }
                    let path = entry.path();
                    let child = if rel.is_empty() {
                        name.clone()
                    } else {
                        format!("{rel}/{name}")
                    };
                    if path.is_dir() {
                        stack.push((child, path));
                    } else if is_vault(&child) {
                        out.push((child, path));
                    }
                }
            }
            out.sort();
            out
        }

        fn snapshot(&self) -> Vec<(PathBuf, Option<SystemTime>)> {
            self.vault_files()
                .into_iter()
                .map(|(_, path)| {
                    let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
                    (path, modified)
                })
                .collect()
        }

        /// The keys in every vault that opens; what could not be used, said.
        fn load(&self, keys: &mut VaultKeys, ask: bool) -> (Vec<LoadedKey>, Vec<String>) {
            let client = self.client();
            let mut loaded = Vec::new();
            let mut notes = Vec::new();
            for (rel, path) in self.vault_files() {
                let Ok(contents) = std::fs::read(&path) else {
                    notes.push(format!("{rel}: could not be read"));
                    continue;
                };
                let file_id = self.file_ids.get(&rel).cloned().unwrap_or_default();
                let Some((db, _)) = keys.open(&client, &rel, &file_id, &contents, ask) else {
                    notes.push(format!("{rel}: no key opens it (KUTUP_VAULT_PASSWORD, a kept key, or run in a terminal)"));
                    continue;
                };
                let (found, skipped) = ssh_keys(&db);
                for skip in skipped {
                    notes.push(format!("{rel}: {}: {}", skip.title, skip.reason));
                }
                loaded.extend(found.into_iter().map(|entry| LoadedKey {
                    vault: rel.clone(),
                    entry,
                }));
            }
            (loaded, notes)
        }
    }

    pub fn agent(profile: &str, args: &AgentArgs) -> Result<()> {
        let mut keys = VaultKeys::from_env()?;
        let source = Source::open(profile, &args.local_dir, &args.collection_id, &mut keys)?;
        let (loaded, notes) = source.load(&mut keys, true);
        for note in &notes {
            eprintln!("kutup ssh-agent: {note}");
        }
        if loaded.is_empty() {
            eprintln!("kutup ssh-agent: no SSH keys yet (entries with KeeAgent settings that allow use); serving anyway");
        }
        for key in &loaded {
            eprintln!(
                "  {} {} ({})",
                key.entry.fingerprint(),
                key.entry.title,
                key.vault
            );
        }
        let socket = args.socket.clone().unwrap_or_else(server::default_socket);
        let listener = server::bind(&socket)?;
        // What ssh-agent -s prints: the shell line to use this agent.
        println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket.display());
        eprintln!(
            "kutup ssh-agent: serving {} key(s) on {}; keys are used only after you allow them here{}",
            loaded.len(),
            socket.display(),
            if args.no_confirm { " (not asking: --no-confirm)" } else { "" }
        );
        let state = Arc::new(Mutex::new(State::new(loaded)));
        let policy = Arc::new(Policy {
            no_confirm: args.no_confirm,
            idle: Duration::from_secs(args.idle.max(1) * 60),
        });
        let watched = Mutex::new(source.snapshot());
        let keys = Mutex::new(keys);
        let reload = Arc::new(move || {
            let now = source.snapshot();
            let mut seen = watched.lock().unwrap_or_else(|e| e.into_inner());
            if *seen == now {
                return None;
            }
            *seen = now;
            let mut keys = keys.lock().unwrap_or_else(|e| e.into_inner());
            // No prompt from here: the keys that opened the vaults before.
            let (loaded, notes) = source.load(&mut keys, false);
            for note in notes {
                eprintln!("kutup ssh-agent: {note}");
            }
            Some(loaded)
        });
        server::serve(
            listener,
            state,
            policy,
            Arc::new(TerminalApprover::new()),
            reload,
        )
    }

    pub fn add(profile: &str, json: bool, args: &AddArgs) -> Result<()> {
        let mut keys = VaultKeys::from_env()?;
        let source = Source::open(profile, &args.local_dir, &args.collection_id, &mut keys)?;
        let (loaded, notes) = source.load(&mut keys, true);
        let matching: Vec<&LoadedKey> = loaded
            .iter()
            .filter(|k| {
                k.entry.title == args.entry
                    || k.entry
                        .entry_id
                        .to_string()
                        .eq_ignore_ascii_case(&args.entry)
            })
            .collect();
        let key = match matching.as_slice() {
            [one] => *one,
            [] => {
                for note in &notes {
                    eprintln!("  {note}");
                }
                bail!("no SSH key entry named {}", args.entry)
            }
            _ => bail!(
                "{} entries are named {}; give its UUID",
                matching.len(),
                args.entry
            ),
        };
        let private = key.entry.private_key()?;
        let settings = &key.entry.settings;
        let lifetime = args
            .lifetime
            .or((settings.use_lifetime).then_some(settings.lifetime_secs));
        let confirm = args.confirm || settings.confirm;
        let mut body = vec![if lifetime.is_some() || confirm {
            proto::ADD_ID_CONSTRAINED
        } else {
            proto::ADD_IDENTITY
        }];
        body.extend_from_slice(&agent_identity_blob(&private, &key.entry.comment())?);
        if let Some(secs) = lifetime {
            body.push(proto::CONSTRAIN_LIFETIME);
            proto::put_u32(&mut body, secs);
        }
        if confirm {
            body.push(proto::CONSTRAIN_CONFIRM);
        }
        let socket = std::env::var_os("SSH_AUTH_SOCK")
            .ok_or_else(|| anyhow!("SSH_AUTH_SOCK is not set: start your agent first"))?;
        let mut stream = UnixStream::connect(&socket)
            .with_context(|| format!("connect to {}", socket.to_string_lossy()))?;
        stream.write_all(&proto::frame(&body))?;
        let mut len = [0u8; 4];
        stream.read_exact(&mut len)?;
        let mut answer = vec![0u8; (u32::from_be_bytes(len) as usize).min(proto::MAX_MESSAGE)];
        stream.read_exact(&mut answer)?;
        if answer.first() != Some(&proto::SUCCESS) {
            bail!("the agent refused the key");
        }
        if json {
            crate::output::print_json(&serde_json::json!({
                "entry": key.entry.title, "fingerprint": key.entry.fingerprint(), "lifetime": lifetime, "confirm": confirm,
            }))?;
        } else {
            println!(
                "Added {} ({}){}{}",
                key.entry.title,
                key.entry.fingerprint(),
                lifetime.map(|s| format!(", for {s} s")).unwrap_or_default(),
                if confirm {
                    ", asking before each use"
                } else {
                    ""
                }
            );
        }
        Ok(())
    }
}
