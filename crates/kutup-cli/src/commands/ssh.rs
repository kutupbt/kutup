//! `kutup ssh-agent` and `kutup ssh-add` (docs/plans/pass.md, K3b): the SSH
//! keys kept in the vaults of a folder `kutup sync` keeps, served by an
//! opt-in agent or pushed into the system's own.

use std::path::PathBuf;

use clap::Args;

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub command: Option<AgentCmd>,
    #[command(flatten)]
    pub run: RunArgs,
}

#[derive(Args)]
pub struct RunArgs {
    /// The local folder `kutup sync` keeps (its .kdbx files are read).
    #[arg(required = true)]
    pub local_dir: Option<PathBuf>,
    /// The Drive folder it syncs with (for the vault keys kept in your account).
    #[arg(required = true)]
    pub collection_id: Option<String>,
    /// The socket to serve (default: $XDG_RUNTIME_DIR/kutup/ssh-agent.sock).
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Forget decrypted keys and approvals after this many minutes unused.
    #[arg(long, default_value_t = 15)]
    pub idle: u64,
    /// Never ask before a key is used (forwarded requests still ask).
    #[arg(long)]
    pub no_confirm: bool,
    /// Where to ask: the terminal, a desktop dialog, or the terminal when
    /// there is one, else the desktop.
    #[arg(long, value_enum, default_value_t = Approve::Auto)]
    pub approve: Approve,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Approve {
    Auto,
    Terminal,
    Desktop,
}

#[derive(clap::Subcommand)]
pub enum AgentCmd {
    /// Start the agent at every login (a systemd user unit on Linux, a
    /// launchd agent on macOS), asking on the desktop.
    Install(InstallArgs),
    /// Stop the agent started at login and remove it.
    Uninstall,
    /// Whether the agent is installed and serving, and its keys.
    Status,
}

#[derive(Args)]
pub struct InstallArgs {
    /// The local folder `kutup sync` keeps.
    pub local_dir: PathBuf,
    /// The Drive folder it syncs with.
    pub collection_id: String,
    /// Forget decrypted keys and approvals after this many minutes unused.
    #[arg(long, default_value_t = 15)]
    pub idle: u64,
    /// Never ask before a key is used (forwarded requests still ask).
    #[arg(long)]
    pub no_confirm: bool,
    /// Show the service file instead of installing it.
    #[arg(long)]
    pub print: bool,
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
pub fn agent(_profile: &str, _json: bool, _args: &AgentArgs) -> anyhow::Result<()> {
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

    use super::{AddArgs, AgentArgs, AgentCmd, Approve, InstallArgs, RunArgs};
    use crate::api::Client;
    use crate::session::{sync_pair_id, Store};
    use crate::sshagent::approval::{Approver, TerminalApprover};
    use crate::sshagent::desktop::{Asker, AutoApprover, DesktopApprover};
    use crate::sshagent::{proto, server, service, LoadedKey, Policy, State};
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
                    keys.sign_in(&ctx.session, profile)?;
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
        /// Also how many vaults no key opened.
        fn load(&self, keys: &mut VaultKeys, ask: bool) -> (Vec<LoadedKey>, Vec<String>, usize) {
            let client = self.client();
            let mut loaded = Vec::new();
            let mut notes = Vec::new();
            let mut unopened = 0;
            for (rel, path) in self.vault_files() {
                let Ok(contents) = std::fs::read(&path) else {
                    notes.push(format!("{rel}: could not be read"));
                    continue;
                };
                let file_id = self.file_ids.get(&rel).cloned().unwrap_or_default();
                let Some((db, _)) = keys.open(&client, &rel, &file_id, &contents, ask) else {
                    notes.push(format!("{rel}: no key opens it (KUTUP_VAULT_PASSWORD, a kept key, or run in a terminal)"));
                    unopened += 1;
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
            (loaded, notes, unopened)
        }

        /// A fresh sign-in for the account's vault keys (a long-running
        /// agent outlives its access token).
        fn sign_in_again(&mut self, profile: &str, keys: &mut VaultKeys) {
            if let Ok(ctx) = crate::context::require_session(profile) {
                if keys.sign_in(&ctx.session, profile).is_ok() {
                    self.server =
                        Some((ctx.session.server.clone(), ctx.session.access_token.clone()));
                }
            }
        }
    }

    /// How often vaults that did not open are tried again (at login the
    /// network may not be up yet).
    const RETRY_UNOPENED: Duration = Duration::from_secs(30);

    pub fn agent(profile: &str, json: bool, args: &AgentArgs) -> Result<()> {
        match &args.command {
            Some(AgentCmd::Install(install_args)) => install(profile, install_args),
            Some(AgentCmd::Uninstall) => uninstall(json),
            Some(AgentCmd::Status) => status(json),
            None => run(profile, &args.run),
        }
    }

    fn run(profile: &str, args: &RunArgs) -> Result<()> {
        let (Some(local_dir), Some(collection_id)) = (&args.local_dir, &args.collection_id) else {
            bail!("give the folder kutup sync keeps and its Drive folder");
        };
        let mut keys = VaultKeys::from_env()?;
        let source = Source::open(profile, local_dir, collection_id, &mut keys)?;
        let (loaded, notes, unopened) = source.load(&mut keys, true);
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
        let approver: Arc<dyn Approver> = match args.approve {
            Approve::Terminal => Arc::new(TerminalApprover::new()),
            Approve::Desktop => Arc::new(DesktopApprover::new(Asker::find())),
            Approve::Auto => Arc::new(AutoApprover::new()),
        };
        let asking = match args.approve {
            Approve::Terminal => "here",
            Approve::Desktop => "in a desktop dialog",
            Approve::Auto => "here, or in a desktop dialog without a terminal",
        };
        eprintln!(
            "kutup ssh-agent: serving {} key(s) on {}; keys are used only after you allow them {asking}{}",
            loaded.len(),
            socket.display(),
            if args.no_confirm { " (not asking: --no-confirm)" } else { "" }
        );
        let state = Arc::new(Mutex::new(State::new(loaded)));
        let policy = Arc::new(Policy {
            no_confirm: args.no_confirm,
            idle: Duration::from_secs(args.idle.max(1) * 60),
        });
        let watched = Mutex::new((source.snapshot(), unopened, std::time::Instant::now()));
        let keys = Mutex::new(keys);
        let source = Mutex::new(source);
        let profile = profile.to_owned();
        let reload = Arc::new(move || {
            let mut source = source.lock().unwrap_or_else(|e| e.into_inner());
            let now = source.snapshot();
            let mut seen = watched.lock().unwrap_or_else(|e| e.into_inner());
            let (files, unopened, tried) = &mut *seen;
            let retry = *unopened > 0 && tried.elapsed() >= RETRY_UNOPENED;
            let changed = *files != now;
            if !changed && !retry {
                return None;
            }
            *files = now;
            *tried = std::time::Instant::now();
            let mut keys = keys.lock().unwrap_or_else(|e| e.into_inner());
            if retry {
                source.sign_in_again(&profile, &mut keys);
            }
            // No prompt from here: the keys that opened the vaults before.
            let (loaded, notes, still) = source.load(&mut keys, false);
            for note in notes {
                eprintln!("kutup ssh-agent: {note}");
            }
            // A retry that opened nothing more changes nothing.
            let opened_more = still < *unopened;
            *unopened = still;
            (changed || opened_more).then_some(loaded)
        });
        server::serve(listener, state, policy, approver, reload)
    }

    /// The keys an agent at `socket` lists; `None` when nothing answers.
    fn listed_keys(socket: &Path) -> Option<u32> {
        let mut stream = UnixStream::connect(socket).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        stream
            .write_all(&proto::frame(&[proto::REQUEST_IDENTITIES]))
            .ok()?;
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).ok()?;
        let mut answer = vec![0u8; (u32::from_be_bytes(len) as usize).min(proto::MAX_MESSAGE)];
        stream.read_exact(&mut answer).ok()?;
        match answer.as_slice() {
            [proto::IDENTITIES_ANSWER, a, b, c, d, ..] => {
                Some(u32::from_be_bytes([*a, *b, *c, *d]))
            }
            _ => None,
        }
    }

    /// The agent the shell uses now, when it is another one that answers.
    fn other_agent(socket: &Path) -> Option<String> {
        let current = std::env::var_os("SSH_AUTH_SOCK")?;
        let current = PathBuf::from(current);
        let same = std::fs::canonicalize(&current).ok() == std::fs::canonicalize(socket).ok()
            || current == socket;
        (!same && UnixStream::connect(&current).is_ok()).then(|| current.display().to_string())
    }

    fn install(profile: &str, args: &InstallArgs) -> Result<()> {
        let program = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .context("where this kutup is")?;
        let local_dir = std::fs::canonicalize(&args.local_dir)
            .with_context(|| format!("{} is not a folder", args.local_dir.display()))?;
        let socket = server::default_socket();
        let mut environment = Vec::new();
        if let Some(askpass) = ["KUTUP_SSH_ASKPASS", "SSH_ASKPASS"]
            .iter()
            .find_map(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
        {
            environment.push(("KUTUP_SSH_ASKPASS".to_owned(), askpass));
        }
        // A server with a self-signed certificate (a test server): the
        // service must reach it as this shell does.
        let insecure_tls = std::env::var("KUTUP_INSECURE_TLS")
            .ok()
            .filter(|v| !v.is_empty());
        if let Some(value) = &insecure_tls {
            environment.push(("KUTUP_INSECURE_TLS".to_owned(), value.clone()));
        }
        let unit = service::Service {
            program: program.clone(),
            profile: profile.to_owned(),
            local_dir: local_dir.clone(),
            collection_id: args.collection_id.clone(),
            socket: socket.clone(),
            idle: args.idle.max(1),
            no_confirm: args.no_confirm,
            environment,
        };
        let text = service::service_text(&unit)?;
        if args.print {
            print!("{text}");
            return Ok(());
        }

        if std::env::var_os("KUTUP_DEVICE_KEY").is_some() {
            bail!("KUTUP_DEVICE_KEY is set: the service could not read your sign-in without it, and it is not written into the service. Sign in without it (kutup login) first");
        }
        // A service has no prompt: the vaults must open with the keys kept
        // in the account.
        if crate::context::require_session(profile).is_err() {
            bail!("sign in first (kutup login): the agent started at login opens your vaults with the keys your account keeps");
        }
        let mut keys = VaultKeys::account_only();
        let source = Source::open(profile, &local_dir, &args.collection_id, &mut keys)?;
        let (loaded, notes, _) = source.load(&mut keys, false);
        for note in &notes {
            eprintln!("  {note}");
        }
        if !notes.is_empty() {
            eprintln!("  A vault that does not open here will not open at login either: keep its key in your account with `kutup pass keep <file-id>`.");
        }
        if !args.no_confirm && Asker::find().is_none() {
            bail!("nothing to ask with on this desktop: install zenity or kdialog, set SSH_ASKPASS to an askpass program, or install with --no-confirm");
        }
        if !service::is_running() && UnixStream::connect(&socket).is_ok() {
            bail!(
                "an agent already serves {}; stop it first (the one started by hand)",
                socket.display()
            );
        }
        let file = service::install(&text, true)?;
        println!("Installed {}", file.display());
        println!(
            "The Kutup SSH agent now starts at login, serving {} key(s) on {}, asking {}.",
            loaded.len(),
            socket.display(),
            if args.no_confirm {
                "only for forwarded requests"
            } else {
                "in a desktop dialog before each use"
            }
        );
        println!();
        println!("To use it, add to your shell's profile (~/.bashrc, ~/.zshrc):");
        println!("  export SSH_AUTH_SOCK=\"{}\"", socket.display());
        println!("or, for ssh alone, to ~/.ssh/config:");
        println!("  Host *");
        println!("    IdentityAgent \"{}\"", socket.display());
        if insecure_tls.is_some() {
            println!();
            println!("Note: KUTUP_INSECURE_TLS is set, so the service also accepts your server's certificate unchecked.");
        }
        if program.components().any(|c| c.as_os_str() == "target") {
            println!();
            println!(
                "Note: this runs {}; install again after moving or rebuilding it.",
                program.display()
            );
        }
        if let Some(other) = other_agent(&socket) {
            println!();
            println!("This shell uses another agent now ({other}); its keys are not the vault's.");
        }
        if cfg!(target_os = "linux") && !args.no_confirm && !systemd_has_display() {
            println!();
            println!("Your service manager has no display yet, so dialogs cannot show. If yours does not pass it on, run once per login:");
            println!("  systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY");
        }
        Ok(())
    }

    /// Whether systemd's user manager passes a display to its services.
    fn systemd_has_display() -> bool {
        std::process::Command::new("systemctl")
            .args(["--user", "show-environment"])
            .output()
            .is_ok_and(|out| {
                String::from_utf8_lossy(&out.stdout).lines().any(|line| {
                    line.starts_with("DISPLAY=") || line.starts_with("WAYLAND_DISPLAY=")
                })
            })
    }

    fn uninstall(json: bool) -> Result<()> {
        let removed = service::uninstall()?;
        if json {
            crate::output::print_json(&serde_json::json!({ "removed": removed }))?;
        } else if removed {
            println!("Removed; the Kutup SSH agent no longer starts at login.");
        } else {
            println!("The Kutup SSH agent was not installed.");
        }
        Ok(())
    }

    fn status(json: bool) -> Result<()> {
        let file = service::service_file()?;
        let installed = std::fs::read_to_string(&file).ok();
        let arguments = installed.as_deref().and_then(service::installed_arguments);
        let socket = arguments
            .as_deref()
            .and_then(|args| service::flag_value(args, "--socket"))
            .map(PathBuf::from)
            .unwrap_or_else(server::default_socket);
        let running = installed.is_some() && service::is_running();
        let keys = listed_keys(&socket);
        let other = other_agent(&socket);
        if json {
            crate::output::print_json(&serde_json::json!({
                "installed": installed.is_some(),
                "serviceFile": file,
                "running": running,
                "socket": socket,
                "serving": keys.is_some(),
                "keys": keys,
                "folder": arguments.as_deref().and_then(|a| a.get(4)),
                "shellUsesAnotherAgent": other,
            }))?;
            return Ok(());
        }
        match &installed {
            Some(_) => println!(
                "Installed ({}), {}",
                file.display(),
                if running { "running" } else { "not running" }
            ),
            None => println!("Not installed (kutup ssh-agent install <folder> <collection>)"),
        }
        if let Some(folder) = arguments.as_deref().and_then(|a| a.get(4)) {
            println!("Vaults from {folder}");
        }
        match keys {
            Some(count) => println!("Serving {count} key(s) on {}", socket.display()),
            None => println!("Nothing serves {}", socket.display()),
        }
        if let Some(other) = other {
            println!("This shell uses another agent ({other}); set SSH_AUTH_SOCK=\"{}\" to use this one.", socket.display());
        }
        Ok(())
    }

    pub fn add(profile: &str, json: bool, args: &AddArgs) -> Result<()> {
        let mut keys = VaultKeys::from_env()?;
        let source = Source::open(profile, &args.local_dir, &args.collection_id, &mut keys)?;
        let (loaded, notes, _) = source.load(&mut keys, true);
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
