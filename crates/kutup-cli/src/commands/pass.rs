//! `kutup pass` — Kutup Pass vault secrets (docs/plans/pass.md, "Vault
//! secrets"): keep a vault's key in the account so Kutup Pass and
//! `kutup sync` open the vault with the Kutup sign-in, list them, forget one,
//! and show a key Kutup Pass generated (for KeePassXC).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;

use crate::context::require_session;
use crate::cryptohelpers::{decrypt_file_meta, locate_file, FoundFile};
use crate::output::print_json;
use crate::vaultsync::{fetch_current, forget_secret, keep_secret, verified_secrets, VaultFile};

#[derive(Subcommand)]
pub enum PassCmd {
    /// Keep a vault's key in your account (KUTUP_VAULT_PASSWORD, or a prompt;
    /// a key file with --key-file or KUTUP_VAULT_KEY_FILE).
    Keep {
        /// The vault's file id.
        file_id: String,
        /// The vault's key file.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// The vault has a key file and no password.
        #[arg(long)]
        no_password: bool,
    },
    /// List the vaults whose keys your account keeps.
    Ls,
    /// Forget a vault's key (the vault itself is untouched).
    Forget {
        /// The vault's file id.
        file_id: String,
        /// Forget a key Kutup Pass generated too (the account may be the only
        /// place it is kept: save it first with `kutup pass show-key`).
        #[arg(long)]
        force: bool,
    },
    /// Show the key Kutup Pass generated for a vault, to open it in KeePassXC.
    ShowKey {
        /// The vault's file id.
        file_id: String,
    },
}

pub fn run(profile: &str, json: bool, cmd: &PassCmd) -> Result<()> {
    match cmd {
        PassCmd::Keep {
            file_id,
            key_file,
            no_password,
        } => keep(profile, json, file_id, key_file.as_ref(), *no_password),
        PassCmd::Ls => ls(profile, json),
        PassCmd::Forget { file_id, force } => forget(profile, json, file_id, *force),
        PassCmd::ShowKey { file_id } => show_key(profile, json, file_id),
    }
}

fn locate(ctx: &crate::context::Ctx, file_id: &str) -> Result<FoundFile> {
    let master_key = ctx.session.master_key_bytes()?;
    let cols = ctx.client.list_collections()?;
    locate_file(&ctx.client, &master_key, &ctx.session, &cols, file_id)
}

fn keep(
    profile: &str,
    json: bool,
    file_id: &str,
    key_file: Option<&PathBuf>,
    no_password: bool,
) -> Result<()> {
    let ctx = require_session(profile)?;
    let found = locate(&ctx, file_id)?;
    let vault = VaultFile {
        file_id,
        collection_id: &found.collection.id,
        folder_epoch: found.collection.key_epoch,
        keys: &found.keys,
    };
    let (contents, _) = fetch_current(&ctx.client, &vault)?;
    let key_file = match key_file
        .cloned()
        .or_else(|| std::env::var_os("KUTUP_VAULT_KEY_FILE").map(PathBuf::from))
    {
        Some(path) => Some(
            std::fs::read(&path).with_context(|| format!("read key file {}", path.display()))?,
        ),
        None => None,
    };
    let password = if no_password {
        None
    } else {
        Some(zeroize::Zeroizing::new(
            match std::env::var("KUTUP_VAULT_PASSWORD") {
                Ok(password) => password,
                Err(_) => rpassword::prompt_password("Vault password: ")?,
            },
        ))
    };
    let master_key = ctx.session.master_key_bytes()?;
    keep_secret(
        &ctx.client,
        &master_key,
        ctx.session.binding(),
        &crate::config::data_dir(profile)?,
        file_id,
        &contents,
        password.as_deref().map(String::as_str),
        key_file.as_deref(),
    )?;
    let (name, _) = decrypt_file_meta(&found.file, &found.keys);
    if json {
        print_json(&serde_json::json!({ "fileId": file_id, "name": name, "kept": true }))?;
    } else {
        println!("Kept the key of {name}: Kutup Pass and sync open it with your sign-in.");
    }
    Ok(())
}

/// The account's vault secrets, held to the account head.
fn secrets(
    ctx: &crate::context::Ctx,
    profile: &str,
) -> Result<Vec<crate::api::pass::VaultSecretRow>> {
    verified_secrets(
        &ctx.client,
        &ctx.session.master_key_bytes()?,
        ctx.session.binding(),
        &crate::config::data_dir(profile)?,
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeptVault {
    file_id: String,
    name: String,
    /// What has become of the vault: only an open one's key is used.
    state: crate::api::pass::VaultSecretState,
}

fn ls(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let mut vaults = Vec::new();
    for row in secrets(&ctx, profile)? {
        let name = locate(&ctx, &row.file_id)
            .map(|found| decrypt_file_meta(&found.file, &found.keys).0)
            .unwrap_or_else(|_| "[not found]".to_owned());
        vaults.push(KeptVault {
            file_id: row.file_id,
            name,
            state: row.state,
        });
    }
    if json {
        print_json(&vaults)?;
    } else if vaults.is_empty() {
        println!("No vault keys kept.");
    } else {
        use crate::api::pass::VaultSecretState;
        for vault in vaults {
            let note = match vault.state {
                VaultSecretState::Open => "",
                VaultSecretState::Trashed => "  (in the trash)",
                VaultSecretState::Unreachable => "  (not shared with you now)",
                VaultSecretState::Gone => "  (deleted for good: `kutup pass forget` it)",
            };
            println!("{}  {}{note}", vault.file_id, vault.name);
        }
    }
    Ok(())
}

fn forget(profile: &str, json: bool, file_id: &str, force: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    if !force {
        // A generated key may be kept nowhere else: forgetting it would lose
        // the vault. Not knowing counts as generated.
        if let Some(row) = secrets(&ctx, profile)?
            .into_iter()
            .find(|row| row.file_id == file_id)
        {
            let generated = kutup_crypto::account_envelope::decode_canonical_b64(&row.envelope)
                .ok()
                .zip(uuid::Uuid::parse_str(file_id).ok())
                .and_then(|(envelope, id)| {
                    kutup_pass::kept::open(
                        &envelope,
                        &ctx.session.master_key_bytes().ok()?,
                        ctx.session.binding(),
                        id.as_bytes(),
                    )
                    .ok()
                })
                .is_none_or(|kept| kept.generated_password.is_some());
            if generated {
                anyhow::bail!(
                    "Kutup Pass made this vault's key, and your account may be the only place it is kept: \
                     save it first (kutup pass show-key {file_id}), then forget it with --force"
                );
            }
        }
    }
    forget_secret(
        &ctx.client,
        &ctx.session.master_key_bytes()?,
        ctx.session.binding(),
        &crate::config::data_dir(profile)?,
        file_id,
    )?;
    if json {
        print_json(&serde_json::json!({ "fileId": file_id, "forgotten": true }))?;
    } else {
        println!("Forgot the key of vault {file_id}.");
    }
    Ok(())
}

/// The password Kutup Pass generated for a vault (docs/plans/pass.md,
/// "Vault keys"). A password the person chose is kept only as its hash, so
/// there is nothing to show for it.
fn show_key(profile: &str, json: bool, file_id: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    let row = secrets(&ctx, profile)?
        .into_iter()
        .find(|row| row.file_id == file_id)
        .ok_or_else(|| anyhow::anyhow!("your account keeps no key for vault {file_id}"))?;
    let envelope = kutup_crypto::account_envelope::decode_canonical_b64(&row.envelope)?;
    let id = uuid::Uuid::parse_str(file_id).context("a vault's file id is a UUID")?;
    let kept = kutup_pass::kept::open(
        &envelope,
        &ctx.session.master_key_bytes()?,
        ctx.session.binding(),
        id.as_bytes(),
    )
    .context("the kept key does not open")?;
    let Some(password) = kept.generated_password else {
        anyhow::bail!(
            "Kutup Pass did not make this vault's key: it opens with the password chosen for it"
        );
    };
    if json {
        print_json(&serde_json::json!({ "fileId": file_id, "key": password.as_str() }))?;
    } else {
        println!("{}", password.as_str());
    }
    Ok(())
}
