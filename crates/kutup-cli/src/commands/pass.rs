//! `kutup pass` — Kutup Pass vault secrets (docs/plans/pass.md, "Vault
//! secrets"): keep a vault's key in the account so Kutup Pass and
//! `kutup sync` open the vault with the Kutup sign-in, list them, forget one.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;

use crate::context::require_session;
use crate::cryptohelpers::{decrypt_file_meta, locate_file, FoundFile};
use crate::output::print_json;
use crate::vaultsync::{fetch_current, keep_secret, VaultFile};

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
        PassCmd::Forget { file_id } => forget(profile, json, file_id),
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeptVault {
    file_id: String,
    name: String,
}

fn ls(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let mut vaults = Vec::new();
    for row in ctx.client.list_vault_secrets()? {
        let name = locate(&ctx, &row.file_id)
            .map(|found| decrypt_file_meta(&found.file, &found.keys).0)
            .unwrap_or_else(|_| "[not found]".to_owned());
        vaults.push(KeptVault {
            file_id: row.file_id,
            name,
        });
    }
    if json {
        print_json(&vaults)?;
    } else if vaults.is_empty() {
        println!("No vault keys kept.");
    } else {
        for vault in vaults {
            println!("{}  {}", vault.file_id, vault.name);
        }
    }
    Ok(())
}

fn forget(profile: &str, json: bool, file_id: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    ctx.client.delete_vault_secret(file_id)?;
    if json {
        print_json(&serde_json::json!({ "fileId": file_id, "forgotten": true }))?;
    } else {
        println!("Forgot the key of vault {file_id}.");
    }
    Ok(())
}
