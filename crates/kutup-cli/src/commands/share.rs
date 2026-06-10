//! `kutup share` — folder/federated/public sharing + federated browse/upload.
//! Mirrors `cmd/share.go`, `share_files.go`, `share_incoming.go`, `share_upload.go`.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use clap::Subcommand;
use rand::RngCore;
use serde::Serialize;

use crate::api::federation::IncomingShare;
use crate::api::{FederatedShareRequest, FileMetadata, PublicShareRequest, ShareRequest};
use crate::commands::prompt_line;
use crate::context::{require_session, Ctx};
use crate::cryptohelpers::{decrypt_collection_key, decrypt_collections, find_collection};
use crate::session::Session;
use kutup_crypto::{sealedbox, secretbox, stream};

#[derive(Subcommand)]
pub enum ShareCmd {
    /// Share a folder with a Kutup user.
    Folder {
        collection_id: String,
        email: String,
        #[arg(long)]
        upload: bool,
        #[arg(long)]
        delete: bool,
    },
    /// Share a folder with a user on another Kutup server (user@server-url).
    Federated {
        collection_id: String,
        target: String,
        #[arg(long)]
        upload: bool,
        #[arg(long)]
        delete: bool,
    },
    /// Create a public link for a folder.
    Public { collection_id: String },
    /// List files inside an accepted federated share.
    Files { share_id: String },
    /// Download a file from a federated share.
    Download {
        share_id: String,
        file_id: String,
        dest: Option<String>,
    },
    /// Upload a file to a federated share you've accepted.
    Upload { share_id: String, path: String },
    /// List, accept, or remove federated shares received from other servers.
    Incoming {
        #[command(subcommand)]
        command: IncomingCmd,
    },
}

#[derive(Subcommand)]
pub enum IncomingCmd {
    /// List federated shares accepted on this account.
    List,
    /// Accept a federated share invite (URL of the form .../invite/{token}).
    Accept { invite_url: String },
    /// Forget a federated share (doesn't notify the remote owner).
    Remove {
        share_id: String,
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(profile: &str, json: bool, cmd: &ShareCmd) -> Result<()> {
    match cmd {
        ShareCmd::Folder {
            collection_id,
            email,
            upload,
            delete,
        } => share_folder(profile, json, collection_id, email, *upload, *delete),
        ShareCmd::Federated {
            collection_id,
            target,
            upload,
            delete,
        } => share_federated(profile, json, collection_id, target, *upload, *delete),
        ShareCmd::Public { collection_id } => share_public(profile, json, collection_id),
        ShareCmd::Files { share_id } => share_files(profile, json, share_id),
        ShareCmd::Download {
            share_id,
            file_id,
            dest,
        } => share_download(profile, json, share_id, file_id, dest.as_deref()),
        ShareCmd::Upload { share_id, path } => share_upload(profile, json, share_id, path),
        ShareCmd::Incoming { command } => match command {
            IncomingCmd::List => incoming_list(profile, json),
            IncomingCmd::Accept { invite_url } => incoming_accept(profile, json, invite_url),
            IncomingCmd::Remove { share_id, yes } => incoming_remove(profile, json, share_id, *yes),
        },
    }
}

/// Looks up an owned collection and returns its unwrapped key.
fn owned_collection_key(ctx: &Ctx, collection_id: &str) -> Result<Vec<u8>> {
    let master_key = ctx.session.master_key_bytes()?;
    let cols = decrypt_collections(ctx.client.list_collections()?, &master_key, &ctx.session);
    let col = find_collection(&cols, collection_id)
        .ok_or_else(|| anyhow!("collection {collection_id} not found"))?;
    decrypt_collection_key(col, &master_key, &ctx.session).context("decrypt collection key")
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn share_folder(
    profile: &str,
    json: bool,
    collection_id: &str,
    email: &str,
    upload: bool,
    delete: bool,
) -> Result<()> {
    let ctx = require_session(profile)?;
    let collection_key = owned_collection_key(&ctx, collection_id)?;

    let recipient = ctx
        .client
        .get_user_by_email(email)
        .with_context(|| format!("look up user {email}"))?;
    let recipient_pub = b64()
        .decode(&recipient.public_key)
        .context("decode recipient public key")?;
    let sealed = sealedbox::seal_anonymous(&collection_key, &recipient_pub)
        .context("seal collection key")?;

    ctx.client
        .share_collection(
            collection_id,
            &ShareRequest {
                recipient_user_id: recipient.user_id,
                encrypted_collection_key: b64().encode(&sealed),
                can_upload: upload,
                can_delete: delete,
                upload_quota_bytes: None,
            },
        )
        .context("share")?;

    if json {
        println!(
            "{}",
            serde_json::json!({ "shared": collection_id, "with": email })
        );
    } else {
        println!("Shared folder with {email}");
    }
    Ok(())
}

fn share_federated(
    profile: &str,
    json: bool,
    collection_id: &str,
    target: &str,
    upload: bool,
    delete: bool,
) -> Result<()> {
    let (username, server) = target
        .rsplit_once('@')
        .filter(|(u, _)| !u.is_empty())
        .ok_or_else(|| {
            anyhow!("format must be username@server-url (e.g. alice@https://other.com)")
        })?;

    let ctx = require_session(profile)?;
    let collection_key = owned_collection_key(&ctx, collection_id)?;

    let remote = ctx
        .client
        .get_fed_pubkey(username, server)
        .context("fetch remote public key")?;
    let recipient_pub = b64()
        .decode(&remote.public_key)
        .context("decode remote public key")?;
    let sealed = sealedbox::seal_anonymous(&collection_key, &recipient_pub)
        .context("seal collection key")?;

    let resp = ctx
        .client
        .share_federated(
            collection_id,
            &FederatedShareRequest {
                recipient_username: username.to_string(),
                recipient_server: server.to_string(),
                encrypted_collection_key: b64().encode(&sealed),
                can_upload: upload,
                can_delete: delete,
                upload_quota_bytes: None,
            },
        )
        .context("federated share")?;

    if json {
        println!("{}", serde_json::json!({ "inviteUrl": resp.invite_url }));
    } else {
        println!("Invite link (send to {target}):\n{}", resp.invite_url);
    }
    Ok(())
}

fn share_public(profile: &str, json: bool, collection_id: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    let collection_key = owned_collection_key(&ctx, collection_id)?;

    // Random link key — never sent to the server (lives in the URL fragment).
    let mut link_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut link_key);
    let (enc_key, key_nonce) = secretbox::seal(&collection_key, &link_key)?;

    let resp = ctx
        .client
        .create_public_share(&PublicShareRequest {
            share_type: "collection".into(),
            target_id: collection_id.to_string(),
            encrypted_collection_key: b64().encode(&enc_key),
            encrypted_collection_key_nonce: b64().encode(key_nonce),
            expires_in_hours: None,
        })
        .context("create public share")?;

    let share_url = format!(
        "{}/s/{}#key={}",
        ctx.session.server,
        resp.token,
        b64().encode(link_key)
    );
    if json {
        println!("{}", serde_json::json!({ "url": share_url }));
    } else {
        println!("Public link (the decryption key is in the URL fragment):");
        println!("{share_url}");
    }
    Ok(())
}

// --- federated browse / download / upload ---

#[derive(Serialize)]
struct FileDisplay {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "is_zero")]
    size: i64,
}
fn is_zero(v: &i64) -> bool {
    *v == 0
}

fn unwrap_shared_collection_key(s: &IncomingShare, sess: &Session) -> Result<Vec<u8>> {
    let enc = b64()
        .decode(&s.encrypted_collection_key)
        .context("collection key base64")?;
    let priv_k = sess.private_key_bytes()?;
    let pub_k = sess.public_key_bytes()?;
    sealedbox::open_anonymous(&enc, &pub_k, &priv_k).context("unseal collection key")
}

fn resolve_shared_collection_key(ctx: &Ctx, share_id: &str) -> Result<(IncomingShare, Vec<u8>)> {
    let shares = ctx.client.list_incoming_shares()?;
    let share = shares
        .into_iter()
        .find(|s| s.id == share_id)
        .ok_or_else(|| {
            anyhow!(
                "share {share_id} not in your accepted shares (run `kutup share incoming list`)"
            )
        })?;
    let key = unwrap_shared_collection_key(&share, &ctx.session)?;
    Ok((share, key))
}

fn decrypt_file_display(f: &crate::api::File, col_key: &[u8]) -> FileDisplay {
    let inner = || -> Result<(String, i64)> {
        let file_key = secretbox::open_b64(&f.encrypted_file_key, &f.file_key_nonce, col_key)?;
        let meta_bytes = secretbox::open_b64(&f.encrypted_metadata, &f.metadata_nonce, &file_key)?;
        let meta: FileMetadata = serde_json::from_slice(&meta_bytes)?;
        Ok((meta.name, meta.size))
    };
    match inner() {
        Ok((name, size)) => FileDisplay {
            id: f.id.clone(),
            name,
            size,
        },
        Err(_) => FileDisplay {
            id: f.id.clone(),
            name: "(undecryptable)".into(),
            size: 0,
        },
    }
}

fn print_file_table(out: &[FileDisplay], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(out)?);
        return Ok(());
    }
    if out.is_empty() {
        println!("(no files in this share)");
        return Ok(());
    }
    println!("{:<36}  {:>12}  NAME", "ID", "SIZE");
    for d in out {
        println!("{:<36}  {:>12}  {}", d.id, d.size, d.name);
    }
    Ok(())
}

fn share_files(profile: &str, json: bool, share_id: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    let (_, col_key) = resolve_shared_collection_key(&ctx, share_id)?;
    let files = ctx.client.proxy_list_files(share_id)?;
    let out: Vec<FileDisplay> = files
        .iter()
        .map(|f| decrypt_file_display(f, &col_key))
        .collect();
    print_file_table(&out, json)
}

fn share_download(
    profile: &str,
    json: bool,
    share_id: &str,
    file_id: &str,
    dest: Option<&str>,
) -> Result<()> {
    let dest_dir = dest.unwrap_or(".");
    let ctx = require_session(profile)?;
    let (_, col_key) = resolve_shared_collection_key(&ctx, share_id)?;

    let files = ctx.client.proxy_list_files(share_id)?;
    let target = files
        .iter()
        .find(|f| f.id == file_id)
        .ok_or_else(|| anyhow!("file {file_id} not found in share {share_id}"))?;

    let file_key =
        secretbox::open_b64(&target.encrypted_file_key, &target.file_key_nonce, &col_key)
            .context("decrypt file key")?;
    let meta_bytes = secretbox::open_b64(
        &target.encrypted_metadata,
        &target.metadata_nonce,
        &file_key,
    )
    .context("decrypt metadata")?;
    let meta: FileMetadata = serde_json::from_slice(&meta_bytes).unwrap_or_default();

    let encrypted = ctx.client.proxy_download(share_id, file_id)?;
    let plain = stream::decrypt_stream(&encrypted, &file_key).context("decrypt")?;

    let dest_path = resolve_dest(dest_dir, &meta.name);
    std::fs::write(&dest_path, &plain)?;

    let dest_str = dest_path.to_string_lossy().into_owned();
    if json {
        println!(
            "{}",
            serde_json::json!({ "shareId": share_id, "fileId": file_id, "size": plain.len(), "dest": dest_str })
        );
    } else {
        println!("Downloaded {} → {dest_str}", meta.name);
    }
    Ok(())
}

fn share_upload(profile: &str, json: bool, share_id: &str, path: &str) -> Result<()> {
    let meta_fs = std::fs::metadata(path)?;
    if meta_fs.is_dir() {
        bail!("federated shares are flat (no sub-folders) — upload one file at a time");
    }

    let ctx = require_session(profile)?;
    let (share, col_key) = resolve_shared_collection_key(&ctx, share_id)?;
    if !share.can_upload {
        bail!("share {share_id} doesn't permit uploads (request can_upload from the owner)");
    }

    let data = std::fs::read(path).context("read local file")?;
    let mut file_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut file_key);
    let encrypted = stream::encrypt_stream(&data, &file_key).context("encrypt content")?;

    // Wrap the file key under the share's unwrapped collection key.
    let (enc_file_key, file_key_nonce) =
        secretbox::seal(&file_key, &col_key).context("wrap file key")?;

    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let meta = FileMetadata {
        name: name.clone(),
        mime_type: guess_mime(Path::new(path)).to_string(),
        size: data.len() as i64,
    };
    let meta_bytes = serde_json::to_vec(&meta)?;
    let (enc_meta, meta_nonce) =
        secretbox::seal(&meta_bytes, &file_key).context("encrypt metadata")?;

    let e = b64();
    let resp = ctx
        .client
        .proxy_upload_file(
            share_id,
            &e.encode(&enc_meta),
            &e.encode(meta_nonce),
            &e.encode(&enc_file_key),
            &e.encode(file_key_nonce),
            encrypted,
        )
        .map_err(|err| {
            let msg = err.to_string();
            if msg.contains("HTTP 403") {
                anyhow!("share doesn't permit uploads (server: {msg})")
            } else if msg.contains("HTTP 413") {
                anyhow!("share upload quota exceeded (server: {msg})")
            } else {
                anyhow!("upload: {msg}")
            }
        })?;

    if json {
        println!(
            "{}",
            serde_json::json!({ "shareId": share_id, "fileId": resp.id, "name": meta.name, "size": meta.size })
        );
    } else if resp.id.is_empty() {
        println!("Uploaded {name} → share {share_id}");
    } else {
        println!("Uploaded {name} → share {share_id} (file {})", resp.id);
    }
    Ok(())
}

// --- incoming ---

#[derive(Serialize)]
struct IncomingDisplay {
    id: String,
    #[serde(rename = "remoteServer")]
    remote_server: String,
    name: String,
    #[serde(rename = "canUpload")]
    can_upload: bool,
    #[serde(rename = "canDelete")]
    can_delete: bool,
    #[serde(rename = "createdAt")]
    created_at: String,
}

fn decrypt_incoming_name(s: &IncomingShare, sess: &Session) -> Result<String> {
    let col_key = unwrap_shared_collection_key(s, sess)?;
    let name = secretbox::open_b64(&s.encrypted_name, &s.name_nonce, &col_key)?;
    Ok(String::from_utf8_lossy(&name).into_owned())
}

fn incoming_list(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let shares = ctx.client.list_incoming_shares()?;

    let out: Vec<IncomingDisplay> = shares
        .iter()
        .map(|s| IncomingDisplay {
            id: s.id.clone(),
            remote_server: s.remote_server.clone(),
            name: decrypt_incoming_name(s, &ctx.session)
                .unwrap_or_else(|_| "(undecryptable)".into()),
            can_upload: s.can_upload,
            can_delete: s.can_delete,
            created_at: s.created_at.clone(),
        })
        .collect();

    if json {
        println!("{}", serde_json::to_string(&out)?);
        return Ok(());
    }
    if out.is_empty() {
        println!("(no incoming federated shares)");
        return Ok(());
    }
    println!("{:<36}  {:<30}  {:<30}  PERMS", "ID", "REMOTE", "NAME");
    for d in &out {
        let mut perms = String::new();
        if d.can_upload {
            perms.push_str("upload ");
        }
        if d.can_delete {
            perms.push_str("delete");
        }
        if perms.is_empty() {
            perms = "read-only".into();
        }
        println!(
            "{:<36}  {:<30}  {:<30}  {}",
            d.id, d.remote_server, d.name, perms
        );
    }
    Ok(())
}

fn incoming_accept(profile: &str, json: bool, invite_url: &str) -> Result<()> {
    if !invite_url.contains("/invite/") {
        bail!("invalid invite URL: must contain /invite/");
    }
    let ctx = require_session(profile)?;
    let share = ctx.client.add_incoming_share(invite_url)?;
    if json {
        println!("{}", serde_json::to_string(&share)?);
    } else {
        println!(
            "Accepted federated share {} from {}",
            share.id, share.remote_server
        );
    }
    Ok(())
}

fn incoming_remove(profile: &str, json: bool, share_id: &str, yes: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    if !yes {
        let ans = prompt_line(&format!(
            "Remove incoming share {share_id}? This forgets your local pointer; the remote owner is not notified. [y/N]: "
        ))?
        .to_lowercase();
        if ans != "y" && ans != "yes" {
            bail!("aborted");
        }
    }
    ctx.client.remove_incoming_share(share_id)?;
    if json {
        println!(
            "{}",
            serde_json::json!({ "shareId": share_id, "removed": true })
        );
    } else {
        println!("Removed incoming share {share_id}");
    }
    Ok(())
}

fn resolve_dest(dest_dir: &str, name: &str) -> std::path::PathBuf {
    let p = Path::new(dest_dir);
    if p.is_dir() {
        p.join(name)
    } else {
        p.to_path_buf()
    }
}

/// Mirrors `guessMIMEFromPath` (with .zip).
fn guess_mime(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("mp4") => "video/mp4",
        Some("mp3") => "audio/mpeg",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}
