//! `kutup share` — folder/federated/public sharing + federated browse/upload.
//! Mirrors `cmd/share.go`, `share_files.go`, `share_incoming.go`, `share_upload.go`.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use clap::Subcommand;
use rand::RngCore;
use serde::Serialize;

use crate::api::federation::IncomingShare;
use crate::api::{
    ApiError, Collection, FederatedShareRequest, FileMetadata, PublicShareRequest, ShareRequest,
};
use crate::commands::confirm;
use crate::context::{require_session, Ctx};
use crate::cryptohelpers::{decrypt_collection_key, decrypt_collections, find_collection};
use crate::errors::NotFound;
use crate::session::Session;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};

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
    /// Share a folder with a user on another Kutup server (user@server).
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
    /// Accept a federated share invite (capability is carried in the URL fragment).
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

/// Looks up an owned collection and returns its record plus unwrapped key.
fn owned_collection(ctx: &Ctx, collection_id: &str) -> Result<(Collection, Vec<u8>)> {
    let master_key = ctx.session.master_key_bytes()?;
    let cols = decrypt_collections(ctx.client.list_collections()?, &master_key, &ctx.session);
    let col = find_collection(&cols, collection_id)
        .ok_or_else(|| NotFound(format!("collection {collection_id} not found")))?;
    let key =
        decrypt_collection_key(col, &master_key, &ctx.session).context("decrypt collection key")?;
    Ok((col.clone(), key))
}

fn owned_collection_key(ctx: &Ctx, collection_id: &str) -> Result<Vec<u8>> {
    Ok(owned_collection(ctx, collection_id)?.1)
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
    let master_key = ctx.session.master_key_bytes()?;
    let master_key_array: &[u8; 32] = master_key
        .as_slice()
        .try_into()
        .context("master key must be 32 bytes")?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(master_key_array)?;
    let (_, domain) = recipient
        .account
        .split_once('@')
        .ok_or_else(|| anyhow!("recipient account is invalid"))?;
    let envelope = kutup_crypto::named_share::NamedShareEnvelopeV1::seal(
        &collection_key,
        collection_id,
        ctx.client
            .list_collections()?
            .into_iter()
            .find(|collection| collection.id == collection_id)
            .ok_or_else(|| NotFound(format!("collection {collection_id} not found")))?
            .key_epoch,
        &format!("{}@{domain}", ctx.session.username),
        &identity.incarnation_id(),
        identity.drive_signing_key(),
        &recipient.account,
        &recipient.account_incarnation_id,
        &b64()
            .decode(&recipient.drive_hpke_public_key)
            .context("decode recipient HPKE public key")?,
    )?;

    ctx.client
        .share_collection(
            collection_id,
            &ShareRequest {
                recipient_user_id: recipient.user_id,
                named_share_envelope: envelope.encode_b64()?,
                can_upload: upload,
                can_delete: delete,
                upload_quota_bytes: None,
            },
        )
        .context("share")?;

    if json {
        crate::output::print_json(&serde_json::json!({ "shared": collection_id, "with": email }))?;
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
        .ok_or_else(|| anyhow!("format must be username@server (e.g. alice@other.example)"))?;

    let ctx = require_session(profile)?;
    let collection_key = owned_collection_key(&ctx, collection_id)?;

    let remote = ctx
        .client
        .get_fed_pubkey(username, server)
        .context("fetch remote public key")?;
    let collection = ctx
        .client
        .list_collections()?
        .into_iter()
        .find(|collection| collection.id == collection_id)
        .ok_or_else(|| NotFound(format!("collection {collection_id} not found")))?;
    let master_key = ctx.session.master_key_bytes()?;
    let master_key_array: &[u8; 32] = master_key
        .as_slice()
        .try_into()
        .context("master key must be 32 bytes")?;
    let identity = kutup_crypto::identity::AccountIdentityKeysV1::derive(master_key_array)?;
    let local_domain = ctx.client.settings()?.chat.server_name;
    let envelope = kutup_crypto::named_share::NamedShareEnvelopeV1::seal(
        &collection_key,
        collection_id,
        collection.key_epoch,
        &format!("{}@{local_domain}", ctx.session.username),
        &identity.incarnation_id(),
        identity.drive_signing_key(),
        &remote.account,
        &remote.account_incarnation_id,
        &b64()
            .decode(&remote.drive_hpke_public_key)
            .context("decode remote HPKE public key")?,
    )?;

    let resp = ctx
        .client
        .share_federated(
            collection_id,
            &FederatedShareRequest {
                recipient_username: username.to_string(),
                recipient_server: server.to_string(),
                named_share_envelope: envelope.encode_b64()?,
                can_upload: upload,
                can_delete: delete,
                upload_quota_bytes: None,
            },
        )
        .context("federated share")?;

    if json {
        crate::output::print_json(&serde_json::json!({ "inviteUrl": resp.invite_url }))?;
    } else {
        println!("Invite link (send to {target}):\n{}", resp.invite_url);
    }
    Ok(())
}

fn share_public(profile: &str, json: bool, collection_id: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    let (collection, collection_key) = owned_collection(&ctx, collection_id)?;

    // Random link key — never sent to the server (lives in the URL fragment).
    let mut link_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut link_key);
    let envelope_context = DriveEnvelopeContextV1::new(
        DriveEnvelopePurpose::PublicLinkCollectionKey,
        collection.key_epoch,
        1,
        collection_id,
        &ctx.session.user_id,
    )?;
    let collection_key_envelope =
        drive_envelope::seal_b64(&collection_key, &link_key, envelope_context)?;

    let resp = ctx
        .client
        .create_public_share(&PublicShareRequest {
            share_type: "collection".into(),
            target_id: collection_id.to_string(),
            collection_key_envelope,
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
        crate::output::print_json(&serde_json::json!({ "url": share_url }))?;
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
    let collection = crate::api::Collection {
        id: s.remote_collection_id.clone(),
        owner_user_id: s.owner_user_id.clone(),
        name_envelope: s.name_envelope.clone(),
        owner_key_envelope: None,
        named_share_envelope: Some(s.named_share_envelope.clone()),
        key_epoch: s.key_epoch,
        name_revision: s.name_revision,
        epoch_statement: s.epoch_statement.clone(),
        epoch_statement_hash: s.epoch_statement_hash.clone(),
        owner_account: Some(s.owner_account.clone()),
        owner_incarnation_id: Some(s.owner_incarnation_id.clone()),
        owner_drive_signing_public_key: Some(s.owner_signing_public_key.clone()),
        owner_authority_public_key: Some(s.owner_authority_public_key.clone()),
        parent_collection_id: None,
        color: None,
        is_shared: true,
        is_remote: true,
        can_upload: s.can_upload,
        can_delete: s.can_delete,
        upload_quota_bytes: s.upload_quota_bytes,
        name: String::new(),
    };
    crate::collection_crypto::open_key(&collection, &sess.master_key_bytes()?, sess)
}

fn resolve_shared_collection_key(ctx: &Ctx, share_id: &str) -> Result<(IncomingShare, Vec<u8>)> {
    let shares = ctx.client.list_incoming_shares()?;
    let share = shares
        .into_iter()
        .find(|s| s.id == share_id)
        .ok_or_else(|| {
            NotFound(format!(
                "share {share_id} not in your accepted shares (run `kutup share incoming list`)"
            ))
        })?;
    let key = unwrap_shared_collection_key(&share, &ctx.session)?;
    Ok((share, key))
}

fn decrypt_file_display(f: &crate::api::File, col_key: &[u8]) -> FileDisplay {
    match crate::file_crypto::open(f, col_key) {
        Ok((_, meta)) => FileDisplay {
            id: f.id.clone(),
            name: meta.name,
            size: meta.size,
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
        crate::output::print_json(&out)?;
        return Ok(());
    }
    if out.is_empty() {
        println!("(no files in this share)");
        return Ok(());
    }
    println!(
        "{}",
        crate::output::header(format!("{:<36}  {:>12}  NAME", "ID", "SIZE"))
    );
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
        .ok_or_else(|| NotFound(format!("file {file_id} not found in share {share_id}")))?;

    let (file_key, meta) =
        crate::file_crypto::open(target, &col_key).context("decrypt file record")?;

    let dest_path = resolve_dest(dest_dir, &meta.name);
    let resp = ctx.client.proxy_download_stream(share_id, file_id)?;
    let bar = crate::output::progress_bar(resp.content_length(), &meta.name);
    let mut out = std::fs::File::create(&dest_path).context("open dest")?;
    let blob_context =
        DriveFileBlobContextV1::new(&target.id, &target.collection_id, target.key_epoch)?;
    let written =
        match crate::transfer::stream_download(resp, &file_key, blob_context, &mut out, |n| {
            bar.set_position(n as u64)
        }) {
            Ok(w) => w,
            Err(e) => {
                drop(out);
                let _ = std::fs::remove_file(&dest_path);
                return Err(e).context("decrypt-write");
            }
        };
    bar.finish_and_clear();

    let dest_str = dest_path.to_string_lossy().into_owned();
    if json {
        crate::output::print_json(
            &serde_json::json!({ "shareId": share_id, "fileId": file_id, "size": written, "dest": dest_str }),
        )?;
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
    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let meta = FileMetadata {
        name: name.clone(),
        mime_type: crate::mimetype::guess_mime(Path::new(path)),
        size: data.len() as i64,
    };
    let record = crate::file_crypto::create(
        &share.remote_collection_id,
        share.key_epoch,
        &col_key,
        &meta,
    )?;
    let blob_context =
        DriveFileBlobContextV1::new(&record.id, &share.remote_collection_id, record.key_epoch)?;
    let encrypted = drive_object::encrypt_file_blob(&data, &record.file_key, blob_context)
        .context("encrypt content")?;
    let resp = ctx
        .client
        .proxy_upload_file(
            share_id,
            &record.id,
            &record.metadata_envelope,
            &record.file_key_envelope,
            encrypted,
        )
        .map_err(|err| {
            let hint = match err.downcast_ref::<ApiError>() {
                Some(e) if e.status == 403 => "share doesn't permit uploads",
                Some(e) if e.status == 413 => "share upload quota exceeded",
                _ => "upload",
            };
            err.context(hint)
        })?;
    if resp.id != record.id {
        bail!("federated server returned a different file id");
    }

    if json {
        crate::output::print_json(
            &serde_json::json!({ "shareId": share_id, "fileId": resp.id, "name": meta.name, "size": meta.size }),
        )?;
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
    #[serde(rename = "remoteDomain")]
    remote_domain: String,
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
    let collection = crate::api::Collection {
        id: s.remote_collection_id.clone(),
        owner_user_id: s.owner_user_id.clone(),
        name_envelope: s.name_envelope.clone(),
        owner_key_envelope: None,
        named_share_envelope: None,
        key_epoch: s.key_epoch,
        name_revision: s.name_revision,
        epoch_statement: s.epoch_statement.clone(),
        epoch_statement_hash: s.epoch_statement_hash.clone(),
        owner_account: None,
        owner_incarnation_id: None,
        owner_drive_signing_public_key: None,
        owner_authority_public_key: None,
        parent_collection_id: None,
        color: None,
        is_shared: true,
        is_remote: true,
        can_upload: s.can_upload,
        can_delete: s.can_delete,
        upload_quota_bytes: s.upload_quota_bytes,
        name: String::new(),
    };
    crate::collection_crypto::open_name(&collection, &col_key)
}

fn incoming_list(profile: &str, json: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let shares = ctx.client.list_incoming_shares()?;

    let out: Vec<IncomingDisplay> = shares
        .iter()
        .map(|s| IncomingDisplay {
            id: s.id.clone(),
            remote_domain: s.remote_domain.clone(),
            name: decrypt_incoming_name(s, &ctx.session)
                .unwrap_or_else(|_| "(undecryptable)".into()),
            can_upload: s.can_upload,
            can_delete: s.can_delete,
            created_at: s.created_at.clone(),
        })
        .collect();

    if json {
        crate::output::print_json(&out)?;
        return Ok(());
    }
    if out.is_empty() {
        println!("(no incoming federated shares)");
        return Ok(());
    }
    println!(
        "{}",
        crate::output::header(format!(
            "{:<36}  {:<30}  {:<30}  PERMS",
            "ID", "REMOTE", "NAME"
        ))
    );
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
            d.id, d.remote_domain, d.name, perms
        );
    }
    Ok(())
}

fn incoming_accept(profile: &str, json: bool, invite_url: &str) -> Result<()> {
    let invite = url::Url::parse(invite_url).context("invalid invite URL")?;
    if invite.path().trim_end_matches('/') != "/invite" {
        bail!("invalid invite URL: path must be /invite");
    }
    let fragment = invite
        .fragment()
        .ok_or_else(|| anyhow!("invalid invite URL: missing fragment"))?;
    let values: std::collections::HashMap<_, _> = url::form_urlencoded::parse(fragment.as_bytes())
        .into_owned()
        .collect();
    let server = values
        .get("server")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("invalid invite URL: missing server"))?;
    let capability = values
        .get("capability")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("invalid invite URL: missing capability"))?;
    let ctx = require_session(profile)?;
    let share = ctx.client.add_incoming_share(server, capability)?;
    if json {
        crate::output::print_json(&share)?;
    } else {
        println!(
            "Accepted federated share {} from {}",
            share.id, share.remote_domain
        );
    }
    Ok(())
}

fn incoming_remove(profile: &str, json: bool, share_id: &str, yes: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    confirm(
        &format!(
            "Remove incoming share {share_id}? This forgets your local pointer; the remote owner is not notified."
        ),
        yes,
    )?;
    ctx.client.remove_incoming_share(share_id)?;
    if json {
        crate::output::print_json(&serde_json::json!({ "shareId": share_id, "removed": true }))?;
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
