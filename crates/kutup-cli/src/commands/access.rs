//! `kutup share access` / `kutup share remove` — who can open a folder, and
//! taking that access away (docs/plans/drive-share-revocation.md).
//!
//! Removing anyone rotates the folder key: a new key, sealed to everyone who
//! stays, applied by the server in one request or not at all. The removed
//! party keeps what it already had; nothing written from now on is readable
//! to it.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

use crate::api::Collection;
use crate::context::{require_session, Ctx};
use crate::errors::NotFound;
use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::collection_keyring;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::named_share::NamedShareEnvelopeV1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Member {
    user_id: String,
    account: String,
    account_incarnation_id: String,
    drive_public_key: String,
    can_upload: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Link {
    id: String,
    token: String,
    owner_link_key_envelope: Option<String>,
    expires_at: Option<String>,
    created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Federated {
    id: String,
    recipient_username: String,
    recipient_server: String,
    recipient_incarnation_id: String,
    can_upload: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Access {
    key_epoch: u32,
    epoch_statement_hash: String,
    members: Vec<Member>,
    public_links: Vec<Link>,
    federated_shares: Vec<Federated>,
}

fn load_access(ctx: &Ctx, collection_id: &str) -> Result<Access> {
    let resp = ctx
        .client
        .get(&format!("/collections/{collection_id}/access"))?;
    crate::api::decode_json(resp).context("load folder access (owner only)")
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// `kutup share access <folder>`
pub fn list(profile: &str, json: bool, collection_id: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    let access = load_access(&ctx, collection_id)?;
    if json {
        return crate::output::print_json(&access);
    }
    println!("Folder key epoch {}", access.key_epoch);
    if access.members.is_empty()
        && access.federated_shares.is_empty()
        && access.public_links.is_empty()
    {
        println!("Only you can open this folder.");
        return Ok(());
    }
    for m in &access.members {
        let role = if m.can_upload { "can edit" } else { "can view" };
        println!("  member     {}  ({role})", m.account);
    }
    for f in &access.federated_shares {
        let role = if f.can_upload { "can edit" } else { "can view" };
        println!(
            "  federated  {}@{}  ({role})  id {}",
            f.recipient_username, f.recipient_server, f.id
        );
    }
    for l in &access.public_links {
        let note = if l.owner_link_key_envelope.is_some() {
            ""
        } else {
            "  (made before links could be kept; removing anyone removes it)"
        };
        println!("  link       {}  created {}{note}", l.id, l.created_at);
    }
    Ok(())
}

/// `kutup share remove <folder> <who>`: `who` is a member's account
/// (`name@server`), a federated recipient (`name@other-server`), or a
/// public link's id.
pub fn remove(profile: &str, json: bool, collection_id: &str, who: &str, yes: bool) -> Result<()> {
    let ctx = require_session(profile)?;
    let master_key = ctx.session.master_key_bytes()?;
    let master: &[u8; 32] = master_key
        .as_slice()
        .try_into()
        .context("master key must be 32 bytes")?;
    let identity = AccountIdentityKeysV1::derive(master)?;
    let cols = ctx.client.list_collections()?;
    let col: &Collection = cols
        .iter()
        .find(|c| c.id == collection_id)
        .ok_or_else(|| NotFound(format!("folder {collection_id} not found")))?;
    if col.is_shared {
        bail!("only the owner can remove access to a folder");
    }
    let key = crate::cryptohelpers::decrypt_collection_key(col, &master_key, &ctx.session)?;
    let name = crate::collection_crypto::open_name(col, &key)?;
    let access = load_access(&ctx, collection_id)?;
    if access.key_epoch != col.key_epoch || access.epoch_statement_hash != col.epoch_statement_hash
    {
        bail!("the folder's key changed meanwhile; run the command again");
    }

    let who_lower = who.to_lowercase();
    let removed_member: Vec<String> = access
        .members
        .iter()
        .filter(|m| m.account.to_lowercase() == who_lower || m.user_id == who)
        .map(|m| m.user_id.clone())
        .collect();
    let removed_federated: Vec<String> = access
        .federated_shares
        .iter()
        .filter(|f| {
            format!("{}@{}", f.recipient_username, f.recipient_server).to_lowercase() == who_lower
                || f.id == who
        })
        .map(|f| f.id.clone())
        .collect();
    let mut removed_links: Vec<String> = access
        .public_links
        .iter()
        .filter(|l| l.id == who)
        .map(|l| l.id.clone())
        .collect();
    if removed_member.is_empty() && removed_federated.is_empty() && removed_links.is_empty() {
        return Err(NotFound(format!("{who} does not have access to this folder")).into());
    }
    // Links the owner has no copy of cannot follow the key.
    let legacy: Vec<String> = access
        .public_links
        .iter()
        .filter(|l| l.owner_link_key_envelope.is_none() && !removed_links.contains(&l.id))
        .map(|l| l.id.clone())
        .collect();
    let prompt = if legacy.is_empty() {
        format!("Remove {who}? The folder moves to a new key they never get.")
    } else {
        format!(
            "Remove {who}? The folder moves to a new key they never get; {} older public link(s) are removed too.",
            legacy.len()
        )
    };
    crate::commands::confirm(&prompt, yes)?;
    removed_links.extend(legacy);

    // The next epoch.
    let next = col.key_epoch + 1;
    let mut new_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut new_key);
    let owner = &col.owner_user_id;
    let context =
        |purpose, revision| DriveEnvelopeContextV1::new(purpose, next, revision, &col.id, owner);
    let statement = CollectionEpochStatementV1::create(
        &col.id,
        owner,
        next,
        Some(&col.epoch_statement_hash),
        &new_key,
        identity.authority_signing_key(),
    )?;
    let owner_key_envelope = drive_envelope::seal_b64(
        &new_key,
        master,
        context(DriveEnvelopePurpose::CollectionKey, 1)?,
    )?;
    let previous_key_envelope =
        collection_keyring::seal_previous_key(&key, &new_key, &col.id, owner, next)?;
    let name_envelope = drive_envelope::seal_b64(
        name.as_bytes(),
        &new_key,
        context(DriveEnvelopePurpose::CollectionName, col.name_revision + 1)?,
    )?;
    let server = server_name(&ctx);
    if server.is_empty() {
        bail!("the server did not publish its name");
    }
    let sender_account = format!("{}@{server}", ctx.session.username);
    let seal = |public_key: &str, account: &str, incarnation: &str| -> Result<String> {
        NamedShareEnvelopeV1::seal(
            &new_key,
            &col.id,
            next,
            &sender_account,
            &identity.incarnation_id(),
            identity.drive_signing_key(),
            account,
            incarnation,
            &b64().decode(public_key).context("recipient key")?,
        )?
        .encode_b64()
        .map_err(Into::into)
    };

    let members = access
        .members
        .iter()
        .filter(|m| !removed_member.contains(&m.user_id))
        .map(|m| {
            Ok(serde_json::json!({
                "userId": m.user_id,
                "namedShareEnvelope": seal(&m.drive_public_key, &m.account, &m.account_incarnation_id)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let links = access
        .public_links
        .iter()
        .filter(|l| !removed_links.contains(&l.id))
        .map(|l| {
            let envelope = l
                .owner_link_key_envelope
                .as_deref()
                .ok_or_else(|| anyhow!("link {} has no owner copy", l.id))?;
            let link_key = drive_envelope::open_b64(
                envelope,
                master,
                DriveEnvelopeContextV1::new(
                    DriveEnvelopePurpose::PublicLinkKey,
                    1,
                    1,
                    &l.id,
                    owner,
                )?,
            )?;
            Ok(serde_json::json!({
                "id": l.id,
                "collectionKeyEnvelope": drive_envelope::seal_b64(
                    &new_key,
                    &link_key,
                    context(DriveEnvelopePurpose::PublicLinkCollectionKey, 1)?,
                )?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let federated = access
        .federated_shares
        .iter()
        .filter(|f| !removed_federated.contains(&f.id))
        .map(|f| {
            // Their Drive key through the signed lookup, for the same account incarnation.
            let remote = ctx.client.get_fed_pubkey(&f.recipient_username, &f.recipient_server)?;
            if remote.account_incarnation_id != f.recipient_incarnation_id {
                bail!("{} has reset their account; remove them too", remote.account);
            }
            Ok(serde_json::json!({
                "id": f.id,
                "namedShareEnvelope": seal(&remote.drive_hpke_public_key, &remote.account, &remote.account_incarnation_id)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;

    let resp = ctx.client.post_json(
        &format!("/collections/{}/rotate", col.id),
        &serde_json::json!({
            "fromEpoch": col.key_epoch,
            "epochStatement": statement.encode_b64(),
            "ownerKeyEnvelope": owner_key_envelope,
            "previousKeyEnvelope": previous_key_envelope,
            "nameEnvelope": name_envelope,
            "members": members,
            "publicLinks": links,
            "federatedShares": federated,
            "removed": {
                "members": removed_member,
                "publicLinks": removed_links,
                "federatedShares": removed_federated,
            },
        }),
    )?;
    if resp.status().as_u16() == 409 {
        bail!("who has access changed meanwhile; run the command again");
    }
    crate::api::check_ok(resp).context("rotate folder key")?;
    if json {
        crate::output::print_json(&serde_json::json!({ "removed": who, "keyEpoch": next }))?;
    } else {
        println!("Removed {who}. The folder now uses key epoch {next}.");
    }
    Ok(())
}

/// This server's name, as named shares bind accounts (`name@server`).
fn server_name(ctx: &Ctx) -> String {
    ctx.client
        .get("/auth/settings")
        .ok()
        .and_then(|resp| crate::api::decode_json::<serde_json::Value>(resp).ok())
        .and_then(|v| v["chat"]["serverName"].as_str().map(str::to_string))
        .unwrap_or_default()
}
