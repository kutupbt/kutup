//! Shared mailboxes' keys (docs/plans/mail-groups.md, G1b). A shared mailbox
//! has its own address key, made in a member's browser. Its secret reaches
//! each member as a share, encrypted to the member's address key; the server
//! only checks that each share is addressed to that member's current key.
//! The group's key lists are signed by the server's own mail-group authority
//! (a group has no account authority), so senders and WKD see which key is
//! current; this trusts the server for group keys, as distribution lists
//! trust it for membership.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use kutup_crypto::identity::{authority_key_id_from_public, incarnation_id_from_authority_public};
use kutup_crypto::mail_key::{
    self, MailKeyEntryV1, MailKeyListV1, SignedMailKeyListV1, DEFAULT_FLAGS, FLAG_NOT_OBSOLETE,
};
use serde::Deserialize;
use sqlx::{PgPool, Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// The key signing shared mailboxes' key lists, made once per server.
pub async fn authority(pool: &PgPool) -> anyhow::Result<SigningKey> {
    let mut seed = crate::server_keys::load_or_create(
        pool,
        crate::server_keys::GeneratedKey::MailGroupAuthority,
    )
    .await?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Ok(key)
}

/// A group key's share for one member, as a browser sends it.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShareInput {
    pub user_id: String,
    /// The group key's secret encrypted to the member's address key, base64.
    pub share: String,
    /// The member's address key it is encrypted to.
    pub member_fingerprint: String,
}

/// A new group key with a share for each member.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewGroupKey {
    /// Binary OpenPGP public key, base64: the address key shape, for the
    /// group's address.
    pub public_key: String,
    pub shares: Vec<ShareInput>,
}

/// A share checked against the member's current primary address key.
pub struct CheckedShare {
    pub user_id: Uuid,
    pub share: Vec<u8>,
    pub member_fingerprint: String,
}

fn decode(value: &str, field: &str) -> AppResult<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|_| AppError::bad_request(format!("{field} must be base64")))
}

/// Checks each share is encrypted to its member's current primary address
/// key (the server cannot open it, but can see whom it is for).
pub async fn check_shares(pool: &PgPool, shares: &[ShareInput]) -> AppResult<Vec<CheckedShare>> {
    let mut checked = Vec::with_capacity(shares.len());
    for input in shares {
        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|_| AppError::bad_request("userId must be an account id"))?;
        let share = decode(&input.share, "share")?;
        let key: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT k.fingerprint, k.public_key FROM mail_addresses a
               JOIN mail_address_keys k ON k.address_id = a.id AND k.is_primary
              WHERE a.user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
        let Some((fingerprint, public_key)) = key else {
            return Err(AppError::bad_request("a member has no address key yet")
                .with_details(serde_json::json!({ "code": "noAddressKey", "userId": user_id })));
        };
        let expected = mail_key::encryption_key_id(&public_key)
            .map_err(|_| AppError::internal("stored address key does not parse"))?;
        if fingerprint != input.member_fingerprint.to_ascii_lowercase()
            || mail_key::message_key_id(&share).ok() != Some(expected)
        {
            return Err(AppError::conflict("a member's key changed; try again")
                .with_details(serde_json::json!({ "code": "keyChanged", "userId": user_id })));
        }
        checked.push(CheckedShare {
            user_id,
            share,
            member_fingerprint: fingerprint,
        });
    }
    Ok(checked)
}

/// Adds `key` as the group's new primary key (older keys stay, to open older
/// mail), with its shares, and signs the next key list. In `tx`, under the
/// group's row lock taken by the caller.
pub async fn publish(
    tx: &mut Transaction<'_, Postgres>,
    authority: &SigningKey,
    group_id: Uuid,
    address: &str,
    key: &NewGroupKey,
    shares: &[CheckedShare],
) -> AppResult<String> {
    let public_key = decode(&key.public_key, "publicKey")?;
    let info = mail_key::inspect_address_public_key(&public_key, address)
        .map_err(|error| AppError::bad_request(format!("publicKey: {error}")))?;
    let fingerprint = hex::encode(info.fingerprint);
    let existing: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT fingerprint, sha256_fingerprint, flags FROM mail_group_keys WHERE group_id = $1",
    )
    .bind(group_id)
    .fetch_all(&mut **tx)
    .await?;
    sqlx::query("UPDATE mail_group_keys SET is_primary = false WHERE group_id = $1")
        .bind(group_id)
        .execute(&mut **tx)
        .await?;
    let key_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mail_group_keys (group_id, fingerprint, sha256_fingerprint, public_key, is_primary, flags)
         VALUES ($1, $2, $3, $4, true, $5)
         ON CONFLICT (fingerprint) DO NOTHING
         RETURNING id",
    )
    .bind(group_id)
    .bind(&fingerprint)
    .bind(hex::encode(info.sha256_fingerprint))
    .bind(&public_key)
    .bind(DEFAULT_FLAGS as i32)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| AppError::conflict("this key is already in use"))?;
    for share in shares {
        sqlx::query(
            "INSERT INTO mail_group_key_shares (group_key_id, user_id, share, member_fingerprint)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(key_id)
        .bind(share.user_id)
        .bind(&share.share)
        .bind(&share.member_fingerprint)
        .execute(&mut **tx)
        .await?;
    }

    // The next list: the older keys as they were, the new one primary.
    let mut keys = existing
        .into_iter()
        .map(
            |(fingerprint, sha256, flags)| -> AppResult<MailKeyEntryV1> {
                Ok(MailKeyEntryV1 {
                    fingerprint: hex_array(&fingerprint)?,
                    sha256_fingerprint: hex_array(&sha256)?,
                    primary: false,
                    flags: flags as u32,
                })
            },
        )
        .collect::<AppResult<Vec<_>>>()?;
    keys.push(MailKeyEntryV1 {
        fingerprint: info.fingerprint,
        sha256_fingerprint: info.sha256_fingerprint,
        primary: true,
        flags: DEFAULT_FLAGS,
    });
    keys.sort_by_key(|key| key.fingerprint);
    let previous: Option<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT data, signature, sequence FROM mail_group_key_lists WHERE group_id = $1
          ORDER BY sequence DESC LIMIT 1",
    )
    .bind(group_id)
    .fetch_optional(&mut **tx)
    .await?;
    let public = authority.verifying_key().to_bytes();
    let (sequence, previous_hash) = match previous {
        Some((data, signature, sequence)) => {
            let previous = SignedMailKeyListV1::verify(&data, &signature, &public)
                .map_err(|_| AppError::internal("stored group key list does not verify"))?;
            (sequence as u64 + 1, Some(previous.hash()))
        }
        None => (1, None),
    };
    let list = MailKeyListV1 {
        account: address.to_string(),
        incarnation_id: hex_array(&incarnation_id_from_authority_public(&public))?,
        authority_key_id: hex_array(&authority_key_id_from_public(&public))?,
        address: address.to_string(),
        sequence,
        previous_hash,
        issued_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        keys,
    }
    .sign(authority)
    .map_err(|error| AppError::internal(format!("signing a group key list: {error}")))?;
    sqlx::query("INSERT INTO mail_group_key_lists (group_id, sequence, data, signature) VALUES ($1, $2, $3, $4)")
        .bind(group_id)
        .bind(sequence as i64)
        .bind(&list.data)
        .bind(list.signature.as_slice())
        .execute(&mut **tx)
        .await?;
    Ok(fingerprint)
}

/// Stores more shares of existing group keys (members joining).
pub async fn add_shares(
    tx: &mut Transaction<'_, Postgres>,
    group_id: Uuid,
    group_fingerprint: &str,
    shares: &[CheckedShare],
) -> AppResult<()> {
    let key_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM mail_group_keys WHERE group_id = $1 AND fingerprint = $2",
    )
    .bind(group_id)
    .bind(group_fingerprint.to_ascii_lowercase())
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| AppError::bad_request("no such group key"))?;
    for share in shares {
        sqlx::query(
            "INSERT INTO mail_group_key_shares (group_key_id, user_id, share, member_fingerprint)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (group_key_id, user_id) DO UPDATE
               SET share = EXCLUDED.share, member_fingerprint = EXCLUDED.member_fingerprint, created_at = now()",
        )
        .bind(key_id)
        .bind(share.user_id)
        .bind(&share.share)
        .bind(&share.member_fingerprint)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// The group's primary key, to encrypt arriving mail to.
pub async fn primary_public_key(pool: &PgPool, group_id: Uuid) -> sqlx::Result<Option<Vec<u8>>> {
    sqlx::query_scalar("SELECT public_key FROM mail_group_keys WHERE group_id = $1 AND is_primary")
        .bind(group_id)
        .fetch_optional(pool)
        .await
}

/// A shared mailbox's keys and key lists for `GET /api/mail/keys`: the
/// lists signed by this server's mail-group authority.
pub async fn lookup(
    pool: &PgPool,
    group_id: Uuid,
    address: &str,
) -> AppResult<Option<crate::handlers::mail_keys::MailKeyLookup>> {
    let keys: Vec<(String, String, Vec<u8>, bool, i32)> = sqlx::query_as(
        "SELECT fingerprint, sha256_fingerprint, public_key, is_primary, flags
           FROM mail_group_keys WHERE group_id = $1 ORDER BY is_primary DESC, created_at DESC",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;
    if keys.is_empty() {
        return Ok(None);
    }
    let lists: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT data, signature FROM mail_group_key_lists WHERE group_id = $1 ORDER BY sequence",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;
    let authority = authority(pool)
        .await
        .map_err(|_| AppError::internal("mail-group authority"))?;
    Ok(Some(crate::handlers::mail_keys::MailKeyLookup {
        address: address.to_string(),
        account: address.to_string(),
        account_authority_public_key: STANDARD.encode(authority.verifying_key().to_bytes()),
        keys: keys
            .into_iter()
            .map(|(fingerprint, sha256, public_key, primary, flags)| {
                crate::handlers::mail_keys::PublicMailKey {
                    fingerprint,
                    sha256_fingerprint: sha256,
                    public_key: STANDARD.encode(public_key),
                    primary,
                    flags,
                }
            })
            .collect(),
        key_lists: lists
            .into_iter()
            .map(
                |(data, signature)| crate::handlers::mail_keys::SignedKeyList {
                    data: STANDARD.encode(data),
                    signature: STANDARD.encode(signature),
                },
            )
            .collect(),
    }))
}

/// A shared mailbox's keys that may be encrypted to, primary first, for WKD.
pub async fn wkd_keys(pool: &PgPool, address: &str) -> sqlx::Result<Vec<Vec<u8>>> {
    sqlx::query_scalar(
        "SELECT k.public_key FROM mail_group_keys k JOIN mail_groups g ON g.id = k.group_id
          WHERE g.address = $1 AND g.kind = 'shared' AND (k.flags & $2) <> 0
          ORDER BY k.is_primary DESC, k.created_at DESC",
    )
    .bind(address)
    .bind(FLAG_NOT_OBSOLETE as i32)
    .fetch_all(pool)
    .await
}

fn hex_array<const N: usize>(value: &str) -> AppResult<[u8; N]> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| AppError::internal("stored fingerprint is not hex"))
}
