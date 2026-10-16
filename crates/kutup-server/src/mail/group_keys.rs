//! Shared mailboxes' keys (docs/plans/mail-groups.md, G1b). A shared mailbox
//! has its own address key, made in a member's browser. Its secret reaches
//! each member as a share sealed to the member's account key (their Drive
//! HPKE key, which their key binding ties to their account id: a rename
//! keeps it; docs/plans/account-ids.md); the server only checks that each
//! share is sealed to that member's current account incarnation.
//!
//! The group's key lists are signed by the group's own signing key, which
//! its owners and managers hold (Proton's Signed Key Lists;
//! `kutup_crypto::mail_group`): this server stores and serves the chain but
//! cannot sign a link, and refuses any link not signed by the signer in
//! force. Senders pin the chain's signer on first sight and check its
//! continuity after (a new chain, an administrator starting over, shows as
//! a change).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::mail_group::{verify_group_key_chain, GroupSignerHandoverV1};
use kutup_crypto::mail_key::{self, MailKeyEntryV1, DEFAULT_FLAGS, FLAG_NOT_OBSOLETE};
use serde::Deserialize;
use sqlx::{PgPool, Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::mail_keys::SignedKeyList;

/// A group key's share for one member, as a browser sends it.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShareInput {
    pub user_id: String,
    /// The group key's secret sealed to the member's account key
    /// (`mail_key::seal_group_key_share`), base64.
    pub share: String,
}

/// A new group key with a share for each member, and the next link of the
/// key-list chain naming it.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewGroupKey {
    /// Binary OpenPGP public key, base64: the address key shape, for the
    /// group's address.
    pub public_key: String,
    pub shares: Vec<ShareInput>,
    /// The next key list (the older keys listed, not primary, no longer to
    /// encrypt to; this one primary), signed by the signer in force after
    /// this change: the current one, or `signer`.
    pub key_list: SignedKeyList,
    /// A new signer from this list on.
    #[serde(default)]
    pub signer: Option<NewGroupSigner>,
}

/// A new signing key for the group's key lists, made in a manager's browser.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewGroupSigner {
    /// Its Ed25519 public key, base64.
    pub public_key: String,
    /// Its seed sealed to each owner and manager
    /// (`mail_group::seal_group_signing_share`).
    pub shares: Vec<ShareInput>,
    /// `GroupSignerHandoverV1` bytes, base64, signed by the signer in force;
    /// none starts a new chain (an administrator only, and senders who
    /// pinned the old one see a change).
    #[serde(default)]
    pub handover: Option<String>,
}

/// The group's key-list chain as stored: its first signer, its lists in
/// order and the handovers between signers.
struct Chain {
    first_signer: Option<[u8; 32]>,
    lists: Vec<(Vec<u8>, Vec<u8>)>,
    handovers: Vec<Vec<u8>>,
}

async fn load_chain(conn: &mut sqlx::PgConnection, group_id: Uuid) -> AppResult<Chain> {
    let signers: Vec<(i64, Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT from_sequence, public_key, handover FROM mail_group_signers
          WHERE group_id = $1 ORDER BY from_sequence",
    )
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await?;
    let lists = sqlx::query_as(
        "SELECT data, signature FROM mail_group_key_lists WHERE group_id = $1 ORDER BY sequence",
    )
    .bind(group_id)
    .fetch_all(&mut *conn)
    .await?;
    let first_signer = signers
        .first()
        .map(|(_, key, _)| {
            key.as_slice()
                .try_into()
                .map_err(|_| AppError::internal("stored group signer is not 32 bytes"))
        })
        .transpose()?;
    Ok(Chain {
        first_signer,
        lists,
        handovers: signers
            .into_iter()
            .filter_map(|(_, _, handover)| handover)
            .collect(),
    })
}

/// The group's signer in force, if it has a chain.
pub async fn current_signer(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
) -> AppResult<Option<[u8; 32]>> {
    let key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT public_key FROM mail_group_signers WHERE group_id = $1
          ORDER BY from_sequence DESC LIMIT 1",
    )
    .bind(group_id)
    .fetch_optional(&mut *conn)
    .await?;
    key.map(|key| {
        key.try_into()
            .map_err(|_| AppError::internal("stored group signer is not 32 bytes"))
    })
    .transpose()
}

fn signer_key(value: &str) -> AppResult<[u8; 32]> {
    decode(value, "signer.publicKey")?
        .try_into()
        .map_err(|_| AppError::bad_request("signer.publicKey must be 32 bytes"))
}

/// A share checked against the member's current account incarnation.
pub struct CheckedShare {
    pub user_id: Uuid,
    pub share: Vec<u8>,
    pub member_incarnation_id: String,
}

fn decode(value: &str, field: &str) -> AppResult<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|_| AppError::bad_request(format!("{field} must be base64")))
}

/// Checks each share is sealed to its member's current account incarnation
/// (the server cannot open it, but can see whose keys it is for).
pub async fn check_shares(
    conn: &mut sqlx::PgConnection,
    shares: &[ShareInput],
) -> AppResult<Vec<CheckedShare>> {
    let mut checked = Vec::with_capacity(shares.len());
    for input in shares {
        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|_| AppError::bad_request("userId must be an account id"))?;
        let share = decode(&input.share, "share")?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT account_incarnation_id FROM users
              WHERE id = $1 AND is_active AND NOT is_first_login AND account_incarnation_id <> ''",
        )
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(current) = current else {
            return Err(AppError::bad_request("a member has no account keys yet")
                .with_details(serde_json::json!({ "code": "noAccountKey", "userId": user_id })));
        };
        if mail_key::group_key_share_incarnation(&share)
            .ok()
            .as_deref()
            != Some(current.as_str())
        {
            return Err(AppError::conflict("a member's keys changed; try again")
                .with_details(serde_json::json!({ "code": "keyChanged", "userId": user_id })));
        }
        checked.push(CheckedShare {
            user_id,
            share,
            member_incarnation_id: current,
        });
    }
    Ok(checked)
}

/// Adds `key` as the group's new primary key (older keys stay, to open older
/// mail), with its shares, and stores the next link of the key-list chain
/// as the browser signed it: the server signs nothing. The link must be
/// signed by the signer in force, or by `key.signer` with a handover from
/// it; a new chain (no handover) only when `may_restart` (an administrator)
/// or the group has none yet. In `tx`, under the group's row lock taken by
/// the caller.
pub async fn publish(
    tx: &mut Transaction<'_, Postgres>,
    group_id: Uuid,
    address: &str,
    key: &NewGroupKey,
    shares: &[CheckedShare],
    signer_shares: &[CheckedShare],
    may_restart: bool,
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

    // The link the browser signed must list exactly the keys after this
    // change: the older ones obsolete, not primary; the new one primary.
    let mut expected = existing
        .iter()
        .map(
            |(fingerprint, sha256, flags)| -> AppResult<MailKeyEntryV1> {
                Ok(MailKeyEntryV1 {
                    fingerprint: hex_array(fingerprint)?,
                    sha256_fingerprint: hex_array(sha256)?,
                    primary: false,
                    flags: *flags as u32 & !FLAG_NOT_OBSOLETE,
                })
            },
        )
        .collect::<AppResult<Vec<_>>>()?;
    expected.push(MailKeyEntryV1 {
        fingerprint: info.fingerprint,
        sha256_fingerprint: info.sha256_fingerprint,
        primary: true,
        flags: DEFAULT_FLAGS,
    });
    expected.sort_by_key(|key| key.fingerprint);
    let data = decode(&key.key_list.data, "keyList.data")?;
    let signature = decode(&key.key_list.signature, "keyList.signature")?;
    append_link(
        tx,
        group_id,
        address,
        &data,
        &signature,
        key.signer.as_ref(),
        signer_shares,
        may_restart,
        &expected,
    )
    .await?;

    // Older keys stay to open older mail, but nobody encrypts to them any
    // more: someone who left may hold them.
    sqlx::query(
        "UPDATE mail_group_keys SET is_primary = false, flags = flags & ~$2 WHERE group_id = $1",
    )
    .bind(group_id)
    .bind(FLAG_NOT_OBSOLETE as i32)
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
            "INSERT INTO mail_group_key_shares (group_key_id, user_id, share, member_incarnation_id)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(key_id)
        .bind(share.user_id)
        .bind(&share.share)
        .bind(&share.member_incarnation_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(fingerprint)
}

/// Checks the chain with the new link (and signer) on it, as every client
/// checks it, then stores it.
#[allow(clippy::too_many_arguments)]
async fn append_link(
    tx: &mut Transaction<'_, Postgres>,
    group_id: Uuid,
    address: &str,
    data: &[u8],
    signature: &[u8],
    signer: Option<&NewGroupSigner>,
    signer_shares: &[CheckedShare],
    may_restart: bool,
    expected: &[MailKeyEntryV1],
) -> AppResult<()> {
    let invalid = |reason: &str| {
        AppError::bad_request(format!("keyList: {reason}"))
            .with_details(serde_json::json!({ "code": "keyListInvalid" }))
    };
    let mut chain = load_chain(tx, group_id).await?;
    let new_signer = signer
        .map(|signer| signer_key(&signer.public_key))
        .transpose()?;
    let handover = signer
        .and_then(|signer| signer.handover.as_deref())
        .map(|handover| {
            GroupSignerHandoverV1::decode(&decode(handover, "signer.handover")?)
                .map_err(|_| invalid("the handover does not parse"))
        })
        .transpose()?;
    let restart = match (chain.first_signer, new_signer, &handover) {
        // The group's first chain.
        (None, Some(_), None) => true,
        (None, _, _) => return Err(invalid("a new group's first list comes with its signer")),
        // A new chain over the old: an administrator only.
        (Some(_), Some(_), None) if may_restart => true,
        (Some(_), Some(_), None) => {
            return Err(AppError::forbidden(
                "only an administrator starts a group's key lists over",
            )
            .with_details(serde_json::json!({ "code": "handoverNeeded" })))
        }
        (Some(_), None, Some(_)) => return Err(invalid("a handover comes with its signer")),
        (Some(_), _, _) => false,
    };
    if restart {
        chain = Chain {
            first_signer: new_signer,
            lists: Vec::new(),
            handovers: Vec::new(),
        };
    }
    let first = chain.first_signer.expect("a chain has a first signer");
    let mut handovers = chain
        .handovers
        .iter()
        .map(|bytes| {
            GroupSignerHandoverV1::decode(bytes)
                .map_err(|_| AppError::internal("a stored handover does not parse"))
        })
        .collect::<AppResult<Vec<_>>>()?;
    if let Some(handover) = &handover {
        if Some(handover.next_signer) != new_signer {
            return Err(invalid("the handover names another signer"));
        }
        handovers.push(handover.clone());
    }
    let mut lists: Vec<(&[u8], &[u8])> = chain
        .lists
        .iter()
        .map(|(data, signature)| (data.as_slice(), signature.as_slice()))
        .collect();
    lists.push((data, signature));
    let view = verify_group_key_chain(&group_id.to_string(), &first, &lists, &handovers)
        .map_err(|error| invalid(&error.to_string()))?;
    if view.newest.address != address || view.newest.keys != expected {
        return Err(invalid(
            "the list must name the group's address and exactly its keys",
        ));
    }

    if restart {
        for table in [
            "mail_group_key_lists",
            "mail_group_signers",
            "mail_group_signing_shares",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE group_id = $1"))
                .bind(group_id)
                .execute(&mut **tx)
                .await?;
        }
    }
    if let Some(signer) = new_signer {
        sqlx::query(
            "INSERT INTO mail_group_signers (group_id, from_sequence, public_key, handover)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(group_id)
        .bind(view.sequence as i64)
        .bind(signer.as_slice())
        .bind(handover.as_ref().map(GroupSignerHandoverV1::encode))
        .execute(&mut **tx)
        .await?;
        // The old signer's shares go: only the signer in force signs.
        sqlx::query("DELETE FROM mail_group_signing_shares WHERE group_id = $1")
            .bind(group_id)
            .execute(&mut **tx)
            .await?;
        add_signing_shares(tx, group_id, &signer, signer_shares).await?;
    }
    sqlx::query(
        "INSERT INTO mail_group_key_lists (group_id, sequence, data, signature) VALUES ($1, $2, $3, $4)",
    )
    .bind(group_id)
    .bind(view.sequence as i64)
    .bind(data)
    .bind(signature)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Stores the signer in force's seed sealed to more owners and managers.
pub async fn add_signing_shares(
    tx: &mut Transaction<'_, Postgres>,
    group_id: Uuid,
    signer: &[u8; 32],
    shares: &[CheckedShare],
) -> AppResult<()> {
    for share in shares {
        sqlx::query(
            "INSERT INTO mail_group_signing_shares
                    (group_id, signer_public_key, user_id, share, member_incarnation_id)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (group_id, signer_public_key, user_id) DO UPDATE
               SET share = EXCLUDED.share, member_incarnation_id = EXCLUDED.member_incarnation_id,
                   created_at = now()",
        )
        .bind(group_id)
        .bind(signer.as_slice())
        .bind(share.user_id)
        .bind(&share.share)
        .bind(&share.member_incarnation_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
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
            "INSERT INTO mail_group_key_shares (group_key_id, user_id, share, member_incarnation_id)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (group_key_id, user_id) DO UPDATE
               SET share = EXCLUDED.share, member_incarnation_id = EXCLUDED.member_incarnation_id, created_at = now()",
        )
        .bind(key_id)
        .bind(share.user_id)
        .bind(&share.share)
        .bind(&share.member_incarnation_id)
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

/// A shared mailbox's keys and its key-list chain for `GET /api/mail/keys`:
/// the lists signed by the group's signers, the first signer and the
/// handovers between them, for senders to verify and pin.
pub async fn lookup(
    pool: &PgPool,
    state_server: &str,
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
    let mut conn = pool.acquire().await?;
    let chain = load_chain(&mut conn, group_id).await?;
    let Some(first_signer) = chain.first_signer else {
        return Ok(None);
    };
    let lists = chain.lists;
    Ok(Some(crate::handlers::mail_keys::MailKeyLookup {
        address: address.to_string(),
        server: state_server.to_owned(),
        account_id: None,
        account_authority_public_key: None,
        group_id: Some(group_id),
        first_signer: Some(STANDARD.encode(first_signer)),
        signer_handovers: chain
            .handovers
            .iter()
            .map(|handover| STANDARD.encode(handover))
            .collect(),
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
          WHERE kutup_fold(split_part(g.address, '@', 1)) || '@' || lower(split_part(g.address, '@', 2))
              = kutup_fold(split_part($1, '@', 1)) || '@' || lower(split_part($1, '@', 2))
            AND g.kind = 'shared' AND (k.flags & $2) <> 0
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
