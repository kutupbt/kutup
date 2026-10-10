//! Mail groups (docs/plans/mail-groups.md, G1a): addresses that belong to a
//! team. A distribution list stores each message once, as one data packet in
//! the group's own storage, with one small key packet per member kept in the
//! member's row; the members read, file and delete their copies on their
//! own. Group mail is charged to the group's quota, never to its members.
//!
//! The role addresses (`postmaster@`, `abuse@`, `security@`, `hostmaster@`)
//! are system groups: they take mail from anyone, and while none of their
//! members can receive it, it goes to every active administrator, so they
//! never bounce.

use std::collections::BTreeMap;

use aws_sdk_s3::primitives::ByteStream;
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::headers::Readable;
use super::lmtp::Reply;
use super::{insert_message, NewMessage};
use crate::AppState;

/// The roles (RFC 2142) answered by system groups.
pub const SYSTEM_ROLES: [&str; 4] = ["postmaster", "abuse", "security", "hostmaster"];

/// A system group's storage when created: 1 GiB, which an administrator can
/// change.
pub const SYSTEM_GROUP_QUOTA_BYTES: i64 = 1024 * 1024 * 1024;

/// Most key packets one stored data packet carries (`kutup-crypto`'s split
/// limit, a group's largest size); larger lists would be stored as several.
const MEMBERS_PER_OBJECT: usize = 1000;

/// A group as delivery sees it.
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Group {
    pub id: Uuid,
    pub address: String,
    pub kind: String,
    pub post_policy: String,
    pub system_role: Option<String>,
}

/// Someone a group's mail goes to: an active account with a primary key.
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Receiver {
    pub user_id: Uuid,
    pub address_id: Uuid,
    pub address: String,
    pub public_key: Vec<u8>,
}

/// Who is sending to a group.
#[derive(Clone, Copy, Debug)]
pub enum Sender {
    /// Mail from the internet, through Stalwart.
    Outside,
    /// A signed-in Kutup user of this server.
    Local(Uuid),
}

/// The group at `address` (canonical), if there is one.
pub async fn find<'e, E: PgExecutor<'e>>(
    executor: E,
    address: &str,
) -> sqlx::Result<Option<Group>> {
    sqlx::query_as(
        "SELECT id, address, kind, post_policy, system_role FROM mail_groups WHERE address = $1",
    )
    .bind(address)
    .fetch_optional(executor)
    .await
}

/// Whether `username` is a group's name on this server (group names and
/// usernames share the address namespace).
pub async fn is_group_name(pool: &PgPool, username: &str, server_name: &str) -> sqlx::Result<bool> {
    let address = format!(
        "{}@{}",
        username.to_ascii_lowercase(),
        server_name.to_ascii_lowercase()
    );
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mail_groups WHERE address = $1)")
        .bind(address)
        .fetch_one(pool)
        .await
}

/// Who receives `group`'s mail now: its active members with a key; for a
/// system group without any, every active administrator with a key.
pub async fn receivers(pool: &PgPool, group: &Group) -> sqlx::Result<Vec<Receiver>> {
    let members: Vec<Receiver> = sqlx::query_as(
        "SELECT u.id AS user_id, a.id AS address_id, a.address, k.public_key
           FROM mail_group_members m
           JOIN users u ON u.id = m.user_id AND u.is_active
           JOIN mail_addresses a ON a.user_id = u.id
           JOIN mail_address_keys k ON k.address_id = a.id AND k.is_primary
          WHERE m.group_id = $1
          ORDER BY a.address",
    )
    .bind(group.id)
    .fetch_all(pool)
    .await?;
    if !members.is_empty() || group.system_role.is_none() {
        return Ok(members);
    }
    sqlx::query_as(
        "SELECT u.id AS user_id, a.id AS address_id, a.address, k.public_key
           FROM users u
           JOIN mail_addresses a ON a.user_id = u.id
           JOIN mail_address_keys k ON k.address_id = a.id AND k.is_primary
          WHERE u.is_admin AND u.is_active
          ORDER BY a.address",
    )
    .fetch_all(pool)
    .await
}

/// Whether `sender` may send to `group` (its post policy). Mail from outside
/// is taken only by groups that take anyone's; a forged From of a Kutup
/// address does not count as a Kutup user.
pub async fn may_post(pool: &PgPool, group: &Group, sender: Sender) -> sqlx::Result<bool> {
    let user = match sender {
        Sender::Outside => return Ok(group.post_policy == "anyone"),
        Sender::Local(user) => user,
    };
    Ok(match group.post_policy.as_str() {
        "anyone" | "local" => true,
        policy => {
            let role: Option<String> = sqlx::query_scalar(
                "SELECT role FROM mail_group_members WHERE group_id = $1 AND user_id = $2",
            )
            .bind(group.id)
            .bind(user)
            .fetch_optional(pool)
            .await?;
            matches!(
                (policy, role.as_deref()),
                ("members", Some(_)) | ("managers", Some("owner" | "manager"))
            )
        }
    })
}

/// Where a group's stored mail lives: apart from every member's, so deleting
/// an account never deletes a group's mail.
pub fn object_key(group_id: Uuid, id: Uuid) -> String {
    format!("mail/groups/{group_id}/{id}")
}

/// Locks the group's row until the transaction ends and reads its storage.
pub async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    group_id: Uuid,
) -> sqlx::Result<crate::storage_pool::Pool> {
    let (quota, used): (i64, i64) = sqlx::query_as(
        "SELECT storage_quota_bytes, storage_used_bytes FROM mail_groups WHERE id = $1 FOR UPDATE",
    )
    .bind(group_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(crate::storage_pool::Pool {
        quota,
        used,
        reserved: 0,
    })
}

/// Whether the group has room for another message (checked at RCPT, before
/// the message is sent).
pub async fn has_room(pool: &PgPool, group_id: Uuid) -> sqlx::Result<bool> {
    let (quota, used): (i64, i64) = sqlx::query_as(
        "SELECT storage_quota_bytes, storage_used_bytes FROM mail_groups WHERE id = $1",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await?;
    Ok(used < quota)
}

/// One stored data packet and the members' key packets for it.
pub struct ListCopy {
    pub data: Vec<u8>,
    /// Each receiver with their key packet for `data`.
    pub members: Vec<(Receiver, Vec<u8>)>,
}

/// How a message to a list fared.
#[derive(Debug, PartialEq, Eq)]
pub enum Stored {
    /// Rows written for this many members (others had it already).
    Delivered(usize),
    /// Every member had it already (a retried delivery).
    AlreadyThere,
    /// The group's storage is full.
    Full,
}

/// What a list row looks like besides its key packet.
pub struct ListRow<'a> {
    pub direction: &'static str,
    pub protection: &'static str,
    pub readable: &'a Readable,
    pub folder: &'static str,
}

/// Stores list mail inside `tx`: each data packet once in the group's
/// storage and a row per member carrying their key packet, charged to the
/// group. The objects are written first and pushed to `written`; when the
/// outcome is not [`Stored::Delivered`], nothing of it stays in `tx` and the
/// caller removes the objects (as it does when the transaction fails).
pub async fn store_list(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    group: &Group,
    copies: Vec<ListCopy>,
    row: &ListRow<'_>,
    written: &mut Written,
) -> anyhow::Result<Stored> {
    let mut objects = Vec::with_capacity(copies.len());
    for copy in &copies {
        let key = object_key(group.id, Uuid::new_v4());
        let size = i64::try_from(copy.data.len())?;
        let version = state
            .storage
            .put_object_versioned(&key, ByteStream::from(copy.data.clone()), size)
            .await?;
        written.0.push((key.clone(), version.clone()));
        objects.push((key, version, size));
    }
    let pool = lock(tx, group.id).await?;
    let total: i64 = objects.iter().map(|(_, _, size)| size).sum();
    if !pool.fits(total, 0) {
        return Ok(Stored::Full);
    }
    let mut delivered = 0;
    for ((key, version, size), copy) in objects.iter().zip(&copies) {
        sqlx::query(
            "INSERT INTO mail_group_objects (object_key, object_version, group_id, size_bytes)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(key)
        .bind(version)
        .bind(group.id)
        .bind(size)
        .execute(&mut **tx)
        .await?;
        for (receiver, packet) in &copy.members {
            let inserted = insert_message(
                tx,
                NewMessage {
                    id: Uuid::new_v4(),
                    user_id: Some(receiver.user_id),
                    address_id: receiver.address_id,
                    thread_id: None,
                    direction: row.direction,
                    folder: row.folder,
                    protection: row.protection,
                    seen: false,
                    object_key: key,
                    object_version: version,
                    size: *size,
                    readable: row.readable,
                    bcc: &[],
                    external_recipients: 0,
                    group_id: Some(group.id),
                    key_packet: Some(packet),
                    sent_by: None,
                },
            )
            .await?;
            if inserted {
                delivered += 1;
            }
        }
    }
    if delivered == 0 {
        // Every member had it already (a retried delivery): keep neither the
        // objects nor their records.
        let keys: Vec<&str> = objects.iter().map(|(key, _, _)| key.as_str()).collect();
        sqlx::query("DELETE FROM mail_group_objects WHERE object_key = ANY($1)")
            .bind(&keys)
            .execute(&mut **tx)
            .await?;
        return Ok(Stored::AlreadyThere);
    }
    sqlx::query(
        "UPDATE mail_groups SET storage_used_bytes = storage_used_bytes + $2 WHERE id = $1",
    )
    .bind(group.id)
    .bind(total)
    .execute(&mut **tx)
    .await?;
    Ok(Stored::Delivered(delivered))
}

/// Objects written for a delivery, to remove when it does not commit.
#[derive(Default)]
pub struct Written(pub Vec<(String, String)>);

impl Written {
    pub async fn remove(&self, state: &AppState) {
        for (key, version) in &self.0 {
            if let Err(error) = state.storage.delete_stored(key, version).await {
                tracing::warn!(error = %error, "mail: unrecorded group object left for the sweep");
            }
        }
    }
}

/// Splits `receivers` into groups that one data packet can carry.
pub fn chunks(receivers: &[Receiver]) -> impl Iterator<Item = &[Receiver]> {
    receivers.chunks(MEMBERS_PER_OBJECT)
}

/// Stores mail from outside for a list: encrypted on arrival once per chunk
/// of members, each member's row carrying their own key packet.
pub async fn store_from_outside(
    state: &AppState,
    group: &Group,
    receivers: &[Receiver],
    raw: &[u8],
) -> Reply {
    match store_from_outside_inner(state, group, receivers, raw).await {
        Ok(reply) => reply,
        Err(error) => {
            tracing::warn!(group = %group.id, error = %error, "mail: storing for a group failed");
            Reply::new(451, "4.3.0", "temporary failure, try again later")
        }
    }
}

async fn store_from_outside_inner(
    state: &AppState,
    group: &Group,
    receivers: &[Receiver],
    raw: &[u8],
) -> anyhow::Result<Reply> {
    if receivers.is_empty() {
        return Ok(Reply::new(
            451,
            "4.3.0",
            "nobody can receive this group's mail yet",
        ));
    }
    let owned = raw.to_vec();
    let chunked: Vec<Vec<Receiver>> = chunks(receivers).map(<[Receiver]>::to_vec).collect();
    let (readable, copies) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let readable = Readable::parse(&owned);
        let mut copies = Vec::with_capacity(chunked.len());
        for chunk in chunked {
            let keys: Vec<&[u8]> = chunk.iter().map(|r| r.public_key.as_slice()).collect();
            let split = kutup_crypto::mail_key::encrypt_split_unsigned(&keys, &owned)?;
            copies.push(ListCopy {
                data: split.data_packet,
                members: chunk.into_iter().zip(split.key_packets).collect(),
            });
        }
        Ok((readable, copies))
    })
    .await??;
    let row = ListRow {
        direction: "inbound",
        protection: if readable.pgp_encrypted {
            "end_to_end"
        } else {
            "zero_access"
        },
        folder: if readable.spam { "spam" } else { "inbox" },
        readable: &readable,
    };
    let mut written = Written::default();
    let mut tx = state.pool.begin().await?;
    let stored = store_list(state, &mut tx, group, copies, &row, &mut written).await;
    let reply = match stored {
        Ok(Stored::Delivered(_)) => {
            tx.commit().await?;
            return Ok(Reply::new(250, "2.0.0", "stored"));
        }
        Ok(Stored::AlreadyThere) => Reply::new(250, "2.0.0", "already delivered"),
        Ok(Stored::Full) => super::full(),
        Err(error) => {
            drop(tx);
            written.remove(state).await;
            return Err(error);
        }
    };
    drop(tx);
    written.remove(state).await;
    Ok(reply)
}

/// Stores mail from outside for a shared mailbox: encrypted on arrival to the
/// group's key, one row owned by the group, charged to it.
pub async fn store_shared(state: &AppState, group: &Group, key: &[u8], raw: &[u8]) -> Reply {
    match store_shared_inner(state, group, key, raw).await {
        Ok(reply) => reply,
        Err(error) => {
            tracing::warn!(group = %group.id, error = %error, "mail: storing for a shared mailbox failed");
            Reply::new(451, "4.3.0", "temporary failure, try again later")
        }
    }
}

async fn store_shared_inner(
    state: &AppState,
    group: &Group,
    key: &[u8],
    raw: &[u8],
) -> anyhow::Result<Reply> {
    let (owned, key) = (raw.to_vec(), key.to_vec());
    let (readable, ciphertext) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let readable = Readable::parse(&owned);
        Ok((
            readable,
            kutup_crypto::mail_key::encrypt_binary(&key, &owned)?,
        ))
    })
    .await??;
    let row = ListRow {
        direction: "inbound",
        protection: if readable.pgp_encrypted {
            "end_to_end"
        } else {
            "zero_access"
        },
        folder: if readable.spam { "spam" } else { "inbox" },
        readable: &readable,
    };
    let mut written = Written::default();
    let mut tx = state.pool.begin().await?;
    let stored = store_shared_copy(state, &mut tx, group, ciphertext, &row, &mut written).await;
    match stored {
        Ok(Stored::Delivered(_)) => {
            tx.commit().await?;
            Ok(Reply::new(250, "2.0.0", "stored"))
        }
        Ok(other) => {
            drop(tx);
            written.remove(state).await;
            Ok(if other == Stored::Full {
                super::full()
            } else {
                Reply::new(250, "2.0.0", "already delivered")
            })
        }
        Err(error) => {
            drop(tx);
            written.remove(state).await;
            Err(error)
        }
    }
}

/// Stores one message for a shared mailbox inside `tx`: its row owned by the
/// group (no account), charged to the group. The object is pushed to
/// `written` for the caller to remove when the outcome is not delivered.
pub async fn store_shared_copy(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    group: &Group,
    message: Vec<u8>,
    row: &ListRow<'_>,
    written: &mut Written,
) -> anyhow::Result<Stored> {
    let id = Uuid::new_v4();
    let key = object_key(group.id, id);
    let size = i64::try_from(message.len())?;
    let version = state
        .storage
        .put_object_versioned(&key, ByteStream::from(message), size)
        .await?;
    written.0.push((key.clone(), version.clone()));
    let pool = lock(tx, group.id).await?;
    if !pool.fits(size, 0) {
        return Ok(Stored::Full);
    }
    let address_id: Uuid = sqlx::query_scalar("SELECT id FROM mail_addresses WHERE group_id = $1")
        .bind(group.id)
        .fetch_one(&mut **tx)
        .await?;
    let inserted = insert_message(
        tx,
        NewMessage {
            id,
            user_id: None,
            address_id,
            thread_id: None,
            direction: row.direction,
            folder: row.folder,
            protection: row.protection,
            seen: row.direction == "outbound",
            object_key: &key,
            object_version: &version,
            size,
            readable: row.readable,
            bcc: &[],
            external_recipients: 0,
            group_id: Some(group.id),
            key_packet: None,
            sent_by: None,
        },
    )
    .await?;
    Ok(if inserted {
        Stored::Delivered(1)
    } else {
        Stored::AlreadyThere
    })
}

/// Removes list objects no row points at any more (every member deleted
/// their copy, or left with their account) and refunds their groups.
pub async fn release_unreferenced(
    pool: &PgPool,
    storage: &crate::storage::StorageService,
) -> anyhow::Result<u64> {
    let mut tx = pool.begin().await?;
    let released: Vec<(String, String, Uuid, i64)> = sqlx::query_as(
        "DELETE FROM mail_group_objects o
          WHERE NOT EXISTS (SELECT 1 FROM mail_messages m WHERE m.object_key = o.object_key)
         RETURNING object_key, object_version, group_id, size_bytes",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut refunds: BTreeMap<Uuid, i64> = BTreeMap::new();
    for (_, _, group, size) in &released {
        *refunds.entry(*group).or_default() += size;
    }
    for (group, size) in refunds {
        sqlx::query(
            "UPDATE mail_groups SET storage_used_bytes = GREATEST(storage_used_bytes - $2, 0) WHERE id = $1",
        )
        .bind(group)
        .bind(size)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    for (key, version, _, _) in &released {
        if let Err(error) = storage.delete_stored(key, version).await {
            tracing::warn!(error = %error, "mail: released group object left for the sweep");
        }
    }
    Ok(released.len() as u64)
}

/// Creates the system groups for this server's name, once.
pub async fn ensure_system_groups(pool: &PgPool, server_name: &str) -> anyhow::Result<()> {
    for role in SYSTEM_ROLES {
        let address = kutup_crypto::mail_key::canonical_address(&format!("{role}@{server_name}"))?;
        let mut tx = pool.begin().await?;
        sqlx::query(
            "INSERT INTO mail_groups (address, display_name, kind, post_policy, system_role, storage_quota_bytes)
             VALUES ($1, $2, 'list', 'anyone', $2, $3)
             ON CONFLICT (system_role) DO NOTHING",
        )
        .bind(&address)
        .bind(role)
        .bind(SYSTEM_GROUP_QUOTA_BYTES)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO mail_addresses (group_id, address)
             SELECT id, address FROM mail_groups WHERE system_role = $1
             ON CONFLICT DO NOTHING",
        )
        .bind(role)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_objects_live_apart_from_accounts() {
        let group = Uuid::nil();
        let key = object_key(group, Uuid::nil());
        assert!(key.starts_with("mail/groups/"));
        assert!(!key.starts_with(&crate::mail::object_prefix(group)));
    }

    #[test]
    fn large_lists_are_stored_in_chunks() {
        let receiver = Receiver {
            user_id: Uuid::nil(),
            address_id: Uuid::nil(),
            address: "a@kutup.test".into(),
            public_key: Vec::new(),
        };
        let receivers = vec![receiver; 2500];
        let sizes: Vec<usize> = chunks(&receivers).map(<[Receiver]>::len).collect();
        assert_eq!(sizes, vec![1000, 1000, 500]);
    }
}
