//! The admin log (docs/plans/server-personal-data.md, A8): what administrators
//! did, append-only for the server and hash-chained.
//!
//! Each row stores the previous row's hash and its own:
//! `row_hash = SHA-256(domain ‖ previous_hash ‖ the row)`, the row being its
//! admin, action, target, time and payload (keys sorted, so the hash
//! recomputes from what Postgres stores). Changing, removing or reordering a
//! row breaks the chain from there, which [`verify`] finds. The retention job
//! deletes rows only from the oldest end, so the oldest row kept names a
//! predecessor that is gone; verification starts from it.

use kutup_crypto::primitives::{Hasher, Suite};
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppResult;

const CHAIN_DOMAIN: &[u8] = kutup_crypto::labels::SERVER_ADMIN_AUDIT_CHAIN_V1;
/// The advisory lock that orders the chain's inserts.
const CHAIN_LOCK: i64 = 0x6b75_7475_7061_7564; // "kutupaud"
/// Rows read per page when verifying.
const VERIFY_PAGE: i64 = 1000;

/// A JSON value with object keys sorted, recursively: the form the hash
/// covers.
fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .into_iter()
                .map(|key| format!("{}:{}", Value::String(key.clone()), canonical(&map[key])))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => other.to_string(),
    }
}

fn row_hash(
    previous: &[u8],
    admin: Uuid,
    action: &str,
    target: Option<Uuid>,
    at_micros: i128,
    payload: &Value,
) -> [u8; 32] {
    let mut hasher = Hasher::new(Suite::V1);
    hasher.update(CHAIN_DOMAIN);
    hasher.update((previous.len() as u32).to_be_bytes());
    hasher.update(previous);
    hasher.update(admin.as_bytes());
    hasher.update((action.len() as u32).to_be_bytes());
    hasher.update(action.as_bytes());
    if let Some(target) = target {
        hasher.update([1u8]);
        hasher.update(target.as_bytes());
    } else {
        hasher.update([0u8]);
    }
    hasher.update(at_micros.to_be_bytes());
    let payload = canonical(payload);
    hasher.update((payload.len() as u32).to_be_bytes());
    hasher.update(payload.as_bytes());
    hasher.finish().to_array()
}

/// The time to the microsecond, as Postgres keeps it.
fn micros(at: OffsetDateTime) -> i128 {
    at.unix_timestamp_nanos() / 1000
}

/// Appends one admin action, chained to the newest row.
pub async fn append(
    pool: &PgPool,
    admin: Uuid,
    action: &str,
    target: Option<Uuid>,
    payload: &Value,
) -> AppResult<()> {
    let now = OffsetDateTime::now_utc();
    let at = now
        .replace_nanosecond(now.nanosecond() / 1000 * 1000)
        .unwrap_or(now);
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CHAIN_LOCK)
        .execute(&mut *tx)
        .await?;
    let previous: Vec<u8> = sqlx::query_scalar(
        "SELECT row_hash FROM admin_audit_log WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or_default();
    let hash = row_hash(&previous, admin, action, target, micros(at), payload);
    sqlx::query(
        "INSERT INTO admin_audit_log
             (admin_user_id, action, target_user_id, payload, occurred_at, previous_hash, row_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(admin)
    .bind(action)
    .bind(target)
    .bind(payload)
    .bind(at)
    .bind((!previous.is_empty()).then_some(&previous))
    .bind(hash.as_slice())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// What [`verify`] found.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    /// Chained rows checked.
    pub checked: u64,
    /// The first row whose hash, or link to the row before, is wrong.
    pub broken_at: Option<i64>,
}

type ChainRow = (
    i64,
    Uuid,
    String,
    Option<Uuid>,
    Value,
    OffsetDateTime,
    Option<Vec<u8>>,
    Vec<u8>,
);

/// Walks the chain from the oldest row kept.
pub async fn verify(pool: &PgPool) -> AppResult<Verification> {
    let mut checked = 0u64;
    let mut after = 0i64;
    let mut expected_previous: Option<Vec<u8>> = None;
    loop {
        let rows: Vec<ChainRow> = sqlx::query_as(
            "SELECT id, admin_user_id, action, target_user_id, payload, occurred_at,
                    previous_hash, row_hash
               FROM admin_audit_log
              WHERE row_hash IS NOT NULL AND id > $1
              ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(VERIFY_PAGE)
        .fetch_all(pool)
        .await?;
        if rows.is_empty() {
            return Ok(Verification {
                checked,
                broken_at: None,
            });
        }
        after = rows.last().map(|row| row.0).unwrap_or(after);
        if let Some(broken) = check(rows, &mut expected_previous, &mut checked) {
            return Ok(Verification {
                checked,
                broken_at: Some(broken),
            });
        }
    }
}

/// Checks `rows` (in order) against the chain so far: the first whose link to
/// the row before, or own hash, is wrong.
fn check(
    rows: Vec<ChainRow>,
    expected_previous: &mut Option<Vec<u8>>,
    checked: &mut u64,
) -> Option<i64> {
    for (id, admin, action, target, payload, at, previous, stored) in rows {
        let previous = previous.unwrap_or_default();
        // The oldest row kept may name a predecessor the retention job
        // removed; every later one names the row before it.
        let linked = expected_previous
            .as_ref()
            .is_none_or(|expected| *expected == previous);
        let hash = row_hash(&previous, admin, &action, target, micros(at), &payload);
        if !linked || hash.as_slice() != stored.as_slice() {
            return Some(id);
        }
        *checked += 1;
        *expected_previous = Some(stored);
    }
    None
}

/// The retention job's part: rows older than `days` go (from the oldest end,
/// so the chain stays whole). Returns how many.
pub async fn prune(pool: &PgPool, days: i64) -> AppResult<u64> {
    Ok(sqlx::query(
        "DELETE FROM admin_audit_log WHERE occurred_at < now() - make_interval(days => $1::int)",
    )
    .bind(days)
    .execute(pool)
    .await?
    .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Three chained rows, as `append` makes them.
    fn chain() -> Vec<ChainRow> {
        let admin = Uuid::from_u128(1);
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let mut previous = Vec::new();
        (1..=3)
            .map(|id| {
                let payload = json!({ "n": id });
                let hash = row_hash(&previous, admin, "user.update", None, micros(at), &payload);
                let row = (
                    id,
                    admin,
                    "user.update".to_owned(),
                    None,
                    payload,
                    at,
                    (!previous.is_empty()).then(|| previous.clone()),
                    hash.to_vec(),
                );
                previous = hash.to_vec();
                row
            })
            .collect()
    }

    #[test]
    fn a_changed_or_removed_row_breaks_the_chain() {
        let (mut expected, mut checked) = (None, 0);
        assert_eq!(check(chain(), &mut expected, &mut checked), None);
        assert_eq!(checked, 3);
        // The oldest rows gone by retention: what is left still holds.
        let (mut expected, mut checked) = (None, 0);
        assert_eq!(
            check(chain().split_off(1), &mut expected, &mut checked),
            None
        );
        // A payload changed in place.
        let mut changed = chain();
        changed[1].4 = json!({ "n": 9 });
        assert_eq!(check(changed, &mut None, &mut 0), Some(2));
        // A row removed from the middle.
        let mut removed = chain();
        removed.remove(1);
        assert_eq!(check(removed, &mut None, &mut 0), Some(3));
    }

    #[test]
    fn the_hash_covers_every_field_and_ignores_key_order() {
        let admin = Uuid::from_u128(1);
        let base = row_hash(
            &[],
            admin,
            "user.delete",
            None,
            10,
            &json!({ "a": 1, "b": [1, 2] }),
        );
        assert_eq!(
            base,
            row_hash(
                &[],
                admin,
                "user.delete",
                None,
                10,
                &json!({ "b": [1, 2], "a": 1 })
            )
        );
        for other in [
            row_hash(
                &[7],
                admin,
                "user.delete",
                None,
                10,
                &json!({ "a": 1, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                Uuid::from_u128(2),
                "user.delete",
                None,
                10,
                &json!({ "a": 1, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                admin,
                "user.wipe",
                None,
                10,
                &json!({ "a": 1, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                admin,
                "user.delete",
                Some(admin),
                10,
                &json!({ "a": 1, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                admin,
                "user.delete",
                None,
                11,
                &json!({ "a": 1, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                admin,
                "user.delete",
                None,
                10,
                &json!({ "a": 2, "b": [1, 2] }),
            ),
            row_hash(
                &[],
                admin,
                "user.delete",
                None,
                10,
                &json!({ "a": 1, "b": [2, 1] }),
            ),
        ] {
            assert_ne!(base, other);
        }
    }
}
