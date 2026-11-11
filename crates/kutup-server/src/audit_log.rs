//! The admin log (docs/plans/server-personal-data.md, A8): what administrators
//! did, append-only for the server and hash-chained.
//!
//! Each row stores the previous row's hash and its own:
//! `row_hash = SHA-256(domain ‖ previous_hash ‖ the row)`, the row being its
//! admin, action, target, time and payload (keys sorted, so the hash
//! recomputes from what Postgres stores). Changing, removing or reordering a
//! row breaks the chain from there, which [`verify`] finds. The retention job
//! deletes rows only from the oldest end and records, in
//! `admin_audit_anchor` (which only the owner role writes), the last row it
//! deleted and that row's hash: verification starts from there, so deleting
//! more of the oldest rows breaks it too. A row is timed after the chain's
//! lock is taken, so the chain's order is also its time order.

use kutup_crypto::primitives::{Hasher, Suite};
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppResult;

const CHAIN_DOMAIN: &[u8] = kutup_crypto::labels::SERVER_ADMIN_AUDIT_CHAIN_V1;
/// The version [`row_hash`] is (`admin_audit_log.chain_version`): a row of
/// another version is one this server can't check, and reads as broken.
const CHAIN_VERSION: i16 = 1;
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

/// Whether `value` holds a number that is not an integer: Postgres's `jsonb`
/// may write such a number back otherwise than it came (`1e2` as `100`), so
/// the chain takes integers only.
fn has_fraction(value: &Value) -> bool {
    match value {
        Value::Number(number) => !(number.is_i64() || number.is_u64()),
        Value::Array(items) => items.iter().any(has_fraction),
        Value::Object(map) => map.values().any(has_fraction),
        _ => false,
    }
}

/// Appends one admin action, chained to the newest row.
pub async fn append(
    pool: &PgPool,
    admin: Uuid,
    action: &str,
    target: Option<Uuid>,
    payload: &Value,
) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    append_in(&mut tx, admin, action, target, payload).await?;
    tx.commit().await?;
    Ok(())
}

/// [`append`] in the caller's transaction, with the action it records: the
/// chain's lock is held until that commits.
pub async fn append_in(
    conn: &mut sqlx::PgConnection,
    admin: Uuid,
    action: &str,
    target: Option<Uuid>,
    payload: &Value,
) -> sqlx::Result<()> {
    if has_fraction(payload) {
        return Err(sqlx::Error::Encode(
            "an admin log payload holds a number that is not an integer".into(),
        ));
    }
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CHAIN_LOCK)
        .execute(&mut *conn)
        .await?;
    // Timed under the lock: a row later in the chain is never earlier in time.
    let at: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *conn)
        .await?;
    let previous: Vec<u8> =
        sqlx::query_scalar("SELECT row_hash FROM admin_audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *conn)
            .await?
            .flatten()
            .unwrap_or_default();
    let hash = row_hash(&previous, admin, action, target, micros(at), payload);
    sqlx::query(
        "INSERT INTO admin_audit_log
             (admin_user_id, action, target_user_id, payload, occurred_at, previous_hash, row_hash,
              chain_version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(admin)
    .bind(action)
    .bind(target)
    .bind(payload)
    .bind(at)
    .bind((!previous.is_empty()).then_some(&previous))
    .bind(hash.as_slice())
    .bind(CHAIN_VERSION)
    .execute(&mut *conn)
    .await?;
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
    Option<Vec<u8>>,
    i16,
);

/// Walks the chain from where the retention job last cut it (its anchor), or
/// from the first row ever.
pub async fn verify(pool: &PgPool) -> AppResult<Verification> {
    let anchor: Option<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT through_id, through_hash FROM admin_audit_anchor")
            .fetch_optional(pool)
            .await?;
    let (mut after, previous) = anchor.unwrap_or_default();
    let mut expected_previous = previous;
    let mut checked = 0u64;
    loop {
        let rows: Vec<ChainRow> = sqlx::query_as(
            "SELECT id, admin_user_id, action, target_user_id, payload, occurred_at,
                    previous_hash, row_hash, chain_version
               FROM admin_audit_log
              WHERE id > $1
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

/// Checks `rows` (in order) against the chain so far (`expected_previous`:
/// the hash the next row must name, empty before the first row): the first
/// row whose link, or own hash, is wrong, or that has none.
fn check(rows: Vec<ChainRow>, expected_previous: &mut Vec<u8>, checked: &mut u64) -> Option<i64> {
    for (id, admin, action, target, payload, at, previous, stored, version) in rows {
        let previous = previous.unwrap_or_default();
        let (Some(stored), CHAIN_VERSION) = (stored, version) else {
            return Some(id);
        };
        let hash = row_hash(&previous, admin, &action, target, micros(at), &payload);
        if *expected_previous != previous || hash.as_slice() != stored.as_slice() {
            return Some(id);
        }
        *checked += 1;
        *expected_previous = stored;
    }
    None
}

/// The retention job's part: rows older than `days` go, from the oldest end
/// (by id, which is time order), and the anchor moves to the last one gone.
/// Returns how many. As the owner (only it writes the anchor).
pub async fn prune(pool: &PgPool, days: i64) -> AppResult<u64> {
    let mut tx = pool.begin().await?;
    let through: Option<(i64, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT id, row_hash FROM admin_audit_log
          WHERE id = (SELECT max(id) FROM admin_audit_log
                       WHERE occurred_at < now() - make_interval(days => $1::int))",
    )
    .bind(days)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((through_id, Some(through_hash))) = through else {
        return Ok(0);
    };
    let deleted = sqlx::query("DELETE FROM admin_audit_log WHERE id <= $1")
        .bind(through_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query(
        "INSERT INTO admin_audit_anchor (through_id, through_hash) VALUES ($1, $2)
         ON CONFLICT (only_row) DO UPDATE SET through_id = $1, through_hash = $2",
    )
    .bind(through_id)
    .bind(&through_hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(deleted)
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
                    Some(hash.to_vec()),
                    CHAIN_VERSION,
                );
                previous = hash.to_vec();
                row
            })
            .collect()
    }

    #[test]
    fn a_changed_removed_or_unhashed_row_breaks_the_chain() {
        let (mut expected, mut checked) = (Vec::new(), 0);
        assert_eq!(check(chain(), &mut expected, &mut checked), None);
        assert_eq!(checked, 3);
        // The oldest row gone by retention, its hash the anchor: the rest holds.
        let rows = chain();
        let mut anchor = rows[0].7.clone().unwrap();
        assert_eq!(check(rows[1..].to_vec(), &mut anchor, &mut 0), None);
        // Gone beyond the anchor (two rows, the anchor naming one): broken.
        let mut anchor = rows[0].7.clone().unwrap();
        assert_eq!(check(rows[2..].to_vec(), &mut anchor, &mut 0), Some(3));
        // Without an anchor the first row must be the chain's first.
        assert_eq!(check(rows[1..].to_vec(), &mut Vec::new(), &mut 0), Some(2));
        // A payload changed in place.
        let mut changed = chain();
        changed[1].4 = json!({ "n": 9 });
        assert_eq!(check(changed, &mut Vec::new(), &mut 0), Some(2));
        // A row removed from the middle.
        let mut removed = chain();
        removed.remove(1);
        assert_eq!(check(removed, &mut Vec::new(), &mut 0), Some(3));
        // A row added without hashes.
        let mut unhashed = chain();
        unhashed[2].7 = None;
        assert_eq!(check(unhashed, &mut Vec::new(), &mut 0), Some(3));
        // A row of a version this server can't check.
        let mut unknown = chain();
        unknown[1].8 = 2;
        assert_eq!(check(unknown, &mut Vec::new(), &mut 0), Some(2));
    }

    #[test]
    fn a_payload_takes_integers_only() {
        assert!(!has_fraction(
            &json!({ "a": [1, -2, { "b": 3 }], "c": "1.5" })
        ));
        assert!(has_fraction(&json!({ "a": [1, { "b": 1.5 }] })));
        assert!(has_fraction(&json!(100.0)));
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
