//! One change feed for every app that keeps a copy in the browser
//! (docs/sync-feeds.md). Mail's body search uses it first; Drive and the
//! other apps' caches follow.
//!
//! - **Rows** carry `change_xid`, the transaction that last changed them (a
//!   trigger sets `pg_current_xact_id()` on insert and update).
//! - **Deletions** leave a tombstone `(owner, id, change_xid)`, purges too
//!   (the delete trigger fires for every row removed).
//! - **The cursor** is `(xid, id)`, written `"<xid>.<uuid>"`. A page answers
//!   the keys after the cursor and below the snapshot's xmin: every
//!   transaction below it has finished, so a change committed late is never
//!   skipped, only answered on a later page.
//! - **The floor** is per owner: tombstones up to it were forgotten (after a
//!   retention period). A cursor at or below the floor, or above the
//!   current xmin (a cursor from before a restore, or another cluster where
//!   transactions count from low again), gets `resync`: the client builds
//!   its copy again.

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// The tables one feed reads. Names are fixed per feed, never input.
pub(crate) struct Feed {
    /// The live rows, with `id`, `change_xid` and the owner column.
    pub rows: &'static str,
    /// An extra condition on `rows` (Mail: only an account's own mail), with
    /// `$1` the owner; empty for none.
    pub rows_filter: &'static str,
    pub owner_column: &'static str,
    /// `(owner, id, change_xid, deleted_at, …)`.
    pub tombstones: &'static str,
    /// `(owner PRIMARY KEY, floor_xid)`.
    pub floors: &'static str,
}

/// A position in a feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cursor {
    pub xid: i64,
    pub id: Uuid,
}

impl Cursor {
    pub(crate) fn encode(self) -> String {
        format!("{}.{}", self.xid, self.id)
    }

    /// 400 for anything that is not a cursor.
    pub(crate) fn parse(value: &str) -> AppResult<Self> {
        let bad = || AppError::bad_request("since is not a cursor");
        let (xid, id) = value.split_once('.').ok_or_else(bad)?;
        let xid: i64 = xid.parse().map_err(|_| bad())?;
        if xid < 0 {
            return Err(bad());
        }
        Ok(Self {
            xid,
            id: Uuid::parse_str(id).map_err(|_| bad())?,
        })
    }
}

/// One page of a feed: the ids that changed and the ids that went, in
/// `(xid, id)` order, and where to ask next.
#[derive(Debug, Default)]
pub(crate) struct Page {
    pub changed: Vec<Uuid>,
    pub gone: Vec<Uuid>,
    pub next: String,
    pub more: bool,
    /// The cursor is no longer answerable: build again from `next`.
    pub resync: bool,
}

/// The page after `since` (or, without one, only where the feed is now),
/// read in `tx` so the caller loads the rows in the same snapshot.
pub(crate) async fn page(
    tx: &mut Transaction<'_, Postgres>,
    feed: &Feed,
    owner: Uuid,
    since: Option<Cursor>,
    limit: i64,
) -> AppResult<Page> {
    // Every transaction below this one has finished.
    let upper: i64 =
        sqlx::query_scalar("SELECT pg_snapshot_xmin(pg_current_snapshot())::text::bigint")
            .fetch_one(&mut **tx)
            .await?;
    let now = Cursor {
        xid: upper,
        id: Uuid::nil(),
    }
    .encode();
    let Some(since) = since else {
        return Ok(Page {
            next: now,
            ..Page::default()
        });
    };
    let floor: Option<i64> = sqlx::query_scalar(&format!(
        "SELECT floor_xid FROM {} WHERE owner = $1",
        feed.floors
    ))
    .bind(owner)
    .fetch_optional(&mut **tx)
    .await?;
    if needs_resync(since, floor, upper) {
        return Ok(Page {
            next: now,
            resync: true,
            ..Page::default()
        });
    }
    let filter = if feed.rows_filter.is_empty() {
        String::new()
    } else {
        format!(" AND {}", feed.rows_filter)
    };
    let keys: Vec<(i64, Uuid, bool)> = sqlx::query_as(&format!(
        "SELECT change_xid, id, false FROM {rows}
          WHERE {owner} = $1{filter}
            AND (change_xid, id) > ($2, $3) AND change_xid < $4
         UNION ALL
         SELECT change_xid, id, true FROM {tombstones}
          WHERE owner = $1
            AND (change_xid, id) > ($2, $3) AND change_xid < $4
         ORDER BY 1, 2
         LIMIT $5",
        rows = feed.rows,
        owner = feed.owner_column,
        tombstones = feed.tombstones,
    ))
    .bind(owner)
    .bind(since.xid)
    .bind(since.id)
    .bind(upper)
    .bind(limit + 1)
    .fetch_all(&mut **tx)
    .await?;
    let more = keys.len() as i64 > limit;
    let keys = &keys[..keys.len().min(limit as usize)];
    let next = match keys.last() {
        Some((xid, id, _)) if more => Cursor { xid: *xid, id: *id }.encode(),
        _ => now,
    };
    Ok(Page {
        changed: keys.iter().filter(|k| !k.2).map(|k| k.1).collect(),
        gone: keys.iter().filter(|k| k.2).map(|k| k.1).collect(),
        next,
        more,
        resync: false,
    })
}

/// Whether `since` can no longer be answered: changes after it were
/// forgotten (at or below the floor), or it is from ahead of this database
/// (above the xmin: a restore, another cluster).
fn needs_resync(since: Cursor, floor: Option<i64>, upper: i64) -> bool {
    floor.is_some_and(|floor| floor >= since.xid) || since.xid > upper
}

/// Forgets tombstones older than `days` and raises each owner's floor past
/// them; a copy that has not caught up since then builds again.
pub(crate) async fn forget_tombstones(
    pool: &sqlx::PgPool,
    feed: &Feed,
    days: i32,
) -> sqlx::Result<u64> {
    Ok(sqlx::query(&format!(
        "WITH gone AS (
             DELETE FROM {tombstones}
              WHERE deleted_at < now() - make_interval(days => $1)
             RETURNING owner, change_xid)
         INSERT INTO {floors} (owner, floor_xid)
         SELECT owner, max(change_xid) FROM gone GROUP BY owner
         ON CONFLICT (owner) DO UPDATE
            SET floor_xid = GREATEST({floors}.floor_xid, EXCLUDED.floor_xid)",
        tombstones = feed.tombstones,
        floors = feed.floors,
    ))
    .bind(days)
    .execute(pool)
    .await?
    .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_round_trip_and_refuse_anything_else() {
        let cursor = Cursor {
            xid: 42,
            id: Uuid::from_bytes([7; 16]),
        };
        assert_eq!(Cursor::parse(&cursor.encode()).unwrap(), cursor);
        for bad in [
            "",
            "42",
            "-1.00000000-0000-0000-0000-000000000000",
            "x.y",
            "42.not-a-uuid",
        ] {
            assert!(Cursor::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn resync_below_the_floor_or_ahead_of_the_database() {
        let at = |xid| Cursor {
            xid,
            id: Uuid::nil(),
        };
        assert!(!needs_resync(at(100), None, 200));
        assert!(!needs_resync(at(100), Some(99), 200));
        assert!(needs_resync(at(100), Some(100), 200));
        assert!(needs_resync(at(300), None, 200));
        assert!(!needs_resync(at(200), None, 200));
    }
}
