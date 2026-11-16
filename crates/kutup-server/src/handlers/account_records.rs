//! The account-records store (docs/plans/account-records.md, W3): one store
//! for the account's synced private records under the account head, as
//! Signal's Storage Service is one store under its manifest. The server keeps
//! the records opaque. Each scope's id form and purpose come from
//! `kutup_crypto::account_records`, and its limits are site settings.
//!
//! - **Reads** page a scope's changes by the account's change counter, with
//!   the head from the same snapshot. Every write holds the account lock and
//!   bumps the counter under it, so writes commit in counter order: any
//!   snapshot sees an exact prefix, and a page always agrees with its head.
//! - **Writes** are one batch of puts and deletes with the next head, in one
//!   transaction. Every item is compare-and-swap on its base revision
//!   (deletes too), and a put's new revision is its sealed header's, never a
//!   body's. A batch that already landed and is sent again fails those
//!   checks, and the client reads again (Signal's model).

use std::collections::BTreeSet;

use axum::extract::{Path, Query, State};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_record;
use kutup_crypto::account_records::{IdForm, RecordScope};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::account_heads::{self, NextHead};
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::site_settings::{
    NumericSetting, ACCOUNT_RECORDS_BATCH_ITEMS, ACCOUNT_RECORDS_CHAT_CONTACTS,
    ACCOUNT_RECORDS_CHAT_GROUPS, ACCOUNT_RECORDS_PAGE, ACCOUNT_RECORDS_PASS_SECRETS,
    ACCOUNT_RECORDS_TOMBSTONE_DAYS,
};
use crate::AppState;

/// The largest batch body: a format bound (the largest record any scope
/// holds, base64, with room for a full batch of the small ones), not a
/// setting. Each envelope is checked against its own purpose's bound.
pub const MAX_BATCH_BODY_BYTES: usize = 16 * 1024 * 1024;

/// How many records of a scope one account may keep: `None` for a
/// single-record scope.
fn max_count(scope: RecordScope) -> Option<NumericSetting> {
    match scope {
        RecordScope::PassSecrets => Some(ACCOUNT_RECORDS_PASS_SECRETS),
        RecordScope::ChatGroups => Some(ACCOUNT_RECORDS_CHAT_GROUPS),
        RecordScope::ChatContacts => Some(ACCOUNT_RECORDS_CHAT_CONTACTS),
        RecordScope::Pins => None,
    }
}

fn scope_named(name: &str) -> AppResult<RecordScope> {
    RecordScope::by_name(name).ok_or_else(|| AppError::not_found("no such scope"))
}

fn read_allowed(user_id: Uuid) -> AppResult<()> {
    if crate::ratelimit::ACCOUNT_HEAD_READS.allow(&user_id.to_string()) {
        Ok(())
    } else {
        Err(AppError::too_many_requests("too many requests")
            .with_details(json!({ "code": "rateLimited" })))
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeedQuery {
    /// The `next` of the last page read; 0 or absent lists every record.
    pub after: Option<i64>,
}

/// One stored record.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecordView {
    /// The record id, in the scope's form.
    pub id: String,
    /// The revision in the envelope's header.
    pub revision: i64,
    /// The sealed record, canonical base64.
    pub envelope: String,
    /// The account's change counter when it was written.
    pub seq: i64,
}

/// A record deleted since the cursor.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeletedView {
    pub id: String,
    pub seq: i64,
}

/// A page of a scope's changes, and the head of the same snapshot.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FeedPage {
    /// Records written after the cursor, in counter order.
    pub records: Vec<RecordView>,
    /// Records deleted after the cursor (none when listing from 0).
    pub deleted: Vec<DeletedView>,
    /// The cursor for the next page.
    pub next: i64,
    /// More changes wait: read again from `next` before checking the head.
    pub more: bool,
    /// The cursor is older than the tombstones kept: read from 0 again.
    pub resync: bool,
    /// The newest sealed head (base64); none before the account's first.
    pub head: Option<String>,
    /// Before the account's first head, what a first head starts on.
    pub basis: Option<String>,
}

/// `GET /api/account/records/{scope}` — a page of the scope's changes after
/// `after`, with the head of the same snapshot. A client checks the head
/// against its anchor before it applies a page, and checks the scope's
/// index against the head once `more` is false.
#[utoipa::path(
    get,
    path = "/api/account/records/{scope}",
    tag = "account",
    security(("BearerAuth" = [])),
    params(("scope" = String, Path, description = "The scope's name"), FeedQuery),
    responses(
        (status = 200, description = "A page", body = FeedPage),
        (status = 404, description = "No such scope"),
    )
)]
pub async fn feed(
    State(state): State<AppState>,
    user: AuthUser,
    Path(scope): Path<String>,
    Query(query): Query<FeedQuery>,
) -> AppResult<Json<FeedPage>> {
    let user_id = trusted_uuid(&user.user_id)?;
    read_allowed(user_id)?;
    let scope = scope_named(&scope)?;
    let after = query.after.unwrap_or(0);
    if after < 0 {
        return Err(AppError::bad_request("after is a cursor"));
    }
    let limit = ACCOUNT_RECORDS_PAGE.load(&state.pool).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let page = page(&mut tx, user_id, scope, after, limit).await?;
    tx.commit().await?;
    Ok(Json(page))
}

/// One page, read in the caller's snapshot.
pub(crate) async fn page(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    scope: RecordScope,
    after: i64,
    limit: i64,
) -> AppResult<FeedPage> {
    let (head, basis) = account_heads::head_and_basis(tx, user_id).await?;
    let (current, floor): (i64, i64) =
        sqlx::query_as("SELECT change_seq, floor_seq FROM account_record_feeds WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await?
            .unwrap_or((0, 0));
    let encode = |head: Option<Vec<u8>>| head.map(|h| STANDARD.encode(h));
    // A cursor past the counter is not one this account gave; one at or
    // below the floor missed forgotten tombstones. From 0 nothing is missed.
    if after > current || (after > 0 && after < floor) {
        return Ok(FeedPage {
            records: Vec::new(),
            deleted: Vec::new(),
            next: 0,
            more: false,
            resync: true,
            head: encode(head),
            basis,
        });
    }
    let rows: Vec<(i64, String, Option<i64>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT change_seq, record_id, revision, envelope FROM account_records
          WHERE user_id = $1 AND scope = $2 AND change_seq > $3
         UNION ALL
         SELECT change_seq, record_id, NULL, NULL FROM account_record_tombstones
          WHERE user_id = $1 AND scope = $2 AND change_seq > $3 AND $3 > 0
         ORDER BY 1
         LIMIT $4",
    )
    .bind(user_id)
    .bind(scope.info().number)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(&mut **tx)
    .await?;
    let more = rows.len() as i64 > limit;
    let rows = &rows[..rows.len().min(limit as usize)];
    let next = match rows.last() {
        Some((seq, ..)) if more => *seq,
        _ => current,
    };
    let mut page = FeedPage {
        records: Vec::new(),
        deleted: Vec::new(),
        next,
        more,
        resync: false,
        head: encode(head),
        basis,
    };
    for (seq, id, revision, envelope) in rows {
        match (revision, envelope) {
            (Some(revision), Some(envelope)) => page.records.push(RecordView {
                id: id.clone(),
                revision: *revision,
                envelope: STANDARD.encode(envelope),
                seq: *seq,
            }),
            _ => page.deleted.push(DeletedView {
                id: id.clone(),
                seq: *seq,
            }),
        }
    }
    Ok(page)
}

/// `GET /api/account/records/{scope}/{id}` — one record.
#[utoipa::path(
    get,
    path = "/api/account/records/{scope}/{id}",
    tag = "account",
    security(("BearerAuth" = [])),
    params(
        ("scope" = String, Path, description = "The scope's name"),
        ("id" = String, Path, description = "The record id, in the scope's form"),
    ),
    responses(
        (status = 200, description = "The record", body = RecordView),
        (status = 404, description = "No such scope or record"),
    )
)]
pub async fn get_one(
    State(state): State<AppState>,
    user: AuthUser,
    Path((scope, id)): Path<(String, String)>,
) -> AppResult<Json<RecordView>> {
    let user_id = trusted_uuid(&user.user_id)?;
    read_allowed(user_id)?;
    let scope = scope_named(&scope)?;
    scope
        .object(&id)
        .map_err(|_| AppError::not_found("not found"))?;
    let row: Option<(i64, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT revision, envelope, change_seq FROM account_records
          WHERE user_id = $1 AND scope = $2 AND record_id = $3",
    )
    .bind(user_id)
    .bind(scope.info().number)
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?;
    let (revision, envelope, seq) = row.ok_or_else(|| AppError::not_found("not found"))?;
    Ok(Json(RecordView {
        id,
        revision,
        envelope: STANDARD.encode(envelope),
        seq,
    }))
}

/// A record to store on top of `baseRevision` (0: a new record).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutItem {
    pub scope: String,
    pub id: String,
    pub base_revision: i64,
    /// The sealed record, canonical base64; the revision in its header must
    /// be above `baseRevision`.
    pub envelope: String,
}

/// A record to delete, read at `baseRevision`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteItem {
    pub scope: String,
    pub id: String,
    pub base_revision: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Batch {
    /// The next account head (base64 of the sealed head), covering the
    /// batch. Required once the account keeps a head.
    pub head: Option<String>,
    #[serde(default)]
    pub puts: Vec<PutItem>,
    #[serde(default)]
    pub deletes: Vec<DeleteItem>,
}

/// What a batch did.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatchResult {
    /// The account's change counter after the batch.
    pub seq: i64,
}

/// One record that was not at the revision its item named.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    pub scope: String,
    pub id: String,
    /// The stored revision; 0 when there is none.
    pub revision: i64,
}

struct Put {
    scope: RecordScope,
    id: String,
    base: i64,
    revision: i64,
    envelope: Vec<u8>,
}

/// `POST /api/account/records` — stores and deletes records with the next
/// head, all or nothing. `409 revision_conflict` lists every record not at
/// its base revision; `head_conflict` and `head_required` as for any listed
/// write.
#[utoipa::path(
    post,
    path = "/api/account/records",
    tag = "account",
    security(("BearerAuth" = [])),
    request_body = Batch,
    responses(
        (status = 200, description = "Applied", body = BatchResult),
        (status = 400, description = "Not a valid batch, or a scope is full"),
        (status = 404, description = "A Pass secret's vault is gone or not the caller's"),
        (status = 409, description = "revision_conflict (with conflicts), head_conflict, head_required or masterKeyStale"),
    )
)]
pub async fn batch(
    State(state): State<AppState>,
    user: AuthUser,
    Json(batch): Json<Batch>,
) -> AppResult<Json<BatchResult>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let items = batch.puts.len() + batch.deletes.len();
    if items == 0 {
        return Err(AppError::bad_request("the batch is empty"));
    }
    if items as i64 > ACCOUNT_RECORDS_BATCH_ITEMS.load(&state.pool).await? {
        return Err(AppError::bad_request("the batch has too many items"));
    }
    let head = NextHead::parse(batch.head.as_deref())?;
    // Each record once per batch.
    let mut seen = BTreeSet::new();
    let mut deletes = Vec::with_capacity(batch.deletes.len());
    for item in &batch.deletes {
        let scope = scope_named(&item.scope)?;
        scope
            .object(&item.id)
            .map_err(|_| AppError::bad_request("not a record id of its scope"))?;
        if item.base_revision < 1 {
            return Err(AppError::bad_request("a delete names the revision it read"));
        }
        if !seen.insert((scope, item.id.clone())) {
            return Err(AppError::bad_request("a record is named twice"));
        }
        deletes.push((scope, item.id.clone(), item.base_revision));
    }
    for item in &batch.puts {
        if !seen.insert((scope_named(&item.scope)?, item.id.clone())) {
            return Err(AppError::bad_request("a record is named twice"));
        }
    }

    let mut tx = state.pool.begin().await?;
    let locked = account_heads::lock(&mut tx, user_id, user.session.session_id).await?;
    let mut puts = Vec::with_capacity(batch.puts.len());
    for item in batch.puts {
        let scope = scope_named(&item.scope)?;
        let info = scope.info();
        let object = scope
            .object(&item.id)
            .map_err(|_| AppError::bad_request("not a record id of its scope"))?;
        let envelope = account_record::decode_record_b64(&item.envelope, info.purpose)
            .ok()
            .filter(|bytes| STANDARD.encode(bytes) == item.envelope)
            .ok_or_else(|| AppError::bad_request("envelope is not canonical base64"))?;
        let header =
            account_record::validate_for(&envelope, info.purpose, locked.binding(), &object)
                .map_err(|_| AppError::bad_request("envelope is not this record's"))?;
        let revision = header
            .revision
            .ok_or_else(|| AppError::bad_request("envelope has no revision"))?;
        let revision = crate::revisions::check_follows(revision, item.base_revision)?;
        if info.id == IdForm::DriveFileId {
            vault_reachable(&state.pool, user_id, &object).await?;
        }
        puts.push(Put {
            scope,
            id: item.id,
            base: item.base_revision,
            revision,
            envelope,
        });
    }

    // Every item at its base revision, or the whole batch is refused with
    // every conflict listed.
    let mut conflicts = Vec::new();
    let named = puts
        .iter()
        .map(|p| (p.scope, p.id.as_str(), p.base))
        .chain(deletes.iter().map(|(s, id, base)| (*s, id.as_str(), *base)));
    for (scope, id, base) in named {
        let stored: Option<i64> = sqlx::query_scalar(
            "SELECT revision FROM account_records
              WHERE user_id = $1 AND scope = $2 AND record_id = $3",
        )
        .bind(user_id)
        .bind(scope.info().number)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let stored = stored.unwrap_or(0);
        if stored != base {
            conflicts.push(Conflict {
                scope: scope.name().to_owned(),
                id: id.to_owned(),
                revision: stored,
            });
        }
    }
    if !conflicts.is_empty() {
        return Err(AppError::conflict("records were changed elsewhere")
            .with_details(json!({ "code": "revision_conflict", "conflicts": conflicts })));
    }

    // The scopes' counts after the batch.
    for scope in RecordScope::ALL {
        let Some(setting) = max_count(scope) else {
            continue;
        };
        let added = puts
            .iter()
            .filter(|p| p.scope == scope && p.base == 0)
            .count() as i64;
        if added == 0 {
            continue;
        }
        let removed = deletes.iter().filter(|d| d.0 == scope).count() as i64;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM account_records WHERE user_id = $1 AND scope = $2",
        )
        .bind(user_id)
        .bind(scope.info().number)
        .fetch_one(&mut *tx)
        .await?;
        if count + added - removed > setting.load_for(&mut *tx, user_id).await? {
            return Err(AppError::bad_request("the scope is full")
                .with_details(json!({ "code": "scopeFull", "scope": scope.name() })));
        }
    }

    // The counter, under the account lock: one number per item.
    sqlx::query("INSERT INTO account_record_feeds (user_id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let mut seq: i64 = sqlx::query_scalar(
        "UPDATE account_record_feeds SET change_seq = change_seq + $2
          WHERE user_id = $1 RETURNING change_seq - $2",
    )
    .bind(user_id)
    .bind(items as i64)
    .fetch_one(&mut *tx)
    .await?;
    for (scope, id, _) in &deletes {
        seq += 1;
        sqlx::query(
            "DELETE FROM account_records WHERE user_id = $1 AND scope = $2 AND record_id = $3",
        )
        .bind(user_id)
        .bind(scope.info().number)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO account_record_tombstones (user_id, scope, record_id, change_seq)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(user_id)
        .bind(scope.info().number)
        .bind(id)
        .bind(seq)
        .execute(&mut *tx)
        .await?;
    }
    for put in &puts {
        seq += 1;
        sqlx::query(
            "INSERT INTO account_records (user_id, scope, record_id, revision, envelope, change_seq)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (user_id, scope, record_id) DO UPDATE
                SET revision = EXCLUDED.revision, envelope = EXCLUDED.envelope,
                    change_seq = EXCLUDED.change_seq, updated_at = now()",
        )
        .bind(user_id)
        .bind(put.scope.info().number)
        .bind(&put.id)
        .bind(put.revision)
        .bind(&put.envelope)
        .bind(seq)
        .execute(&mut *tx)
        .await?;
    }
    account_heads::advance(&mut tx, &locked, head.as_ref()).await?;
    tx.commit().await?;
    Ok(Json(BatchResult { seq }))
}

/// A Pass secret's vault: a live file the caller can open (decision 9 of the
/// note); else 404, as the old route answered.
async fn vault_reachable(pool: &sqlx::PgPool, user_id: Uuid, object: &[u8]) -> AppResult<()> {
    let file_id = Uuid::from_slice(object).map_err(|_| AppError::bad_request("bad file id"))?;
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM files WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(file_id)
    .fetch_one(pool)
    .await?;
    if !live || !crate::handlers::can_access_file(pool, user_id, file_id).await? {
        return Err(AppError::not_found("not found"));
    }
    Ok(())
}

const TOMBSTONE_JOB_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Runs [`forget_tombstones`] soon after start, then hourly.
pub fn spawn(state: AppState) {
    crate::job_health::register("account_records.tombstones", TOMBSTONE_JOB_INTERVAL);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TOMBSTONE_JOB_INTERVAL);
        loop {
            tick.tick().await;
            match forget_tombstones(&state.pool).await {
                Ok(_) => crate::job_health::beat(&state.pool, "account_records.tombstones").await,
                Err(error) => {
                    tracing::warn!(error = ?error, "account records: forgetting tombstones failed")
                }
            }
        }
    });
}

/// Forgets tombstones older than the site's days, raising each account's
/// floor so an older cursor starts over (the daily job).
pub async fn forget_tombstones(pool: &sqlx::PgPool) -> AppResult<u64> {
    let days = ACCOUNT_RECORDS_TOMBSTONE_DAYS.load(pool).await?;
    let forgotten = sqlx::query(
        "WITH gone AS (
             DELETE FROM account_record_tombstones
              WHERE deleted_at < now() - make_interval(days => $1::int)
             RETURNING user_id, change_seq)
         UPDATE account_record_feeds f
            SET floor_seq = GREATEST(f.floor_seq, g.top)
           FROM (SELECT user_id, max(change_seq) AS top FROM gone GROUP BY user_id) g
          WHERE f.user_id = g.user_id",
    )
    .bind(days)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(forgotten)
}

/// An account reset (a new incarnation): its records go, and every older
/// cursor starts over (the counter moves past them all, and the floor with
/// it).
pub async fn clear(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM account_records WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM account_record_tombstones WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "UPDATE account_record_feeds
            SET change_seq = change_seq + 1, floor_seq = change_seq + 1
          WHERE user_id = $1",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read(pool: &sqlx::PgPool, user_id: Uuid, after: i64) -> FeedPage {
        let mut tx = pool.begin().await.unwrap();
        let page = page(&mut tx, user_id, RecordScope::ChatGroups, after, 100)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        page
    }

    /// Tombstones past the site's days are forgotten and raise the floor: a
    /// cursor below it starts over, one at it or above reads on, and 0 (a new
    /// device) is never told to. A reset sends every older cursor back.
    #[tokio::test]
    async fn live_forgotten_tombstones_send_older_cursors_back() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key)
             VALUES ($1, $2, '', '', '', '', '', $3, '')",
        )
        .bind(user_id)
        .bind(format!("records{}", &user_id.simple().to_string()[..12]))
        .bind("cd".repeat(32))
        .execute(&pool)
        .await
        .unwrap();
        let scope = RecordScope::ChatGroups.info().number;
        let id = |n: u8| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([n; 32]);
        // Seq 1: record a; 2: b deleted 200 days ago; 3: c deleted now; 4: d.
        sqlx::query("INSERT INTO account_record_feeds (user_id, change_seq) VALUES ($1, 4)")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        for (seq, n) in [(1, 1u8), (4, 4)] {
            sqlx::query(
                "INSERT INTO account_records (user_id, scope, record_id, revision, envelope, change_seq)
                 VALUES ($1, $2, $3, 1, '\\x00', $4)",
            )
            .bind(user_id)
            .bind(scope)
            .bind(id(n))
            .bind(seq)
            .execute(&pool)
            .await
            .unwrap();
        }
        for (seq, n, age) in [(2, 2u8, 200), (3, 3, 0)] {
            sqlx::query(
                "INSERT INTO account_record_tombstones (user_id, scope, record_id, change_seq, deleted_at)
                 VALUES ($1, $2, $3, $4, now() - make_interval(days => $5))",
            )
            .bind(user_id)
            .bind(scope)
            .bind(id(n))
            .bind(seq)
            .bind(age)
            .execute(&pool)
            .await
            .unwrap();
        }
        // Before: from 1, both tombstones and d.
        let page = read(&pool, user_id, 1).await;
        assert!(!page.resync);
        assert_eq!(page.deleted.len(), 2);
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.next, 4);

        forget_tombstones(&pool).await.unwrap();
        let floor: i64 =
            sqlx::query_scalar("SELECT floor_seq FROM account_record_feeds WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(floor, 2);
        // Below the floor: start over. At it: read on (the forgotten one was
        // already seen). From 0: every record, no tombstones, never resync.
        assert!(read(&pool, user_id, 1).await.resync);
        let at = read(&pool, user_id, 2).await;
        assert!(!at.resync);
        assert_eq!(
            at.deleted.iter().map(|d| d.seq).collect::<Vec<_>>(),
            vec![3]
        );
        let fresh = read(&pool, user_id, 0).await;
        assert!(!fresh.resync);
        assert!(fresh.deleted.is_empty());
        assert_eq!(
            fresh.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 4]
        );
        // A cursor this account never gave.
        assert!(read(&pool, user_id, 5).await.resync);

        // A reset: nothing left, and even the newest cursor starts over.
        let mut tx = pool.begin().await.unwrap();
        clear(&mut tx, user_id).await.unwrap();
        tx.commit().await.unwrap();
        assert!(read(&pool, user_id, 4).await.resync);
        let after_reset = read(&pool, user_id, 0).await;
        assert!(after_reset.records.is_empty() && !after_reset.resync);

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
