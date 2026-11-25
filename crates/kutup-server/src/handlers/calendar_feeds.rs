//! Calendars from a URL (docs/plans/calendar.md, E5a; Proton's "Add calendar
//! from URL"). The server is a client of someone else's public `.ics` feed:
//! it fetches the feed through [`crate::public_fetch`], reads it with the
//! reader the browser import uses (`calendar_ics::import`), and seals every
//! event to the calendar's public key, signed by its own feed key. It writes
//! events it can never read back; the calendar is read-only and unshared.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use kutup_crypto::calendar as cal;
use kutup_crypto::calendar_ics::import::{
    import, FileError, ImportOptionsV1, ImportOutcomeV1, ImportedEventV1,
};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Transaction};
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::handlers::calendar::{check_event, check_parent, coded, insert_as, Checked, Kept};
use crate::public_fetch::{self, Checks};
use crate::site_settings::{
    CALENDAR_EVENTS_PER_CALENDAR, CALENDAR_FEEDS_PER_ACCOUNT, CALENDAR_FEED_BATCH,
    CALENDAR_FEED_MAX_BYTES, CALENDAR_FEED_MAX_EVENTS, CALENDAR_FEED_REFRESH_HOURS,
    CALENDAR_FEED_TIMEOUT_SECONDS, CALENDAR_MAX_COUNT, CALENDAR_REMINDERS_PER_EVENT,
};
use crate::AppState;

/// How often the job looks for feeds due.
const TICK: Duration = Duration::from_secs(60);
/// Proton's: a feed unreachable is tried again sooner than a good one.
const RETRY_MINUTES: i64 = 30;
const USER_AGENT: &str = "Kutup-Calendar/1 (+calendar subscriptions)";

/// A feed as the calendar's members see it. The URL is its owner's only: it
/// can hold a secret (Google's secret address does).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FeedView {
    pub url: Option<String>,
    /// `syncing` (never fetched), `ok`, or why the last fetch failed:
    /// `unreachable`, `tooBig`, `notACalendar`, `tooManyEvents`,
    /// `storageFull`, `unavailable`.
    pub status: String,
    /// The last fetch that left the calendar matching the feed: a client
    /// says "not synced" past 12 hours (Proton's).
    #[serde(with = "time::serde::rfc3339::option")]
    pub synced_at: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub checked_at: Option<time::OffsetDateTime>,
    /// Events in the feed that couldn't be taken (unsupported or invalid).
    pub skipped: i32,
}

/// The feeds of `calendars`, by calendar; the URL only where `owner` owns it.
pub(crate) async fn views(
    pool: &PgPool,
    calendars: &[Uuid],
    owner: Uuid,
) -> AppResult<HashMap<Uuid, FeedView>> {
    type Row = (
        Uuid,
        String,
        String,
        Option<time::OffsetDateTime>,
        Option<time::OffsetDateTime>,
        i32,
        Uuid,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT f.calendar_id, f.url, f.status, f.synced_at, f.checked_at, f.skipped,
                c.owner_account_id
           FROM calendar_feeds f JOIN calendars c ON c.id = f.calendar_id
          WHERE f.calendar_id = ANY($1)",
    )
    .bind(calendars)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, url, status, synced_at, checked_at, skipped, by)| {
            let url = (by == owner).then_some(url);
            (
                id,
                FeedView {
                    url,
                    status,
                    synced_at,
                    checked_at,
                    skipped,
                },
            )
        })
        .collect())
}

/// Whether `calendar` is a subscription.
pub(crate) async fn is_feed<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    calendar: Uuid,
) -> AppResult<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM calendar_feeds WHERE calendar_id = $1)")
            .bind(calendar)
            .fetch_one(executor)
            .await?,
    )
}

/// Refuses a change to a subscription's events, members or links: the feed
/// is its only writer, and it isn't shared (Proton's).
pub(crate) async fn refuse_feed<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    calendar: Uuid,
) -> AppResult<()> {
    if is_feed(executor, calendar).await? {
        return Err(coded(
            AppError::forbidden("a calendar from a URL is read-only and isn't shared"),
            "feedReadOnly",
        ));
    }
    Ok(())
}

/// A feed's address as written: `webcal://` is `https://` (Proton's), and
/// only a public https address on port 443 is taken.
pub fn parse_url(value: &str) -> AppResult<Url> {
    let value = value.trim();
    let value = match value.get(..9) {
        Some(scheme) if scheme.eq_ignore_ascii_case("webcal://") => {
            format!("https://{}", &value[9..])
        }
        _ => value.to_owned(),
    };
    public_fetch::parse_long_public_https(&value).map_err(|_| {
        coded(
            AppError::bad_request("the address is not a public https address"),
            "feedUrlInvalid",
        )
    })
}

/// Checks, inside the calendar's creation, that the owner may subscribe to
/// one more feed, and records it: the job fetches it on its next pass.
pub(crate) async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    calendar: Uuid,
    owner: Uuid,
    url: &Url,
) -> AppResult<()> {
    let most = CALENDAR_FEEDS_PER_ACCOUNT
        .load_for(&mut **tx, owner)
        .await?;
    let held: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM calendar_feeds f JOIN calendars c ON c.id = f.calendar_id
          WHERE c.owner_account_id = $1",
    )
    .bind(owner)
    .fetch_one(&mut **tx)
    .await?;
    if held >= most {
        return Err(coded(
            AppError::conflict(format!("an account subscribes to at most {most} calendars")),
            "feedLimit",
        ));
    }
    sqlx::query("INSERT INTO calendar_feeds (calendar_id, url) VALUES ($1, $2)")
        .bind(calendar)
        .bind(url.as_str())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

// ----- the feed key -----

struct FeedKey {
    secret: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
}

/// The server's feed key, made once on first use (another instance racing
/// to make it loses, and both use what is stored).
async fn feed_key(pool: &PgPool, server_name: &str) -> anyhow::Result<FeedKey> {
    if let Some(key) = load_feed_key(pool).await? {
        return Ok(key);
    }
    let now = u32::try_from(time::OffsetDateTime::now_utc().unix_timestamp())?;
    let made = cal::generate_feed_key(server_name, now)?;
    sqlx::query(
        "INSERT INTO calendar_feed_key (secret_key, public_key) VALUES ($1, $2)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(made.secret_key.as_slice())
    .bind(&made.public_key)
    .execute(pool)
    .await?;
    load_feed_key(pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("the calendar feed key was not stored"))
}

async fn load_feed_key(pool: &PgPool) -> anyhow::Result<Option<FeedKey>> {
    let row: Option<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT secret_key, public_key FROM calendar_feed_key")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(secret, public)| FeedKey {
        secret: Zeroizing::new(secret),
        public,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FeedKeyView {
    /// The binary OpenPGP public key, base64: it signs every event of a
    /// calendar from a URL.
    pub public_key: String,
}

/// `GET /api/v1/calendar/feed-key` — the key that signs subscriptions'
/// events: a client verifies them against it and shows them "from a
/// subscription", not as from a person.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/feed-key",
    tag = "calendar",
    security(("BearerAuth" = [])),
    responses((status = 200, body = FeedKeyView))
)]
pub async fn get_feed_key(
    State(state): State<AppState>,
    _user: crate::middleware::AuthAccount,
) -> AppResult<Json<FeedKeyView>> {
    let key = feed_key(&state.pool, &state.config.federation_server_name)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(Json(FeedKeyView {
        public_key: STANDARD.encode(&key.public),
    }))
}

// ----- refreshing -----

/// Which addresses a refresh may fetch: always [`PUBLIC`] but in tests.
pub(crate) struct Reach<'a> {
    pub checks: &'a Checks,
    pub allow_http: bool,
}

const PUBLIC: Reach<'static> = Reach {
    checks: &Checks::PUBLIC,
    allow_http: false,
};

/// Spawns the refresh job: every minute, the feeds due, a batch at a time.
pub fn spawn(pool: PgPool, server_name: String) {
    use crate::job_health::{beat, register};
    register("calendar.feeds", TICK);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            if let Err(error) = refresh_due(&pool, &server_name, &PUBLIC).await {
                tracing::warn!(%error, "calendar: the feed refresh failed");
            }
            beat(&pool, "calendar.feeds").await;
        }
    });
}

/// Fetches a new subscription now, off the request (Proton's: a calendar
/// from a URL fills in at once, "syncing" meanwhile).
pub(crate) fn refresh_soon(pool: PgPool, server_name: String, calendar: Uuid) {
    tokio::spawn(async move {
        if let Err(error) = refresh_calendar(&pool, &server_name, calendar, &PUBLIC).await {
            tracing::warn!(%error, %calendar, "calendar: the first feed fetch failed");
        }
    });
}

/// A feed claimed: its calendar, address, last body's hash and status.
type Claimed = (Uuid, String, Option<Vec<u8>>, String);

/// Claims feeds (their next time moved on first, so another instance or a
/// slow fetch never takes one twice): those due, or `only` whether due or
/// not.
async fn claim(pool: &PgPool, only: Option<Uuid>) -> anyhow::Result<Vec<Claimed>> {
    let batch = CALENDAR_FEED_BATCH.load(pool).await?;
    let hours = CALENDAR_FEED_REFRESH_HOURS.load(pool).await?;
    Ok(sqlx::query_as(
        "UPDATE calendar_feeds f SET next_at = now() + make_interval(hours => $2::int)
          WHERE f.calendar_id IN (
                SELECT calendar_id FROM calendar_feeds
                 WHERE CASE WHEN $3::uuid IS NULL THEN next_at <= now() ELSE calendar_id = $3 END
                 ORDER BY next_at LIMIT $1 FOR UPDATE SKIP LOCKED)
          RETURNING f.calendar_id, f.url, f.content_hash, f.status",
    )
    .bind(batch)
    .bind(hours as i32)
    .bind(only)
    .fetch_all(pool)
    .await?)
}

/// Refreshes the feeds due.
pub(crate) async fn refresh_due(
    pool: &PgPool,
    server_name: &str,
    reach: &Reach<'_>,
) -> anyhow::Result<()> {
    let due = claim(pool, None).await?;
    run(pool, server_name, due, reach).await
}

/// Refreshes one calendar's feed now.
pub(crate) async fn refresh_calendar(
    pool: &PgPool,
    server_name: &str,
    calendar: Uuid,
    reach: &Reach<'_>,
) -> anyhow::Result<()> {
    let due = claim(pool, Some(calendar)).await?;
    run(pool, server_name, due, reach).await
}

async fn run(
    pool: &PgPool,
    server_name: &str,
    due: Vec<Claimed>,
    reach: &Reach<'_>,
) -> anyhow::Result<()> {
    if due.is_empty() {
        return Ok(());
    }
    let key = feed_key(pool, server_name).await?;
    for (calendar, url, hash, status) in due {
        let outcome =
            refresh_one(pool, &key, calendar, &url, hash.as_deref(), &status, reach).await;
        let (status, synced, hash, skipped) = match outcome {
            Ok(Refreshed::Unchanged) => ("ok", true, None, None),
            Ok(Refreshed::Applied { hash, skipped }) => ("ok", true, Some(hash), Some(skipped)),
            Err(Failure::Status(status)) => (status, false, None, None),
            Err(Failure::Fault(error)) => {
                tracing::warn!(%error, %calendar, "calendar: a feed refresh failed");
                ("unavailable", false, None, None)
            }
        };
        // A failed fetch is tried again sooner (within the half hour).
        sqlx::query(
            "UPDATE calendar_feeds SET status = $2, checked_at = now(),
                    synced_at = CASE WHEN $3 THEN now() ELSE synced_at END,
                    content_hash = COALESCE($4, content_hash),
                    skipped = COALESCE($5, skipped),
                    next_at = CASE WHEN $3 THEN next_at
                                   ELSE LEAST(next_at, now() + make_interval(mins => $6::int)) END
              WHERE calendar_id = $1",
        )
        .bind(calendar)
        .bind(status)
        .bind(synced)
        .bind(hash)
        .bind(skipped)
        .bind(RETRY_MINUTES as i32)
        .execute(pool)
        .await?;
    }
    Ok(())
}

enum Refreshed {
    Unchanged,
    Applied { hash: Vec<u8>, skipped: i32 },
}

enum Failure {
    /// What the owner is told (a [`FeedView::status`]).
    Status(&'static str),
    /// A fault of this server's: logged, shown as `unavailable`.
    Fault(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for Failure {
    fn from(error: E) -> Self {
        Failure::Fault(error.into())
    }
}

async fn refresh_one(
    pool: &PgPool,
    key: &FeedKey,
    calendar: Uuid,
    url: &str,
    old_hash: Option<&[u8]>,
    old_status: &str,
    reach: &Reach<'_>,
) -> Result<Refreshed, Failure> {
    let max_bytes = CALENDAR_FEED_MAX_BYTES.load(pool).await?;
    let timeout = CALENDAR_FEED_TIMEOUT_SECONDS.load(pool).await?;
    let body = fetch(url, max_bytes, timeout, reach).await?;
    let hash = digest(&body);
    if old_status == "ok" && old_hash == Some(hash.as_slice()) {
        return Ok(Refreshed::Unchanged);
    }
    let text = String::from_utf8(body).map_err(|_| Failure::Status("notACalendar"))?;
    let skipped = apply(pool, key, calendar, &text, max_bytes).await?;
    Ok(Refreshed::Applied { hash, skipped })
}

async fn fetch(
    url: &str,
    max_bytes: i64,
    timeout: i64,
    reach: &Reach<'_>,
) -> Result<Vec<u8>, Failure> {
    // Checked again: the setting or the address rules may have changed.
    let url = public_fetch::parse_checked_long(url, reach.checks, reach.allow_http)
        .map_err(|_| Failure::Status("unreachable"))?;
    let request = public_fetch::Request {
        accept: "text/calendar, */*;q=0.5",
        user_agent: USER_AGENT,
        timeout: Duration::from_secs(u64::try_from(timeout).unwrap_or(30)),
        limit: usize::try_from(max_bytes).unwrap_or(usize::MAX),
        truncate: false,
        // The reader decides: feeds are served as anything.
        wanted: &|_| true,
        body: None,
    };
    let options = public_fetch::Options {
        allow_http: reach.allow_http,
        ..Default::default()
    };
    match public_fetch::fetch(url, &request, &options, reach.checks).await {
        Ok(fetched) => Ok(fetched.body),
        Err(error) if error.message == "the answer is too large" => Err(Failure::Status("tooBig")),
        Err(error) if error.status.is_server_error() => {
            Err(Failure::Fault(anyhow::anyhow!(error.message)))
        }
        Err(_) => Err(Failure::Status("unreachable")),
    }
}

/// The 32-byte digest feeds and their events are compared by.
fn digest(data: &[u8]) -> Vec<u8> {
    kutup_crypto::primitives::hash(kutup_crypto::primitives::Suite::V1, data).to_vec()
}

/// What one refresh reads: the hashes kept, the events sealed, and how
/// many weren't taken.
type Read = (HashSet<Vec<u8>>, Vec<Sealed>, i32);

/// One feed event sealed and checked, with what identifies it.
struct Sealed {
    source_hash: Vec<u8>,
    checked: Checked,
}

/// The hash a feed event is compared by: its fields as read, less DTSTAMP
/// (many feeds write the time of the request there).
fn source_hash(event: &ImportedEventV1) -> Vec<u8> {
    let mut fields = event.fields.clone();
    fields.dtstamp = String::new();
    digest(&serde_json::to_vec(&fields).expect("fields serialize"))
}

/// Makes the calendar match the feed: events whose source is unchanged stay
/// as they are (ids, reminders, alarms), changed ones are sealed again in
/// place, new ones added, and the ones gone deleted; one transaction.
/// Returns how many of the feed's events weren't taken.
async fn apply(
    pool: &PgPool,
    key: &FeedKey,
    calendar: Uuid,
    text: &str,
    max_bytes: i64,
) -> Result<i32, Failure> {
    let max_events = CALENDAR_FEED_MAX_EVENTS
        .load(pool)
        .await?
        .min(CALENDAR_EVENTS_PER_CALENDAR.load(pool).await?);
    let max_count = CALENDAR_MAX_COUNT.load(pool).await?;
    let max_reminders = CALENDAR_REMINDERS_PER_EVENT.load(pool).await?;
    let options = ImportOptionsV1 {
        primary_zone: "UTC".into(),
        max_bytes: u64::try_from(max_bytes).unwrap_or(u64::MAX),
        max_events: u32::try_from(max_events).unwrap_or(u32::MAX),
        max_count: u16::try_from(max_count).unwrap_or(u16::MAX),
        max_reminders: u16::try_from(max_reminders).unwrap_or(u16::MAX),
        now: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?,
    };
    let (public_key, generation): (Vec<u8>, i32) = sqlx::query_as(
        "SELECT k.public_key, c.key_generation FROM calendars c
           JOIN calendar_keys k ON k.calendar_id = c.id AND k.key_generation = c.key_generation
          WHERE c.id = $1",
    )
    .bind(calendar)
    .fetch_one(pool)
    .await?;
    let existing: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT id, feed_source_hash FROM calendar_events
          WHERE calendar_id = $1 AND feed_source_hash IS NOT NULL",
    )
    .bind(calendar)
    .fetch_all(pool)
    .await?;
    let kept_hashes: HashSet<Vec<u8>> = existing.iter().map(|(_, hash)| hash.clone()).collect();
    // The CPU work (reading, sealing, checking) off the async threads.
    let (text, secret, public) = (text.to_owned(), key.secret.clone(), key.public.clone());
    let (unchanged, sealed, skipped) =
        tokio::task::spawn_blocking(move || -> Result<Read, Failure> {
            let read = match import(&text, &options).map_err(|e| anyhow::anyhow!(e.to_string()))? {
                ImportOutcomeV1::Read(read) => read,
                ImportOutcomeV1::Refused(FileError::NoEvents) => {
                    return Ok((HashSet::new(), Vec::new(), 0))
                }
                ImportOutcomeV1::Refused(FileError::FileTooBig) => {
                    return Err(Failure::Status("tooBig"))
                }
                ImportOutcomeV1::Refused(FileError::TooManyEvents) => {
                    return Err(Failure::Status("tooManyEvents"))
                }
                ImportOutcomeV1::Refused(_) => return Err(Failure::Status("notACalendar")),
            };
            let mut skipped = i32::try_from(read.errors.len()).unwrap_or(i32::MAX);
            let mut unchanged = HashSet::new();
            let mut sealed = Vec::new();
            let mut seen = HashSet::new();
            for event in &read.events {
                let hash = source_hash(event);
                if !seen.insert(hash.clone()) {
                    continue;
                }
                if kept_hashes.contains(&hash) {
                    unchanged.insert(hash);
                    continue;
                }
                let mut fields = event.fields.clone();
                // Not an invitation here: nobody answers a subscription.
                fields.organizer = None;
                let result = fields
                    .to_parts()
                    .and_then(|parts| cal::seal_feed_event(&parts, &public_key, &secret))
                    .map_err(|e| AppError::bad_request(e.to_string()))
                    .and_then(|event| {
                        check_event(
                            &cal::SealedEventV1::of(&event),
                            &public_key,
                            std::slice::from_ref(&public),
                            "",
                            max_count,
                        )
                    });
                match result {
                    Ok(checked) => sealed.push(Sealed {
                        source_hash: hash,
                        checked,
                    }),
                    Err(_) => skipped = skipped.saturating_add(1),
                }
            }
            Ok((unchanged, sealed, skipped))
        })
        .await
        .map_err(|error| Failure::Fault(error.into()))??;
    let mut skipped = skipped;
    let mut tx = pool.begin().await?;
    // The calendar orders its writes; its key may have rotated meanwhile
    // (then the next pass seals again).
    let locked: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT c.owner_account_id, c.key_generation FROM calendars c
           JOIN calendar_feeds f ON f.calendar_id = c.id
          WHERE c.id = $1 FOR UPDATE OF c",
    )
    .bind(calendar)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((owner, newest)) = locked else {
        // Deleted meanwhile.
        return Ok(0);
    };
    if newest != generation {
        return Err(Failure::Fault(anyhow::anyhow!(
            "the calendar's key rotated"
        )));
    }
    // What is stored, by UID and RECURRENCE-ID.
    type Stored = (
        Uuid,
        String,
        Option<time::OffsetDateTime>,
        Option<Vec<u8>>,
        i64,
        i64,
        i64,
    );
    let stored: Vec<Stored> = sqlx::query_as(
        "SELECT e.id, se.uid, se.recurrence_id, e.feed_source_hash, e.bytes, se.bytes, e.revision
           FROM calendar_events e JOIN calendar_shared_events se ON se.id = e.shared_event_id
          WHERE e.calendar_id = $1",
    )
    .bind(calendar)
    .fetch_all(&mut *tx)
    .await?;
    let mut by_key: HashMap<(String, Option<time::OffsetDateTime>), (Uuid, i64, i64)> =
        HashMap::new();
    let mut gone: HashMap<Uuid, i64> = HashMap::new();
    for (id, uid, recurrence_id, hash, own_bytes, shared_bytes, revision) in stored {
        if hash.as_ref().is_some_and(|hash| unchanged.contains(hash)) {
            continue;
        }
        by_key.insert(
            (uid, recurrence_id),
            (id, own_bytes + shared_bytes, revision),
        );
        gone.insert(id, own_bytes + shared_bytes);
    }
    // Series before their changed occurrences, as the reader orders them.
    let mut delta: i64 = 0;
    let mut writes: Vec<(Option<(Uuid, i64)>, Sealed)> = Vec::new();
    let mut taken = HashSet::new();
    for item in sealed {
        let key = (item.checked.shared.uid.clone(), item.checked.recurrence_id);
        if !taken.insert(key.clone()) {
            skipped = skipped.saturating_add(1);
            continue;
        }
        match by_key.get(&key) {
            Some(&(id, old_bytes, revision)) => {
                gone.remove(&id);
                delta += item.checked.bytes - old_bytes;
                writes.push((Some((id, revision)), item));
            }
            None => {
                delta += item.checked.bytes;
                writes.push((None, item));
            }
        }
    }
    delta -= gone.values().sum::<i64>();
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM calendar_events WHERE calendar_id = $1")
            .bind(calendar)
            .fetch_one(&mut *tx)
            .await?;
    let adding = writes.iter().filter(|(at, _)| at.is_none()).count() as i64;
    if count - gone.len() as i64 + adding > CALENDAR_EVENTS_PER_CALENDAR.load(&mut *tx).await? {
        return Err(Failure::Status("tooManyEvents"));
    }
    for id in gone.keys() {
        sqlx::query(
            "DELETE FROM calendar_shared_events
              WHERE id = (SELECT shared_event_id FROM calendar_events WHERE id = $1)",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    let mut written = Vec::with_capacity(writes.len());
    for (at, item) in &writes {
        // Each in a savepoint: one the server refuses (a RECURRENCE-ID that
        // is no occurrence of its series, a UID another calendar's
        // invitation holds) is skipped, the rest go on.
        let mut one = sqlx::Acquire::begin(&mut *tx).await?;
        let outcome = match at {
            Some((id, revision)) => rewrite(&mut one, *id, *revision, &item.checked)
                .await
                .map(|()| *id)
                .map_err(Failure::Fault),
            None => {
                let id = Uuid::new_v4();
                let kept = Kept {
                    id,
                    shared_id: id,
                    created_at: time::OffsetDateTime::now_utc(),
                    revision: 1,
                };
                match check_parent(&mut one, calendar, &item.checked, true).await {
                    Ok(()) => insert_as(&mut one, kept, calendar, None, None, &item.checked)
                        .await
                        .map_err(|error| refused(error, "insert")),
                    Err(error) => Err(refused(error, "parent")),
                }
            }
        };
        match outcome {
            Ok(id) => {
                one.commit().await?;
                written.push((id, item));
            }
            Err(Failure::Status(_)) => {
                one.rollback().await?;
                delta -= match at {
                    Some((id, _)) => {
                        // The stored version stays as it was.
                        let old = by_key
                            .values()
                            .find(|(stored, _, _)| stored == id)
                            .map_or(0, |(_, bytes, _)| *bytes);
                        item.checked.bytes - old
                    }
                    None => item.checked.bytes,
                };
                skipped = skipped.saturating_add(1);
            }
            Err(fault) => return Err(fault),
        }
    }
    for (id, item) in &written {
        sqlx::query("UPDATE calendar_events SET feed_source_hash = $2 WHERE id = $1")
            .bind(id)
            .bind(&item.source_hash)
            .execute(&mut *tx)
            .await?;
        crate::calendar_alarms::recompute(&mut tx, *id).await?;
    }
    if delta > 0 {
        if let Err(error) = crate::storage_pool::charge_within_quota(&mut tx, owner, delta).await {
            if error.status.is_server_error() {
                return Err(Failure::Fault(anyhow::anyhow!(error.message)));
            }
            return Err(Failure::Status("storageFull"));
        }
    } else if delta < 0 {
        crate::storage_pool::charge(&mut *tx, crate::storage_pool::Payer::Account(owner), delta)
            .await?;
    }
    // Changed occurrences make their series' alarms skip them.
    let series: HashSet<&str> = written
        .iter()
        .filter(|(_, item)| item.checked.recurrence_id.is_some())
        .map(|(_, item)| item.checked.shared.uid.as_str())
        .collect();
    for uid in series {
        crate::calendar_alarms::recompute_series(&mut tx, calendar, uid).await?;
    }
    tx.commit().await?;
    Ok(skipped)
}

/// A write the server refused for this one event (a client error): skipped.
fn refused(error: AppError, what: &str) -> Failure {
    if error.status.is_server_error() {
        return Failure::Fault(anyhow::anyhow!("feed {what}: {}", error.message));
    }
    Failure::Status("skipped")
}

/// Writes a feed event again over the stored one with its UID and
/// RECURRENCE-ID: its ids, reminders and alarms stay. A feed may lower
/// SEQUENCE (it is someone else's), so no order is enforced.
async fn rewrite(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    revision: i64,
    checked: &Checked,
) -> anyhow::Result<()> {
    use kutup_crypto::calendar_event::EventTime;
    let event = &checked.event;
    let text = |data: &[u8]| String::from_utf8(data.to_vec()).expect("checked as text");
    let shared = &checked.shared;
    sqlx::query(
        "UPDATE calendar_shared_events SET
                shared_signed = $2, shared_signed_signature = $3,
                shared_encrypted = $4, shared_encrypted_signature = $5,
                start_utc = $6, end_utc = $7, start_tz = $8, end_tz = $9, full_day = $10,
                rrule = $11, range_end_utc = $12, sequence = $13, revision = revision + 1,
                bytes = $14, modified_at = now()
          WHERE id = (SELECT shared_event_id FROM calendar_events WHERE id = $1)",
    )
    .bind(id)
    .bind(text(&event.shared_signed.data))
    .bind(&event.shared_signed.signature)
    .bind(&event.shared_encrypted.data)
    .bind(&event.shared_encrypted.signature)
    .bind(checked.start)
    .bind(checked.end)
    .bind(shared.dtstart.tzid())
    .bind(shared.dtend.as_ref().and_then(EventTime::tzid))
    .bind(shared.dtstart.is_date())
    .bind(&shared.rrule)
    .bind(checked.range_end)
    .bind(shared.sequence.min(i32::MAX as u32) as i32)
    .bind(checked.shared_bytes)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE calendar_events SET shared_key_packet = $2, calendar_key_packet = $3,
                calendar_signed = $4, calendar_signed_signature = $5,
                calendar_encrypted = $6, calendar_encrypted_signature = $7,
                revision = $8, bytes = $9, modified_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&event.shared_key_packet)
    .bind(&event.calendar_key_packet)
    .bind(text(&event.calendar_signed.data))
    .bind(&event.calendar_signed.signature)
    .bind(
        event
            .calendar_encrypted
            .as_ref()
            .map(|part| part.data.clone()),
    )
    .bind(
        event
            .calendar_encrypted
            .as_ref()
            .map(|part| part.signature.clone()),
    )
    .bind(revision + 1)
    .bind(checked.own_bytes)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn webcal_is_https_and_only_public_https_is_taken() {
        assert_eq!(
            parse_url(" webcal://example.org/a.ics ").unwrap().as_str(),
            "https://example.org/a.ics"
        );
        assert_eq!(
            parse_url("WEBCAL://example.org/a.ics").unwrap().as_str(),
            "https://example.org/a.ics"
        );
        for bad in [
            "http://example.org/a.ics",
            "https://127.0.0.1/a.ics",
            "https://10.0.0.1/a.ics",
            "https://[::1]/a.ics",
            "https://example.org:8443/a.ics",
            "https://user:pw@example.org/a.ics",
            "file:///etc/passwd",
            "webcal://169.254.169.254/latest",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    const LOCAL_CHECKS: Checks = Checks {
        public: |_| true,
        any_port: true,
    };
    const LOCAL: Reach<'static> = Reach {
        checks: &LOCAL_CHECKS,
        allow_http: true,
    };

    /// A feed server answering every request with what the test set.
    async fn serve(answer: Arc<Mutex<(u16, String)>>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let (status, body) = answer.lock().unwrap().clone();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let _ = socket.read(&mut buffer).await;
                    let head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: text/calendar\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(body.as_bytes()).await;
                });
            }
        });
        port
    }

    fn ics(events: &[(&str, &str, &str)]) -> String {
        let mut text = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n");
        for (uid, summary, extra) in events {
            // DTSTAMP changes on every request, as many feeds write it.
            text.push_str(&format!(
                "BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:{}\r\nDTSTART:20270105T090000Z\r\nDTEND:20270105T100000Z\r\nSUMMARY:{summary}\r\n{extra}END:VEVENT\r\n",
                time::OffsetDateTime::now_utc()
                    .format(&time::macros::format_description!(
                        "[year][month][day]T[hour][minute][second]Z"
                    ))
                    .unwrap()
            ));
        }
        text.push_str("END:VCALENDAR\r\n");
        text
    }

    type Row = (Uuid, String, i64, Option<Vec<u8>>);
    async fn events(pool: &PgPool, calendar: Uuid) -> Vec<Row> {
        sqlx::query_as(
            "SELECT e.id, se.uid, e.revision, e.feed_source_hash FROM calendar_events e
               JOIN calendar_shared_events se ON se.id = e.shared_event_id
              WHERE e.calendar_id = $1 ORDER BY se.uid, se.recurrence_id NULLS FIRST",
        )
        .bind(calendar)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    async fn status(pool: &PgPool, calendar: Uuid) -> (String, bool, i32) {
        sqlx::query_as(
            "SELECT status, synced_at IS NOT NULL, skipped FROM calendar_feeds WHERE calendar_id = $1",
        )
        .bind(calendar)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// The whole refresh against Postgres: sealed to the public key, signed by
    /// the feed key, unchanged events kept, changed ones resealed in place,
    /// gone ones deleted, failures leaving the events as they were.
    #[tokio::test]
    async fn live_a_feed_refreshes_into_its_calendar() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO accounts (id, username, identity_suite, drive_key_binding_epoch, master_key_generation) VALUES ($1, $2, 2, 1, 1)")
            .bind(user)
            .bind(format!("feeds{}", &user.simple().to_string()[..12]))
            .execute(&pool)
            .await
            .unwrap();
        let passphrase = cal::Passphrase::generate();
        let key = cal::generate_calendar_key(&passphrase, 1_790_000_000).unwrap();
        let calendar = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO calendars (id, owner_account_id, suite, key_generation,
                 metadata_key_packet, metadata_data_packet, metadata_signature, bytes)
             VALUES ($1, $2, 1, 1, '\\x01', '\\x01', 'x', 0)",
        )
        .bind(calendar)
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO calendar_keys (calendar_id, key_generation, public_key, fingerprint, locked_secret_key)
             VALUES ($1, 1, $2, $3, $4)",
        )
        .bind(calendar)
        .bind(&key.public_key)
        .bind(hex::encode(key.fingerprint))
        .bind(&key.locked_secret_key)
        .execute(&pool)
        .await
        .unwrap();
        let answer = Arc::new(Mutex::new((
            200,
            ics(&[
                ("a@feed", "Standup", "RRULE:FREQ=DAILY;COUNT=5\r\n"),
                ("b@feed", "Lunch", ""),
            ]),
        )));
        let port = serve(answer.clone()).await;
        sqlx::query("INSERT INTO calendar_feeds (calendar_id, url) VALUES ($1, $2)")
            .bind(calendar)
            .bind(format!("http://127.0.0.1:{port}/feed.ics"))
            .execute(&pool)
            .await
            .unwrap();
        let used = |pool: PgPool| async move {
            crate::storage_pool::quota_and_used(&pool, user)
                .await
                .unwrap()
                .1
        };
        let server = "feeds.test";

        refresh_calendar(&pool, server, calendar, &LOCAL)
            .await
            .unwrap();
        assert_eq!(status(&pool, calendar).await, ("ok".into(), true, 0));
        let first = events(&pool, calendar).await;
        assert_eq!(first.len(), 2);
        let charged = used(pool.clone()).await;
        assert!(charged > 0);
        // Sealed to the calendar, signed by the feed key: the owner's
        // client opens and verifies it; the server can't.
        let feed = load_feed_key(&pool).await.unwrap().unwrap();
        let unlocked = cal::unlock_calendar_key(&key.locked_secret_key, &passphrase).unwrap();
        type Stored = (
            String,
            String,
            Vec<u8>,
            String,
            Vec<u8>,
            Vec<u8>,
            String,
            String,
        );
        let sealed: Stored =
            sqlx::query_as(
                "SELECT se.shared_signed, se.shared_signed_signature, se.shared_encrypted,
                        se.shared_encrypted_signature, e.shared_key_packet, e.calendar_key_packet,
                        e.calendar_signed, e.calendar_signed_signature
                   FROM calendar_events e JOIN calendar_shared_events se ON se.id = e.shared_event_id
                  WHERE e.id = $1",
            )
            .bind(first[1].0)
            .fetch_one(&pool)
            .await
            .unwrap();
        let event = cal::SealedEvent {
            shared_key_packet: sealed.4,
            calendar_key_packet: sealed.5,
            shared_signed: cal::EventPart {
                data: sealed.0.into_bytes(),
                signature: sealed.1,
            },
            shared_encrypted: cal::EventPart {
                data: sealed.2,
                signature: sealed.3,
            },
            calendar_signed: cal::EventPart {
                data: sealed.6.into_bytes(),
                signature: sealed.7,
            },
            calendar_encrypted: None,
        };
        let opened = unlocked.open_event(&event, &[&feed.public]).unwrap();
        assert!(opened.verified);
        assert_eq!(
            opened.parts.shared_encrypted.summary.as_deref(),
            Some("Lunch")
        );

        // The same events again (only DTSTAMP moved): nothing is written.
        *answer.lock().unwrap() = (
            200,
            ics(&[
                ("a@feed", "Standup", "RRULE:FREQ=DAILY;COUNT=5\r\n"),
                ("b@feed", "Lunch", ""),
            ]),
        );
        refresh_calendar(&pool, server, calendar, &LOCAL)
            .await
            .unwrap();
        assert_eq!(events(&pool, calendar).await, first);

        // One changed, one gone, one new, one the reader can't take.
        *answer.lock().unwrap() = (
            200,
            ics(&[
                ("a@feed", "Standup moved", "RRULE:FREQ=DAILY;COUNT=5\r\n"),
                ("c@feed", "Review", ""),
                ("d@feed", "Broken", "RRULE:FREQ=SECONDLY\r\n"),
            ]),
        );
        refresh_calendar(&pool, server, calendar, &LOCAL)
            .await
            .unwrap();
        let (state, synced, skipped) = status(&pool, calendar).await;
        assert_eq!((state.as_str(), synced), ("ok", true));
        assert_eq!(skipped, 1);
        let second = events(&pool, calendar).await;
        assert_eq!(
            second.iter().map(|row| row.1.as_str()).collect::<Vec<_>>(),
            ["a@feed", "c@feed"]
        );
        // Changed in place: its id stays, its revision moves.
        assert_eq!(second[0].0, first[0].0);
        assert_eq!(second[0].2, 2);

        // A feed gone bad leaves the calendar as it was.
        *answer.lock().unwrap() = (200, "not a calendar".into());
        refresh_calendar(&pool, server, calendar, &LOCAL)
            .await
            .unwrap();
        assert_eq!(status(&pool, calendar).await.0, "notACalendar");
        assert_eq!(events(&pool, calendar).await, second);
        *answer.lock().unwrap() = (404, String::new());
        refresh_calendar(&pool, server, calendar, &LOCAL)
            .await
            .unwrap();
        assert_eq!(status(&pool, calendar).await.0, "unreachable");
        assert_eq!(events(&pool, calendar).await, second);

        // An empty feed empties the calendar and gives its storage back.
        *answer.lock().unwrap() = (200, ics(&[]));
        refresh_calendar(&pool, server, calendar, &LOCAL)
            .await
            .unwrap();
        assert_eq!(status(&pool, calendar).await.0, "ok");
        assert!(events(&pool, calendar).await.is_empty());
        assert_eq!(used(pool.clone()).await, 0);

        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
    }
}
