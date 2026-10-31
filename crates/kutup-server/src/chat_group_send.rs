//! Group send endorsements, the server's part
//! (docs/plans/group-send-endorsements.md): this server's endorsement keys
//! (§4), each account's daily endorsement (§3.2) and the keys senders check
//! endorsements with (`params`, this server's or another's).
//!
//! The home's part (members' blobs) is in `chat_groups::gateway`, the token
//! check on the multi route in `handlers::chat_multi`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::group_send::{
    GroupSendEndorsementResponseV1, GroupSendKeyV1, GroupSendParamsV1,
};
use kutup_crypto::primitives::{hash, Suite};
use kutup_federation_proto::{FederationFeature, FederationGroupSendKeyV1};
use kutup_group_send::{open_server_key, seal_server_key, ServerKey};
use serde::Deserialize;
use sqlx::PgPool;
use time::OffsetDateTime;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::federation::FederationDirection;
use crate::middleware::AuthUser;
use crate::opaque_setup::OpaqueSetupKeys;
use crate::AppState;

/// What a key that still issues publishes as `issuesUntil`: "until it is
/// rotated", as the largest whole number every client reads exactly
/// (JavaScript's `Number.MAX_SAFE_INTEGER`).
pub(crate) const STILL_ISSUING: u64 = (1 << 53) - 1;

/// How long instances keep the keys they read: a rotation by another
/// process reaches them within this.
const CACHE_FOR: Duration = Duration::from_secs(60);

/// One stored key, opened.
#[derive(Clone)]
pub(crate) struct StoredKey {
    pub key_id: u32,
    pub key: ServerKey,
    pub public_key: Vec<u8>,
    /// `None` while it issues.
    pub issues_until: Option<i64>,
    /// The latest token expiration a retired key verifies (`None` while it
    /// issues): the last endorsement it can have issued.
    pub verifies_until: Option<i64>,
    /// The `OPAQUE_SETUP_KEYS` entry it is sealed under.
    sealing_key_id: u16,
}

/// A stored key's row: id, sealing key id, sealed secret, public key, and
/// when it stopped issuing and stops verifying.
type KeyRow = (i32, i16, Vec<u8>, Vec<u8>, Option<i64>, Option<i64>);

impl StoredKey {
    fn published(&self) -> FederationGroupSendKeyV1 {
        FederationGroupSendKeyV1 {
            key_id: self.key_id,
            endorsement_public_key: STANDARD.encode(&self.public_key),
            issues_until: self
                .issues_until
                .and_then(|until| u64::try_from(until).ok())
                .unwrap_or(STILL_ISSUING),
        }
    }
}

/// This server's endorsement keys (§4): stored sealed under
/// `OPAQUE_SETUP_KEYS`, opened on read and kept for [`CACHE_FOR`].
pub(crate) struct GroupSendKeys {
    pool: PgPool,
    sealing: OpaqueSetupKeys,
    cache: tokio::sync::Mutex<Option<(Instant, Arc<Vec<StoredKey>>)>>,
}

impl GroupSendKeys {
    pub(crate) fn new(pool: PgPool, sealing: OpaqueSetupKeys) -> Self {
        Self {
            pool,
            sealing,
            cache: tokio::sync::Mutex::new(None),
        }
    }

    /// At startup: makes the first key if there is none (another instance
    /// starting at once may win; then its key is used), opens every stored
    /// one, so a wrong `OPAQUE_SETUP_KEYS` stops the server here, and seals
    /// again under the current sealing key each one sealed under an older
    /// one, so an operator who added a key may drop the old id after one
    /// start (docs/self-hosting.md, `OPAQUE_SETUP_KEYS`).
    pub(crate) async fn ensure(&self) -> anyhow::Result<()> {
        let issuing: Option<i32> =
            sqlx::query_scalar("SELECT key_id FROM chat_zk_server_keys WHERE issues_until IS NULL")
                .fetch_optional(&self.pool)
                .await?;
        if issuing.is_none() {
            let next = next_key_id(&self.pool).await?;
            insert(&self.pool, &self.sealing, next).await?;
            tracing::info!(key_id = next, "made a group send endorsement key");
        }
        let keys = self.read().await?;
        self.reseal(&keys).await?;
        anyhow::ensure!(
            keys.iter().any(|key| key.issues_until.is_none()),
            "no group send endorsement key issues"
        );
        *self.cache.lock().await = Some((Instant::now(), Arc::new(keys)));
        Ok(())
    }

    /// Seals each key held under an older `OPAQUE_SETUP_KEYS` entry under
    /// the current one; another instance doing the same at once changes
    /// nothing twice.
    async fn reseal(&self, keys: &[StoredKey]) -> anyhow::Result<()> {
        let (current, sealing_key) = self
            .sealing
            .current()
            .ok_or_else(|| anyhow::anyhow!("OPAQUE_SETUP_KEYS has no key"))?;
        for key in keys.iter().filter(|key| key.sealing_key_id != current) {
            let sealed = seal_server_key(&key.key, sealing_key, current, key.key_id)
                .map_err(|error| anyhow::anyhow!("seal the group send key: {error}"))?;
            sqlx::query(
                "UPDATE chat_zk_server_keys SET server_secret_sealed = $1, sealing_key_id = $2
                 WHERE key_id = $3 AND sealing_key_id = $4",
            )
            .bind(sealed)
            .bind(i16::try_from(current)?)
            .bind(i32::try_from(key.key_id)?)
            .bind(i16::try_from(key.sealing_key_id)?)
            .execute(&self.pool)
            .await?;
            tracing::info!(
                key_id = key.key_id,
                from = key.sealing_key_id,
                to = current,
                "sealed a group send key under the current OPAQUE_SETUP_KEYS key"
            );
        }
        Ok(())
    }

    /// The stored keys that still verify, the issuing one first.
    async fn read(&self) -> anyhow::Result<Vec<StoredKey>> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let rows: Vec<KeyRow> = sqlx::query_as(
            "SELECT key_id, sealing_key_id, server_secret_sealed, public_key, issues_until,
                    verifies_until
             FROM chat_zk_server_keys
             WHERE verifies_until IS NULL OR verifies_until >= $1
             ORDER BY issues_until IS NOT NULL, key_id DESC",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|row| self.open(row)).collect()
    }

    fn open(&self, row: KeyRow) -> anyhow::Result<StoredKey> {
        let (key_id, sealing_key_id, sealed, public_key, issues_until, verifies_until) = row;
        let key_id = u32::try_from(key_id)?;
        let sealing_key_id = u16::try_from(sealing_key_id)?;
        let sealing = self.sealing.get(sealing_key_id).ok_or_else(|| {
            anyhow::anyhow!(
                "group send key {key_id} is sealed under OPAQUE_SETUP_KEYS key {sealing_key_id}, \
                 which is not configured"
            )
        })?;
        let key = open_server_key(&sealed, sealing, sealing_key_id, key_id).map_err(|_| {
            anyhow::anyhow!(
                "group send key {key_id} does not open under OPAQUE_SETUP_KEYS key \
                 {sealing_key_id}: the key is wrong"
            )
        })?;
        Ok(StoredKey {
            key_id,
            key,
            public_key,
            issues_until,
            verifies_until,
            sealing_key_id,
        })
    }

    /// The keys now, from the cache while it is fresh.
    pub(crate) async fn keys(&self) -> AppResult<Arc<Vec<StoredKey>>> {
        let mut cache = self.cache.lock().await;
        if let Some((read_at, keys)) = cache.as_ref() {
            if read_at.elapsed() < CACHE_FOR {
                return Ok(Arc::clone(keys));
            }
        }
        let keys = Arc::new(
            self.read()
                .await
                .map_err(|error| AppError::internal(format!("group send keys: {error}")))?,
        );
        *cache = Some((Instant::now(), Arc::clone(&keys)));
        Ok(keys)
    }

    /// The key that issues.
    pub(crate) async fn issuing(&self) -> AppResult<StoredKey> {
        self.keys()
            .await?
            .iter()
            .find(|key| key.issues_until.is_none())
            .cloned()
            .ok_or_else(|| AppError::internal("no group send endorsement key issues"))
    }

    /// What discovery and `params` publish: the issuing key and, while it
    /// verifies, the previous one.
    pub(crate) async fn published(&self) -> AppResult<Vec<FederationGroupSendKeyV1>> {
        Ok(self
            .keys()
            .await?
            .iter()
            .map(StoredKey::published)
            .collect())
    }
}

async fn next_key_id(pool: &PgPool) -> anyhow::Result<u32> {
    let highest: Option<i32> = sqlx::query_scalar("SELECT max(key_id) FROM chat_zk_server_keys")
        .fetch_one(pool)
        .await?;
    Ok(u32::try_from(highest.unwrap_or(0))? + 1)
}

/// Stores a new issuing key `key_id`, sealed under the current sealing key.
/// Nothing when another key issues already or the id is taken.
async fn insert<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    sealing: &OpaqueSetupKeys,
    key_id: u32,
) -> anyhow::Result<()> {
    let (sealing_key_id, sealing_key) = sealing
        .current()
        .ok_or_else(|| anyhow::anyhow!("OPAQUE_SETUP_KEYS has no key"))?;
    let key = ServerKey::generate();
    let sealed = seal_server_key(&key, sealing_key, sealing_key_id, key_id)
        .map_err(|error| anyhow::anyhow!("seal the group send key: {error}"))?;
    sqlx::query(
        "INSERT INTO chat_zk_server_keys
             (key_id, sealing_key_id, server_secret_sealed, public_key)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(i32::try_from(key_id)?)
    .bind(i16::try_from(sealing_key_id)?)
    .bind(sealed)
    .bind(key.public_key().to_bytes())
    .execute(executor)
    .await?;
    Ok(())
}

/// `kutup-server chat-zk-keys rotate` (§4): the new key issues from now on;
/// the old one stops issuing at once and verifies until the latest
/// expiration it could have issued, then goes. Instances keep the keys they
/// read for [`CACHE_FOR`], so one may still issue with the old key that long:
/// its window counts from then. Refused while an earlier rotation's key
/// still verifies, so a server never has more than two.
pub(crate) async fn rotate(pool: &PgPool, sealing: &OpaqueSetupKeys) -> anyhow::Result<u32> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut tx = pool.begin().await?;
    sqlx::query("LOCK TABLE chat_zk_server_keys IN EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM chat_zk_server_keys WHERE verifies_until < $1")
        .bind(now)
        .execute(&mut *tx)
        .await?;
    let waiting: Option<i64> = sqlx::query_scalar(
        "SELECT max(verifies_until) FROM chat_zk_server_keys WHERE verifies_until IS NOT NULL",
    )
    .fetch_one(&mut *tx)
    .await?;
    if let Some(until) = waiting {
        anyhow::bail!(
            "the key retired by the last rotation verifies until {until} (Unix time); \
             rotate again after that"
        );
    }
    let last_issue = u64::try_from(now)? + CACHE_FOR.as_secs();
    let last_issued = i64::try_from(kutup_group_send::default_expiration(last_issue))?;
    sqlx::query(
        "UPDATE chat_zk_server_keys SET issues_until = $1, verifies_until = $2
         WHERE issues_until IS NULL",
    )
    .bind(now)
    .bind(last_issued)
    .execute(&mut *tx)
    .await?;
    let highest: Option<i32> = sqlx::query_scalar("SELECT max(key_id) FROM chat_zk_server_keys")
        .fetch_one(&mut *tx)
        .await?;
    let key_id = u32::try_from(highest.unwrap_or(0))? + 1;
    insert(&mut *tx, sealing, key_id).await?;
    tx.commit().await?;
    Ok(key_id)
}

/// Drops keys past their verification window (a maintenance job).
pub(crate) async fn sweep_keys(pool: &PgPool) -> AppResult<u64> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    Ok(
        sqlx::query("DELETE FROM chat_zk_server_keys WHERE verifies_until < $1")
            .bind(now)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

/// Where group sends are (`CHAT_GROUPS` and federation); elsewhere `404`.
fn enabled(state: &AppState) -> AppResult<&GroupSendKeys> {
    match (&state.group_send, state.federation.is_some()) {
        (Some(keys), true) if state.config.chat_groups => Ok(keys),
        _ => Err(AppError::not_found("not found")),
    }
}

/// `GET /api/chat/group-send/endorsement` (§3.2): today's endorsement of
/// the signed-in account, by this server's issuing key. It says nothing
/// about groups: every account fetches one a day.
#[utoipa::path(
    get,
    path = "/api/chat/group-send/endorsement",
    tag = "chat groups",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, body = GroupSendEndorsementResponseV1, description = "Sent with `Cache-Control: no-store`"),
        (status = 404, description = "Groups are off"),
        (status = 429, description = "Over the account's endorsements a day"),
    )
)]
pub(crate) async fn endorsement(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<impl axum::response::IntoResponse> {
    let keys = enabled(&state)?;
    let account =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::unauthorized("unauthorized"))?;
    let allowed = crate::site_settings::CHAT_GROUP_SEND_ENDORSEMENTS_PER_DAY
        .load(&state.pool)
        .await?;
    let digest: [u8; 32] = hash(
        Suite::V1,
        [
            kutup_crypto::labels::GROUP_SEND_ISSUE_V1,
            account.as_bytes(),
        ]
        .concat(),
    )
    .into();
    let mut tx = state.pool.begin().await?;
    let used =
        crate::handlers::chat::anonymous_count(&mut tx, "group_send_issue", &digest, 1, 86_400)
            .await?;
    tx.commit().await?;
    if used > allowed {
        return Err(AppError::too_many_requests(
            "too many group send endorsements today",
        ));
    }
    let issuing = keys.issuing().await?;
    let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| AppError::internal("clock"))?;
    let key = issuing.key.clone();
    let issued = tokio::task::spawn_blocking(move || key.issue(account, now))
        .await
        .map_err(|error| AppError::internal(format!("issue an endorsement: {error}")))?;
    // An account's own credential: no cache keeps it.
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(GroupSendEndorsementResponseV1 {
            key_id: issuing.key_id,
            expiration: issued.expiration,
            response: STANDARD.encode(issued.response),
        }),
    ))
}

#[derive(Debug, Deserialize, IntoParams)]
pub(crate) struct ParamsQuery {
    /// Another server, whose keys come from its verified discovery.
    server: Option<String>,
}

fn params_of(keys: Vec<FederationGroupSendKeyV1>) -> GroupSendParamsV1 {
    GroupSendParamsV1 {
        keys: keys
            .into_iter()
            .map(|key| GroupSendKeyV1 {
                key_id: key.key_id,
                endorsement_public_key: key.endorsement_public_key,
                issues_until: key.issues_until,
            })
            .collect(),
    }
}

/// `GET /api/chat/group-send/params?server=` (§4): the endorsement keys of
/// this server, or of `server` from its signed discovery, verified and
/// cached by this server's federation. A sender checks a recipient's
/// endorsement with its server's key; a wrong one costs only that check
/// (the recipient's copy goes pairwise), as each server verifies tokens with
/// its own secret.
#[utoipa::path(
    get,
    path = "/api/chat/group-send/params",
    tag = "chat groups",
    security(("BearerAuth" = [])),
    params(ParamsQuery),
    responses(
        (status = 200, body = GroupSendParamsV1),
        (status = 404, description = "Groups are off, or that server publishes no keys"),
        (status = 502, description = "That server is unreachable"),
    )
)]
pub(crate) async fn params(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(query): Query<ParamsQuery>,
) -> AppResult<Json<GroupSendParamsV1>> {
    let keys = enabled(&state)?;
    let federation = state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("not found"))?;
    let published = match query.server.as_deref() {
        None => keys.published().await?,
        Some(server) if server == federation.server_name() => keys.published().await?,
        Some(server) => {
            kutup_federation_proto::validate_server_name(server)
                .map_err(|_| AppError::bad_request("invalid server"))?;
            federation
                .resolve_peer(
                    server,
                    FederationFeature::ChatV2,
                    FederationDirection::Outbound,
                    OffsetDateTime::now_utc(),
                )
                .await
                .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "that server is unreachable"))?
                .chat_group_send
        }
    };
    if published.is_empty() {
        return Err(AppError::not_found(
            "that server publishes no group send keys",
        ));
    }
    Ok(Json(params_of(published)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealing(entries: &[(u16, u8)]) -> OpaqueSetupKeys {
        let list: Vec<String> = entries
            .iter()
            .map(|(id, byte)| format!("{id}:{}", STANDARD.encode([*byte; 32])))
            .collect();
        OpaqueSetupKeys::parse(&list.join(",")).unwrap()
    }

    async fn stored(pool: &PgPool) -> Vec<(i32, i16, Vec<u8>)> {
        sqlx::query_as(
            "SELECT key_id, sealing_key_id, public_key FROM chat_zk_server_keys ORDER BY key_id",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// The start-up reseal (docs/self-hosting.md, `OPAQUE_SETUP_KEYS`): a key
    /// sealed under entry 1 is sealed under 2 once 2 is added, the server
    /// then starts with 2 alone, and two instances starting at once leave it
    /// consistent. Needs a database whose server runs without groups (the
    /// backup gate's), as the test owns `chat_zk_server_keys`.
    #[tokio::test]
    async fn live_keys_are_resealed_under_the_current_entry_at_start() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        assert!(
            stored(&pool).await.is_empty(),
            "the gate's server runs without groups, so no key is stored yet"
        );
        let (one, both, two) = (
            sealing(&[(1, 0x11)]),
            sealing(&[(1, 0x11), (2, 0x22)]),
            sealing(&[(2, 0x22)]),
        );

        // First start: the key is made under entry 1.
        GroupSendKeys::new(pool.clone(), one.clone())
            .ensure()
            .await
            .unwrap();
        let first = stored(&pool).await;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].1, 1);
        let public = first[0].2.clone();

        // Entry 2 added: the next start seals it under 2, the same key.
        let started = GroupSendKeys::new(pool.clone(), both.clone());
        started.ensure().await.unwrap();
        let resealed = stored(&pool).await;
        assert_eq!((resealed[0].0, resealed[0].1), (first[0].0, 2));
        assert_eq!(started.issuing().await.unwrap().public_key, public);

        // Entry 1 dropped: the server still starts, with the same key.
        let only_two = GroupSendKeys::new(pool.clone(), two.clone());
        only_two.ensure().await.unwrap();
        let key = only_two.issuing().await.unwrap();
        assert_eq!(key.public_key, public);
        let issued = key.key.issue(Uuid::new_v4(), 1_700_000_000);
        assert!(!issued.response.is_empty());

        // Back under entry 1, then two instances start at once with both.
        let (key_id, _, _) = stored(&pool).await.remove(0);
        let sealed = seal_server_key(&key.key, &[0x11; 32], 1, key.key_id).unwrap();
        sqlx::query(
            "UPDATE chat_zk_server_keys SET server_secret_sealed = $1, sealing_key_id = 1
             WHERE key_id = $2",
        )
        .bind(sealed)
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
        let (a, b) = (
            GroupSendKeys::new(pool.clone(), both.clone()),
            GroupSendKeys::new(pool.clone(), both),
        );
        let (first_start, second_start) = tokio::join!(a.ensure(), b.ensure());
        first_start.unwrap();
        second_start.unwrap();
        let after = stored(&pool).await;
        assert_eq!(after.len(), 1, "no second key was made");
        assert_eq!((after[0].1, &after[0].2), (2, &public));
        let alone = GroupSendKeys::new(pool.clone(), two);
        alone.ensure().await.unwrap();
        assert_eq!(alone.issuing().await.unwrap().public_key, public);

        // A key whose entry is gone stops the start, as documented.
        let wrong = GroupSendKeys::new(pool.clone(), one);
        assert!(wrong.ensure().await.is_err());

        sqlx::query("DELETE FROM chat_zk_server_keys")
            .execute(&pool)
            .await
            .unwrap();
    }
}
