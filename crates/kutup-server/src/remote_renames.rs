//! Renames across servers (docs/plans/username-renames.md, R2): the chains
//! this server publishes for its own accounts, the announces it sends when one
//! of them renames, and the chains it keeps of other servers' accounts.
//!
//! A chain proves itself: every statement is signed by the account authority,
//! and the incarnation it names is the hash of that authority. A server keeps
//! one only for the domain that signed it (every address in it on that
//! domain), never lets a shorter or different one replace it, and moves its
//! own rows (shares, profile keys, collaboration devices) to the chain's
//! current address by incarnation alone. A peer can sign a chain for a fresh
//! authority claiming any of its names; that is another incarnation, and moves
//! nothing that belongs to an existing one.

use std::collections::HashMap;
use std::str::FromStr as _;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_rename::{verify_chain, AccountRenameV1, RenameChainView};
use kutup_crypto::names::fold_address;
use kutup_federation_proto::FederationFeature;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::drive_federation::{signed_app_error, signed_json, JSON_CONTENT_TYPE};
use crate::error::{AppError, AppResult};
use crate::federation::{
    lacks_capability, AuthenticatedFederationResponse, FederationAdmissionError,
    FederationRequestSpec, FederationStack,
};
use crate::AppState;

/// The one chain-list format there is (`{ "version": 1, "chains": [...] }`).
pub const VERSION: u64 = 1;
/// The most chains kept of one domain: an announce past it is `429`.
const MAX_PER_DOMAIN: i64 = 50_000;
/// The most chains one answer may carry (a reused name is in several).
const MAX_CHAINS_PER_ANSWER: usize = 50;
const ANNOUNCE_PATH: &str = "/api/fed/accounts/renames";
const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
/// A kept chain younger than this answers a lookup without asking its server.
const FRESH_SECONDS: f64 = 24.0 * 3600.0;
/// Lookups of one address within this share one fetch.
const COALESCE_SECONDS: f64 = 60.0;
/// An announce not delivered in this long is dropped (peers learn on their
/// next lookup instead, from `409 renamed`).
const GIVE_UP_DAYS: i64 = 7;
const ANNOUNCES_PER_PASS: i64 = 50;
const FEATURE_HEADER: &str = "kutup-federation-feature";

/// One account incarnation's chain, as lookups and `409 renamed` carry it:
/// the signed statements unaltered, with what the answering server says of it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChainEntry {
    pub incarnation_id: String,
    pub authority_public_key: String,
    pub current: String,
    /// `current`, `held` or `gone` (unknown): shown, never trusted.
    pub state: String,
    pub chain: Vec<AccountRenameV1>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChainsV1 {
    version: u64,
    chains: Vec<ChainEntry>,
}

/// What a server sends its peers after one of its accounts renames.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnnounceV1 {
    pub version: u64,
    /// The chain's last `current`, without its domain (the sender's).
    pub username: String,
    pub incarnation_id: String,
    pub authority_public_key: String,
    pub chain: Vec<AccountRenameV1>,
}

struct Verified {
    entry: ChainEntry,
    view: RenameChainView,
}

/// What keeping a verified chain did.
#[derive(Debug, PartialEq, Eq)]
enum Stored {
    /// New, or longer than the one kept: kept, and rows moved.
    Advanced,
    /// The one kept already.
    Same,
    /// Shorter than the one kept: a rollback, not kept.
    Behind,
    /// Neither extends the other (the authority signed two histories): the
    /// kept one stays.
    Forked,
}

fn key32(value: &str) -> Option<[u8; 32]> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|raw| STANDARD.encode(raw) == value)
        .and_then(|raw| raw.try_into().ok())
}

/// Checks a chain `domain` gave: it verifies under its authority (which the
/// incarnation is the hash of), every address in it is on `domain`, and its
/// `current` is the chain's.
fn verify(domain: &str, mut entry: ChainEntry) -> Result<Verified, &'static str> {
    let authority = key32(&entry.authority_public_key).ok_or("authority key")?;
    let view = verify_chain(&authority, &entry.chain).map_err(|_| "the chain")?;
    if view.incarnation_id != entry.incarnation_id {
        return Err("another incarnation");
    }
    if !view
        .addresses
        .iter()
        .all(|address| address.rsplit_once('@').is_some_and(|(_, d)| d == domain))
    {
        return Err("an address on another server");
    }
    if entry.current != view.current {
        return Err("current is not the chain's");
    }
    if !matches!(entry.state.as_str(), "current" | "held" | "gone") {
        entry.state = "gone".into();
    }
    Ok(Verified { entry, view })
}

/// Keeps a verified chain of `domain`: new, or replacing a shorter one of the
/// same incarnation (rows then move to its current address); never a shorter
/// or a different one.
async fn store(pool: &sqlx::PgPool, domain: &str, verified: &Verified) -> AppResult<Stored> {
    let entry = &verified.entry;
    let mut tx = pool.begin().await?;
    let kept: Option<(Value, String)> = sqlx::query_as(
        "SELECT chain, authority_public_key FROM remote_account_renames
          WHERE domain = $1 AND incarnation_id = $2 FOR UPDATE",
    )
    .bind(domain)
    .bind(&entry.incarnation_id)
    .fetch_optional(&mut *tx)
    .await?;
    let addresses: Vec<String> = verified
        .view
        .addresses
        .iter()
        .filter_map(|address| fold_address(address))
        .collect();
    let chain = serde_json::to_value(&entry.chain).expect("serialisable");
    let digest = verified
        .view
        .digests
        .last()
        .expect("a verified chain has one")
        .to_vec();
    let outcome = match kept {
        None => {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM remote_account_renames WHERE domain = $1")
                    .bind(domain)
                    .fetch_one(&mut *tx)
                    .await?;
            if count >= MAX_PER_DOMAIN {
                return Err(AppError::too_many_requests(
                    "this server keeps no more renames of that server",
                )
                .with_details(json!({ "code": "rateLimited" })));
            }
            let inserted = sqlx::query(
                "INSERT INTO remote_account_renames
                     (domain, incarnation_id, authority_public_key, sequence, head_digest,
                      current_address, state, chain, addresses)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT DO NOTHING",
            )
            .bind(domain)
            .bind(&entry.incarnation_id)
            .bind(&entry.authority_public_key)
            .bind(verified.view.sequence as i32)
            .bind(&digest)
            .bind(&entry.current)
            .bind(&entry.state)
            .bind(&chain)
            .bind(&addresses)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if inserted == 0 {
                // Another request kept it meanwhile; that one moved the rows.
                Stored::Same
            } else {
                apply_rows(&mut tx, domain, &entry.incarnation_id, &entry.current).await?;
                Stored::Advanced
            }
        }
        Some((chain_kept, authority)) => {
            let old: Vec<AccountRenameV1> = serde_json::from_value(chain_kept)
                .map_err(|_| AppError::internal("a kept rename chain"))?;
            let authority =
                key32(&authority).ok_or_else(|| AppError::internal("a kept authority"))?;
            let old = verify_chain(&authority, &old)
                .map_err(|_| AppError::internal("a kept rename chain"))?;
            if verified.view.extends(&old) {
                let longer = verified.view.sequence > old.sequence;
                sqlx::query(
                    "UPDATE remote_account_renames
                        SET sequence = $3, head_digest = $4, current_address = $5, state = $6,
                            chain = $7, addresses = $8, updated_at = now()
                      WHERE domain = $1 AND incarnation_id = $2",
                )
                .bind(domain)
                .bind(&entry.incarnation_id)
                .bind(verified.view.sequence as i32)
                .bind(&digest)
                .bind(&entry.current)
                .bind(&entry.state)
                .bind(&chain)
                .bind(&addresses)
                .execute(&mut *tx)
                .await?;
                if longer {
                    apply_rows(&mut tx, domain, &entry.incarnation_id, &entry.current).await?;
                    Stored::Advanced
                } else {
                    Stored::Same
                }
            } else if old.extends(&verified.view) {
                Stored::Behind
            } else {
                Stored::Forked
            }
        }
    };
    tx.commit().await?;
    Ok(outcome)
}

/// Moves this server's rows about the account (`incarnation` on `domain`) to
/// its current address, by incarnation only: a reused name's earlier owner is
/// another incarnation, and keeps its rows.
async fn apply_rows(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    domain: &str,
    incarnation: &str,
    current: &str,
) -> AppResult<()> {
    let username = current.rsplit_once('@').map_or("", |(local, _)| local);
    for statement in [
        "UPDATE federated_incoming_shares SET owner_account = $3
          WHERE remote_domain = $1 AND owner_incarnation_id = $2 AND owner_account <> $3",
        "UPDATE federated_incoming_file_shares SET owner_account = $3
          WHERE remote_domain = $1 AND owner_incarnation_id = $2 AND owner_account <> $3",
        "UPDATE remote_collab_devices SET account = $3
          WHERE domain = $1 AND incarnation_id = $2 AND account <> $3",
    ] {
        sqlx::query(statement)
            .bind(domain)
            .bind(incarnation)
            .bind(current)
            .execute(&mut **tx)
            .await?;
    }
    for statement in [
        "UPDATE federated_outgoing_shares SET recipient_username = $3
          WHERE recipient_domain = $1 AND recipient_incarnation_id = $2
            AND recipient_username <> $3",
        "UPDATE federated_outgoing_file_shares SET recipient_username = $3
          WHERE recipient_domain = $1 AND recipient_incarnation_id = $2
            AND recipient_username <> $3",
    ] {
        sqlx::query(statement)
            .bind(domain)
            .bind(incarnation)
            .bind(username)
            .execute(&mut **tx)
            .await?;
    }
    // Profile keys are keyed by the peer's address: a row whose new address
    // is already taken (a key exchanged with the new address already) stays
    // under the old one until the next key exchange replaces it.
    let collisions: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT d.user_id, d.direction, d.peer_account FROM drive_profile_keys d
          WHERE d.peer_incarnation_id = $2 AND lower(split_part(d.peer_account, '@', 2)) = $1
            AND d.peer_account <> $3
            AND EXISTS (SELECT 1 FROM drive_profile_keys o
                         WHERE o.user_id = d.user_id AND o.direction = d.direction
                           AND o.peer_account = $3)",
    )
    .bind(domain)
    .bind(incarnation)
    .bind(current)
    .fetch_all(&mut **tx)
    .await?;
    for (user_id, direction, peer) in &collisions {
        tracing::warn!(%user_id, %direction, %peer, %current,
            "a profile key stays under the old address: one for the new address exists");
    }
    sqlx::query(
        "UPDATE drive_profile_keys d SET peer_account = $3
          WHERE d.peer_incarnation_id = $2 AND lower(split_part(d.peer_account, '@', 2)) = $1
            AND d.peer_account <> $3
            AND NOT EXISTS (SELECT 1 FROM drive_profile_keys o
                             WHERE o.user_id = d.user_id AND o.direction = d.direction
                               AND o.peer_account = $3)",
    )
    .bind(domain)
    .bind(incarnation)
    .bind(current)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The kept chains naming `folded` (a folded address of `domain`), newest
/// first, each with its age in seconds.
async fn kept(
    pool: &sqlx::PgPool,
    domain: &str,
    folded: &str,
) -> AppResult<Vec<(ChainEntry, f64)>> {
    type Row = (String, String, String, String, Value, f64);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT incarnation_id, authority_public_key, current_address, state, chain,
                EXTRACT(EPOCH FROM now() - updated_at)::float8
           FROM remote_account_renames
          WHERE domain = $1 AND addresses @> ARRAY[$2]
          ORDER BY updated_at DESC, incarnation_id
          LIMIT $3",
    )
    .bind(domain)
    .bind(folded)
    .bind(MAX_CHAINS_PER_ANSWER as i64)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(incarnation_id, authority, current, state, chain, age)| {
            Ok((
                ChainEntry {
                    incarnation_id,
                    authority_public_key: authority,
                    current,
                    state,
                    chain: serde_json::from_value(chain)
                        .map_err(|_| AppError::internal("a kept rename chain"))?,
                },
                age,
            ))
        })
        .collect()
}

fn answer(entries: Vec<ChainEntry>) -> Value {
    json!({ "version": VERSION, "chains": entries })
}

fn bad_gateway(why: &str) -> AppError {
    AppError::new(
        StatusCode::BAD_GATEWAY,
        format!("the other server's renames do not check out: {why}"),
    )
}

/// Verifies and keeps the chains `domain` gave for `folded` (each must name
/// it), then answers what is kept for it: a peer's shorter chain does not
/// replace a longer one this server holds.
async fn take(
    pool: &sqlx::PgPool,
    domain: &str,
    folded: &str,
    chains: ChainsV1,
) -> AppResult<Vec<ChainEntry>> {
    if chains.version != VERSION {
        return Err(bad_gateway("an unknown version"));
    }
    if chains.chains.len() > MAX_CHAINS_PER_ANSWER {
        return Err(bad_gateway("too many chains"));
    }
    for entry in chains.chains {
        let verified = verify(domain, entry).map_err(bad_gateway)?;
        if !verified
            .view
            .addresses
            .iter()
            .any(|address| fold_address(address).as_deref() == Some(folded))
        {
            return Err(bad_gateway("a chain that does not name the address"));
        }
        if store(pool, domain, &verified).await? == Stored::Forked {
            tracing::warn!(%domain, incarnation = %verified.entry.incarnation_id,
                "a peer's rename chain forks the one kept; the kept one stays");
        }
    }
    Ok(kept(pool, domain, folded)
        .await?
        .into_iter()
        .map(|(entry, _)| entry)
        .collect())
}

/// The answer to a lookup of `asked` (an address of `domain`) whose server
/// said `409 renamed`: its chains verified and kept, and the same `409` for
/// this server's client, carrying the chains as signed. `None` when the
/// answer was something else (the caller maps it as before).
pub async fn relay(
    state: &AppState,
    domain: &str,
    asked: &str,
    response: &AuthenticatedFederationResponse,
) -> Option<AppError> {
    if response.status != StatusCode::CONFLICT {
        return None;
    }
    let body: Value = serde_json::from_slice(&response.body).ok()?;
    if body["code"] != "renamed" {
        return None;
    }
    let result = async {
        let folded = fold_address(asked).ok_or_else(|| bad_gateway("the address"))?;
        let chains: ChainsV1 = serde_json::from_value(body["renames"].clone())
            .map_err(|_| bad_gateway("the chain list"))?;
        let entries = take(&state.pool, domain, &folded, chains).await?;
        if entries.is_empty() {
            return Err(bad_gateway("no chain"));
        }
        Ok(renamed(entries))
    }
    .await;
    Some(result.unwrap_or_else(|error| error))
}

/// `409 renamed` with `entries`, as a local lookup answers it.
fn renamed(entries: Vec<ChainEntry>) -> AppError {
    AppError::conflict("this account goes by another name now").with_details(json!({
        "code": "renamed",
        "renames": answer(entries),
    }))
}

/// One fetch per address at a time: lookups made meanwhile wait for it and
/// answer from what it kept.
static FETCHES: LazyLock<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(Default::default);

fn fetch_lock(folded: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut fetches = FETCHES.lock().unwrap();
    fetches.retain(|_, lock| Arc::strong_count(lock) > 1);
    fetches.entry(folded.to_owned()).or_default().clone()
}

/// `GET /api/users/renames/:address` for another server's address: the
/// chains kept of it, asked of its server when none is fresh. The server
/// unreachable and nothing kept: `{ "chains": [], "unavailable": true }`,
/// which says nothing either way.
pub async fn lookup(state: &AppState, user_id: Uuid, address: &str) -> AppResult<Value> {
    let (username, domain) = address
        .rsplit_once('@')
        .ok_or_else(|| AppError::bad_request("an address is username@server"))?;
    let folded = fold_address(address)
        .ok_or_else(|| AppError::bad_request("an address is username@server"))?;
    let fresh =
        |entries: &[(ChainEntry, f64)], within: f64| entries.iter().any(|(_, age)| *age < within);
    let found = kept(&state.pool, domain, &folded).await?;
    if fresh(&found, FRESH_SECONDS) {
        return Ok(answer(found.into_iter().map(|(entry, _)| entry).collect()));
    }
    if !crate::ratelimit::RENAME_LOOKUPS.allow(&user_id.to_string()) {
        return Err(AppError::too_many_requests("too many requests")
            .with_details(json!({ "code": "rateLimited" })));
    }
    let unavailable = |found: Vec<(ChainEntry, f64)>| {
        if found.is_empty() {
            json!({ "version": VERSION, "chains": [], "unavailable": true })
        } else {
            answer(found.into_iter().map(|(entry, _)| entry).collect())
        }
    };
    let lock = fetch_lock(&folded);
    let _fetching = lock.lock().await;
    let found = kept(&state.pool, domain, &folded).await?;
    if fresh(&found, COALESCE_SECONDS) {
        return Ok(answer(found.into_iter().map(|(entry, _)| entry).collect()));
    }
    let Some(federation) = state.federation.as_deref() else {
        return Ok(unavailable(found));
    };
    if !crate::ratelimit::RENAME_PEER_FETCHES.allow(domain) {
        return Ok(unavailable(found));
    }
    let fetched = async {
        let response = send_any(
            federation,
            domain,
            Method::GET,
            format!("/api/fed/accounts/{username}/renames"),
            Vec::new(),
        )
        .await
        .map_err(|error| bad_gateway(&format!("{error:#}")))?;
        if response.status != StatusCode::OK {
            return Err(bad_gateway(&format!("it answered {}", response.status)));
        }
        let chains: ChainsV1 =
            serde_json::from_slice(&response.body).map_err(|_| bad_gateway("the chain list"))?;
        take(&state.pool, domain, &folded, chains).await
    }
    .await;
    match fetched {
        Ok(entries) => Ok(answer(entries)),
        Err(error) => {
            tracing::warn!(%domain, error = %error.message, "remote rename lookup failed");
            Ok(unavailable(found))
        }
    }
}

/// Sends a renames request under the first federation feature `domain`
/// admits (renames concern the account, for Chat and Drive alike).
async fn send_any(
    federation: &FederationStack,
    domain: &str,
    method: Method,
    path: String,
    body: Vec<u8>,
) -> anyhow::Result<AuthenticatedFederationResponse> {
    let mut last = None;
    for feature in [FederationFeature::ChatV2, FederationFeature::DriveV1] {
        let spec = FederationRequestSpec {
            feature,
            method: method.clone(),
            path: path.clone(),
            query: None,
            content_type: JSON_CONTENT_TYPE.into(),
            body: body.clone(),
            request_id: Uuid::new_v4().to_string(),
            extra_headers: Vec::new(),
            response_limit: RESPONSE_LIMIT,
        };
        match federation.send(domain, spec).await {
            Ok(response) => return Ok(response),
            Err(error) if refused_feature(&error) => last = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(last.expect("two features tried"))
}

fn refused_feature(error: &anyhow::Error) -> bool {
    lacks_capability(error) || error.downcast_ref::<FederationAdmissionError>().is_some()
}

fn configured(state: &AppState) -> AppResult<&FederationStack> {
    state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("federation is not configured"))
}

/// The feature a signed request names (Chat's or Drive's): renames are the
/// account's, so either is admitted, under that feature's policy.
fn feature_of(headers: &HeaderMap) -> AppResult<FederationFeature> {
    headers
        .get(FEATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| FederationFeature::from_str(value).ok())
        .ok_or_else(|| AppError::unauthorized("federation feature missing"))
}

/// `GET /api/fed/accounts/{username}/renames[?incarnationId=]` — every chain
/// naming `username@<this server>`, for a signed peer.
#[utoipa::path(
    get,
    path = "/api/fed/accounts/{username}/renames",
    tag = "federation",
    params(("username" = String, Path, description = "A name on this server, any spelling")),
    responses((status = 200, description = "The chains naming it (an empty list when none does)"))
)]
pub async fn publish(
    State(state): State<AppState>,
    Path(username): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = configured(&state)?;
    let feature = feature_of(&headers)?;
    let path = format!("/api/fed/accounts/{username}/renames");
    let authenticated = federation
        .authenticate_inbound(&headers, "GET", &path, query.as_deref(), &[], feature)
        .await?;
    let result = async {
        if username.is_empty()
            || username.len() > 64
            || !username
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            return Err(AppError::bad_request("a name on this server"));
        }
        let incarnation = query.as_deref().and_then(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == "incarnationId")
                .map(|(_, value)| value.into_owned())
        });
        crate::account_names::chains(
            &state.pool,
            &format!("{username}@{}", federation.server_name()),
            incarnation.as_deref(),
        )
        .await
    }
    .await;
    match result {
        Ok(found) => signed_json(federation, &authenticated, StatusCode::OK, &found),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

/// `POST /api/fed/accounts/renames` — a peer's account renamed: its chain,
/// verified and kept (`204`), and this server's rows about that incarnation
/// moved to its new address. `400` for a chain that does not verify or is not
/// the peer's, `409` for one that does not extend the one kept, `429` past
/// the per-domain cap.
#[utoipa::path(
    post,
    path = "/api/fed/accounts/renames",
    tag = "federation",
    request_body(content = Object, description = "AnnounceV1: the account's whole rename chain"),
    responses(
        (status = 204, description = "Kept"),
        (status = 400, description = "Not a chain of the sending server's"),
        (status = 409, description = "Does not extend the chain kept"),
        (status = 429, description = "Too many chains of that server")
    )
)]
pub async fn announce(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = configured(&state)?;
    let feature = feature_of(&headers)?;
    let authenticated = federation
        .authenticate_inbound(&headers, "POST", ANNOUNCE_PATH, None, &body, feature)
        .await?;
    let origin = authenticated.origin().to_owned();
    let result = async {
        if !crate::ratelimit::RENAME_ANNOUNCES.allow(&origin) {
            return Err(AppError::too_many_requests("too many announces")
                .with_details(json!({ "code": "rateLimited" })));
        }
        let announced: AnnounceV1 = serde_json::from_slice(&body)
            .map_err(|_| AppError::bad_request("not a rename announce"))?;
        if announced.version != VERSION {
            return Err(AppError::bad_request("an unknown announce version"));
        }
        let verified = verify(
            &origin,
            ChainEntry {
                incarnation_id: announced.incarnation_id,
                authority_public_key: announced.authority_public_key,
                current: format!("{}@{origin}", announced.username),
                state: "current".into(),
                chain: announced.chain,
            },
        )
        .map_err(|why| AppError::bad_request(format!("the chain does not check out: {why}")))?;
        match store(&state.pool, &origin, &verified).await? {
            Stored::Advanced | Stored::Same => Ok(()),
            Stored::Behind | Stored::Forked => {
                Err(AppError::conflict("the chain does not extend the one kept"))
            }
        }
    }
    .await;
    match result {
        Ok(()) => federation.signed_response(
            &authenticated,
            StatusCode::NO_CONTENT,
            JSON_CONTENT_TYPE,
            Vec::new(),
        ),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

/// Queues the announce of `incarnation`'s rename `sequence` to every peer
/// this server has pinned (and not quarantined), in the rename's transaction.
pub async fn enqueue(
    conn: &mut sqlx::PgConnection,
    server_name: &str,
    incarnation: &str,
    sequence: u64,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO rename_announce_outbox (destination, incarnation_id, sequence)
         SELECT domain, $1, $2 FROM federation_peer_identities
          WHERE trust_state <> 'quarantined' AND domain <> $3
         ON CONFLICT DO NOTHING",
    )
    .bind(incarnation)
    .bind(sequence as i32)
    .bind(server_name)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Sends the announces due: one per peer and account, with the whole chain.
pub async fn deliver_due(state: &AppState) -> AppResult<usize> {
    let Some(federation) = state.federation.as_deref() else {
        return Ok(0);
    };
    type Due = (String, String, i32, i32, bool);
    let due: Vec<Due> = sqlx::query_as(
        "SELECT destination, incarnation_id, max(sequence), max(attempts),
                min(created_at) < now() - make_interval(days => $1)
           FROM rename_announce_outbox
          WHERE next_attempt_at <= now()
          GROUP BY destination, incarnation_id
          ORDER BY min(next_attempt_at)
          LIMIT $2",
    )
    .bind(GIVE_UP_DAYS as i32)
    .bind(ANNOUNCES_PER_PASS)
    .fetch_all(&state.pool)
    .await?;
    let done = |destination: String, incarnation: String, through: i32| {
        let pool = state.pool.clone();
        async move {
            sqlx::query(
                "DELETE FROM rename_announce_outbox
                  WHERE destination = $1 AND incarnation_id = $2 AND sequence <= $3",
            )
            .bind(destination)
            .bind(incarnation)
            .bind(through)
            .execute(&pool)
            .await
        }
    };
    let count = due.len();
    for (destination, incarnation, through, attempts, expired) in due {
        let rows: Vec<(Value, String, String)> = sqlx::query_as(
            "SELECT statement, authority_public_key, current FROM account_renames
              WHERE incarnation_id = $1 ORDER BY sequence",
        )
        .bind(&incarnation)
        .fetch_all(&state.pool)
        .await?;
        let Some((_, authority, current)) = rows.last().cloned() else {
            done(destination, incarnation, through).await?;
            continue;
        };
        let chain: Vec<AccountRenameV1> = rows
            .into_iter()
            .map(|(statement, ..)| serde_json::from_value(statement))
            .collect::<Result<_, _>>()
            .map_err(|_| AppError::internal("a stored rename"))?;
        let body = serde_json::to_vec(&AnnounceV1 {
            version: VERSION,
            username: current
                .rsplit_once('@')
                .map_or("", |(local, _)| local)
                .to_owned(),
            incarnation_id: incarnation.clone(),
            authority_public_key: authority,
            chain,
        })
        .expect("serialisable");
        let sent = send_any(
            federation,
            &destination,
            Method::POST,
            ANNOUNCE_PATH.into(),
            body,
        )
        .await;
        let failure = match sent {
            // Kept, or the peer holds as much or refuses it for good.
            Ok(response)
                if response.status.is_success()
                    || response.status == StatusCode::CONFLICT
                    || response.status == StatusCode::BAD_REQUEST =>
            {
                if response.status == StatusCode::BAD_REQUEST {
                    tracing::warn!(%destination, %incarnation, "a peer refused a rename announce");
                }
                done(destination, incarnation, through).await?;
                continue;
            }
            Ok(response) => format!("answered {}", response.status),
            // A peer without Chat and Drive federation, or one this server
            // may not send to: it learns on its next lookup.
            Err(error) if refused_feature(&error) => {
                done(destination, incarnation, through).await?;
                continue;
            }
            Err(error) => format!("{error:#}"),
        };
        if expired {
            tracing::warn!(%destination, %incarnation, error = %failure,
                "a rename announce was never delivered; dropped");
            done(destination, incarnation, through).await?;
            continue;
        }
        let wait = (30_i64 << attempts.clamp(0, 10)).min(6 * 3600);
        sqlx::query(
            "UPDATE rename_announce_outbox
                SET attempts = attempts + 1, last_error = left($3, 500),
                    next_attempt_at = now() + make_interval(secs => $4)
              WHERE destination = $1 AND incarnation_id = $2",
        )
        .bind(&destination)
        .bind(&incarnation)
        .bind(&failure)
        .bind(wait as f64)
        .execute(&state.pool)
        .await?;
    }
    Ok(count)
}

/// Sends announces every half minute, for as long as the server runs.
pub fn spawn_announcer(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            if let Err(error) = deliver_due(&state).await {
                tracing::warn!(error = %error.message, "rename announces failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_crypto::identity::AccountIdentityKeysV1;

    const PEER: &str = "peer.test";

    fn identity(seed: u8) -> AccountIdentityKeysV1 {
        AccountIdentityKeysV1::derive(&[seed; 32]).unwrap()
    }

    /// `who`'s chain through `addresses` (local parts on PEER).
    fn entry(who: &AccountIdentityKeysV1, addresses: &[&str]) -> ChainEntry {
        let chain: Vec<AccountRenameV1> = addresses
            .windows(2)
            .enumerate()
            .map(|(i, pair)| {
                kutup_crypto::account_rename::sign(
                    who,
                    i as u64 + 1,
                    &format!("{}@{PEER}", pair[0]),
                    &format!("{}@{PEER}", pair[1]),
                    1_790_000_000_000 + i as i64,
                )
                .unwrap()
            })
            .collect();
        ChainEntry {
            incarnation_id: who.incarnation_id(),
            authority_public_key: STANDARD.encode(who.authority_public_key()),
            current: format!("{}@{PEER}", addresses.last().unwrap()),
            state: "current".into(),
            chain,
        }
    }

    #[test]
    fn a_chain_is_kept_only_for_the_server_that_signed_it() {
        let who = identity(1);
        assert!(verify(PEER, entry(&who, &["a", "b"])).is_ok());
        // Its addresses are on PEER, not on the server asked about.
        assert!(verify("other.test", entry(&who, &["a", "b"])).is_err());
        // Its `current` is the chain's.
        let mut wrong = entry(&who, &["a", "b"]);
        wrong.current = format!("a@{PEER}");
        assert!(verify(PEER, wrong).is_err());
        // Another authority's key does not verify it.
        let mut other = entry(&who, &["a", "b"]);
        other.authority_public_key = STANDARD.encode(identity(2).authority_public_key());
        assert!(verify(PEER, other).is_err());
        // An unknown state is shown as unknown.
        let mut odd = entry(&who, &["a", "b"]);
        odd.state = "whatever".into();
        assert_eq!(verify(PEER, odd).unwrap().entry.state, "gone");
    }

    async fn pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("KUTUP_LIVE_DATABASE_URL").ok()?;
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .unwrap(),
        )
    }

    async fn clean(pool: &sqlx::PgPool, incarnations: &[String]) {
        sqlx::query(
            "DELETE FROM remote_account_renames WHERE domain = $1 AND incarnation_id = ANY($2)",
        )
        .bind(PEER)
        .bind(incarnations)
        .execute(pool)
        .await
        .unwrap();
    }

    /// Kept, then the same again, never a shorter one or another history.
    #[tokio::test]
    async fn live_a_kept_chain_only_grows() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let who = identity(11);
        clean(&pool, &[who.incarnation_id()]).await;
        let one = verify(PEER, entry(&who, &["k1", "k2"])).unwrap();
        let two = verify(PEER, entry(&who, &["k1", "k2", "k3"])).unwrap();
        let fork = verify(PEER, entry(&who, &["k1", "k2", "k9"])).unwrap();
        assert_eq!(store(&pool, PEER, &one).await.unwrap(), Stored::Advanced);
        assert_eq!(store(&pool, PEER, &one).await.unwrap(), Stored::Same);
        assert_eq!(store(&pool, PEER, &two).await.unwrap(), Stored::Advanced);
        assert_eq!(store(&pool, PEER, &one).await.unwrap(), Stored::Behind);
        assert_eq!(store(&pool, PEER, &fork).await.unwrap(), Stored::Forked);
        // Found by any address it names, in any spelling, as the longest.
        let found = kept(&pool, PEER, "k1@peer.test").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0.current, format!("k3@{PEER}"));
        assert_eq!(kept(&pool, PEER, "k2@peer.test").await.unwrap().len(), 1);
        clean(&pool, &[who.incarnation_id()]).await;
    }

    /// Rows move by incarnation alone: a reused name's earlier owner keeps
    /// its rows, and a chain a peer mints under a fresh authority, claiming
    /// an existing name, moves nothing that is not its own.
    #[tokio::test]
    async fn live_rows_move_by_incarnation_only() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let (alice, earlier, forger) = (identity(21), identity(22), identity(23));
        let incarnations = [
            alice.incarnation_id(),
            earlier.incarnation_id(),
            forger.incarnation_id(),
        ];
        clean(&pool, &incarnations).await;
        let local = Uuid::new_v4();
        let tag = &local.simple().to_string()[..10];
        sqlx::query(
            "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                drive_private_key_envelope, public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key)
             VALUES ($1, $2, '', '', '', '', '', '', '', '')",
        )
        .bind(local)
        .bind(format!("local{tag}"))
        .execute(&pool)
        .await
        .unwrap();
        let name = format!("al{tag}");
        let address = format!("{name}@{PEER}");
        // Profile keys this account exchanged with `address`: once with an
        // earlier holder of the name, now with Alice.
        for (direction, incarnation) in [
            ("received", alice.incarnation_id()),
            ("sent", earlier.incarnation_id()),
        ] {
            sqlx::query(
                "INSERT INTO drive_profile_keys
                     (user_id, direction, peer_account, peer_incarnation_id, envelope, profile_version)
                 VALUES ($1, $2, $3, $4, 'e', $5)",
            )
            .bind(local)
            .bind(direction)
            .bind(&address)
            .bind(incarnation)
            .bind("0".repeat(64))
            .execute(&pool)
            .await
            .unwrap();
        }
        let peer_of = |direction: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, String>(
                    "SELECT peer_account FROM drive_profile_keys WHERE user_id = $1 AND direction = $2",
                )
                .bind(local)
                .bind(direction)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        // A forger's chain for the name under a fresh authority: kept as its
        // own incarnation, moving nothing of Alice's or the earlier holder's.
        let forged = verify(PEER, entry(&forger, &[&name, &format!("mallory{tag}")])).unwrap();
        assert_eq!(store(&pool, PEER, &forged).await.unwrap(), Stored::Advanced);
        assert_eq!(peer_of("received").await, address);
        assert_eq!(peer_of("sent").await, address);
        // Alice's own chain moves her row only.
        let alicia = format!("alicia{tag}");
        let hers = verify(PEER, entry(&alice, &[&name, &alicia])).unwrap();
        assert_eq!(store(&pool, PEER, &hers).await.unwrap(), Stored::Advanced);
        assert_eq!(peer_of("received").await, format!("{alicia}@{PEER}"));
        assert_eq!(
            peer_of("sent").await,
            address,
            "the earlier holder's row stays"
        );
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(local)
            .execute(&pool)
            .await
            .unwrap();
        clean(&pool, &incarnations).await;
    }
}
