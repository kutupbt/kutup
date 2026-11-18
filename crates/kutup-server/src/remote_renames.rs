//! Renames across servers (docs/plans/username-renames.md, R2): the chains
//! this server publishes for its own accounts, the announces it sends when one
//! of them renames, and the chains it keeps of other servers' accounts.
//!
//! A chain proves itself: every statement is signed by the account authority,
//! and the incarnation it names is the hash of that authority. A server keeps
//! one only for the domain that signed it (every address in it on that
//! domain), never lets a shorter or different one replace it.
//!
//! `remote_account_renames` holds one row per remote account, keyed by
//! (server, account id) (docs/plans/w7-schema.md §1.3): the one place this
//! server keeps another server's account's address. Rows that name a remote
//! account (the federated shares) carry its id only and join this table to
//! show it, so a rename that reaches this server shows everywhere at once and
//! nothing is relabelled. The row is made when the account is first met
//! ([`note_account`], before the share naming it), from what its server
//! says; a chain that reaches this server later replaces that label with the
//! signed one.

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
use kutup_crypto::account_ref::AccountId;
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
const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
/// A kept chain younger than this answers a lookup without asking its server.
const FRESH_SECONDS: f64 = 24.0 * 3600.0;
/// Lookups of one address within this share one fetch.
const COALESCE_SECONDS: f64 = 60.0;
/// Announces sent at once: a dead peer does not hold up live ones.
const ANNOUNCES_AT_ONCE: usize = 8;
const FEATURE_HEADER: &str = "kutup-federation-feature";

/// The endpoint namespace a feature's requests live under (the transport
/// refuses any other): renames are served under both Chat's and Drive's.
fn namespace(feature: FederationFeature) -> &'static str {
    match feature {
        FederationFeature::ChatV2 => "chat",
        FederationFeature::DriveV1 => "drive",
    }
}

pub(crate) fn chains_path(feature: FederationFeature, username: &str) -> String {
    format!("/api/fed/{}/names/{username}/renames", namespace(feature))
}

pub(crate) fn announce_path(feature: FederationFeature) -> String {
    format!("/api/fed/{}/accounts/renames", namespace(feature))
}

/// One account incarnation's chain, as lookups and `409 renamed` carry it:
/// the signed statements unaltered, with what the answering server says of it.
/// The account it is of is in every statement (`accountId`, signed by the
/// account authority), never beside them.
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
    /// The account's permanent id: routing only. The statements sign it,
    /// and an announce whose id is not theirs is refused.
    pub account_id: Uuid,
    pub incarnation_id: String,
    pub authority_public_key: String,
    pub chain: Vec<AccountRenameV1>,
}

struct Verified {
    /// The account the chain is of, as its statements sign it.
    account_id: Uuid,
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
    /// The account is kept under another incarnation, and what brought this
    /// one (a lookup's answer, which lists old incarnations too) does not say
    /// which is the account's now: the kept one stays.
    OtherIncarnation,
}

/// Where a chain came from, which says whether its incarnation is the
/// account's current one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// An announce: its server sends one only for an account's current
    /// incarnation, so it replaces a kept one of an older (an admin reset).
    Announce,
    /// A lookup's answer: every chain naming an address, old incarnations
    /// too.
    Lookup,
}

fn key32(value: &str) -> Option<[u8; 32]> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|raw| STANDARD.encode(raw) == value)
        .and_then(|raw| raw.try_into().ok())
}

/// The crypto's form of an account id.
fn signed_id(account_id: Uuid) -> AccountId {
    AccountId::from_bytes(account_id.into_bytes())
}

/// Checks a chain `domain` gave: it verifies under its authority (which the
/// incarnation is the hash of) for the one account id its statements name
/// (`expected`, when the caller knows whose chain it must be), every address
/// in it is on `domain`, and its `current` is the chain's.
fn verify(
    domain: &str,
    mut entry: ChainEntry,
    expected: Option<Uuid>,
) -> Result<Verified, &'static str> {
    let authority = key32(&entry.authority_public_key).ok_or("authority key")?;
    let named: AccountId = entry
        .chain
        .first()
        .and_then(|statement| statement.account_id.parse().ok())
        .ok_or("the chain")?;
    let account_id = Uuid::from_bytes(*named.as_bytes());
    if expected.is_some_and(|expected| expected != account_id) {
        return Err("another account");
    }
    let view = verify_chain(&authority, named, &entry.chain).map_err(|_| "the chain")?;
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
    Ok(Verified {
        account_id,
        entry,
        view,
    })
}

/// Keeps a verified chain of `domain`'s account (the one it signs): new, or
/// replacing a shorter one of the same incarnation, or the label the account
/// was first met by; never a shorter or a different one. Another incarnation
/// replaces the kept one only from an announce (an admin reset on that
/// server).
/// A chain that advanced (an announce, or one a lookup brought) also drops
/// what was fetched of that account by id (`handlers::accounts`), so its new
/// name shows at once rather than when that answer goes stale.
async fn store(
    pool: &sqlx::PgPool,
    domain: &str,
    verified: &Verified,
    source: Source,
) -> AppResult<Stored> {
    let stored = store_capped(pool, domain, verified, source, MAX_PER_DOMAIN).await?;
    if stored == Stored::Advanced {
        crate::handlers::accounts::forget_remote(domain, &verified.entry.incarnation_id);
    }
    Ok(stored)
}

/// [`store`] with the per-domain cap given (tests use a small one).
async fn store_capped(
    pool: &sqlx::PgPool,
    domain: &str,
    verified: &Verified,
    source: Source,
    cap: i64,
) -> AppResult<Stored> {
    let entry = &verified.entry;
    let account_id = verified.account_id;
    let mut tx = pool.begin().await?;
    type Kept = (String, i32, Value, Option<String>);
    let kept: Option<Kept> = sqlx::query_as(
        "SELECT encode(incarnation_id, 'hex'), sequence, chain, kutup_b64(authority_public_key)
           FROM remote_account_renames
          WHERE server = $1 AND account_id = $2 FOR UPDATE",
    )
    .bind(domain)
    .bind(account_id)
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
            // One new chain per domain at a time, so the cap holds.
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('remote_account_renames:' || $1, 0))")
                .bind(domain)
                .execute(&mut *tx)
                .await?;
            // Rows made when an account was first met (no chain) are this
            // server's users' doing, not the peer's: they don't count.
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM remote_account_renames WHERE server = $1 AND sequence >= 1",
            )
            .bind(domain)
            .fetch_one(&mut *tx)
            .await?;
            if count >= cap {
                return Err(AppError::too_many_requests(
                    "this server keeps no more renames of that server",
                )
                .with_details(json!({ "code": "rateLimited" })));
            }
            let inserted = sqlx::query(
                "INSERT INTO remote_account_renames
                     (server, account_id, incarnation_id, authority_public_key, sequence,
                      head_digest, current_address, state, chain, addresses)
                 VALUES ($1, $2, decode($3, 'hex'), kutup_unb64($4), $5, $6, $7, $8, $9, $10)
                 ON CONFLICT DO NOTHING",
            )
            .bind(domain)
            .bind(account_id)
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
                // Another request kept it meanwhile.
                Stored::Same
            } else {
                Stored::Advanced
            }
        }
        Some((incarnation, _, _, _)) if incarnation != entry.incarnation_id => {
            if source == Source::Announce {
                write_chain(
                    &mut tx, domain, account_id, verified, &digest, &chain, &addresses,
                )
                .await?;
                Stored::Advanced
            } else {
                Stored::OtherIncarnation
            }
        }
        // Only the label it was first met by: the chain replaces it.
        Some((_, 0, _, _)) => {
            write_chain(
                &mut tx, domain, account_id, verified, &digest, &chain, &addresses,
            )
            .await?;
            Stored::Advanced
        }
        Some((_, _, chain_kept, authority)) => {
            let old: Vec<AccountRenameV1> = serde_json::from_value(chain_kept)
                .map_err(|_| AppError::internal("a kept rename chain"))?;
            let authority = authority
                .as_deref()
                .and_then(key32)
                .ok_or_else(|| AppError::internal("a kept authority"))?;
            let old = verify_chain(&authority, signed_id(account_id), &old)
                .map_err(|_| AppError::internal("a kept rename chain"))?;
            if verified.view.extends(&old) {
                write_chain(
                    &mut tx, domain, account_id, verified, &digest, &chain, &addresses,
                )
                .await?;
                if verified.view.sequence > old.sequence {
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

/// Writes a verified chain over the kept row of `domain`'s `account_id`: an
/// equal chain keeps a more specific state it was told (held, gone) over an
/// announce's plain `current`.
async fn write_chain(
    conn: &mut sqlx::PgConnection,
    domain: &str,
    account_id: Uuid,
    verified: &Verified,
    digest: &[u8],
    chain: &Value,
    addresses: &[String],
) -> AppResult<()> {
    let entry = &verified.entry;
    sqlx::query(
        "UPDATE remote_account_renames
            SET incarnation_id = decode($3, 'hex'), authority_public_key = kutup_unb64($4),
                state = CASE WHEN incarnation_id = decode($3, 'hex') AND sequence = $5
                                  AND $7 = 'current'
                             THEN state ELSE $7 END,
                sequence = $5, head_digest = $6, current_address = $8,
                chain = $9, addresses = $10, updated_at = now()
          WHERE server = $1 AND account_id = $2",
    )
    .bind(domain)
    .bind(account_id)
    .bind(&entry.incarnation_id)
    .bind(&entry.authority_public_key)
    .bind(verified.view.sequence as i32)
    .bind(digest)
    .bind(&entry.state)
    .bind(&entry.current)
    .bind(chain)
    .bind(addresses)
    .execute(conn)
    .await?;
    Ok(())
}

/// Notes the address `server` gives for its account `account_id`
/// (incarnation `incarnation`, hex) where this server first meets it: a
/// share made to it, or one it made. Done before the row naming the account,
/// whose foreign key needs it, so the account always has an address to show.
/// A kept row of the same incarnation with a signed chain stays (a chain is
/// the better word for its name, and the next one moves it); a row without a
/// chain takes the address given; another incarnation (the account was reset
/// on its server, which is the one to say so) replaces the kept row. Answers
/// the address shown now.
pub(crate) async fn note_account<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    server: &str,
    account_id: Uuid,
    incarnation: &str,
    address: &str,
) -> AppResult<String> {
    let folded = fold_address(address)
        .filter(|_| address.rsplit_once('@').is_some_and(|(_, at)| at == server))
        .ok_or_else(|| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                "the other server gave an address that is not its own",
            )
        })?;
    let shown: String = sqlx::query_scalar(
        "WITH noted AS (
             INSERT INTO remote_account_renames
                 (server, account_id, incarnation_id, sequence, current_address, state, chain,
                  addresses)
             VALUES ($1, $2, decode($3, 'hex'), 0, $4, 'current', '[]'::jsonb, ARRAY[$5])
             ON CONFLICT (server, account_id) DO UPDATE SET
                 incarnation_id = EXCLUDED.incarnation_id, authority_public_key = NULL,
                 sequence = 0, head_digest = NULL, current_address = EXCLUDED.current_address,
                 state = 'current', chain = '[]'::jsonb, addresses = EXCLUDED.addresses,
                 updated_at = now()
              WHERE remote_account_renames.incarnation_id <> EXCLUDED.incarnation_id
                 OR (remote_account_renames.sequence = 0
                     AND remote_account_renames.current_address <> EXCLUDED.current_address)
             RETURNING current_address)
         SELECT COALESCE((SELECT current_address FROM noted),
                         (SELECT current_address FROM remote_account_renames
                           WHERE server = $1 AND account_id = $2))",
    )
    .bind(server)
    .bind(account_id)
    .bind(incarnation)
    .bind(address)
    .bind(&folded)
    .fetch_one(executor)
    .await?;
    Ok(shown)
}

/// The kept chains naming `folded` (a folded address of `domain`), newest
/// first, each with its age in seconds. Rows without a chain (an account
/// only met, never seen renamed) are no answer to a lookup.
async fn kept(
    pool: &sqlx::PgPool,
    domain: &str,
    folded: &str,
) -> AppResult<Vec<(ChainEntry, f64)>> {
    type Row = (String, String, String, String, Value, f64);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT encode(incarnation_id, 'hex'), kutup_b64(authority_public_key),
                current_address, state, chain,
                EXTRACT(EPOCH FROM now() - updated_at)::float8
           FROM remote_account_renames
          WHERE server = $1 AND sequence >= 1 AND addresses @> ARRAY[$2]
          ORDER BY updated_at DESC, account_id
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
    let mut given = Vec::with_capacity(chains.chains.len());
    for entry in chains.chains {
        let verified = verify(domain, entry, None).map_err(bad_gateway)?;
        if !verified
            .view
            .addresses
            .iter()
            .any(|address| fold_address(address).as_deref() == Some(folded))
        {
            return Err(bad_gateway("a chain that does not name the address"));
        }
        // Kept by the account its statements sign.
        if store(pool, domain, &verified, Source::Lookup).await? == Stored::Forked {
            tracing::warn!(%domain, incarnation = %verified.entry.incarnation_id,
                "a peer's rename chain forks the one kept; the kept one stays");
        }
        given.push(verified.entry);
    }
    // What is kept first (a longer chain than the peer gave stays), then
    // what was given and not kept (an old incarnation of an account kept under a newer one).
    let mut answer: Vec<ChainEntry> = kept(pool, domain, folded)
        .await?
        .into_iter()
        .map(|(entry, _)| entry)
        .collect();
    for entry in given {
        if !answer
            .iter()
            .any(|kept| kept.incarnation_id == entry.incarnation_id)
        {
            answer.push(entry);
        }
    }
    answer.truncate(MAX_CHAINS_PER_ANSWER);
    Ok(answer)
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

pub(crate) fn fetch_lock(folded: &str) -> Arc<tokio::sync::Mutex<()>> {
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
    if !path_name(username) || kutup_federation_proto::validate_server_name(domain).is_err() {
        return Err(AppError::bad_request("an address is username@server"));
    }
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
            |feature| chains_path(feature, username),
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
    path: impl Fn(FederationFeature) -> String,
    body: Vec<u8>,
) -> anyhow::Result<AuthenticatedFederationResponse> {
    let mut last = None;
    for feature in [FederationFeature::ChatV2, FederationFeature::DriveV1] {
        let spec = FederationRequestSpec {
            feature,
            method: method.clone(),
            path: path(feature),
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

/// A name as it may go into a signed request's path: 1-64 of `a-z 0-9 . _ -`,
/// something left once folded (so never `.` or `..`, nor `/` or `%`).
fn path_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && !kutup_crypto::names::fold(name).is_empty()
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

/// `GET /api/fed/{chat|drive}/names/{username}/renames[?incarnationId=]`
/// — every chain naming `username@<this server>`, for a signed peer.
#[utoipa::path(
    get,
    path = "/api/fed/chat/names/{username}/renames",
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
    let path = chains_path(feature, &username);
    let authenticated = federation
        .authenticate_inbound(&headers, "GET", &path, query.as_deref(), &[], feature)
        .await?;
    let result = async {
        if !path_name(&username) {
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
            true,
        )
        .await
    }
    .await;
    match result {
        Ok(found) => signed_json(federation, &authenticated, StatusCode::OK, &found),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

/// `POST /api/fed/{chat|drive}/accounts/renames` — a peer's account renamed: its chain,
/// verified and kept (`204`) as that account's address here, which every row
/// naming the account shows. `400` for a chain that does not verify or is not
/// the peer's, `409` for one that does not extend the one kept, `429` past
/// the per-domain cap.
#[utoipa::path(
    post,
    path = "/api/fed/chat/accounts/renames",
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
        .authenticate_inbound(
            &headers,
            "POST",
            &announce_path(feature),
            None,
            &body,
            feature,
        )
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
        // The routing id must be the one the statements sign.
        let verified = verify(
            &origin,
            ChainEntry {
                incarnation_id: announced.incarnation_id,
                authority_public_key: announced.authority_public_key,
                current: format!("{}@{origin}", announced.username),
                state: "current".into(),
                chain: announced.chain,
            },
            Some(announced.account_id),
        )
        .map_err(|why| AppError::bad_request(format!("the chain does not check out: {why}")))?;
        match store(&state.pool, &origin, &verified, Source::Announce).await? {
            Stored::Advanced | Stored::Same => Ok(()),
            Stored::Behind | Stored::Forked | Stored::OtherIncarnation => {
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
/// this server has pinned, not quarantined, and been in touch with in the
/// last `federationAnnouncePeerDays`, in the rename's transaction: rows of
/// the one federation outbox (docs/plans/federation-outbox.md), without a
/// transport sequence (applying a chain is idempotent). An account whose
/// federation is off announces nothing (docs/plans/server-personal-data.md,
/// the federation switch).
pub async fn enqueue(
    conn: &mut sqlx::PgConnection,
    server_name: &str,
    incarnation: &str,
    sequence: u64,
) -> AppResult<()> {
    let peer_days = crate::site_settings::FEDERATION_ANNOUNCE_PEER_DAYS
        .load(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO federation_outbox (kind, destination, idempotency_key, payload)
         SELECT $5, domain, domain || ':' || $1 || ':' || $2::text,
                jsonb_build_object('incarnation', $1::text, 'chainSequence', $2)
           FROM federation_peer_identities
          WHERE trust_state <> 'quarantined' AND domain <> $3
            AND last_seen_at > now() - make_interval(days => $4)
            AND EXISTS (SELECT 1 FROM accounts u
                         WHERE u.account_incarnation_id = decode($1, 'hex')
                           AND kutup_account_federates(u.id))
         ON CONFLICT DO NOTHING",
    )
    .bind(incarnation)
    .bind(sequence as i32)
    .bind(server_name)
    .bind(peer_days as i32)
    .bind(crate::federation_outbox::Kind::Rename.as_str())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// One announce due: its peer, the account, the newest sequence queued, how
/// often it was tried, and whether it is past being worth trying.
type Due = (String, String, i32, i32, bool);

/// Sends the announces due, a few at a time (each with its own time limit,
/// so a peer that does not answer holds up no other): one per peer and
/// account, with the whole chain.
pub async fn deliver_due(state: &AppState) -> AppResult<usize> {
    use futures_util::StreamExt as _;
    let Some(federation) = state.federation.as_deref() else {
        return Ok(0);
    };
    let give_up_days = crate::site_settings::FEDERATION_ANNOUNCE_DAYS
        .load(&state.pool)
        .await?;
    let per_pass = crate::site_settings::FEDERATION_HEADS_PER_TICK
        .load(&state.pool)
        .await?;
    let due: Vec<Due> = sqlx::query_as(
        "SELECT destination, payload->>'incarnation',
                max((payload->>'chainSequence')::integer), max(attempts),
                min(created_at) < now() - make_interval(days => $1)
           FROM federation_outbox
          WHERE kind = 'rename' AND state = 'pending' AND next_attempt_at <= now()
          GROUP BY destination, payload->>'incarnation'
          ORDER BY min(next_attempt_at)
          LIMIT $2",
    )
    .bind(give_up_days as i32)
    .bind(per_pass)
    .fetch_all(&state.pool)
    .await?;
    let count = due.len();
    let results: Vec<AppResult<()>> = futures_util::stream::iter(due)
        .map(|due| deliver_one(state, federation, due))
        .buffer_unordered(ANNOUNCES_AT_ONCE)
        .collect()
        .await;
    for result in results {
        result?;
    }
    Ok(count)
}

/// The longest one announce may take before it counts as failed.
const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(20);

async fn deliver_one(
    state: &AppState,
    federation: &FederationStack,
    (destination, incarnation, through, attempts, expired): Due,
) -> AppResult<()> {
    // Settles every row of the account's announce to this peer up to the
    // chain sequence sent: delivered, or given up with why.
    let settle = |delivered: bool, class: Option<&'static str>, answer: Value| {
        let (destination, incarnation) = (&destination, &incarnation);
        async move {
            sqlx::query(
                "UPDATE federation_outbox
                    SET state = $4, error_class = $5, answer = $6, last_error = NULL,
                        attempts = attempts + 1, updated_at = now()
                  WHERE kind = 'rename' AND state = 'pending' AND destination = $1
                    AND payload->>'incarnation' = $2
                    AND (payload->>'chainSequence')::integer <= $3",
            )
            .bind(destination)
            .bind(incarnation)
            .bind(through)
            .bind(if delivered { "delivered" } else { "rejected" })
            .bind(class)
            .bind(answer)
            .execute(&state.pool)
            .await
            .map(|_| ())
            .map_err(AppError::from)
        }
    };
    // An account whose federation went off since this was queued: never
    // sent (docs/plans/server-personal-data.md, the federation switch).
    let account_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT u.id FROM accounts u
          WHERE u.account_incarnation_id = decode($1, 'hex')
            AND kutup_account_federates(u.id)",
    )
    .bind(&incarnation)
    .fetch_optional(&state.pool)
    .await?;
    let Some(account_id) = account_id else {
        return settle(false, Some("federationOff"), json!({})).await;
    };
    let rows: Vec<(Value, String, String)> = sqlx::query_as(
        "SELECT statement, kutup_b64(authority_public_key), current FROM account_renames
          WHERE incarnation_id = decode($1, 'hex') ORDER BY sequence",
    )
    .bind(&incarnation)
    .fetch_all(&state.pool)
    .await?;
    let Some((_, authority, current)) = rows.last().cloned() else {
        return settle(false, Some("noChain"), json!({})).await;
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
        account_id,
        incarnation_id: incarnation.clone(),
        authority_public_key: authority,
        chain,
    })
    .expect("serialisable");
    let sent = tokio::time::timeout(
        ANNOUNCE_TIMEOUT,
        send_any(federation, &destination, Method::POST, announce_path, body),
    )
    .await;
    let failure = match sent {
        Err(_) => "timed out".to_owned(),
        // Kept, or the peer holds as much.
        Ok(Ok(response))
            if response.status.is_success() || response.status == StatusCode::CONFLICT =>
        {
            return settle(true, None, json!({ "status": response.status.as_u16() })).await;
        }
        // Refused for good.
        Ok(Ok(response)) if response.status == StatusCode::BAD_REQUEST => {
            tracing::warn!(%destination, %incarnation, "a peer refused a rename announce");
            return settle(
                false,
                Some("remoteRejection"),
                json!({ "status": response.status.as_u16() }),
            )
            .await;
        }
        Ok(Ok(response)) => format!("answered {}", response.status),
        // A peer without Chat and Drive federation, or one this server may
        // not send to: it learns on its next lookup.
        Ok(Err(error)) if refused_feature(&error) => {
            return settle(false, Some("peerUnsupported"), json!({})).await;
        }
        Ok(Err(error)) => format!("{error:#}"),
    };
    if expired {
        tracing::warn!(%destination, %incarnation, error = %failure,
            "a rename announce was never delivered; given up");
        return settle(false, Some("expired"), json!({ "error": failure })).await;
    }
    let base = crate::site_settings::FEDERATION_RETRY_BASE_SECONDS
        .load(&state.pool)
        .await?;
    let cap = crate::site_settings::FEDERATION_RETRY_MAX_SECONDS
        .load(&state.pool)
        .await?;
    let wait = crate::federation_outbox::retry_delay(attempts, base, cap);
    sqlx::query(
        "UPDATE federation_outbox
            SET attempts = attempts + 1, error_class = 'transport', last_error = left($3, 500),
                next_attempt_at = now() + ($4 * interval '1 millisecond'), updated_at = now()
          WHERE kind = 'rename' AND state = 'pending' AND destination = $1
            AND payload->>'incarnation' = $2",
    )
    .bind(&destination)
    .bind(&incarnation)
    .bind(&failure)
    .bind(wait.as_millis() as i64)
    .execute(&state.pool)
    .await?;
    Ok(())
}

/// Asks the federation worker to send what is queued now: a rename just
/// committed, and peers should show the new name at once, not at the next
/// look.
pub fn announce_soon() {
    crate::federation_outbox::wake();
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_crypto::identity::AccountIdentityKeysV1;

    const PEER: &str = "peer.test";

    fn identity(seed: u8) -> AccountIdentityKeysV1 {
        AccountIdentityKeysV1::derive(&kutup_crypto::account_roots::IdentityRoot::from_bytes(
            [seed; 32],
        ))
        .unwrap()
    }

    /// The account id the tests give `who`'s account (any fixed one will do).
    fn account_of(who: &AccountIdentityKeysV1) -> Uuid {
        Uuid::parse_str(&who.incarnation_id()[..32]).unwrap()
    }

    /// Keeps `verified` for the account it names, as a lookup brings it.
    async fn keep(pool: &sqlx::PgPool, domain: &str, verified: &Verified) -> AppResult<Stored> {
        store(pool, domain, verified, Source::Lookup).await
    }

    /// Verifies a chain whatever account it signs, as a lookup's answer.
    fn verify_any(domain: &str, entry: ChainEntry) -> Result<Verified, &'static str> {
        verify(domain, entry, None)
    }

    /// `who`'s chain through `addresses` (local parts on PEER).
    fn entry(who: &AccountIdentityKeysV1, addresses: &[&str]) -> ChainEntry {
        entry_at(who, PEER, addresses)
    }

    /// `who`'s chain through `addresses` (local parts on `domain`).
    fn entry_at(who: &AccountIdentityKeysV1, domain: &str, addresses: &[&str]) -> ChainEntry {
        entry_for(who, account_of(who), domain, addresses)
    }

    /// A chain signed by `who` for the account `account_id`.
    fn entry_for(
        who: &AccountIdentityKeysV1,
        account_id: Uuid,
        domain: &str,
        addresses: &[&str],
    ) -> ChainEntry {
        let chain: Vec<AccountRenameV1> = addresses
            .windows(2)
            .enumerate()
            .map(|(i, pair)| {
                kutup_crypto::account_rename::sign(
                    who,
                    signed_id(account_id),
                    i as u64 + 1,
                    &format!("{}@{domain}", pair[0]),
                    &format!("{}@{domain}", pair[1]),
                    1_790_000_000_000 + i as i64,
                )
                .unwrap()
            })
            .collect();
        ChainEntry {
            incarnation_id: who.incarnation_id(),
            authority_public_key: STANDARD.encode(who.authority_public_key()),
            current: format!("{}@{domain}", addresses.last().unwrap()),
            state: "current".into(),
            chain,
        }
    }

    #[test]
    fn only_a_plain_name_goes_into_a_signed_path() {
        for name in ["ada", "ada.l", "ada_l", "a-b"] {
            assert!(path_name(name), "{name}");
        }
        for name in [
            "",
            ".",
            "..",
            "...",
            "a/b",
            "..%2f..%2fdrive",
            "Ada",
            "a b",
            &"a".repeat(65),
        ] {
            assert!(!path_name(name), "{name}");
        }
    }

    #[tokio::test]
    async fn lookups_of_one_address_share_one_fetch() {
        let first = fetch_lock("ada@peer.test");
        let _held = first.lock().await;
        // Another lookup of the address waits on the same fetch...
        let second = fetch_lock("ada@peer.test");
        assert!(Arc::ptr_eq(&first, &second));
        assert!(second.try_lock().is_err());
        // ...and another address does not.
        assert!(fetch_lock("bob@peer.test").try_lock().is_ok());
    }

    #[test]
    fn a_chain_is_kept_only_for_the_server_that_signed_it() {
        let who = identity(1);
        let verified = verify_any(PEER, entry(&who, &["a", "b"])).unwrap();
        assert_eq!(verified.account_id, account_of(&who));
        // Its addresses are on PEER, not on the server asked about.
        assert!(verify_any("other.test", entry(&who, &["a", "b"])).is_err());
        // Its `current` is the chain's.
        let mut wrong = entry(&who, &["a", "b"]);
        wrong.current = format!("a@{PEER}");
        assert!(verify_any(PEER, wrong).is_err());
        // Another authority's key does not verify it.
        let mut other = entry(&who, &["a", "b"]);
        other.authority_public_key = STANDARD.encode(identity(2).authority_public_key());
        assert!(verify_any(PEER, other).is_err());
        // An unknown state is shown as unknown.
        let mut odd = entry(&who, &["a", "b"]);
        odd.state = "whatever".into();
        assert_eq!(verify_any(PEER, odd).unwrap().entry.state, "gone");
    }

    #[test]
    fn a_chain_is_of_the_account_it_signs() {
        let who = identity(1);
        // An announce's routing id must be the signed one.
        let id = account_of(&who);
        assert!(verify(PEER, entry(&who, &["a", "b"]), Some(id)).is_ok());
        let elsewhere = account_of(&identity(2));
        assert!(verify(PEER, entry(&who, &["a", "b"]), Some(elsewhere)).is_err());
        // A peer can't hang the chain onto another id by relabelling it.
        let mut relabelled = entry(&who, &["a", "b", "c"]);
        for statement in &mut relabelled.chain {
            statement.account_id = elsewhere.to_string();
        }
        assert!(verify_any(PEER, relabelled).is_err());
        // Nor mix statements about two ids.
        let mut mixed = entry(&who, &["a", "b", "c"]);
        mixed.chain[1] = entry_for(&who, elsewhere, PEER, &["a", "b", "c"]).chain[1].clone();
        assert!(verify_any(PEER, mixed).is_err());
        // An empty chain names nobody.
        let mut empty = entry(&who, &["a", "b"]);
        empty.chain.clear();
        assert!(verify_any(PEER, empty).is_err());
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

    async fn clean(pool: &sqlx::PgPool, accounts: &[Uuid]) {
        sqlx::query(
            "DELETE FROM remote_account_renames WHERE server = $1 AND account_id = ANY($2)",
        )
        .bind(PEER)
        .bind(accounts)
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
        clean(&pool, &[account_of(&who)]).await;
        let one = verify_any(PEER, entry(&who, &["k1", "k2"])).unwrap();
        let two = verify_any(PEER, entry(&who, &["k1", "k2", "k3"])).unwrap();
        let fork = verify_any(PEER, entry(&who, &["k1", "k2", "k9"])).unwrap();
        assert_eq!(keep(&pool, PEER, &one).await.unwrap(), Stored::Advanced);
        assert_eq!(keep(&pool, PEER, &one).await.unwrap(), Stored::Same);
        assert_eq!(keep(&pool, PEER, &two).await.unwrap(), Stored::Advanced);
        assert_eq!(keep(&pool, PEER, &one).await.unwrap(), Stored::Behind);
        assert_eq!(keep(&pool, PEER, &fork).await.unwrap(), Stored::Forked);
        // Found by any address it names, in any spelling, as the longest.
        let found = kept(&pool, PEER, "k1@peer.test").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0.current, format!("k3@{PEER}"));
        assert_eq!(found[0].0.chain[0].account_id, account_of(&who).to_string());
        assert_eq!(kept(&pool, PEER, "k2@peer.test").await.unwrap().len(), 1);
        clean(&pool, &[account_of(&who)]).await;
    }

    /// At most so many chains of one domain: one more is `429`. Accounts
    /// only met (no chain) don't count.
    #[tokio::test]
    async fn live_a_domain_keeps_at_most_its_cap() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        // A domain of its own: other tests keep chains of PEER meanwhile.
        const CAPPED: &str = "capped.test";
        let (one, two, met) = (identity(31), identity(32), identity(33));
        sqlx::query("DELETE FROM remote_account_renames WHERE server = $1")
            .bind(CAPPED)
            .execute(&pool)
            .await
            .unwrap();
        let cap = 1;
        note_account(
            &pool,
            CAPPED,
            account_of(&met),
            &met.incarnation_id(),
            &format!("m1@{CAPPED}"),
        )
        .await
        .unwrap();
        let first = verify_any(CAPPED, entry_at(&one, CAPPED, &["c1", "c2"])).unwrap();
        let second = verify_any(CAPPED, entry_at(&two, CAPPED, &["d1", "d2"])).unwrap();
        assert_eq!(
            store_capped(&pool, CAPPED, &first, Source::Lookup, cap)
                .await
                .unwrap(),
            Stored::Advanced
        );
        let refused = store_capped(&pool, CAPPED, &second, Source::Lookup, cap)
            .await
            .unwrap_err();
        assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
        // The one kept still grows.
        let longer = verify_any(CAPPED, entry_at(&one, CAPPED, &["c1", "c2", "c3"])).unwrap();
        assert_eq!(
            store_capped(&pool, CAPPED, &longer, Source::Lookup, cap)
                .await
                .unwrap(),
            Stored::Advanced
        );
        sqlx::query("DELETE FROM remote_account_renames WHERE server = $1")
            .bind(CAPPED)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// The same chain again keeps a more specific state it was told (held)
    /// over an announce's plain `current`; a longer one says anew.
    #[tokio::test]
    async fn live_an_equal_chain_keeps_its_state() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let who = identity(41);
        clean(&pool, &[account_of(&who)]).await;
        let state = || {
            let pool = pool.clone();
            let account_id = account_of(&who);
            async move {
                sqlx::query_scalar::<_, String>(
                    "SELECT state FROM remote_account_renames WHERE server = $1 AND account_id = $2",
                )
                .bind(PEER)
                .bind(account_id)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let mut held = entry(&who, &["s1", "s2"]);
        held.state = "held".into();
        keep(&pool, PEER, &verify_any(PEER, held).unwrap())
            .await
            .unwrap();
        assert_eq!(state().await, "held");
        keep(
            &pool,
            PEER,
            &verify_any(PEER, entry(&who, &["s1", "s2"])).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(state().await, "held");
        keep(
            &pool,
            PEER,
            &verify_any(PEER, entry(&who, &["s1", "s2", "s3"])).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(state().await, "current");
        clean(&pool, &[account_of(&who)]).await;
    }

    /// A chain a peer mints under a fresh authority, claiming an existing
    /// name, is kept for the account it says it is of; the name's owner's
    /// own chain still advances.
    #[tokio::test]
    async fn live_a_forged_chain_is_its_own_account() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let (alice, forger) = (identity(21), identity(23));
        let accounts = [account_of(&alice), account_of(&forger)];
        clean(&pool, &accounts).await;
        let tag = &Uuid::new_v4().simple().to_string()[..10];
        let name = format!("al{tag}");
        let forged = verify_any(PEER, entry(&forger, &[&name, &format!("mallory{tag}")])).unwrap();
        assert_eq!(keep(&pool, PEER, &forged).await.unwrap(), Stored::Advanced);
        let hers = verify_any(PEER, entry(&alice, &[&name, &format!("alicia{tag}")])).unwrap();
        assert_eq!(keep(&pool, PEER, &hers).await.unwrap(), Stored::Advanced);
        let shown: Vec<String> = sqlx::query_scalar(
            "SELECT current_address FROM remote_account_renames
              WHERE server = $1 AND account_id = ANY($2) ORDER BY current_address",
        )
        .bind(PEER)
        .bind(&accounts[..])
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            shown,
            [
                format!("alicia{tag}@{PEER}"),
                format!("mallory{tag}@{PEER}")
            ],
            "each chain under its own account"
        );
        clean(&pool, &accounts).await;
    }

    /// An account first met by its address: the label shows until a chain
    /// replaces it; then the label no longer moves it. Another incarnation
    /// (a reset on its server) replaces it from an announce or a new meeting,
    /// never from a lookup.
    #[tokio::test]
    async fn live_an_account_met_shows_its_address_until_a_chain() {
        let Some(pool) = pool().await else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let (who, reset) = (identity(51), identity(52));
        let id = account_of(&who);
        clean(&pool, &[id]).await;
        let tag = &Uuid::new_v4().simple().to_string()[..10];
        let at = |name: &str| format!("{name}{tag}@{PEER}");
        let noted = |address: String, incarnation: String| {
            let pool = pool.clone();
            async move {
                note_account(&pool, PEER, id, &incarnation, &address)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(noted(at("n1"), who.incarnation_id()).await, at("n1"));
        // A row without a chain is no answer to a lookup.
        assert!(kept(&pool, PEER, &at("n1")).await.unwrap().is_empty());
        // Its server says another address: shown.
        assert_eq!(noted(at("n2"), who.incarnation_id()).await, at("n2"));
        // An address on another server is refused.
        assert!(
            note_account(&pool, PEER, id, &who.incarnation_id(), "n3@else.test")
                .await
                .is_err()
        );
        // A chain replaces the label...
        let chain = verify_any(
            PEER,
            entry(&who, &[&format!("n2{tag}"), &format!("n4{tag}")]),
        )
        .unwrap();
        assert_eq!(keep(&pool, PEER, &chain).await.unwrap(), Stored::Advanced);
        // ...and a label of the same incarnation no longer moves it.
        assert_eq!(noted(at("n2"), who.incarnation_id()).await, at("n4"));
        // Another incarnation from a lookup: the kept one stays.
        let other = verify_any(
            PEER,
            entry_for(
                &reset,
                id,
                PEER,
                &[&format!("n4{tag}"), &format!("n5{tag}")],
            ),
        )
        .unwrap();
        assert_eq!(
            keep(&pool, PEER, &other).await.unwrap(),
            Stored::OtherIncarnation
        );
        // From an announce, it replaces it.
        assert_eq!(
            store(&pool, PEER, &other, Source::Announce).await.unwrap(),
            Stored::Advanced
        );
        assert_eq!(noted(at("n5"), reset.incarnation_id()).await, at("n5"));
        // A meeting under yet another incarnation replaces the chain.
        assert_eq!(noted(at("n6"), who.incarnation_id()).await, at("n6"));
        clean(&pool, &[id]).await;
    }
}
