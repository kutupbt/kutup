//! The per-account federation switch (docs/plans/server-personal-data.md,
//! A4, decision 4): whether an account's Chat and Drive talk to other Kutup
//! servers. Mail is email, not federation, and isn't covered.
//!
//! - **Off:** the account reaches no other server (its own requests that would
//!   are refused `403 federationOff`), and to other servers it is no account
//!   at all: every answer about it is the one an unknown account gets, by the
//!   same code path (the inbound queries ask `kutup_account_federates`).
//!   Its groups and shares stay; federated ones go quiet, as with a member who
//!   can't be reached. Nothing is deleted.
//! - The switch is the account's entitlement `server.federation` (1 on,
//!   0 off). A new account gets one from the site setting
//!   `server.federation_default` (`on`) as it is made, so a later change of the
//!   default leaves existing accounts as they are; an account without one
//!   follows the default.
//! - Where the site asks for it (the site setting
//!   `server.federation_consent_required`, off in the core; a jurisdiction
//!   that needs it turns it on), turning it on asks the `federation` consent
//!   ("share data with other servers"): given before, or now under the
//!   purpose's current text when one is published (`409 consentRequired`
//!   without it). Withdrawing that consent turns it off, asked or not.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::AppState;

/// The site setting a new account's switch starts from (`on`, `off`).
pub const DEFAULT_SETTING: &str = "server.federation_default";

/// The consent purpose turning it on asks for.
pub const PURPOSE: &str = "federation";

/// The site setting saying whether turning it on asks for [`PURPOSE`] (`on`,
/// `off`; off unless set). Not `server.federation.…`: the entitlement key
/// `server.federation` is never also a prefix.
pub const CONSENT_REQUIRED_SETTING: &str = "server.federation_consent_required";

/// The refusal of a request that would reach another server for an account
/// whose federation is off.
pub fn federation_off() -> AppError {
    AppError::forbidden("this account doesn't talk to other servers")
        .with_details(json!({ "code": "federationOff" }))
}

/// Whether the account talks to other servers.
pub async fn federates<'e, E: sqlx::PgExecutor<'e>>(executor: E, user_id: Uuid) -> AppResult<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT kutup_account_federates($1)")
            .bind(user_id)
            .fetch_one(executor)
            .await?,
    )
}

/// Refuses with [`federation_off`] unless the account talks to other servers:
/// before any of its requests goes to one.
pub async fn ensure_federates(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
    if federates(pool, user_id).await? {
        Ok(())
    } else {
        Err(federation_off())
    }
}

/// The site's default for new accounts: `on` unless an administrator set `off`.
pub async fn site_default(pool: &PgPool) -> AppResult<bool> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT value FROM site_settings WHERE key = $1")
            .bind(DEFAULT_SETTING)
            .fetch_optional(pool)
            .await?;
    Ok(stored.as_deref() != Some("off"))
}

/// Where a new account's switch starts: the site's default, but off where
/// the site asks for the consent (a new account hasn't given it).
pub async fn new_account_state(pool: &PgPool) -> AppResult<bool> {
    Ok(site_default(pool).await? && !consent_required(pool).await?)
}

/// Whether turning federation on asks for the consent: `off` unless an
/// administrator set `on`.
pub async fn consent_required<'e, E: sqlx::PgExecutor<'e>>(executor: E) -> sqlx::Result<bool> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT value FROM site_settings WHERE key = $1")
            .bind(CONSENT_REQUIRED_SETTING)
            .fetch_optional(executor)
            .await?;
    Ok(stored.as_deref() == Some("on"))
}

/// Stores whether turning federation on asks for the consent.
pub async fn set_consent_required(
    tx: &mut Transaction<'_, Postgres>,
    required: bool,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO site_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(CONSENT_REQUIRED_SETTING)
    .bind(if required { "on" } else { "off" })
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Stores the site's default.
pub async fn set_site_default(tx: &mut Transaction<'_, Postgres>, on: bool) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO site_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(DEFAULT_SETTING)
    .bind(if on { "on" } else { "off" })
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Writes the account's switch.
async fn store(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    on: bool,
    source: crate::entitlements::Source,
) -> sqlx::Result<()> {
    crate::entitlements::set(
        &mut **tx,
        crate::entitlements::Holder::Account(user_id),
        crate::entitlements::FEDERATION,
        i64::from(on),
        source,
    )
    .await
}

/// Sets a new account's switch, in its creating transaction (`default_on`:
/// [`new_account_state`], read before it).
pub async fn start_account(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    default_on: bool,
) -> sqlx::Result<()> {
    store(tx, user_id, default_on, crate::entitlements::Source::Admin).await
}

/// Who turns the switch: the account itself (Settings → Privacy, its
/// consent withdrawn) or an administrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum By {
    Account,
    Admin,
}

impl By {
    fn source(self) -> crate::entitlements::Source {
        match self {
            Self::Account => crate::entitlements::Source::Account,
            Self::Admin => crate::entitlements::Source::Admin,
        }
    }

    /// The consent's channel when turning it on gives one.
    fn channel(self) -> &'static str {
        match self {
            Self::Account => "settings",
            Self::Admin => "admin",
        }
    }
}

/// Turns the account's federation off (its consent withdrawn, or its choice).
/// What it queued that carries no transport sequence (its rename announces)
/// is given up at once; a send that is sent checks the switch again.
pub async fn turn_off(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    by: By,
) -> sqlx::Result<()> {
    store(tx, user_id, false, by.source()).await?;
    sqlx::query(
        "UPDATE federation_outbox
            SET state = 'rejected', error_class = 'federationOff', updated_at = now()
          WHERE kind = 'rename' AND state = 'pending'
            AND payload->>'incarnation' IN
                (SELECT encode(account_incarnation_id, 'hex') FROM accounts WHERE id = $1)",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// After a turn-off committed: what is live for the account across servers
/// stops now, not at its next check (its editors' rooms on other servers'
/// files; other servers' subscriptions to the files it owns).
pub async fn after_off(state: &AppState, user_id: Uuid) -> AppResult<()> {
    state.collab_federation.close_account(state, user_id).await
}

/// Turns it on, in the caller's transaction. Where the site asks for the
/// `federation` consent ([`consent_required`]), it is given now (under
/// `document_id`, the purpose's current text, when one is published) or was
/// given before; an administrator's switch gives none, so it needs the
/// person's own.
pub async fn turn_on(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    document_id: Option<Uuid>,
    by: By,
) -> AppResult<()> {
    if consent_required(&mut **tx).await? {
        match (by, document_id) {
            (By::Account, Some(id)) => {
                crate::legal::set_consent(tx, user_id, PURPOSE, true, Some(id), by.channel())
                    .await?
            }
            _ if crate::legal::given(&mut **tx, user_id, PURPOSE).await? => {}
            // No text published: the person's yes is the consent itself.
            (By::Account, None)
                if !crate::legal::current(&mut **tx)
                    .await?
                    .iter()
                    .any(|d| d.kind == PURPOSE) =>
            {
                crate::legal::set_consent(tx, user_id, PURPOSE, true, None, by.channel()).await?
            }
            _ => {
                return Err(AppError::conflict(
                    "give the consent to share data with other servers first",
                )
                .with_details(json!({ "code": "consentRequired", "purpose": PURPOSE })))
            }
        }
    }
    store(tx, user_id, true, by.source()).await?;
    Ok(())
}

/// `PUT /api/user/federation` body.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct FederationRequest {
    /// Talk to other servers.
    on: bool,
    /// Turning it on where the site asks for the consent: the `federation`
    /// text the person read, when one is published (the consent is given
    /// with it).
    document_id: Option<Uuid>,
}

/// `PUT /api/user/federation` — the account's own switch.
#[utoipa::path(
    put,
    path = "/api/user/federation",
    tag = "legal",
    security(("BearerAuth" = [])),
    request_body = FederationRequest,
    responses(
        (status = 204, description = "Set"),
        (status = 409, description = "consentRequired: the site asks for the federation consent and it isn't given"),
    )
)]
pub async fn put_federation(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<FederationRequest>,
) -> AppResult<Response> {
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    let mut tx = state.pool.begin().await?;
    if req.on {
        turn_on(&mut tx, user_id, req.document_id, By::Account).await?;
    } else {
        turn_off(&mut tx, user_id, By::Account).await?;
    }
    tx.commit().await?;
    if !req.on {
        after_off(&state, user_id).await?;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_crypto::account_ref::AccountRef;

    async fn account(pool: &PgPool) -> Uuid {
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO accounts (id, username, identity_suite, drive_key_binding_epoch, master_key_generation) VALUES ($1, $2, 2, 1, 1)")
            .bind(user_id)
            .bind(format!("fed{}", &user_id.simple().to_string()[..12]))
            .execute(pool)
            .await
            .unwrap();
        user_id
    }

    /// Off: a peer's lookup finds nothing, as for an unknown account, while
    /// this server's own still does. On again: found. Where the site asks for
    /// the consent, turning it on needs it, given by the person.
    #[tokio::test]
    async fn live_an_account_that_doesnt_federate_is_no_account_to_peers() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let server = "fed.test";
        let user = account(&pool).await;
        let me = AccountRef::new(server, &user.to_string()).unwrap();
        let unknown = AccountRef::new(server, &Uuid::new_v4().to_string()).unwrap();

        assert_eq!(
            crate::account_ids::local_user_for_peer(&pool, server, &me)
                .await
                .unwrap(),
            Some(user)
        );
        let mut tx = pool.begin().await.unwrap();
        turn_off(&mut tx, user, By::Account).await.unwrap();
        tx.commit().await.unwrap();
        assert!(!federates(&pool, user).await.unwrap());
        assert_eq!(
            crate::account_ids::local_user_for_peer(&pool, server, &me)
                .await
                .unwrap(),
            crate::account_ids::local_user_for_peer(&pool, server, &unknown)
                .await
                .unwrap(),
        );
        assert_eq!(
            crate::account_ids::local_user(&pool, server, &me)
                .await
                .unwrap(),
            Some(user),
            "this server's own lookups still find it"
        );

        // A text for the purpose: the core asks for no consent.
        let text: Uuid = sqlx::query_scalar(
            "INSERT INTO legal_documents (kind, version, language, url, sha256)
             VALUES ('federation', $1, 'en', 'https://example.org/f', sha256('f'))
             RETURNING id",
        )
        .bind(Uuid::new_v4().to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        turn_on(&mut tx, user, None, By::Account).await.unwrap();
        tx.rollback().await.unwrap();
        // Where the site asks for it (set inside each transaction, so no other
        // test sees it): on needs the consent, given with it; an
        // administrator can't give it.
        let mut tx = pool.begin().await.unwrap();
        set_consent_required(&mut tx, true).await.unwrap();
        let refused = turn_on(&mut tx, user, None, By::Account).await.unwrap_err();
        assert_eq!(refused.status, StatusCode::CONFLICT);
        tx.rollback().await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        set_consent_required(&mut tx, true).await.unwrap();
        let refused = turn_on(&mut tx, user, Some(text), By::Admin)
            .await
            .unwrap_err();
        assert_eq!(refused.status, StatusCode::CONFLICT);
        tx.rollback().await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        set_consent_required(&mut tx, true).await.unwrap();
        turn_on(&mut tx, user, Some(text), By::Account)
            .await
            .unwrap();
        sqlx::query("DELETE FROM site_settings WHERE key = $1")
            .bind(CONSENT_REQUIRED_SETTING)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(federates(&pool, user).await.unwrap());
        assert!(crate::legal::given(&pool, user, PURPOSE).await.unwrap());

        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// Off, nothing of the account leaves: a rename announce isn't queued,
    /// one queued before is given up at the switch, and other servers read
    /// none of its live locations.
    #[tokio::test]
    async fn live_turning_off_stops_what_would_leave() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let user = account(&pool).await;
        let incarnation = format!("{:064x}", user.as_u128());
        sqlx::query("UPDATE accounts SET account_incarnation_id = decode($2, 'hex') WHERE id = $1")
            .bind(user)
            .bind(&incarnation)
            .execute(&pool)
            .await
            .unwrap();
        let peer = format!("peer-{}.test", &user.simple().to_string()[..12]);
        sqlx::query(
            "INSERT INTO federation_peer_identities
                 (domain, trust_state, current_sequence, current_document_hash, current_key_id,
                  current_public_key, first_seen_at, last_seen_at)
             VALUES ($1, 'tofu', 1, decode($2, 'hex'), decode($2, 'hex'), kutup_unb64($3), now(), now())",
        )
        .bind(&peer)
        .bind("ab".repeat(32))
        .bind(format!("{}=", "A".repeat(43)))
        .execute(&pool)
        .await
        .unwrap();
        let queued = |sequence: u64| {
            let (pool, incarnation, peer) = (pool.clone(), incarnation.clone(), peer.clone());
            async move {
                let mut conn = pool.acquire().await.unwrap();
                crate::remote_renames::enqueue(&mut conn, "fed.test", &incarnation, sequence)
                    .await
                    .unwrap();
                sqlx::query_as::<_, (String, Option<String>)>(
                    "SELECT state, error_class FROM federation_outbox
                      WHERE kind = 'rename' AND destination = $1
                        AND payload->>'incarnation' = $2 ORDER BY created_at",
                )
                .bind(&peer)
                .bind(&incarnation)
                .fetch_all(&pool)
                .await
                .unwrap()
            }
        };
        // On: queued for the peer.
        assert_eq!(queued(1).await, vec![("pending".into(), None)]);
        // Off: the one queued is given up, and no other is queued.
        let mut tx = pool.begin().await.unwrap();
        turn_off(&mut tx, user, By::Account).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            queued(2).await,
            vec![("rejected".into(), Some("federationOff".into()))]
        );

        // A live location it shares: read here, not by a peer.
        let stream = uuid::Uuid::new_v4().as_bytes().to_vec();
        let read = [7u8; 32];
        let verifier =
            kutup_crypto::primitives::hash(kutup_crypto::primitives::Suite::V1, read).to_vec();
        sqlx::query(
            "INSERT INTO chat_live_location_streams
                 (stream_id, write_verifier, read_verifier, expires_at, created_by_account_id)
             VALUES ($1, $2, $2, now() + interval '1 hour', $3)",
        )
        .bind(&stream)
        .bind(&verifier)
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            crate::live_locations::read_for_tests(&pool, &stream, &verifier, false)
                .await
                .is_ok()
        );
        assert!(
            crate::live_locations::read_for_tests(&pool, &stream, &verifier, true)
                .await
                .is_err()
        );

        sqlx::query("DELETE FROM federation_outbox WHERE destination = $1")
            .bind(&peer)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM federation_peer_identities WHERE domain = $1")
            .bind(&peer)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
    }
}
