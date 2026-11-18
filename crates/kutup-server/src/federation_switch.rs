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
//! - A new account takes the site setting `federation_default` (`on`).
//! - Turning it on asks the `federationAbroad` consent when a document for it
//!   is published (`409 consentRequired` without it); withdrawing that
//!   consent turns it off.

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
pub const DEFAULT_SETTING: &str = "federation_default";

/// The consent purpose turning it on asks for.
pub const PURPOSE: &str = "federationAbroad";

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

/// Sets a new account's switch from the site's default, in its creating
/// transaction (`default_on`: [`site_default`], read before it).
pub async fn start_account(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    default_on: bool,
) -> sqlx::Result<()> {
    if !default_on {
        sqlx::query("UPDATE accounts SET federation = 'off' WHERE id = $1")
            .bind(user_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Turns the account's federation off (its consent withdrawn, or its choice).
/// What it queued that carries no transport sequence (its rename announces)
/// is given up at once; a send that is sent checks the switch again.
pub async fn turn_off(tx: &mut Transaction<'_, Postgres>, user_id: Uuid) -> sqlx::Result<()> {
    sqlx::query("UPDATE accounts SET federation = 'off' WHERE id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
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

/// Turns it on, in the caller's transaction: with the `federationAbroad`
/// consent given (now, under `document_id`, or before) when its document is
/// published.
pub async fn turn_on(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    document_id: Option<Uuid>,
    channel: &str,
) -> AppResult<()> {
    let text_published = crate::legal::current(&mut **tx)
        .await?
        .iter()
        .any(|d| d.kind == PURPOSE);
    if text_published {
        match document_id {
            Some(id) => {
                crate::legal::set_consent(tx, user_id, PURPOSE, true, Some(id), channel).await?
            }
            None if crate::legal::given(&mut **tx, user_id, PURPOSE).await? => {}
            None => {
                return Err(
                    AppError::conflict("give the consent to talk to other servers first")
                        .with_details(json!({ "code": "consentRequired", "purpose": PURPOSE })),
                )
            }
        }
    }
    sqlx::query("UPDATE accounts SET federation = 'on' WHERE id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// `PUT /api/user/federation` body.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct FederationRequest {
    /// Talk to other servers.
    on: bool,
    /// Turning it on: the `federationAbroad` text the person read, when one
    /// is published (the consent is given with it).
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
        (status = 409, description = "consentRequired: a federationAbroad document is published and the consent isn't given"),
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
        turn_on(&mut tx, user_id, req.document_id, "settings").await?;
    } else {
        turn_off(&mut tx, user_id).await?;
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
        sqlx::query("INSERT INTO accounts (id, username, identity_suite) VALUES ($1, $2, 2)")
            .bind(user_id)
            .bind(format!("fed{}", &user_id.simple().to_string()[..12]))
            .execute(pool)
            .await
            .unwrap();
        user_id
    }

    /// Off: a peer's lookup finds nothing, as for an unknown account, while
    /// this server's own still does. On again: found. With a text published
    /// for the purpose, turning it on needs the consent; withdrawing the
    /// consent turns it off.
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
        turn_off(&mut tx, user).await.unwrap();
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

        // A text for the purpose: on needs the consent, given with it.
        let text: Uuid = sqlx::query_scalar(
            "INSERT INTO legal_documents (kind, version, language, url, sha256)
             VALUES ('federationAbroad', $1, 'en', 'https://example.org/f', sha256('f'))
             RETURNING id",
        )
        .bind(Uuid::new_v4().to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        let refused = turn_on(&mut tx, user, None, "settings").await.unwrap_err();
        assert_eq!(refused.status, StatusCode::CONFLICT);
        tx.rollback().await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        turn_on(&mut tx, user, Some(text), "settings")
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
        turn_off(&mut tx, user).await.unwrap();
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
