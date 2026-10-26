//! Security keys as a second factor (docs/plans/security-keys.md): the
//! relying party this server is, the ceremonies in flight, and a key's
//! answer checked. The WebAuthn checks themselves are kutup-crypto's
//! `webauthn` adapter; this module keeps what it hands back.

use kutup_crypto::webauthn::{
    self, AssertionResponse, AuthenticationRefusal, KeyRef, RelyingParty, Started, StoredKey,
};
use sqlx::{PgExecutor, Postgres, Transaction};
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// The relying party: the account app's origin (where keys are added and
/// used) and the configured RP id (`Config::webauthn_rp_id`), which must be
/// that origin's host or a domain it ends in. An error where the
/// deployment's origins can't use WebAuthn (plain http off localhost, as a
/// two-server test stack): security keys are off then, and production
/// refuses to start (`check-config`).
pub fn relying_party(config: &Config) -> Result<RelyingParty, String> {
    RelyingParty::new(&config.webauthn_rp_id, vec![config.apps.account.clone()])
        .map_err(|error| format!("{error} (RP id {:?})", config.webauthn_rp_id))
}

/// Which ceremony a stored state belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyKind {
    /// Adding a key (a signed-in session).
    Register,
    /// A sign-in's second step (its first step's pre-auth token).
    SignIn,
    /// The second factor proved again by a signed-in session (renewing
    /// recovery codes, removing a factor).
    Proof,
}

impl CeremonyKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::SignIn => "signIn",
            Self::Proof => "proof",
        }
    }
}

/// What a ceremony is bound to, as stored: the SHA-256 of the session id or
/// the pre-auth token that started it.
pub fn binding(secret: &str) -> Vec<u8> {
    kutup_crypto::primitives::hash(kutup_crypto::primitives::Suite::V1, secret.as_bytes())
        .as_bytes()
        .to_vec()
}

/// Ceremonies one account may have open of one kind: the oldest go first.
const OPEN_PER_KIND: i64 = 5;

/// Keeps `started`'s state until it is finished or `seconds` pass;
/// `second_factor_proved`: adding a key, the start proved a factor.
pub async fn store_ceremony(
    tx: &mut Transaction<'_, Postgres>,
    started: &Started,
    kind: CeremonyKind,
    user_id: Uuid,
    bound_to: &[u8],
    seconds: i64,
    second_factor_proved: bool,
) -> AppResult<()> {
    sqlx::query("DELETE FROM webauthn_ceremonies WHERE expires_at < now()")
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO webauthn_ceremonies
             (challenge, kind, user_id, bound_to, state, second_factor_proved, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))",
    )
    .bind(&started.challenge)
    .bind(kind.as_str())
    .bind(user_id)
    .bind(bound_to)
    .bind(&started.state)
    .bind(second_factor_proved)
    .bind(seconds as f64)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "DELETE FROM webauthn_ceremonies WHERE challenge IN (
             SELECT challenge FROM webauthn_ceremonies
             WHERE user_id = $1 AND kind = $2
             ORDER BY expires_at DESC OFFSET $3)",
    )
    .bind(user_id)
    .bind(kind.as_str())
    .bind(OPEN_PER_KIND)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A ceremony taken to be finished.
#[derive(Debug, sqlx::FromRow)]
pub struct Ceremony {
    pub state: Vec<u8>,
    pub second_factor_proved: bool,
    pub created_at: time::OffsetDateTime,
}

/// The ceremony `challenge` names, if it is `user_id`'s, of `kind`, bound
/// to `bound_to` and not expired; taken (single use).
pub async fn take_ceremony(
    tx: &mut Transaction<'_, Postgres>,
    challenge: &[u8],
    kind: CeremonyKind,
    user_id: Uuid,
    bound_to: &[u8],
) -> AppResult<Ceremony> {
    sqlx::query_as(
        "DELETE FROM webauthn_ceremonies
         WHERE challenge = $1 AND kind = $2 AND user_id = $3 AND bound_to = $4
           AND expires_at > now()
         RETURNING state, second_factor_proved, created_at",
    )
    .bind(challenge)
    .bind(kind.as_str())
    .bind(user_id)
    .bind(bound_to)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(ceremony_gone)
}

pub fn ceremony_gone() -> AppError {
    AppError::bad_request("the security key prompt expired or was already answered")
        .with_details(serde_json::json!({ "code": "securityKeyCeremony" }))
}

/// One of the account's keys, as options name it.
#[derive(Debug, sqlx::FromRow)]
pub struct KeyRow {
    pub credential_id: Vec<u8>,
    pub transports: Vec<u8>,
}

/// The account's usable keys (not compromised).
pub async fn usable_keys<'e, E: PgExecutor<'e>>(
    executor: E,
    user_id: Uuid,
) -> sqlx::Result<Vec<KeyRow>> {
    sqlx::query_as(
        "SELECT credential_id, transports FROM user_security_keys
         WHERE user_id = $1 AND NOT compromised ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(executor)
    .await
}

pub fn key_refs(keys: &[KeyRow]) -> Vec<KeyRef<'_>> {
    keys.iter()
        .map(|key| KeyRef {
            credential_id: &key.credential_id,
            transports: &key.transports,
        })
        .collect()
}

/// Whether the account requires user verification ("Require PIN").
pub async fn requires_uv<'e, E: PgExecutor<'e>>(executor: E, user_id: Uuid) -> sqlx::Result<bool> {
    sqlx::query_scalar("SELECT security_keys_require_uv FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(executor)
        .await
}

/// Starts a ceremony asking one of the account's usable keys (a sign-in's
/// second step, or a proof): its options for the browser. `409` when the
/// account has none.
pub async fn start_assertion(
    tx: &mut Transaction<'_, Postgres>,
    rp: &RelyingParty,
    kind: CeremonyKind,
    user_id: Uuid,
    bound_to: &[u8],
    seconds: i64,
) -> AppResult<serde_json::Value> {
    let keys = usable_keys(&mut **tx, user_id).await?;
    if keys.is_empty() {
        return Err(AppError::conflict("no security keys")
            .with_details(serde_json::json!({ "code": "noSecurityKeys" })));
    }
    let require_uv = requires_uv(&mut **tx, user_id).await?;
    let started = webauthn::start_authentication(
        rp,
        &key_refs(&keys),
        require_uv,
        u32::try_from(seconds * 1000).unwrap_or(u32::MAX),
    )
    .map_err(|error| AppError::internal(format!("WebAuthn options: {error}")))?;
    store_ceremony(tx, &started, kind, user_id, bound_to, seconds, false).await?;
    serde_json::from_str(&started.options_json)
        .map_err(|error| AppError::internal(format!("WebAuthn options: {error}")))
}

/// Why a key's answer was refused.
#[derive(Debug)]
pub enum Refused {
    /// The answer doesn't hold: `400` to the client.
    Invalid,
    /// Its counter went back with no other use of it since the ceremony
    /// started: the key is now marked compromised (and the owner told),
    /// within the caller's transaction.
    Compromised,
    /// Its counter went back, but the key was used after this ceremony
    /// started (two tabs, a double submit): refused, to be tried again.
    Concurrent,
}

/// Checks a key's answer to the `kind` ceremony it names, for `user_id`,
/// bound to `bound_to`: the ceremony taken, the key one of the account's
/// usable ones, the answer verified, and the key's new counter stored. The
/// key's id.
pub async fn finish_assertion(
    tx: &mut Transaction<'_, Postgres>,
    rp: &RelyingParty,
    kind: CeremonyKind,
    user_id: Uuid,
    bound_to: &[u8],
    response_json: &[u8],
) -> AppResult<Result<Uuid, Refused>> {
    let Ok(response) = AssertionResponse::parse(response_json) else {
        return Ok(Err(Refused::Invalid));
    };
    let Ok(challenge) = response.challenge() else {
        return Ok(Err(Refused::Invalid));
    };
    let ceremony = match take_ceremony(tx, &challenge, kind, user_id, bound_to).await {
        Ok(ceremony) => ceremony,
        Err(_) => return Ok(Err(Refused::Invalid)),
    };
    let key: Option<(Uuid, String, Vec<u8>, Vec<u8>, Option<time::OffsetDateTime>)> =
        sqlx::query_as(
            "SELECT id, name, static_state, dynamic_state, last_used_at FROM user_security_keys
         WHERE user_id = $1 AND credential_id = $2 AND NOT compromised
         FOR UPDATE",
        )
        .bind(user_id)
        .bind(response.credential_id())
        .fetch_optional(&mut **tx)
        .await?;
    let Some((key_id, name, static_state, dynamic_state, last_used_at)) = key else {
        return Ok(Err(Refused::Invalid));
    };
    let credential_id = response.credential_id();
    let checked = webauthn::finish_authentication(
        rp,
        &ceremony.state,
        &response,
        StoredKey {
            credential_id: &credential_id,
            account: *user_id.as_bytes(),
            static_state: &static_state,
            dynamic_state: &dynamic_state,
        },
    );
    match checked {
        Ok(asserted) => {
            sqlx::query(
                "UPDATE user_security_keys
                 SET dynamic_state = $2, sign_count = $3, last_used_at = now()
                 WHERE id = $1",
            )
            .bind(key_id)
            .bind(&asserted.dynamic_state)
            .bind(i64::from(asserted.sign_count))
            .execute(&mut **tx)
            .await?;
            Ok(Ok(key_id))
        }
        Err(AuthenticationRefusal::CounterWentBack)
            if last_used_at.is_some_and(|used| used >= ceremony.created_at) =>
        {
            Ok(Err(Refused::Concurrent))
        }
        Err(AuthenticationRefusal::CounterWentBack) => {
            sqlx::query("UPDATE user_security_keys SET compromised = true WHERE id = $1")
                .bind(key_id)
                .execute(&mut **tx)
                .await?;
            crate::security_events::record_names(
                tx,
                user_id,
                crate::security_events::Kind::SecurityKeyCompromised,
                None,
                None,
                &name,
                None,
            )
            .await?;
            Ok(Err(Refused::Compromised))
        }
        Err(AuthenticationRefusal::Invalid(reason)) => {
            tracing::info!(%reason, "security key answer refused");
            Ok(Err(Refused::Invalid))
        }
    }
}
