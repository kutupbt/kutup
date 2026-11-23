//! A public link's password, on the server (docs/plans/drive-link-password.md).
//!
//! The server never sees the password or the link's URL secret: it keeps a
//! verifier of the proof both derive (`kutup_crypto::link_password`) and,
//! for a protected link, answers every read through it (the link, its
//! files, its key history, its album, and the content, state, pictures and
//! thumbnails of its files) only to a request whose `X-Kutup-Link-Proof`
//! matches, as Proton gates every read of a protected link:
//!
//! - none: `401 linkPassword` (the page asks for the password);
//! - a wrong one: `401 linkPasswordWrong`, counted;
//! - past either limit: `429 linkPasswordLocked` with `Retry-After`, until
//!   the window is over.
//!
//! As Proton Drive: a wrong password is "Incorrect password. Please try
//! again."; too many make the client wait as `Retry-After` says. There is no
//! lock of the link itself, which anyone with the URL could set off for
//! everyone: wrong guesses count per link and address
//! (`drive.rate.link_password_failures`, in the database, every server
//! process together) and per address over every link
//! (`drive.rate.link_password_address_failures`). Every try is reserved in
//! both before its proof is checked; a right proof gives its reservations
//! back, so a parallel burst gets no more checks than the limits.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::primitives::{hash, Suite};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::ratelimit::counters::{self, Scope};
use crate::ratelimit::{Limit, LINK_PASSWORD_ADDRESS_FAILURES};

/// The header a protected link's reads carry the proof in (base64).
pub const PROOF_HEADER: &str = "x-kutup-link-proof";

/// The proof a request carries, and where it comes from.
pub struct LinkProof {
    proof: Option<String>,
    client: String,
}

#[axum::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for LinkProof {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let proof = parts
            .headers
            .get(PROOF_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| *addr)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let client = crate::middleware::client_key(
            crate::middleware::client_ip_from_headers(&parts.headers),
            peer,
        );
        Ok(Self { proof, client })
    }
}

fn required() -> AppError {
    AppError::new(StatusCode::UNAUTHORIZED, "this link needs its password")
        .with_details(json!({ "code": "linkPassword" }))
}

fn wrong() -> AppError {
    AppError::new(StatusCode::UNAUTHORIZED, "wrong link password")
        .with_details(json!({ "code": "linkPasswordWrong" }))
}

fn locked(retry_after: u64) -> AppError {
    AppError::too_many_requests("too many wrong passwords for this link")
        .with_details(json!({ "code": "linkPasswordLocked" }))
        .with_retry_after(retry_after.max(1))
}

/// The counter subject of one link from one address: a digest under its
/// own label.
fn subject(link_id: Uuid, client: &str) -> [u8; 32] {
    hash(
        Suite::V1,
        [
            kutup_crypto::labels::DRIVE_LINK_PASSWORD_RATE_V1,
            link_id.as_bytes().as_slice(),
            client.as_bytes(),
        ]
        .concat(),
    )
    .into()
}

/// Reserves one try in a link and address's count, in its own short
/// transaction; the new count.
async fn reserve(pool: &PgPool, counted: &[u8; 32], window: i64) -> AppResult<i64> {
    let mut tx = pool.begin().await?;
    let count = counters::add(&mut tx, Scope::DriveLinkPassword, counted, 1, window).await?;
    tx.commit().await?;
    Ok(count)
}

/// A protected link opened: its key under the password wrap key (purpose 14).
pub struct Unlocked {
    pub link_key_envelope: String,
}

/// Checks the password of the link with `token`, if it has one: `Ok(None)`
/// for an unprotected link (or none by that token: the caller answers for
/// it), `Ok(Some(..))` for a right proof, an error otherwise.
pub async fn unlock(pool: &PgPool, token: &str, proof: &LinkProof) -> AppResult<Option<Unlocked>> {
    let row: Option<(Uuid, Option<Vec<u8>>, Option<String>)> = sqlx::query_as(
        "SELECT id, password_verifier, kutup_b64(password_link_key_envelope)
           FROM drive_public_shares WHERE token = $1",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    let Some((link_id, Some(verifier), Some(link_key_envelope))) = row else {
        return Ok(None);
    };
    let Some(sent) = proof.proof.as_deref() else {
        return Err(required());
    };
    // Each try is reserved before it is checked, so a burst in parallel
    // gets no more checks than the limits: one in the address limiter, one
    // in this link and address's counter (its own row, no shared hotspot).
    // A right proof gives both back.
    if !LINK_PASSWORD_ADDRESS_FAILURES.allow(&proof.client) {
        return Err(locked(
            LINK_PASSWORD_ADDRESS_FAILURES.wait(&proof.client).as_secs(),
        ));
    }
    let (limit, window) = crate::ratelimit::budget(Limit::LinkPasswordFailures);
    let counted = subject(link_id, &proof.client);
    let reserved = reserve(pool, &counted, window).await;
    let count = match reserved {
        Ok(count) => count,
        Err(error) => {
            LINK_PASSWORD_ADDRESS_FAILURES.pop(&proof.client);
            return Err(error);
        }
    };
    if count > limit {
        // Over: this try is refused, and its reservation stays counted (the
        // window ends at the same time either way).
        LINK_PASSWORD_ADDRESS_FAILURES.pop(&proof.client);
        let (_, left) = counters::current(pool, Scope::DriveLinkPassword, &counted, window).await?;
        return Err(locked(u64::try_from(left).unwrap_or(1)));
    }
    let right = STANDARD
        .decode(sent)
        .is_ok_and(|bytes| kutup_crypto::link_password::verify(&bytes, &verifier));
    if right {
        LINK_PASSWORD_ADDRESS_FAILURES.pop(&proof.client);
        counters::give_back(pool, Scope::DriveLinkPassword, &counted, window).await?;
        return Ok(Some(Unlocked { link_key_envelope }));
    }
    Err(wrong())
}
