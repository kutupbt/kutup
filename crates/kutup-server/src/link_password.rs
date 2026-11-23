//! A public link's password, on the server (docs/plans/drive-link-password.md).
//!
//! The server never sees the password or the link's URL secret: it keeps a
//! verifier of the proof both derive (`kutup_crypto::link_password`) and,
//! for a protected link, answers the reads that reveal what the link holds
//! (the link, its files, its key history, its album) only to a request whose
//! `X-Kutup-Link-Proof` matches:
//!
//! - none: `401 linkPassword` (the page asks for the password);
//! - a wrong one: `401 linkPasswordWrong`, counted against the link (in the
//!   database, every server process together) and against the address;
//! - past either limit: `429 linkPasswordLocked`, whatever is sent, until
//!   the window is over (`drive.rate.link_password_failures`,
//!   `drive.rate.link_password_address_failures`).
//!
//! Each try is reserved before the check, in the transaction that holds the
//! link's counter row, so parallel guesses get no more; a right proof gives
//! its reservation back.

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

fn locked() -> AppError {
    AppError::too_many_requests("too many wrong passwords for this link")
        .with_details(json!({ "code": "linkPasswordLocked" }))
}

/// The counter subject of one link: a digest under its own label.
fn subject(link_id: Uuid) -> [u8; 32] {
    hash(
        Suite::V1,
        [
            kutup_crypto::labels::DRIVE_LINK_PASSWORD_RATE_V1,
            link_id.as_bytes().as_slice(),
        ]
        .concat(),
    )
    .into()
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
    if !LINK_PASSWORD_ADDRESS_FAILURES.has_room(&proof.client) {
        return Err(locked());
    }
    let (limit, window) = crate::ratelimit::budget(Limit::LinkPasswordFailures);
    let mut tx = pool.begin().await?;
    let count = counters::add(
        &mut tx,
        Scope::DriveLinkPassword,
        &subject(link_id),
        1,
        window,
    )
    .await?;
    if count > limit {
        tx.rollback().await?;
        return Err(locked());
    }
    let right = STANDARD
        .decode(sent)
        .is_ok_and(|bytes| kutup_crypto::link_password::verify(&bytes, &verifier));
    if right {
        // The reservation goes back with the transaction.
        tx.rollback().await?;
        return Ok(Some(Unlocked { link_key_envelope }));
    }
    tx.commit().await?;
    LINK_PASSWORD_ADDRESS_FAILURES.allow(&proof.client);
    Err(wrong())
}
