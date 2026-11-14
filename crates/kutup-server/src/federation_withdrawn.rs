//! Withdrawn sequences (docs/plans/server-personal-data.md, the federation
//! switch): a queued plain Chat send or media offer whose account turned its
//! federation off never leaves. Its transport sequence still must, or the
//! destination waits for it forever (and a gap would bring the row back), so
//! the origin sends a signed [`FederatedWithdrawnV1`] in its place: no sender,
//! recipient or payload. The destination uses the sequence up and answers a
//! repeat of it the same; the stream goes on with no gap.
//!
//! Sealed sends are the exception: the server can't tell whose they are (the
//! sender is sealed), so it can't withdraw them; the client's own check stops
//! new ones while its federation is off.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use kutup_chat_proto::{
    FederatedWithdrawnV1, FederationDeliveryError, FederationWithdrawnResponseV1,
    WithdrawnStreamV1, FEDERATION_WITHDRAWN_VERSION,
};
use kutup_federation_proto::FederationFeature;
use uuid::Uuid;

use crate::chat_federation::{signed_app_error, signed_json, JSON_CONTENT_TYPE};
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::federation_outbox::{self, Kind};
use crate::AppState;

/// Where a withdrawn sequence goes.
pub const PATH: &str = "/api/fed/chat/withdrawn";

/// The largest withdrawn transaction taken.
const MAX_BYTES: usize = 1024;

fn kind_of(stream: WithdrawnStreamV1) -> Kind {
    match stream {
        WithdrawnStreamV1::Chat => Kind::Chat,
        WithdrawnStreamV1::Media => Kind::Media,
    }
}

/// What the destination made of a withdrawn sequence.
pub enum Withdrawal {
    /// Used up (now, or before: a repeat).
    Accepted,
    /// The destination expects `expected` first: what it is waiting for goes
    /// before this one.
    Gap { expected: i64 },
    /// No answer that settles it (transport, or a passing refusal): later.
    Retry(String),
}

/// Sends the withdrawal of `stream`'s `sequence` (the queued transaction
/// `transaction_id`) to `destination`.
pub async fn withdraw(
    state: &AppState,
    stream: WithdrawnStreamV1,
    destination: &str,
    sequence: i64,
    transaction_id: Uuid,
) -> AppResult<Withdrawal> {
    let federation = state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("federation is not configured"))?;
    let body = serde_json::to_vec(&FederatedWithdrawnV1 {
        version: FEDERATION_WITHDRAWN_VERSION,
        transaction_id: transaction_id.to_string(),
        stream,
        sequence: u64::try_from(sequence)
            .map_err(|_| AppError::internal("invalid federation sequence"))?,
        origin: federation.server_name().to_owned(),
        destination: destination.to_owned(),
    })
    .map_err(|error| AppError::internal(format!("serialize a withdrawal: {error}")))?;
    let response = match federation
        .send(
            destination,
            FederationRequestSpec {
                feature: FederationFeature::ChatV2,
                method: Method::POST,
                path: PATH.into(),
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body,
                // Stable: a repeat of the same withdrawal is the same request
                // (URI-safe, as a transport nonce must be).
                request_id: format!("{transaction_id}.withdrawn"),
                extra_headers: Vec::new(),
                response_limit: MAX_BYTES,
            },
        )
        .await
    {
        Ok(response) => response,
        Err(error) => return Ok(Withdrawal::Retry(error.to_string())),
    };
    if response.status == StatusCode::OK {
        return Ok(Withdrawal::Accepted);
    }
    if response.status == StatusCode::CONFLICT {
        if let Ok(FederationDeliveryError::SequenceGap { expected_sequence }) =
            serde_json::from_slice(&response.body)
        {
            if let Ok(expected) = i64::try_from(expected_sequence) {
                return Ok(Withdrawal::Gap { expected });
            }
        }
    }
    Ok(Withdrawal::Retry(format!("answered {}", response.status)))
}

/// `POST /api/fed/chat/withdrawn` — a sequence of the origin's stream given
/// up before it left: used up here, with nothing delivered.
pub async fn receive(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    if body.len() > MAX_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "withdrawal is too large",
        ));
    }
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            PATH,
            None,
            &body,
            FederationFeature::ChatV2,
        )
        .await?;
    let withdrawn: FederatedWithdrawnV1 = match serde_json::from_slice(&body) {
        Ok(withdrawn) => withdrawn,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid withdrawal"),
            )
        }
    };
    if withdrawn.version != FEDERATION_WITHDRAWN_VERSION
        || withdrawn.origin != authenticated.origin()
        || withdrawn.destination != federation.server_name()
        || Uuid::parse_str(&withdrawn.transaction_id).is_err()
    {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::bad_request("invalid withdrawal"),
        );
    }
    let Some(sequence) = i64::try_from(withdrawn.sequence)
        .ok()
        .filter(|sequence| *sequence > 0)
    else {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::bad_request("invalid withdrawal sequence"),
        );
    };
    let kind = kind_of(withdrawn.stream);
    let answer = FederationWithdrawnResponseV1 {
        accepted_sequence: withdrawn.sequence,
    };
    let mut tx = state.pool.begin().await?;
    let last = federation_outbox::lock_stream(&mut tx, kind, &withdrawn.origin).await?;
    if sequence <= last {
        let prior = federation_outbox::prior(&mut tx, kind, &withdrawn.origin, sequence).await?;
        tx.rollback().await?;
        // The same withdrawal again: the same answer.
        if prior.is_some_and(|prior| {
            prior.transaction_id.as_deref() == Some(withdrawn.transaction_id.as_str())
        }) {
            return signed_json(federation, &authenticated, StatusCode::OK, &answer);
        }
        return signed_json(
            federation,
            &authenticated,
            StatusCode::CONFLICT,
            &FederationDeliveryError::SequenceGap {
                expected_sequence: (last + 1) as u64,
            },
        );
    }
    if sequence != last + 1 {
        tx.rollback().await?;
        return signed_json(
            federation,
            &authenticated,
            StatusCode::CONFLICT,
            &FederationDeliveryError::SequenceGap {
                expected_sequence: (last + 1) as u64,
            },
        );
    }
    let value = serde_json::to_value(&answer)
        .map_err(|error| AppError::internal(format!("serialize a withdrawal answer: {error}")))?;
    federation_outbox::record(
        &mut tx,
        kind,
        &withdrawn.origin,
        sequence,
        Some(&withdrawn.transaction_id),
        None,
        StatusCode::OK.as_u16(),
        &serde_json::json!({ "withdrawn": true, "answer": value }),
    )
    .await?;
    tx.commit().await?;
    signed_json(federation, &authenticated, StatusCode::OK, &answer)
}
