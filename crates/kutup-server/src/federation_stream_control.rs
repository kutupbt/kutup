//! Stream control messages: a signed [`FederatedStreamControlV1`] uses up one
//! sequence of an origin's sequenced federation stream (plain Chat sends or
//! media offers) with no delivery. Its `control` code says why; the ranges
//! (on [`kutup_chat_proto::STREAM_CONTROL_MUST_UNDERSTAND`]) let the next one
//! come with no protocol bump: an unknown skip-safe code (`1..=0x7fff`) is
//! used up as a withdrawal is, an unknown must-understand one
//! (`0x8000..=0xffff`) is refused with its sequence left, and `0` is invalid.
//!
//! The one defined today is [`STREAM_CONTROL_WITHDRAWN`]
//! (docs/plans/server-personal-data.md, the federation switch): a queued
//! plain Chat send or media offer whose account turned its federation off
//! never leaves. Its transport sequence still must, or the destination waits
//! for it forever (and a gap would bring the row back), so the origin sends a
//! withdrawal in its place: no sender, recipient or payload. The destination
//! uses the sequence up and answers a repeat of it the same; the stream goes
//! on with no gap.
//!
//! Sealed sends are the exception: the server can't tell whose they are (the
//! sender is sealed), so it can't withdraw them; the client's own check stops
//! new ones while its federation is off.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use kutup_chat_proto::{
    FederatedStreamControlV1, FederationDeliveryError, FederationStreamControlResponseV1,
    FederationStreamV1, StreamControlRange, FEDERATION_STREAM_CONTROL_VERSION,
    STREAM_CONTROL_WITHDRAWN,
};
use kutup_federation_proto::FederationFeature;
use sqlx::PgPool;
use uuid::Uuid;

use crate::chat_federation::{signed_app_error, signed_json, JSON_CONTENT_TYPE};
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::federation_outbox::{self, Kind};
use crate::AppState;

/// Where a stream control message goes.
pub const PATH: &str = "/api/fed/v2/chat/stream-control";

/// The largest stream control message taken.
const MAX_BYTES: usize = 1024;

fn kind_of(stream: FederationStreamV1) -> Kind {
    match stream {
        FederationStreamV1::Chat => Kind::Chat,
        FederationStreamV1::Media => Kind::Media,
        FederationStreamV1::Sealed => Kind::Sealed,
    }
}

/// A queued transaction this server can no longer read (a retired format, a
/// damaged payload) must not hold its destination's queue: its sequence is
/// withdrawn, as an off account's send is, so the peer moves on with no gap,
/// and the row is settled as rejected (`undecodable`). Only the row's id is
/// logged. Returns whether it is settled; otherwise it is tried again later
/// (the peer waits for an earlier sequence, or did not answer).
pub async fn settle_undecodable(
    state: &AppState,
    stream: FederationStreamV1,
    row_id: Uuid,
    destination: &str,
    sequence: i64,
    attempts: i32,
) -> AppResult<bool> {
    tracing::warn!(row = %row_id, "a queued federation transaction no longer decodes: its sequence is withdrawn");
    match withdraw(state, stream, destination, sequence, row_id).await? {
        Withdrawal::Accepted => {
            federation_outbox::settle(
                &state.pool,
                row_id,
                Some(sequence),
                false,
                Some("undecodable"),
                &serde_json::json!({ "withdrawn": true }),
            )
            .await?;
            Ok(true)
        }
        Withdrawal::Gap { expected } => {
            federation_outbox::retry_later(
                &state.pool,
                row_id,
                Some(sequence),
                attempts,
                "sequence_gap",
                &format!("remote expects sequence {expected}"),
            )
            .await?;
            Ok(false)
        }
        Withdrawal::Retry(error) => {
            federation_outbox::retry_later(
                &state.pool,
                row_id,
                Some(sequence),
                attempts,
                "transport",
                &error,
            )
            .await?;
            Ok(false)
        }
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
    stream: FederationStreamV1,
    destination: &str,
    sequence: i64,
    transaction_id: Uuid,
) -> AppResult<Withdrawal> {
    let federation = state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("federation is not configured"))?;
    let body = serde_json::to_vec(&FederatedStreamControlV1 {
        version: FEDERATION_STREAM_CONTROL_VERSION,
        control: STREAM_CONTROL_WITHDRAWN,
        transaction_id: transaction_id.to_string(),
        stream,
        sequence: u64::try_from(sequence)
            .map_err(|_| AppError::internal("invalid federation sequence"))?,
        origin: federation.server_name().to_owned(),
        destination: destination.to_owned(),
        data: None,
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

/// What this server does with a control code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handling {
    /// [`STREAM_CONTROL_WITHDRAWN`]: used up, recorded as a withdrawal.
    Withdrawn,
    /// A skip-safe code this server doesn't know: used up all the same.
    Skipped(u16),
}

/// The handling of `control`, or the refusal it gets (its sequence left).
fn handling(control: u16) -> Result<Handling, AppError> {
    if control == STREAM_CONTROL_WITHDRAWN {
        return Ok(Handling::Withdrawn);
    }
    match StreamControlRange::of(control) {
        StreamControlRange::Invalid => Err(AppError::bad_request("invalid stream control")),
        StreamControlRange::SkipSafe => Ok(Handling::Skipped(control)),
        StreamControlRange::MustUnderstand => Err(AppError::bad_request(
            "unknown must-understand stream control",
        )
        .with_details(serde_json::json!({ "code": "unknownStreamControl" }))),
    }
}

/// What using a sequence up came to.
#[derive(Debug, PartialEq, Eq)]
enum Applied {
    /// Used up (now, or before by the same transaction).
    Accepted(FederationStreamControlResponseV1),
    /// Not the next sequence: the destination expects `expected` first.
    Gap { expected: u64 },
}

/// Uses up `sequence` of `origin`'s `kind` stream for `transaction_id`, if
/// it is the next one, answering a repeat of the same transaction the same.
async fn apply(
    pool: &PgPool,
    kind: Kind,
    origin: &str,
    sequence: i64,
    transaction_id: &str,
    handled: Handling,
) -> AppResult<Applied> {
    let answer = FederationStreamControlResponseV1 {
        accepted_sequence: sequence as u64,
    };
    let mut tx = pool.begin().await?;
    let last = federation_outbox::lock_stream(&mut tx, kind, origin).await?;
    if sequence <= last {
        let prior = federation_outbox::prior(&mut tx, kind, origin, sequence).await?;
        tx.rollback().await?;
        // The same message again: the same answer.
        if prior.is_some_and(|prior| prior.transaction_id.as_deref() == Some(transaction_id)) {
            return Ok(Applied::Accepted(answer));
        }
        return Ok(Applied::Gap {
            expected: (last + 1) as u64,
        });
    }
    if sequence != last + 1 {
        tx.rollback().await?;
        return Ok(Applied::Gap {
            expected: (last + 1) as u64,
        });
    }
    let value = serde_json::to_value(&answer).map_err(|error| {
        AppError::internal(format!("serialize a stream control answer: {error}"))
    })?;
    let recorded = match handled {
        Handling::Withdrawn => serde_json::json!({ "withdrawn": true, "answer": value }),
        Handling::Skipped(control) => {
            serde_json::json!({ "control": control, "skipped": true, "answer": value })
        }
    };
    federation_outbox::record(
        &mut tx,
        kind,
        origin,
        sequence,
        Some(transaction_id),
        None,
        StatusCode::OK.as_u16(),
        &recorded,
    )
    .await?;
    tx.commit().await?;
    Ok(Applied::Accepted(answer))
}

/// `POST /api/fed/v2/chat/stream-control` — a sequence of the origin's stream
/// used up with nothing delivered (a withdrawal, or a skip-safe code).
pub async fn receive(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    if body.len() > MAX_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "stream control message is too large",
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
    let message: FederatedStreamControlV1 = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid stream control message"),
            )
        }
    };
    if message.version != FEDERATION_STREAM_CONTROL_VERSION
        || message.origin != authenticated.origin()
        || message.destination != federation.server_name()
        || Uuid::parse_str(&message.transaction_id).is_err()
    {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::bad_request("invalid stream control message"),
        );
    }
    let Some(sequence) = i64::try_from(message.sequence)
        .ok()
        .filter(|sequence| *sequence > 0)
    else {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::bad_request("invalid stream control sequence"),
        );
    };
    // Refused before the stream is touched: its sequence stays.
    let handled = match handling(message.control) {
        Ok(handled) => handled,
        Err(error) => return signed_app_error(federation, &authenticated, error),
    };
    match apply(
        &state.pool,
        kind_of(message.stream),
        &message.origin,
        sequence,
        &message.transaction_id,
        handled,
    )
    .await?
    {
        Applied::Accepted(answer) => {
            signed_json(federation, &authenticated, StatusCode::OK, &answer)
        }
        Applied::Gap { expected } => signed_json(
            federation,
            &authenticated,
            StatusCode::CONFLICT,
            &FederationDeliveryError::SequenceGap {
                expected_sequence: expected,
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_withdrawal_is_known() {
        assert_eq!(
            handling(STREAM_CONTROL_WITHDRAWN).unwrap(),
            Handling::Withdrawn
        );
    }

    #[test]
    fn an_unknown_skip_safe_code_is_used_up() {
        for code in [2, 0x1234, 0x7fff] {
            assert_eq!(handling(code).unwrap(), Handling::Skipped(code));
        }
    }

    #[test]
    fn an_unknown_must_understand_code_is_refused() {
        for code in [0x8000, 0xabcd, 0xffff] {
            let error = handling(code).unwrap_err();
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert_eq!(
                error.details.unwrap()["code"],
                serde_json::json!("unknownStreamControl")
            );
        }
    }

    #[test]
    fn code_zero_is_invalid() {
        let error = handling(0).unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        // The status's default code (`invalid`), not unknownStreamControl.
        assert!(error.details.is_none());
    }

    async fn live_pool() -> Option<PgPool> {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return None;
        };
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .unwrap(),
        )
    }

    async fn last_sequence(pool: &PgPool, origin: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT last_sequence FROM federation_inbound_state
             WHERE kind = 'chat' AND origin = $1",
        )
        .bind(origin)
        .fetch_optional(pool)
        .await
        .unwrap()
        .unwrap_or(0)
    }

    /// A known code and an unknown skip-safe one each use a sequence up and
    /// answer a repeat the same; a must-understand one (refused before the
    /// stream is touched) and code 0 leave it; the next one still goes.
    #[tokio::test]
    async fn live_control_codes_use_sequences_up_or_leave_them() {
        let Some(pool) = live_pool().await else {
            return;
        };
        let origin = format!("control-{}.test", Uuid::new_v4().simple());
        let use_up = |sequence: i64, control: u16| {
            let pool = pool.clone();
            let origin = origin.clone();
            async move {
                let transaction = Uuid::new_v4().to_string();
                let handled = handling(control).unwrap();
                let applied = apply(&pool, Kind::Chat, &origin, sequence, &transaction, handled)
                    .await
                    .unwrap();
                (transaction, handled, applied)
            }
        };

        // Known: used up, recorded as a withdrawal; a repeat answers the same.
        let (withdrawn, handled, applied) = use_up(1, STREAM_CONTROL_WITHDRAWN).await;
        let accepted = |sequence: u64| {
            Applied::Accepted(FederationStreamControlResponseV1 {
                accepted_sequence: sequence,
            })
        };
        assert_eq!(applied, accepted(1));
        assert_eq!(last_sequence(&pool, &origin).await, 1);
        assert_eq!(
            apply(&pool, Kind::Chat, &origin, 1, &withdrawn, handled)
                .await
                .unwrap(),
            accepted(1)
        );
        let mut tx = pool.begin().await.unwrap();
        let record = federation_outbox::prior(&mut tx, Kind::Chat, &origin, 1)
            .await
            .unwrap()
            .unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(record.answer["withdrawn"], serde_json::json!(true));

        // Unknown, skip-safe: used up all the same.
        let (_, _, applied) = use_up(2, 0x0042).await;
        assert_eq!(applied, accepted(2));
        assert_eq!(last_sequence(&pool, &origin).await, 2);

        // Unknown, must understand, and code 0: refused, the sequence left.
        assert!(handling(0x8001).is_err());
        assert!(handling(0).is_err());
        assert_eq!(last_sequence(&pool, &origin).await, 2);

        // Another transaction on a used sequence, or one ahead: a gap.
        let other = Uuid::new_v4().to_string();
        for sequence in [2, 4] {
            assert_eq!(
                apply(&pool, Kind::Chat, &origin, sequence, &other, handled)
                    .await
                    .unwrap(),
                Applied::Gap { expected: 3 }
            );
        }
        let (_, _, applied) = use_up(3, STREAM_CONTROL_WITHDRAWN).await;
        assert_eq!(applied, accepted(3));

        sqlx::query("DELETE FROM federation_inbound WHERE origin = $1")
            .bind(&origin)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM federation_inbound_state WHERE origin = $1")
            .bind(&origin)
            .execute(&pool)
            .await
            .unwrap();
    }
}
