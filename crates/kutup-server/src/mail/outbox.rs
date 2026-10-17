//! Undo send (docs/plans/mail-parity.md, P4), as Proton's DelaySendSeconds:
//! `POST /api/mail/send` checks a send, then [`hold`]s it; [`spawn`]'s loop
//! sends it when the delay is up through the same `deliver`, unless it was
//! taken back ([`cancel`]). A send that was going out when the server
//! stopped is not sent again: it fails, and its draft stays.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::AppState;

const TICK: Duration = Duration::from_secs(1);

/// A held send, as `POST /api/mail/send` answers 202.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeldSend {
    pub outbox_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub deliver_at: OffsetDateTime,
}

fn object_key(user_id: Uuid, id: Uuid) -> String {
    format!("mail-outbox/{user_id}/{id}")
}

/// When a held send goes.
#[derive(Debug, Clone, Copy)]
pub enum Until {
    /// Undo send: this many seconds from now; the draft stays in Drafts.
    Delay(i32),
    /// Scheduled send: then; the draft waits in Scheduled.
    At(OffsetDateTime),
}

/// Scheduled messages an account may have waiting (Proton's 100).
pub const MAX_SCHEDULED: i64 = 100;

/// Keeps `parts` until they go.
pub async fn hold(
    state: &AppState,
    user_id: Uuid,
    is_admin: bool,
    draft: Uuid,
    parts: &BTreeMap<String, Vec<u8>>,
    until: Until,
) -> AppResult<HeldSend> {
    let (delay, at) = match until {
        Until::Delay(seconds) => (seconds, None),
        Until::At(at) => (0, Some(at)),
    };
    let id = Uuid::new_v4();
    let encoded: BTreeMap<&str, String> = parts
        .iter()
        .map(|(name, bytes)| (name.as_str(), STANDARD.encode(bytes)))
        .collect();
    let bytes = serde_json::to_vec(&encoded).map_err(|_| AppError::internal("outbox encoding"))?;
    let key = object_key(user_id, id);
    let size = bytes.len() as i64;
    let version = state
        .storage
        .put_object_versioned(&key, aws_sdk_s3::primitives::ByteStream::from(bytes), size)
        .await
        .map_err(|_| AppError::internal("storage"))?;
    let deliver_at: Result<OffsetDateTime, sqlx::Error> = sqlx::query_scalar(
        "WITH held AS (
             INSERT INTO mail_outbox (id, user_id, draft_id, is_admin, deliver_at, parts_key,
                                      parts_version, scheduled)
             VALUES ($1, $2, $3, $4, COALESCE($8, now() + make_interval(secs => $5)), $6, $7,
                     $8::timestamptz IS NOT NULL)
             RETURNING deliver_at
         ), moved AS (
             UPDATE mail_messages SET folder = 'scheduled', folder_changed_at = now()
              WHERE id = $3 AND user_id = $2 AND folder = 'drafts' AND $8::timestamptz IS NOT NULL
         )
         SELECT deliver_at FROM held",
    )
    .bind(id)
    .bind(user_id)
    .bind(draft)
    .bind(is_admin)
    .bind(f64::from(delay))
    .bind(&key)
    .bind(&version)
    .bind(at)
    .fetch_one(&state.pool)
    .await;
    match deliver_at {
        Ok(deliver_at) => Ok(HeldSend {
            outbox_id: id.to_string(),
            deliver_at,
        }),
        Err(error) => {
            let _ = state.storage.delete_stored(&key, &version).await;
            if error
                .as_database_error()
                .is_some_and(|e| e.is_unique_violation())
            {
                return Err(AppError::conflict("this draft is already being sent"));
            }
            Err(error.into())
        }
    }
}

/// Takes a held send back: `true` when it had not gone yet.
pub async fn cancel(state: &AppState, user_id: Uuid, id: Uuid) -> AppResult<bool> {
    let row: Option<(String, String)> = sqlx::query_as(
        "WITH taken AS (
             UPDATE mail_outbox SET state = 'cancelled', finished_at = now()
              WHERE id = $1 AND user_id = $2 AND state = 'pending'
              RETURNING draft_id, parts_key, parts_version
         ), back AS (
             UPDATE mail_messages SET folder = 'drafts', folder_changed_at = now()
              WHERE id IN (SELECT draft_id FROM taken) AND folder = 'scheduled'
         )
         SELECT parts_key, parts_version FROM taken",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((key, version)) = row else {
        return Ok(false);
    };
    if let Err(error) = state.storage.delete_stored(&key, &version).await {
        tracing::warn!(error = %error, "mail: a taken-back send's parts left for the sweep");
    }
    Ok(true)
}

/// Starts the loop that sends what is due. A send left `sending` by a
/// server that stopped fails rather than going twice.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        if let Err(error) = sqlx::query(
            "WITH failed AS (
                 UPDATE mail_outbox SET state = 'failed', finished_at = now(),
                        result = '{\"error\": \"interrupted\"}'
                  WHERE state = 'sending'
                  RETURNING draft_id
             )
             UPDATE mail_messages SET folder = 'drafts', folder_changed_at = now()
              WHERE id IN (SELECT draft_id FROM failed) AND folder = 'scheduled'",
        )
        .execute(&state.pool)
        .await
        {
            tracing::warn!(error = %error, "mail: interrupted sends not marked");
        }
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            if let Err(error) = send_due(&state).await {
                tracing::warn!(error = %error, "mail: outbox pass failed");
            }
        }
    });
}

async fn send_due(state: &AppState) -> anyhow::Result<()> {
    loop {
        let due: Option<(Uuid, Uuid, bool, String, String)> = sqlx::query_as(
            "UPDATE mail_outbox SET state = 'sending'
              WHERE id = (SELECT id FROM mail_outbox
                           WHERE state = 'pending' AND deliver_at <= now()
                           ORDER BY deliver_at LIMIT 1 FOR UPDATE SKIP LOCKED)
              RETURNING id, user_id, is_admin, parts_key, parts_version",
        )
        .fetch_optional(&state.pool)
        .await?;
        let Some((id, user_id, is_admin, key, version)) = due else {
            return Ok(());
        };
        let outcome = send_one(state, user_id, is_admin, &key, &version).await;
        let (final_state, result) = match outcome {
            Ok(result) => ("sent", json!({ "recipients": result.recipients })),
            Err(error) => {
                tracing::info!(error = %error, "mail: a held send failed");
                ("failed", error)
            }
        };
        // A send that failed leaves its draft in Drafts, scheduled or not.
        sqlx::query(
            "WITH done AS (
                 UPDATE mail_outbox SET state = $2, result = $3, finished_at = now() WHERE id = $1
                 RETURNING draft_id
             )
             UPDATE mail_messages SET folder = 'drafts', folder_changed_at = now()
              WHERE $2 = 'failed' AND id IN (SELECT draft_id FROM done) AND folder = 'scheduled'",
        )
        .bind(id)
        .bind(final_state)
        .bind(result)
        .execute(&state.pool)
        .await?;
        if let Err(error) = state.storage.delete_stored(&key, &version).await {
            tracing::warn!(error = %error, "mail: a sent message's held parts left for the sweep");
        }
    }
}

/// Sends one held message; a failure as the send's error body would be
/// (`status`, `error`, and its `code` and details).
async fn send_one(
    state: &AppState,
    user_id: Uuid,
    is_admin: bool,
    key: &str,
    version: &str,
) -> Result<crate::handlers::mail_send::SendResult, serde_json::Value> {
    let internal = |what: &str| json!({ "status": 500, "error": what });
    let (stream, _) = state
        .storage
        .get_stored(key, version)
        .await
        .map_err(|_| internal("storage"))?;
    let bytes = stream
        .collect()
        .await
        .map_err(|_| internal("storage"))?
        .into_bytes();
    let encoded: BTreeMap<String, String> =
        serde_json::from_slice(&bytes).map_err(|_| internal("outbox encoding"))?;
    let parts = encoded
        .into_iter()
        .map(|(name, value)| STANDARD.decode(value).map(|bytes| (name, bytes)))
        .collect::<Result<BTreeMap<String, Vec<u8>>, _>>()
        .map_err(|_| internal("outbox encoding"))?;
    match crate::handlers::mail_send::deliver(state, user_id, is_admin, &parts, false).await {
        Ok(Some(result)) => Ok(result),
        Ok(None) => Err(internal("not delivered")),
        Err(error) => {
            let mut body = error.details.clone().unwrap_or_default();
            body.insert("status".into(), json!(error.status.as_u16()));
            body.insert("error".into(), json!(error.message));
            Err(serde_json::Value::Object(body))
        }
    }
}
