//! Authenticated local access to the immutable public MLS control history.
//!
//! The server is a bounded cache, not a trust oracle. Clients receive the
//! original quorum-certified requests and independently replay them.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::{
    CommitMlsControlBlockV1, MlsClientControlHistoryPageV1, MlsConversationGenesisV1,
    MLS_PROTOCOL_VERSION,
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::active_policy;
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

const DEFAULT_PAGE_SIZE: u16 = 64;
const MAX_PAGE_SIZE: u16 = 64;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ControlHistoryQuery {
    after_height: Option<String>,
    limit: Option<u16>,
}

pub(crate) async fn get_control_history(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, incarnation)): Path<(Uuid, u64)>,
    Query(query): Query<ControlHistoryQuery>,
) -> AppResult<Response> {
    active_policy(&state).await?;
    if conversation_id.is_nil() || incarnation == 0 || incarnation > i64::MAX as u64 {
        return Err(AppError::bad_request(
            "MLS control-history identifiers are invalid",
        ));
    }
    let after_height = parse_height(query.after_height.as_deref())?;
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(AppError::bad_request(
            "MLS control-history limit is outside 1-64",
        ));
    }
    let user_id = trusted_uuid(&auth.user_id)?;
    let membership: Option<(String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT membership_status, joined_epoch, removed_epoch
         FROM chat_mls_local_members
         WHERE conversation_id = $1 AND incarnation = $2 AND user_id = $3
         ORDER BY joined_epoch DESC
         LIMIT 1",
    )
    .bind(conversation_id)
    .bind(incarnation as i64)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let (membership_status, joined_epoch, removed_epoch) =
        membership.ok_or_else(|| AppError::not_found("MLS conversation not found"))?;
    let maximum_epoch = match membership_status.as_str() {
        "pending" => Some(joined_epoch),
        "active" => removed_epoch,
        _ => {
            return Err(AppError::forbidden(
                "MLS control history is unavailable for this membership state",
            ))
        }
    };

    let incarnation_row: Option<(Value, Value)> = sqlx::query_as(
        "SELECT genesis, genesis_participant_domains
         FROM chat_mls_incarnations
         WHERE conversation_id = $1 AND incarnation = $2",
    )
    .bind(conversation_id)
    .bind(incarnation as i64)
    .fetch_optional(&state.pool)
    .await?;
    let (genesis_value, domains_value) =
        incarnation_row.ok_or_else(|| AppError::not_found("MLS conversation not found"))?;
    let genesis: MlsConversationGenesisV1 = serde_json::from_value(genesis_value)
        .map_err(|error| AppError::internal(format!("stored MLS genesis is invalid: {error}")))?;
    let genesis_participant_domains: Vec<String> =
        serde_json::from_value(domains_value).map_err(|error| {
            AppError::internal(format!(
                "stored MLS genesis participant domains are invalid: {error}"
            ))
        })?;
    let values: Vec<Value> = sqlx::query_scalar(
        "SELECT commit_request
         FROM chat_mls_control_blocks
         WHERE conversation_id = $1 AND incarnation = $2 AND height > $3
           AND ($4::bigint IS NULL OR epoch_after <= $4)
         ORDER BY height
         LIMIT $5",
    )
    .bind(conversation_id)
    .bind(incarnation as i64)
    .bind(after_height)
    .bind(maximum_epoch)
    .bind(i64::from(limit))
    .fetch_all(&state.pool)
    .await?;
    let commits = values
        .into_iter()
        .map(|value| {
            serde_json::from_value::<CommitMlsControlBlockV1>(value).map_err(|error| {
                AppError::internal(format!("stored MLS control request is invalid: {error}"))
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    let page = MlsClientControlHistoryPageV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        genesis,
        genesis_participant_domains,
        after_height: after_height.to_string(),
        next_height: commits
            .last()
            .map(|request| request.finalized.block.height.to_string()),
        commits,
    };
    page.validate().map_err(|error| {
        AppError::internal(format!(
            "stored MLS client control history is invalid: {error}"
        ))
    })?;
    Ok(Json(page).into_response())
}

fn parse_height(value: Option<&str>) -> AppResult<i64> {
    let Some(value) = value else {
        return Ok(0);
    };
    value
        .parse::<i64>()
        .ok()
        .filter(|height| *height >= 0 && height.to_string() == value)
        .ok_or_else(|| AppError::bad_request("MLS afterHeight is not canonical decimal"))
}

#[cfg(test)]
mod tests {
    use super::parse_height;

    #[test]
    fn control_history_cursor_is_lossless_and_canonical() {
        assert_eq!(parse_height(None).unwrap(), 0);
        assert_eq!(parse_height(Some("0")).unwrap(), 0);
        assert_eq!(parse_height(Some("9223372036854775807")).unwrap(), i64::MAX);
        for invalid in ["", "-1", "+1", "01", " 1", "9223372036854775808"] {
            assert!(parse_height(Some(invalid)).is_err(), "{invalid}");
        }
    }
}
