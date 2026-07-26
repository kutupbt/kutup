//! Restart-safe public-history transfer for a newly added participant server.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use kutup_chat_proto::{
    mls_authority_history_digest, verify_mls_participant_bootstrap_history,
    CommitMlsControlBlockV1, CreateMlsConversationRequestV1, FederatedMlsControlReplicaV1,
    FederatedMlsParticipantBootstrapPageV1, MlsParticipantBootstrapDescriptorV1,
    MLS_PROTOCOL_VERSION,
};
use kutup_federation_proto::FederationFeature;
use reqwest::Method;
use serde_json::Value;
use uuid::Uuid;

use super::authority_bootstrap::bounded_history_chunks;
use super::{
    active_policy, authenticated_remote_policy, signed_federation_error, signed_federation_json,
    MlsRepository,
};
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::telemetry;
use crate::AppState;

pub(super) async fn bootstrap_new_participant(
    state: &AppState,
    destination: &str,
    replica: &FederatedMlsControlReplicaV1,
) -> AppResult<()> {
    replica.validate().map_err(AppError::bad_request)?;
    let Some(transition) = replica.commit.membership_transition.as_ref() else {
        return Ok(());
    };
    if transition
        .previous_participant_domains
        .binary_search_by(|domain| domain.as_str().cmp(destination))
        .is_ok()
        || transition
            .next_participant_domains
            .binary_search_by(|domain| domain.as_str().cmp(destination))
            .is_err()
    {
        return Ok(());
    }
    let delivery = replica.membership_delivery.as_ref().ok_or_else(|| {
        AppError::internal("new MLS participant outbox replica has no private delivery")
    })?;
    let block = &replica.commit.finalized.block;
    let row: Option<(Value, Value)> = sqlx::query_as(
        "SELECT genesis, genesis_participant_domains
         FROM chat_mls_incarnations
         WHERE conversation_id = $1 AND incarnation = $2",
    )
    .bind(block.conversation_id)
    .bind(block.incarnation as i64)
    .fetch_optional(&state.pool)
    .await?;
    let (genesis_value, genesis_domains_value) =
        row.ok_or_else(|| AppError::not_found("MLS conversation not found"))?;
    let genesis = serde_json::from_value(genesis_value)
        .map_err(|error| AppError::internal(format!("stored MLS genesis invalid: {error}")))?;
    let genesis_participant_domains =
        serde_json::from_value(genesis_domains_value).map_err(|error| {
            AppError::internal(format!(
                "stored MLS genesis participant domains invalid: {error}"
            ))
        })?;
    let history_values: Vec<Value> = sqlx::query_scalar(
        "SELECT commit_request
         FROM chat_mls_control_blocks
         WHERE conversation_id = $1 AND incarnation = $2 AND height < $3
         ORDER BY height",
    )
    .bind(block.conversation_id)
    .bind(block.incarnation as i64)
    .bind(block.height as i64)
    .fetch_all(&state.pool)
    .await?;
    let history: Vec<CommitMlsControlBlockV1> = history_values
        .into_iter()
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                AppError::internal(format!("stored MLS control request invalid: {error}"))
            })
        })
        .collect::<AppResult<_>>()?;
    let descriptor = MlsParticipantBootstrapDescriptorV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        genesis,
        genesis_participant_domains,
        destination: destination.to_owned(),
        transition_request: replica.commit.clone(),
        delivery_digest: delivery.delivery_digest().map_err(AppError::internal)?,
        history_block_count: history.len() as u64,
        history_digest: mls_authority_history_digest(&history).map_err(AppError::internal)?,
    };
    verify_mls_participant_bootstrap_history(&descriptor, &history, delivery)
        .map_err(AppError::internal)?;
    let bootstrap_id = descriptor.bootstrap_id().map_err(AppError::internal)?;
    let chunks = bounded_history_chunks(&history)?;
    let page_count = u32::try_from(chunks.len())
        .map_err(|_| AppError::internal("MLS participant bootstrap has too many pages"))?;
    let mut pages = Vec::with_capacity(chunks.len());
    let mut previous_page_hash = None;
    let mut start_height = 1u64;
    for (index, commits) in chunks.into_iter().enumerate() {
        let is_last = index + 1 == page_count as usize;
        let page = FederatedMlsParticipantBootstrapPageV1 {
            descriptor: descriptor.clone(),
            bootstrap_id: bootstrap_id.clone(),
            page_index: index as u32,
            page_count,
            start_height,
            previous_page_hash: previous_page_hash.clone(),
            commits,
            membership_delivery: is_last.then(|| delivery.clone()),
        };
        page.validate().map_err(AppError::internal)?;
        previous_page_hash = Some(page.page_hash().map_err(AppError::internal)?);
        start_height = start_height
            .checked_add(page.commits.len() as u64)
            .ok_or_else(|| AppError::internal("MLS participant bootstrap height overflow"))?;
        pages.push(page);
    }
    send_participant_bootstrap_pages(state, destination, &pages).await
}

async fn send_participant_bootstrap_pages(
    state: &AppState,
    destination: &str,
    pages: &[FederatedMlsParticipantBootstrapPageV1],
) -> AppResult<()> {
    authenticated_remote_policy(state, destination).await?;
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    for page in pages {
        let page_hash = page.page_hash().map_err(AppError::internal)?;
        let body = serde_json::to_vec(page).map_err(|error| {
            AppError::internal(format!("serialize MLS participant bootstrap: {error}"))
        })?;
        let response = federation
            .send(
                destination,
                FederationRequestSpec {
                    feature: FederationFeature::ChatV1,
                    method: Method::POST,
                    path: "/api/fed/chat/mls/control/participant-bootstrap".into(),
                    query: None,
                    content_type: "application/json".into(),
                    body,
                    request_id: Uuid::new_v4().to_string(),
                    extra_headers: Vec::new(),
                    response_limit: 64 * 1024,
                },
            )
            .await
            .map_err(|error| AppError::new(StatusCode::BAD_GATEWAY, error.to_string()))?;
        if response.status != StatusCode::OK {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                format!(
                    "remote MLS participant bootstrap returned {}",
                    response.status
                ),
            ));
        }
        let acknowledgement: Value = serde_json::from_slice(&response.body).map_err(|_| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote MLS participant bootstrap acknowledgement is invalid",
            )
        })?;
        if acknowledgement.get("bootstrapId").and_then(Value::as_str)
            != Some(page.bootstrap_id.as_str())
            || acknowledgement.get("pageIndex").and_then(Value::as_u64)
                != Some(page.page_index as u64)
            || acknowledgement.get("pageHash").and_then(Value::as_str) != Some(page_hash.as_str())
        {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote MLS participant bootstrap acknowledgement does not match",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn federated_stage_participant_bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            "/api/fed/chat/mls/control/participant-bootstrap",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    if let Err(error) = active_policy(&state).await {
        return signed_federation_error(federation, &authenticated, error);
    }
    let page: FederatedMlsParticipantBootstrapPageV1 = match serde_json::from_slice(&body) {
        Ok(page) => page,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid MLS participant bootstrap page"),
            )
        }
    };
    if let Err(error) = page.validate() {
        return signed_federation_error(federation, &authenticated, AppError::bad_request(error));
    }
    let transition = page
        .descriptor
        .transition_request
        .membership_transition
        .as_ref()
        .expect("validated participant bootstrap transition");
    if authenticated.destination() != federation.server_name()
        || page.descriptor.destination != federation.server_name()
        || transition
            .previous_participant_domains
            .binary_search_by(|domain| domain.as_str().cmp(authenticated.origin()))
            .is_err()
    {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::forbidden("MLS participant bootstrap routing is unauthorized"),
        );
    }
    match stage_participant_page(&state, authenticated.origin(), &page).await {
        Ok(page_hash) => signed_federation_json(
            federation,
            &authenticated,
            StatusCode::OK,
            &serde_json::json!({
                "bootstrapId": page.bootstrap_id,
                "pageIndex": page.page_index,
                "pageHash": page_hash,
            }),
        ),
        Err(error) => signed_federation_error(federation, &authenticated, error),
    }
}

async fn stage_participant_page(
    state: &AppState,
    origin: &str,
    page: &FederatedMlsParticipantBootstrapPageV1,
) -> AppResult<String> {
    let page_hash = page.page_hash().map_err(AppError::bad_request)?;
    let descriptor_value = serde_json::to_value(&page.descriptor).map_err(|error| {
        AppError::internal(format!("serialize MLS participant descriptor: {error}"))
    })?;
    let page_value = serde_json::to_value(page).map_err(|error| {
        AppError::internal(format!("serialize MLS participant bootstrap page: {error}"))
    })?;
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO chat_mls_participant_bootstraps
             (bootstrap_id, origin_domain, conversation_id, incarnation,
              descriptor, page_count)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (bootstrap_id) DO NOTHING",
    )
    .bind(&page.bootstrap_id)
    .bind(origin)
    .bind(page.descriptor.genesis.conversation_id)
    .bind(page.descriptor.genesis.incarnation as i64)
    .bind(&descriptor_value)
    .bind(page.page_count as i32)
    .execute(&mut *tx)
    .await?;
    let row: (String, Value, i32, i32, Option<String>, String) = sqlx::query_as(
        "SELECT origin_domain, descriptor, page_count, next_page,
                last_page_hash, state
         FROM chat_mls_participant_bootstraps
         WHERE bootstrap_id = $1
         FOR UPDATE",
    )
    .bind(&page.bootstrap_id)
    .fetch_one(&mut *tx)
    .await?;
    if row.0 != origin || row.1 != descriptor_value || row.2 != page.page_count as i32 {
        return Err(AppError::conflict(
            "MLS participant bootstrap id is bound to different metadata",
        ));
    }
    if row.5 == "rejected" {
        return Err(AppError::conflict(
            "MLS participant bootstrap was durably rejected",
        ));
    }
    if page.page_index < row.3 as u32 {
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT page_hash
             FROM chat_mls_participant_bootstrap_pages
             WHERE bootstrap_id = $1 AND page_index = $2",
        )
        .bind(&page.bootstrap_id)
        .bind(page.page_index as i32)
        .fetch_optional(&mut *tx)
        .await?;
        if existing.as_deref() != Some(page_hash.as_str()) {
            return Err(AppError::conflict(
                "conflicting MLS participant bootstrap page exists",
            ));
        }
        tx.commit().await?;
        return Ok(page_hash);
    }
    if page.page_index != row.3 as u32 || page.previous_page_hash != row.4 {
        return Err(AppError::conflict(
            "MLS participant bootstrap page is out of order",
        ));
    }
    sqlx::query(
        "INSERT INTO chat_mls_participant_bootstrap_pages
             (bootstrap_id, page_index, start_height, page_hash, page)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(&page.bootstrap_id)
    .bind(page.page_index as i32)
    .bind(page.start_height as i64)
    .bind(&page_hash)
    .bind(page_value)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE chat_mls_participant_bootstraps
         SET next_page = next_page + 1, last_page_hash = $2,
             updated_at = now()
         WHERE bootstrap_id = $1",
    )
    .bind(&page.bootstrap_id)
    .bind(&page_hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    materialize_participant_bootstrap(state, origin, &page.bootstrap_id).await?;
    Ok(page_hash)
}

async fn materialize_participant_bootstrap(
    state: &AppState,
    origin: &str,
    bootstrap_id: &str,
) -> AppResult<bool> {
    let state_row: Option<(i32, i32, String)> = sqlx::query_as(
        "SELECT page_count, next_page, state
         FROM chat_mls_participant_bootstraps
         WHERE bootstrap_id = $1",
    )
    .bind(bootstrap_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((page_count, next_page, bootstrap_state)) = state_row else {
        return Err(AppError::not_found("MLS participant bootstrap not found"));
    };
    if bootstrap_state == "materialized" {
        return Ok(true);
    }
    if next_page != page_count {
        return Ok(false);
    }
    let values: Vec<Value> = sqlx::query_scalar(
        "SELECT page
         FROM chat_mls_participant_bootstrap_pages
         WHERE bootstrap_id = $1
         ORDER BY page_index",
    )
    .bind(bootstrap_id)
    .fetch_all(&state.pool)
    .await?;
    let pages: Vec<FederatedMlsParticipantBootstrapPageV1> = values
        .into_iter()
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                AppError::internal(format!(
                    "stored MLS participant bootstrap page invalid: {error}"
                ))
            })
        })
        .collect::<AppResult<_>>()?;
    let first = pages
        .first()
        .ok_or_else(|| AppError::conflict("MLS participant bootstrap is incomplete"))?;
    if pages.len() != first.page_count as usize {
        return Ok(false);
    }
    let mut expected_previous = None;
    let mut expected_start = 1u64;
    let mut history = Vec::new();
    for (index, page) in pages.iter().enumerate() {
        page.validate().map_err(AppError::bad_request)?;
        if page.bootstrap_id != bootstrap_id
            || page.page_index as usize != index
            || page.previous_page_hash != expected_previous
            || page.start_height != expected_start
            || page.descriptor != first.descriptor
        {
            reject_participant_bootstrap(state, bootstrap_id, "invalid_page_chain").await?;
            return Err(AppError::conflict(
                "MLS participant bootstrap page chain is inconsistent",
            ));
        }
        expected_previous = Some(page.page_hash().map_err(AppError::bad_request)?);
        expected_start = expected_start
            .checked_add(page.commits.len() as u64)
            .ok_or_else(|| AppError::bad_request("MLS participant bootstrap height overflow"))?;
        history.extend(page.commits.clone());
    }
    let delivery = pages
        .last()
        .and_then(|page| page.membership_delivery.as_ref())
        .ok_or_else(|| AppError::conflict("MLS participant bootstrap delivery is absent"))?;
    if let Err(error) =
        verify_mls_participant_bootstrap_history(&first.descriptor, &history, delivery)
    {
        reject_participant_bootstrap(state, bootstrap_id, "invalid_history").await?;
        return Err(AppError::bad_request(error));
    }
    sqlx::query(
        "UPDATE chat_mls_participant_bootstraps
         SET state = 'verified', updated_at = now()
         WHERE bootstrap_id = $1 AND state != 'materialized'",
    )
    .bind(bootstrap_id)
    .execute(&state.pool)
    .await?;

    let local_domain = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?
        .server_name();
    let policy = active_policy(state).await?;
    MlsRepository::new(state.pool.clone())
        .create_conversation(
            None,
            local_domain,
            &CreateMlsConversationRequestV1 {
                genesis: first.descriptor.genesis.clone(),
                members: Vec::new(),
            },
            &first.descriptor.genesis_participant_domains,
            policy.maximum_group_members,
        )
        .await?;
    for request in &history {
        MlsRepository::new(state.pool.clone())
            .commit_control_block(
                local_domain,
                None,
                Some(origin),
                request,
                None,
                policy.maximum_group_members,
                true,
            )
            .await?;
    }
    MlsRepository::new(state.pool.clone())
        .commit_control_block(
            local_domain,
            None,
            Some(origin),
            &first.descriptor.transition_request,
            Some(delivery),
            policy.maximum_group_members,
            false,
        )
        .await?;
    sqlx::query(
        "UPDATE chat_mls_participant_bootstraps
         SET state = 'materialized', updated_at = now()
         WHERE bootstrap_id = $1",
    )
    .bind(bootstrap_id)
    .execute(&state.pool)
    .await?;
    telemetry::mls_bootstrap_event("participant", "materialized", pages.len() as u64);
    Ok(true)
}

async fn reject_participant_bootstrap(
    state: &AppState,
    bootstrap_id: &str,
    failure_class: &str,
) -> AppResult<()> {
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE chat_mls_participant_bootstraps
         SET state = 'rejected', failure_class = $2, updated_at = now()
         WHERE bootstrap_id = $1 AND state != 'materialized'",
    )
    .bind(bootstrap_id)
    .bind(failure_class)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO chat_mls_admin_audit_events
             (event_type, conversation_id, incarnation, details)
         SELECT 'cryptographic_failure', conversation_id, incarnation,
                jsonb_build_object(
                    'component', 'participant_bootstrap',
                    'bootstrapId', bootstrap_id,
                    'failureClass', $2
                )
         FROM chat_mls_participant_bootstraps
         WHERE bootstrap_id = $1",
    )
    .bind(bootstrap_id)
    .bind(failure_class)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    telemetry::mls_bootstrap_event("participant", "rejected", 0);
    Ok(())
}
