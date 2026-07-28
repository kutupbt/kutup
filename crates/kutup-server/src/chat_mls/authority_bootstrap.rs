//! Staged history transfer for newly added MLS ordering authorities.
//!
//! A server does not vote merely because it appears in a proposed next set.
//! It first imports the exact genesis and complete finalized control history,
//! verifies every old quorum/owner certificate, and verifies that the current
//! authority quorum authorized the pending transition.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use kutup_chat_proto::{
    mls_authority_history_digest, verify_mls_authority_bootstrap_history, CommitMlsControlBlockV1,
    CreateMlsConversationRequestV1, FederatedMlsAuthorityBootstrapPageV1,
    FederatedMlsOrderingVoteRequestV1, MlsAuthorityBootstrapDescriptorV1, MlsAuthoritySetV1,
    MLS_PROTOCOL_VERSION,
};
use kutup_federation_proto::FederationFeature;
use reqwest::Method;
use serde_json::Value;
use uuid::Uuid;

use super::{
    active_policy, authenticated_remote_policy, signed_federation_error, signed_federation_json,
    MlsRepository,
};
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::telemetry;
use crate::AppState;

const MAX_PAGE_COMMIT_JSON_BYTES: usize = 4 * 1024 * 1024;

impl MlsRepository {
    async fn authority_bootstrap_pages(
        &self,
        request: &FederatedMlsOrderingVoteRequestV1,
    ) -> AppResult<(MlsAuthoritySetV1, Vec<FederatedMlsAuthorityBootstrapPageV1>)> {
        request.validate().map_err(AppError::bad_request)?;
        let previous_certificate = request
            .previous_set_certificate
            .as_ref()
            .ok_or_else(|| AppError::bad_request("authority bootstrap requires old-set quorum"))?;
        let block = &request.block;
        let row: Option<(Value, Value, Value)> = sqlx::query_as(
            "SELECT i.genesis, i.genesis_participant_domains, i.participant_domains
             FROM chat_mls_conversations c
             JOIN chat_mls_incarnations i
               ON i.conversation_id = c.conversation_id
              AND i.incarnation = c.current_incarnation
             WHERE c.conversation_id = $1 AND i.incarnation = $2
               AND c.status IN ('active', 'closed')
               AND i.status IN ('active', 'closed')",
        )
        .bind(block.conversation_id)
        .bind(block.incarnation as i64)
        .fetch_optional(&self.pool)
        .await?;
        let (genesis_value, genesis_participant_value, participant_value) =
            row.ok_or_else(|| AppError::not_found("MLS conversation not found"))?;
        let genesis = serde_json::from_value(genesis_value)
            .map_err(|error| AppError::internal(format!("stored MLS genesis invalid: {error}")))?;
        let participant_domains = serde_json::from_value(participant_value).map_err(|error| {
            AppError::internal(format!("stored MLS participant domains invalid: {error}"))
        })?;
        let genesis_participant_domains = serde_json::from_value(genesis_participant_value)
            .map_err(|error| {
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
        .fetch_all(&self.pool)
        .await?;
        let history: Vec<CommitMlsControlBlockV1> = history_values
            .into_iter()
            .map(|value| {
                serde_json::from_value(value).map_err(|error| {
                    AppError::internal(format!("stored MLS control request invalid: {error}"))
                })
            })
            .collect::<AppResult<_>>()?;
        let descriptor = MlsAuthorityBootstrapDescriptorV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            genesis,
            genesis_participant_domains,
            participant_domains,
            transition_block: block.clone(),
            previous_set_certificate: previous_certificate.clone(),
            authority_change: request
                .authority_change
                .clone()
                .expect("validated next-set vote carries authority change"),
            history_block_count: history.len() as u64,
            history_digest: mls_authority_history_digest(&history).map_err(AppError::internal)?,
        };
        let current_authorities = verify_mls_authority_bootstrap_history(&descriptor, &history)
            .map_err(AppError::bad_request)?;
        if request.authority_set == current_authorities {
            return Err(AppError::bad_request(
                "MLS authority bootstrap does not add a new authority set",
            ));
        }
        let bootstrap_id = descriptor.bootstrap_id().map_err(AppError::internal)?;

        let chunks = bounded_history_chunks(&history)?;
        let page_count = u32::try_from(chunks.len())
            .map_err(|_| AppError::internal("MLS authority bootstrap has too many pages"))?;
        let mut pages = Vec::with_capacity(chunks.len());
        let mut previous_page_hash = None;
        let mut start_height = 1u64;
        for (page_index, commits) in chunks.into_iter().enumerate() {
            let page = FederatedMlsAuthorityBootstrapPageV1 {
                descriptor: descriptor.clone(),
                bootstrap_id: bootstrap_id.clone(),
                page_index: page_index as u32,
                page_count,
                start_height,
                previous_page_hash: previous_page_hash.clone(),
                commits,
            };
            page.validate().map_err(AppError::internal)?;
            previous_page_hash = Some(page.page_hash().map_err(AppError::internal)?);
            start_height = start_height
                .checked_add(page.commits.len() as u64)
                .ok_or_else(|| AppError::internal("MLS bootstrap height overflow"))?;
            pages.push(page);
        }
        Ok((current_authorities, pages))
    }
}

pub(super) fn bounded_history_chunks(
    history: &[CommitMlsControlBlockV1],
) -> AppResult<Vec<Vec<CommitMlsControlBlockV1>>> {
    if history.is_empty() {
        return Ok(vec![Vec::new()]);
    }
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_bytes = 0usize;
    for request in history {
        let bytes = serde_json::to_vec(request)
            .map_err(|error| AppError::internal(format!("serialize MLS history: {error}")))?
            .len();
        if bytes > MAX_PAGE_COMMIT_JSON_BYTES {
            return Err(AppError::internal(
                "one MLS control request exceeds the bootstrap page budget",
            ));
        }
        if !current.is_empty()
            && (current.len() == 64
                || current_bytes.saturating_add(bytes) > MAX_PAGE_COMMIT_JSON_BYTES)
        {
            chunks.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current.push(request.clone());
        current_bytes = current_bytes.saturating_add(bytes);
    }
    chunks.push(current);
    Ok(chunks)
}

pub(super) async fn bootstrap_new_authorities(
    state: &AppState,
    request: &FederatedMlsOrderingVoteRequestV1,
) -> AppResult<()> {
    if request.previous_set_certificate.is_none() {
        return Ok(());
    }
    let (current, pages) = MlsRepository::new(state.pool.clone())
        .authority_bootstrap_pages(request)
        .await?;
    for authority in request
        .authority_set
        .authorities
        .iter()
        .filter(|authority| current.authority(&authority.domain).is_none())
    {
        if let Err(error) = send_bootstrap_pages(state, &authority.domain, &pages).await {
            tracing::warn!(
                authority = %authority.domain,
                status = %error.status,
                "new MLS authority bootstrap unavailable"
            );
        }
    }
    Ok(())
}

pub(super) async fn bootstrap_finalized_authority(
    state: &AppState,
    destination: &str,
    request: &CommitMlsControlBlockV1,
) -> AppResult<()> {
    let Some(change) = request.authority_change.as_ref() else {
        return Ok(());
    };
    let next = &change.next_authority_set;
    if next.authority(destination).is_none() {
        return Ok(());
    }
    let transition = request
        .authority_transition
        .as_ref()
        .ok_or_else(|| AppError::internal("stored authority transition certificate is absent"))?;
    let vote_request = FederatedMlsOrderingVoteRequestV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        block: request.finalized.block.clone(),
        authority_change: Some(change.clone()),
        authority_set: next.clone(),
        previous_set_certificate: Some(transition.previous_set_certificate.clone()),
    };
    let (current, pages) = MlsRepository::new(state.pool.clone())
        .authority_bootstrap_pages(&vote_request)
        .await?;
    if current.authority(destination).is_none() {
        send_bootstrap_pages(state, destination, &pages).await?;
    }
    Ok(())
}

async fn send_bootstrap_pages(
    state: &AppState,
    destination: &str,
    pages: &[FederatedMlsAuthorityBootstrapPageV1],
) -> AppResult<()> {
    let federation = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?;
    let expected = pages
        .first()
        .and_then(|page| {
            page.descriptor
                .authority_change
                .next_authority_set
                .authority(destination)
        })
        .ok_or_else(|| AppError::bad_request("bootstrap destination is not a new authority"))?;
    let remote_policy = authenticated_remote_policy(state, destination).await?;
    if remote_policy.control_signing_key_id != expected.key_id
        || remote_policy.control_signing_public_key != expected.public_key
    {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote MLS policy does not match the new authority key",
        ));
    }
    for page in pages {
        let page_hash = page.page_hash().map_err(AppError::internal)?;
        let body = serde_json::to_vec(page)
            .map_err(|error| AppError::internal(format!("serialize MLS bootstrap: {error}")))?;
        let response = federation
            .send(
                destination,
                FederationRequestSpec {
                    feature: FederationFeature::ChatV1,
                    method: Method::POST,
                    path: "/api/fed/chat/mls/control/authority-bootstrap".into(),
                    query: None,
                    content_type: "application/json".into(),
                    body,
                    request_id: Uuid::new_v4().to_string(),
                    extra_headers: Vec::new(),
                    response_limit: 64 * 1024,
                },
            )
            .await
            .map_err(|error| {
                AppError::new(
                    StatusCode::BAD_GATEWAY,
                    format!("remote MLS authority bootstrap failed: {error}"),
                )
            })?;
        if response.status != StatusCode::OK {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                format!(
                    "remote MLS authority bootstrap returned {}",
                    response.status
                ),
            ));
        }
        let acknowledgement: Value = serde_json::from_slice(&response.body).map_err(|_| {
            AppError::new(
                StatusCode::BAD_GATEWAY,
                "remote MLS bootstrap acknowledgement is invalid",
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
                "remote MLS bootstrap acknowledgement does not match",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn federated_stage_authority_bootstrap(
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
            "/api/fed/chat/mls/control/authority-bootstrap",
            None,
            &body,
            FederationFeature::ChatV1,
        )
        .await?;
    if let Err(error) = active_policy(&state).await {
        return signed_federation_error(federation, &authenticated, error);
    }
    let page: FederatedMlsAuthorityBootstrapPageV1 = match serde_json::from_slice(&body) {
        Ok(page) => page,
        Err(_) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request("invalid MLS authority bootstrap page"),
            )
        }
    };
    if let Err(error) = page.validate() {
        return signed_federation_error(federation, &authenticated, AppError::bad_request(error));
    }
    let local_domain = federation.server_name();
    let Some(local_authority) = page
        .descriptor
        .authority_change
        .next_authority_set
        .authority(local_domain)
    else {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::forbidden("this server is not in the next MLS authority set"),
        );
    };
    let Some(ordering) = state.mls_ordering.as_deref() else {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::not_found("MLS ordering unavailable"),
        );
    };
    if authenticated.destination() != local_domain
        || page
            .descriptor
            .participant_domains
            .binary_search_by(|domain| domain.as_str().cmp(authenticated.origin()))
            .is_err()
        || local_authority.key_id != ordering.signer().key_id()
        || local_authority.public_key != ordering.signer().public_key()
    {
        return signed_federation_error(
            federation,
            &authenticated,
            AppError::forbidden("MLS authority bootstrap routing or key is unauthorized"),
        );
    }
    let page_hash = match page.page_hash() {
        Ok(hash) => hash,
        Err(error) => {
            return signed_federation_error(
                federation,
                &authenticated,
                AppError::bad_request(error),
            )
        }
    };
    let outcome =
        stage_page_and_materialize(&state, authenticated.origin(), &page, &page_hash).await;
    match outcome {
        Ok(materialized) => signed_federation_json(
            federation,
            &authenticated,
            StatusCode::OK,
            &serde_json::json!({
                "bootstrapId": page.bootstrap_id,
                "pageIndex": page.page_index,
                "pageHash": page_hash,
                "materialized": materialized,
            }),
        ),
        Err(error) => signed_federation_error(federation, &authenticated, error),
    }
}

async fn stage_page_and_materialize(
    state: &AppState,
    origin: &str,
    page: &FederatedMlsAuthorityBootstrapPageV1,
    page_hash: &str,
) -> AppResult<bool> {
    let page_count = i32::try_from(page.page_count)
        .map_err(|_| AppError::bad_request("MLS bootstrap page count is too large"))?;
    let page_index = i32::try_from(page.page_index)
        .map_err(|_| AppError::bad_request("MLS bootstrap page index is too large"))?;
    let start_height = i64::try_from(page.start_height)
        .map_err(|_| AppError::bad_request("MLS bootstrap start height is too large"))?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 693072))")
        .bind(&page.bootstrap_id)
        .execute(&mut *tx)
        .await?;
    let descriptor_value = serde_json::to_value(&page.descriptor)
        .map_err(|error| AppError::internal(format!("serialize MLS bootstrap: {error}")))?;
    sqlx::query(
        "INSERT INTO chat_mls_authority_bootstraps
             (bootstrap_id, origin_domain, conversation_id, incarnation,
              descriptor, page_count)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT DO NOTHING",
    )
    .bind(&page.bootstrap_id)
    .bind(origin)
    .bind(page.descriptor.genesis.conversation_id)
    .bind(page.descriptor.genesis.incarnation as i64)
    .bind(&descriptor_value)
    .bind(page_count)
    .execute(&mut *tx)
    .await?;
    let header: (String, Value, i32, i32, Option<String>, String) = sqlx::query_as(
        "SELECT origin_domain, descriptor, page_count, next_page,
                last_page_hash, state
         FROM chat_mls_authority_bootstraps
         WHERE bootstrap_id = $1 FOR UPDATE",
    )
    .bind(&page.bootstrap_id)
    .fetch_one(&mut *tx)
    .await?;
    if header.0 != origin
        || header.1 != descriptor_value
        || header.2 != page_count
        || header.5 == "rejected"
    {
        return Err(AppError::conflict(
            "MLS authority bootstrap id is bound to different state",
        ));
    }
    if header.5 == "materialized" {
        tx.commit().await?;
        return Ok(true);
    }
    if page_index < header.3 {
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT page_hash FROM chat_mls_authority_bootstrap_pages
             WHERE bootstrap_id = $1 AND page_index = $2",
        )
        .bind(&page.bootstrap_id)
        .bind(page_index)
        .fetch_optional(&mut *tx)
        .await?;
        if existing.as_deref() != Some(page_hash) {
            return Err(AppError::conflict(
                "MLS authority bootstrap page conflicts with durable history",
            ));
        }
    } else {
        if page_index != header.3 || page.previous_page_hash != header.4 {
            return Err(AppError::conflict(
                "MLS authority bootstrap page is out of order",
            ));
        }
        sqlx::query(
            "INSERT INTO chat_mls_authority_bootstrap_pages
                 (bootstrap_id, page_index, start_height, page_hash, page)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(&page.bootstrap_id)
        .bind(page_index)
        .bind(start_height)
        .bind(page_hash)
        .bind(
            serde_json::to_value(page)
                .map_err(|error| AppError::internal(format!("serialize MLS page: {error}")))?,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE chat_mls_authority_bootstraps
             SET next_page = next_page + 1, last_page_hash = $2, updated_at = now()
             WHERE bootstrap_id = $1",
        )
        .bind(&page.bootstrap_id)
        .bind(page_hash)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    if page.page_index + 1 != page.page_count {
        return Ok(false);
    }
    materialize_complete_bootstrap(state, origin, &page.bootstrap_id).await
}

async fn materialize_complete_bootstrap(
    state: &AppState,
    origin: &str,
    bootstrap_id: &str,
) -> AppResult<bool> {
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT page FROM chat_mls_authority_bootstrap_pages
         WHERE bootstrap_id = $1 ORDER BY page_index",
    )
    .bind(bootstrap_id)
    .fetch_all(&state.pool)
    .await?;
    let pages: Vec<FederatedMlsAuthorityBootstrapPageV1> = rows
        .into_iter()
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                AppError::internal(format!("stored MLS bootstrap page invalid: {error}"))
            })
        })
        .collect::<AppResult<_>>()?;
    let first = pages
        .first()
        .ok_or_else(|| AppError::conflict("MLS authority bootstrap is incomplete"))?;
    if pages.len() != first.page_count as usize {
        return Ok(false);
    }
    let mut expected_previous = None;
    let mut expected_start = 1u64;
    let mut history = Vec::new();
    for (index, page) in pages.iter().enumerate() {
        if let Err(error) = page.validate() {
            reject_bootstrap(state, bootstrap_id, "invalid_page").await?;
            return Err(AppError::bad_request(error));
        }
        if page.bootstrap_id != bootstrap_id
            || page.page_index as usize != index
            || page.previous_page_hash != expected_previous
            || page.start_height != expected_start
            || page.descriptor != first.descriptor
        {
            reject_bootstrap(state, bootstrap_id, "invalid_page_chain").await?;
            return Err(AppError::conflict(
                "MLS authority bootstrap page chain is inconsistent",
            ));
        }
        expected_previous = Some(page.page_hash().map_err(AppError::bad_request)?);
        expected_start = expected_start
            .checked_add(page.commits.len() as u64)
            .ok_or_else(|| AppError::bad_request("MLS bootstrap height overflow"))?;
        history.extend(page.commits.clone());
    }
    if let Err(error) = verify_mls_authority_bootstrap_history(&first.descriptor, &history) {
        reject_bootstrap(state, bootstrap_id, "invalid_history").await?;
        return Err(AppError::bad_request(error));
    }
    sqlx::query(
        "UPDATE chat_mls_authority_bootstraps
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
    let create = CreateMlsConversationRequestV1 {
        genesis: first.descriptor.genesis.clone(),
        members: Vec::new(),
        initial_devices: Vec::new(),
    };
    MlsRepository::new(state.pool.clone())
        .create_conversation(
            None,
            local_domain,
            &create,
            &first.descriptor.genesis_participant_domains,
            active_policy(state).await?.maximum_group_members,
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
                active_policy(state).await?.maximum_group_members,
                true,
            )
            .await?;
    }
    sqlx::query(
        "UPDATE chat_mls_authority_bootstraps
         SET state = 'materialized', updated_at = now()
         WHERE bootstrap_id = $1",
    )
    .bind(bootstrap_id)
    .execute(&state.pool)
    .await?;
    telemetry::mls_bootstrap_event("authority", "materialized", pages.len() as u64);
    Ok(true)
}

async fn reject_bootstrap(
    state: &AppState,
    bootstrap_id: &str,
    failure_class: &str,
) -> AppResult<()> {
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE chat_mls_authority_bootstraps
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
                    'component', 'authority_bootstrap',
                    'bootstrapId', bootstrap_id,
                    'failureClass', $2
                )
         FROM chat_mls_authority_bootstraps
         WHERE bootstrap_id = $1",
    )
    .bind(bootstrap_id)
    .bind(failure_class)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    telemetry::mls_bootstrap_event("authority", "rejected", 0);
    Ok(())
}
