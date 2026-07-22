//! Restart-safe remote transparency policy pinning and scheduled monitoring.

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::{
    verify_checkpoint_against_policy, ChatTransparencyPolicyV1, TransparencyCheckpointResponse,
};
use kutup_federation_proto::FederatedFeaturePolicyTypeV1;
use rand::Rng as _;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::error::{AppError, AppResult};
use crate::federation::RemotePolicySyncError;
use crate::handlers::chat::CheckpointQuery;
use crate::middleware::AuthUser;
use crate::AppState;

const HEALTHY_INTERVAL_SECONDS: i64 = 15 * 60;
const MAX_RETRY_SECONDS: i64 = 15 * 60;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MonitorStatus {
    pub domain: String,
    pub policy_sequence: u64,
    pub log_id: Option<String>,
    pub checkpoint: Option<TransparencyCheckpointResponse>,
    pub last_successful_at: Option<String>,
    pub next_attempt_at: String,
    pub consecutive_failures: u32,
    pub failure_class: Option<String>,
    pub warning: bool,
    pub blocked: bool,
    pub evidence_digest: Option<String>,
}

#[derive(sqlx::FromRow)]
struct MonitorRow {
    domain: String,
    policy_sequence: i64,
    log_id: Option<String>,
    checkpoint: Option<serde_json::Value>,
    last_successful_at: Option<OffsetDateTime>,
    next_attempt_at: OffsetDateTime,
    consecutive_failures: i32,
    failure_class: Option<String>,
    warning: bool,
    blocked: bool,
    evidence_digest: Option<String>,
}

pub(crate) fn spawn_monitor(state: AppState) {
    if state.federation.is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            let domains: Result<Vec<String>, sqlx::Error> = sqlx::query_scalar(
                "SELECT domain FROM chat_transparency_monitor_cursors
                 WHERE next_attempt_at <= now() ORDER BY next_attempt_at LIMIT 32",
            )
            .fetch_all(&state.pool)
            .await;
            match domains {
                Ok(domains) => {
                    for domain in domains {
                        if let Err(error) = monitor_domain(&state, &domain).await {
                            tracing::warn!(domain, error = %error.message, "remote transparency monitor attempt failed");
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to load due transparency monitor cursors")
                }
            }
        }
    });
}

pub(crate) async fn verify_before_remote_use(state: &AppState, domain: &str) -> AppResult<()> {
    let existing = load_status(state, domain).await?;
    let now = OffsetDateTime::now_utc();
    if existing.as_ref().is_some_and(|status| {
        !status.blocked
            && status.last_successful_at.is_some()
            && OffsetDateTime::parse(
                &status.next_attempt_at,
                &time::format_description::well_known::Rfc3339,
            )
            .is_ok_and(|next| next > now)
    }) {
        return Ok(());
    }
    let status = monitor_domain(state, domain).await?;
    if status.blocked {
        return Err(AppError::forbidden(format!(
            "transparency verification blocks new sends to {domain}"
        )));
    }
    if status.last_successful_at.is_none() {
        return Err(AppError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            format!("no valid transparency evidence is pinned for {domain}"),
        ));
    }
    Ok(())
}

#[tracing::instrument(name = "chat.transparency.monitor.verify", skip_all)]
pub(crate) async fn monitor_domain(state: &AppState, domain: &str) -> AppResult<MonitorStatus> {
    kutup_federation_proto::validate_server_name(domain)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let federation = state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::bad_request("chat federation is not configured"))?;
    if domain == federation.server_name() {
        return Err(AppError::bad_request(
            "remote transparency monitor requires a remote domain",
        ));
    }
    let floor = u16::try_from(state.config.chat_remote_transparency_min_quorum)
        .map_err(|_| AppError::internal("remote transparency quorum floor is too large"))?;
    let envelope = match federation
        .feature_policies()
        .sync_remote(
            federation,
            domain,
            FederatedFeaturePolicyTypeV1::ChatTransparency,
            floor,
        )
        .await
    {
        Ok(envelope) => envelope,
        Err(RemotePolicySyncError::Unavailable(error)) => {
            tracing::warn!(
                remote_domain = %domain,
                error = %error,
                "remote transparency policy is unavailable"
            );
            record_failure(state, domain, None, "unavailable", false, &error).await?;
            return load_status(state, domain)
                .await?
                .ok_or_else(|| AppError::internal("monitor cursor was not persisted"));
        }
        Err(RemotePolicySyncError::Invalid(error)) => {
            record_failure(state, domain, None, "policy_chain", true, &error).await?;
            return load_status(state, domain)
                .await?
                .ok_or_else(|| AppError::internal("monitor cursor was not persisted"));
        }
    };
    let policy = ChatTransparencyPolicyV1::from_canonical_bytes(
        &envelope
            .payload_bytes()
            .map_err(|error| AppError::internal(error.to_string()))?,
    )
    .map_err(AppError::internal)?;
    let previous = load_status(state, domain).await?;
    if previous.as_ref().is_some_and(|status| {
        status
            .log_id
            .as_deref()
            .is_some_and(|log_id| log_id != policy.log_id)
    }) {
        record_failure(
            state,
            domain,
            Some((&envelope, &policy)),
            "log_replacement",
            true,
            "authenticated policy attempted to replace the pinned transparency log",
        )
        .await?;
        return load_status(state, domain)
            .await?
            .ok_or_else(|| AppError::internal("monitor cursor was not persisted"));
    }
    let prior_checkpoint = previous
        .as_ref()
        .and_then(|status| status.checkpoint.as_ref())
        .map(|response| &response.checkpoint);
    let from_tree_size = prior_checkpoint.map_or(0, |checkpoint| checkpoint.tree_size);
    let response = match crate::chat_federation::fetch_remote_checkpoint(
        state,
        domain,
        from_tree_size,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            record_failure(
                state,
                domain,
                Some((&envelope, &policy)),
                "unavailable",
                false,
                &error.message,
            )
            .await?;
            return load_status(state, domain)
                .await?
                .ok_or_else(|| AppError::internal("monitor cursor was not persisted"));
        }
    };
    if let Err(error) = verify_checkpoint_against_policy(
        &policy,
        &response,
        prior_checkpoint,
        OffsetDateTime::now_utc().unix_timestamp(),
    ) {
        let warning = error.contains("stale or from the future")
            || error.contains("authenticated policy witnesses");
        let class = if error.contains("stale") {
            "stale"
        } else if warning {
            "witness_unavailable"
        } else {
            "cryptographic_failure"
        };
        record_failure(
            state,
            domain,
            Some((&envelope, &policy)),
            class,
            !warning,
            &format!("{error}:{}", digest_json(&response)?),
        )
        .await?;
        return load_status(state, domain)
            .await?
            .ok_or_else(|| AppError::internal("monitor cursor was not persisted"));
    }
    record_success(state, domain, &envelope, &policy, &response).await?;
    load_status(state, domain)
        .await?
        .ok_or_else(|| AppError::internal("monitor cursor was not persisted"))
}

pub(crate) async fn get_status(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(domain): Path<String>,
) -> AppResult<Response> {
    let status = load_status(&state, &domain)
        .await?
        .ok_or_else(|| AppError::not_found("remote transparency domain has not been monitored"))?;
    Ok(Json(status).into_response())
}

pub(crate) async fn verify_now(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(domain): Path<String>,
) -> AppResult<Response> {
    Ok(Json(monitor_domain(&state, &domain).await?).into_response())
}

/// Same-origin access to the complete authenticated policy history. The
/// federation layer fetches and pins the remote chain; the browser still
/// verifies every identity document, policy signature, and typed payload.
pub(crate) async fn get_policy_history(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(domain): Path<String>,
) -> AppResult<Response> {
    kutup_federation_proto::validate_server_name(&domain)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let federation = state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let is_local = domain == federation.server_name();
    if !is_local {
        let floor = u16::try_from(state.config.chat_remote_transparency_min_quorum)
            .map_err(|_| AppError::internal("remote transparency quorum floor is too large"))?;
        federation
            .feature_policies()
            .sync_remote(
                federation,
                &domain,
                FederatedFeaturePolicyTypeV1::ChatTransparency,
                floor,
            )
            .await
            .map_err(|error| {
                AppError::new(axum::http::StatusCode::BAD_GATEWAY, error.to_string())
            })?;
    }
    let history = federation
        .feature_policies()
        .history(
            &domain,
            FederatedFeaturePolicyTypeV1::ChatTransparency,
            is_local,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("transparency policy not found"))?;
    Ok(Json(history).into_response())
}

/// Proxy one exact signed checkpoint/consistency response through the unified
/// federation transport. No client-provided URL is ever accepted.
pub(crate) async fn get_remote_checkpoint(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(domain): Path<String>,
    Query(query): Query<CheckpointQuery>,
) -> AppResult<Response> {
    kutup_federation_proto::validate_server_name(&domain)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let federation = state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    if domain == federation.server_name() {
        let mut tx = state.pool.begin().await?;
        let response =
            crate::chat_transparency::prove_checkpoint(&mut tx, query.from_tree_size.unwrap_or(0))
                .await?;
        tx.commit().await?;
        return Ok(Json(response).into_response());
    }
    let response = crate::chat_federation::fetch_remote_checkpoint(
        &state,
        &domain,
        query.from_tree_size.unwrap_or(0),
    )
    .await?;
    Ok(Json(response).into_response())
}

async fn record_success(
    state: &AppState,
    domain: &str,
    envelope: &kutup_federation_proto::FederatedFeaturePolicyEnvelopeV1,
    policy: &ChatTransparencyPolicyV1,
    response: &TransparencyCheckpointResponse,
) -> AppResult<()> {
    let now = OffsetDateTime::now_utc();
    let jitter = rand::thread_rng().gen_range(0..=60);
    sqlx::query(
        "INSERT INTO chat_transparency_monitor_cursors
         (domain, policy_sequence, log_id, checkpoint, last_successful_at,
          next_attempt_at, consecutive_failures, failure_class, warning, blocked,
          evidence_digest, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,0,NULL,false,false,NULL,$5)
         ON CONFLICT (domain) DO UPDATE SET
          policy_sequence = EXCLUDED.policy_sequence, log_id = EXCLUDED.log_id,
          checkpoint = EXCLUDED.checkpoint, last_successful_at = EXCLUDED.last_successful_at,
          next_attempt_at = EXCLUDED.next_attempt_at, consecutive_failures = 0,
          failure_class = CASE WHEN chat_transparency_monitor_cursors.blocked
                               THEN chat_transparency_monitor_cursors.failure_class ELSE NULL END,
          warning = false,
          blocked = chat_transparency_monitor_cursors.blocked,
          evidence_digest = CASE WHEN chat_transparency_monitor_cursors.blocked
                                 THEN chat_transparency_monitor_cursors.evidence_digest ELSE NULL END,
          updated_at = EXCLUDED.updated_at",
    )
    .bind(domain)
    .bind(envelope.sequence as i64)
    .bind(&policy.log_id)
    .bind(serde_json::to_value(response).map_err(|error| AppError::internal(error.to_string()))?)
    .bind(now)
    .bind(now + time::Duration::seconds(HEALTHY_INTERVAL_SECONDS + jitter))
    .execute(&state.pool)
    .await?;
    let checkpoint_age = now
        .unix_timestamp()
        .saturating_sub(response.authentication.issued_at);
    crate::telemetry::monitor_event("verified", u64::try_from(checkpoint_age).ok());
    Ok(())
}

async fn record_failure(
    state: &AppState,
    domain: &str,
    policy: Option<(
        &kutup_federation_proto::FederatedFeaturePolicyEnvelopeV1,
        &ChatTransparencyPolicyV1,
    )>,
    class: &str,
    blocked: bool,
    evidence: &str,
) -> AppResult<()> {
    let prior = load_status(state, domain).await?;
    let failures = prior
        .as_ref()
        .map_or(1, |status| status.consecutive_failures.saturating_add(1));
    let exponent = failures.min(5);
    let retry = (30i64.saturating_mul(1i64 << exponent)).min(MAX_RETRY_SECONDS);
    let jitter = rand::thread_rng().gen_range(0..=30);
    let now = OffsetDateTime::now_utc();
    let evidence_digest = hex::encode(Sha256::digest(evidence.as_bytes()));
    let policy_sequence = policy
        .map(|(envelope, _)| envelope.sequence)
        .or_else(|| prior.as_ref().map(|status| status.policy_sequence))
        .unwrap_or(0);
    let log_id = policy
        .map(|(_, policy)| policy.log_id.clone())
        .or_else(|| prior.as_ref().and_then(|status| status.log_id.clone()));
    sqlx::query(
        "INSERT INTO chat_transparency_monitor_cursors
         (domain, policy_sequence, log_id, next_attempt_at, consecutive_failures,
          failure_class, warning, blocked, evidence_digest, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8,$9)
         ON CONFLICT (domain) DO UPDATE SET
          policy_sequence = GREATEST(chat_transparency_monitor_cursors.policy_sequence, EXCLUDED.policy_sequence),
          log_id = COALESCE(chat_transparency_monitor_cursors.log_id, EXCLUDED.log_id),
          next_attempt_at = EXCLUDED.next_attempt_at,
          consecutive_failures = EXCLUDED.consecutive_failures,
          failure_class = CASE WHEN chat_transparency_monitor_cursors.blocked
                               THEN chat_transparency_monitor_cursors.failure_class
                               ELSE EXCLUDED.failure_class END,
          warning = true,
          blocked = chat_transparency_monitor_cursors.blocked OR EXCLUDED.blocked,
          evidence_digest = CASE WHEN chat_transparency_monitor_cursors.blocked
                                 THEN chat_transparency_monitor_cursors.evidence_digest
                                 ELSE EXCLUDED.evidence_digest END,
          updated_at = EXCLUDED.updated_at",
    )
    .bind(domain)
    .bind(policy_sequence as i64)
    .bind(log_id)
    .bind(now + time::Duration::seconds(retry + jitter))
    .bind(failures as i32)
    .bind(class)
    .bind(blocked)
    .bind(&evidence_digest)
    .bind(now)
    .execute(&state.pool)
    .await?;
    crate::telemetry::monitor_event(
        if blocked {
            "blocked"
        } else {
            match class {
                "unavailable" => "unavailable",
                "stale" => "stale",
                "witness_unavailable" => "witness_unavailable",
                "audit_unavailable" => "audit_unavailable",
                _ => "warning",
            }
        },
        None,
    );
    if blocked {
        let mut tx = state.pool.begin().await?;
        crate::federation::insert_system_audit(
            &mut tx,
            "chat.transparency.quarantine",
            serde_json::json!({
                "actorType": "system",
                "domain": domain,
                "failureClass": class,
                "evidenceDigest": evidence_digest,
            }),
            now,
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

async fn load_status(state: &AppState, domain: &str) -> AppResult<Option<MonitorStatus>> {
    let row: Option<MonitorRow> = sqlx::query_as(
        "SELECT domain, policy_sequence, log_id, checkpoint, last_successful_at,
                next_attempt_at, consecutive_failures, failure_class, warning,
                blocked, evidence_digest
         FROM chat_transparency_monitor_cursors WHERE domain = $1",
    )
    .bind(domain)
    .fetch_optional(&state.pool)
    .await?;
    row.map(|row| {
        Ok(MonitorStatus {
            domain: row.domain,
            policy_sequence: u64::try_from(row.policy_sequence)
                .map_err(|_| AppError::internal("negative policy sequence"))?,
            log_id: row.log_id.map(|value| value.trim_end().to_owned()),
            checkpoint: row
                .checkpoint
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    AppError::internal(format!("stored checkpoint is invalid: {error}"))
                })?,
            last_successful_at: row
                .last_successful_at
                .map(|value| value.format(&time::format_description::well_known::Rfc3339))
                .transpose()
                .map_err(|error| AppError::internal(error.to_string()))?,
            next_attempt_at: row
                .next_attempt_at
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| AppError::internal(error.to_string()))?,
            consecutive_failures: u32::try_from(row.consecutive_failures)
                .map_err(|_| AppError::internal("negative monitor failure count"))?,
            failure_class: row.failure_class,
            warning: row.warning,
            blocked: row.blocked,
            evidence_digest: row.evidence_digest.map(|value| value.trim_end().to_owned()),
        })
    })
    .transpose()
}

fn digest_json(value: &impl Serialize) -> AppResult<String> {
    let bytes = serde_json::to_vec(value).map_err(|error| AppError::internal(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
