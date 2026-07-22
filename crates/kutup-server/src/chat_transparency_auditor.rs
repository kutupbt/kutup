//! Scheduled cross-view auditing using the same verifier as the standalone
//! auditor. Only signed cryptographic contradictions set the durable block.

use std::time::Duration;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::{
    audit_operator_witness_view, audit_witness_views, ChatTransparencyPolicyV1,
    TransparencyCheckpointResponse, TransparencyForkEvidenceV1, TransparencySignedStatementV1,
    WitnessViewV1,
};
use kutup_federation_proto::FederatedFeaturePolicyTypeV1;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::error::{AppError, AppResult};
use crate::middleware::AdminUser;
use crate::AppState;

const MAX_WITNESS_VIEW_BYTES: usize = 256 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditResult {
    domain: String,
    fork_detected: bool,
    evidence: Option<TransparencyForkEvidenceV1>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecoveryRequest {
    evidence_digest: String,
    reason: String,
}

pub(crate) fn spawn_auditor(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let domains: Result<Vec<String>, sqlx::Error> = sqlx::query_scalar(
                "SELECT DISTINCT domain FROM chat_transparency_witness_views ORDER BY domain",
            )
            .fetch_all(&state.pool)
            .await;
            match domains {
                Ok(domains) => {
                    for domain in domains {
                        match collect_witness_views(&state, &domain).await {
                            Ok(failures) if failures.is_empty() => {
                                if let Err(error) = clear_collection_warning(&state, &domain).await
                                {
                                    tracing::warn!(domain, error = %error.message, "failed to clear witness collection warning");
                                }
                            }
                            Ok(failures) => {
                                for failure in &failures {
                                    tracing::warn!(
                                        domain,
                                        error = failure,
                                        "transparency witness collection failed"
                                    );
                                }
                                if let Err(error) =
                                    record_collection_warning(&state, &domain, &failures).await
                                {
                                    tracing::warn!(domain, error = %error.message, "failed to persist witness collection warning");
                                }
                            }
                            Err(error) => {
                                tracing::warn!(domain, error = %error.message, "cannot load authenticated witness policy");
                            }
                        }
                        if let Err(error) = audit_domain(&state, &domain).await {
                            crate::telemetry::fork_event("audit_failed");
                            tracing::warn!(domain, error = %error.message, "transparency cross-view audit failed");
                        }
                    }
                }
                Err(error) => tracing::warn!(%error, "failed to enumerate witness views"),
            }
        }
    });
}

pub(crate) async fn submit_witness_view(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(domain): Path<String>,
    Json(view): Json<WitnessViewV1>,
) -> AppResult<Response> {
    kutup_federation_proto::validate_server_name(&domain)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let policy = load_policy(&state, &domain).await?;
    validate_view(&view, &policy).map_err(AppError::bad_request)?;
    store_witness_view(&state, &domain, &view).await?;
    let evidence = match audit_domain(&state, &domain).await {
        Ok(evidence) => evidence,
        Err(error) => {
            crate::telemetry::fork_event("audit_failed");
            return Err(error);
        }
    };
    Ok(Json(AuditResult {
        domain,
        fork_detected: evidence.is_some(),
        evidence,
    })
    .into_response())
}

async fn store_witness_view(state: &AppState, domain: &str, view: &WitnessViewV1) -> AppResult<()> {
    let encoded =
        serde_json::to_vec(&view).map_err(|error| AppError::internal(error.to_string()))?;
    let view_hash = hex::encode(Sha256::digest(&encoded));
    let first = view
        .statements
        .first()
        .expect("verified view is non-empty")
        .checkpoint
        .tree_size;
    let last = view
        .statements
        .last()
        .expect("verified view is non-empty")
        .checkpoint
        .tree_size;
    sqlx::query(
        "INSERT INTO chat_transparency_witness_views
         (domain, witness_id, key_id, first_tree_size, last_tree_size, view_hash, signed_view)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (domain, witness_id, view_hash) DO NOTHING",
    )
    .bind(&domain)
    .bind(&view.witness_id)
    .bind(&view.key_id)
    .bind(i64::try_from(first).map_err(|_| AppError::bad_request("tree size is too large"))?)
    .bind(i64::try_from(last).map_err(|_| AppError::bad_request("tree size is too large"))?)
    .bind(view_hash)
    .bind(serde_json::to_value(&view).map_err(|error| AppError::internal(error.to_string()))?)
    .execute(&state.pool)
    .await?;
    Ok(())
}

async fn load_policy(state: &AppState, domain: &str) -> AppResult<ChatTransparencyPolicyV1> {
    let federation = state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let envelope = federation
        .feature_policies()
        .get(domain, FederatedFeaturePolicyTypeV1::ChatTransparency, None)
        .await?
        .ok_or_else(|| AppError::not_found("transparency policy is not pinned"))?;
    ChatTransparencyPolicyV1::from_canonical_bytes(
        &envelope
            .payload_bytes()
            .map_err(|error| AppError::internal(error.to_string()))?,
    )
    .map_err(AppError::internal)
}

fn validate_view(view: &WitnessViewV1, policy: &ChatTransparencyPolicyV1) -> Result<(), String> {
    view.verify()?;
    let authorized = policy.witnesses.iter().any(|witness| {
        witness.witness_id == view.witness_id
            && witness.key_id == view.key_id
            && witness.public_key == view.public_key
    });
    if !authorized
        || view
            .statements
            .iter()
            .any(|statement| statement.checkpoint.log_id != policy.log_id)
    {
        return Err("witness view is outside the authenticated transparency policy".into());
    }
    Ok(())
}

async fn collect_witness_views(state: &AppState, domain: &str) -> AppResult<Vec<String>> {
    let federation = state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::not_found("chat federation is not configured"))?;
    let policy = load_policy(state, domain).await?;
    let mut failures = Vec::new();
    for witness in &policy.witnesses {
        let result = async {
            let bytes = federation
                .fetch_signed_public_object(&witness.public_endpoint, MAX_WITNESS_VIEW_BYTES)
                .await
                .map_err(|error| error.to_string())?;
            let view: WitnessViewV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            validate_view(&view, &policy)?;
            if view.witness_id != witness.witness_id {
                return Err("witness endpoint returned a different witness identity".into());
            }
            store_witness_view(state, domain, &view)
                .await
                .map_err(|error| error.message)?;
            Ok::<(), String>(())
        }
        .await;
        if let Err(error) = result {
            failures.push(format!("{}: {error}", witness.witness_id));
        }
    }
    Ok(failures)
}

async fn record_collection_warning(
    state: &AppState,
    domain: &str,
    failures: &[String],
) -> AppResult<()> {
    crate::telemetry::witness_event("collection_unavailable", failures.len() as u64);
    let now = OffsetDateTime::now_utc();
    let mut tx = state.pool.begin().await?;
    let changed: Option<bool> = sqlx::query_scalar(
        "UPDATE chat_transparency_monitor_cursors SET
         warning = true,
         failure_class = CASE WHEN blocked THEN failure_class ELSE 'audit_unavailable' END,
         updated_at = $2
         WHERE domain = $1 AND (warning = false OR failure_class IS DISTINCT FROM 'audit_unavailable')
         RETURNING true",
    )
    .bind(domain)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    if changed.is_some() {
        crate::federation::insert_system_audit(
            &mut tx,
            "chat.transparency.witness_collection_warning",
            json!({
                "domain": domain,
                "failedWitnesses": failures.len(),
                "evidenceDigest": hex::encode(Sha256::digest(failures.join("\n").as_bytes())),
            }),
            now,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn clear_collection_warning(state: &AppState, domain: &str) -> AppResult<()> {
    sqlx::query(
        "UPDATE chat_transparency_monitor_cursors SET warning = false,
         failure_class = NULL, updated_at = now()
         WHERE domain = $1 AND blocked = false AND failure_class = 'audit_unavailable'",
    )
    .bind(domain)
    .execute(&state.pool)
    .await?;
    Ok(())
}

pub(crate) async fn list_evidence(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(domain): Path<String>,
) -> AppResult<Response> {
    kutup_federation_proto::validate_server_name(&domain)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let values: Vec<(
        String,
        serde_json::Value,
        OffsetDateTime,
        Option<OffsetDateTime>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT evidence_digest, evidence, detected_at, acknowledged_at, recovery_reason
         FROM chat_transparency_fork_evidence
         WHERE domain = $1 ORDER BY detected_at, evidence_digest",
    )
    .bind(domain)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        values
            .into_iter()
            .map(
                |(digest, evidence, detected_at, acknowledged_at, recovery_reason)| {
                    json!({
                        "evidenceDigest": digest,
                        "evidence": evidence,
                        "detectedAt": detected_at,
                        "acknowledgedAt": acknowledged_at,
                        "recoveryReason": recovery_reason,
                    })
                },
            )
            .collect::<Vec<_>>(),
    )
    .into_response())
}

/// Deliberate administrative recovery. Immutable evidence is retained; the
/// supplied digest prevents acknowledging a different event than the active
/// block. A new successful monitor observation is required first.
pub(crate) async fn recover_domain(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(domain): Path<String>,
    Json(request): Json<RecoveryRequest>,
) -> AppResult<Response> {
    kutup_federation_proto::validate_server_name(&domain)
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    if request.reason.trim().is_empty() || request.reason.len() > 1024 {
        return Err(AppError::bad_request(
            "recovery reason is empty or too long",
        ));
    }
    let before: Option<(bool, Option<String>, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT blocked, evidence_digest, last_successful_at
         FROM chat_transparency_monitor_cursors WHERE domain = $1",
    )
    .bind(&domain)
    .fetch_optional(&state.pool)
    .await?;
    let (blocked, digest, prior_success) =
        before.ok_or_else(|| AppError::not_found("transparency monitor cursor not found"))?;
    if !blocked || digest.as_deref() != Some(request.evidence_digest.as_str()) {
        return Err(AppError::new(
            axum::http::StatusCode::CONFLICT,
            "recovery digest does not match the active transparency block",
        ));
    }
    crate::chat_transparency_monitor::monitor_domain(&state, &domain).await?;
    let after: Option<OffsetDateTime> = sqlx::query_scalar(
        "SELECT last_successful_at FROM chat_transparency_monitor_cursors WHERE domain = $1",
    )
    .bind(&domain)
    .fetch_one(&state.pool)
    .await?;
    if after.is_none() || after == prior_success {
        return Err(AppError::new(
            axum::http::StatusCode::CONFLICT,
            "fresh valid transparency evidence is required before recovery",
        ));
    }
    let now = OffsetDateTime::now_utc();
    let admin_id = uuid::Uuid::parse_str(&admin.user_id)
        .map_err(|_| AppError::unauthorized("unauthorized"))?;
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE chat_transparency_monitor_cursors SET blocked = false, warning = false,
         failure_class = NULL, evidence_digest = NULL, updated_at = $2 WHERE domain = $1",
    )
    .bind(&domain)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE chat_transparency_fork_evidence SET acknowledged_at = $2,
         acknowledged_by = $3, recovery_reason = $4
         WHERE evidence_digest = $1 AND domain = $5",
    )
    .bind(&request.evidence_digest)
    .bind(now)
    .bind(admin_id)
    .bind(request.reason.trim())
    .bind(&domain)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO admin_audit_log
         (admin_user_id, action, target_user_id, payload, occurred_at)
         VALUES ($1, 'chat.transparency.recovery', NULL, $2, $3)",
    )
    .bind(admin_id)
    .bind(json!({
        "domain": domain,
        "evidenceDigest": request.evidence_digest,
        "reason": request.reason,
    }))
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "domain": domain, "recovered": true })).into_response())
}

#[tracing::instrument(name = "chat.transparency.cross_view_audit", skip_all)]
async fn audit_domain(
    state: &AppState,
    domain: &str,
) -> AppResult<Option<TransparencyForkEvidenceV1>> {
    let checkpoint: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT checkpoint FROM chat_transparency_monitor_cursors WHERE domain = $1",
    )
    .bind(domain)
    .fetch_optional(&state.pool)
    .await?
    .flatten();
    let Some(checkpoint) = checkpoint else {
        return Ok(None);
    };
    let checkpoint: TransparencyCheckpointResponse = serde_json::from_value(checkpoint)
        .map_err(|error| AppError::internal(format!("stored checkpoint is invalid: {error}")))?;
    let operator = TransparencySignedStatementV1 {
        checkpoint: checkpoint.checkpoint,
        map_root: checkpoint.map_root,
        authentication: checkpoint.authentication,
    };
    let values: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT signed_view FROM chat_transparency_witness_views WHERE domain = $1
         ORDER BY received_at DESC, witness_id, view_hash LIMIT 256",
    )
    .bind(domain)
    .fetch_all(&state.pool)
    .await?;
    let views: Vec<WitnessViewV1> = values
        .into_iter()
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                AppError::internal(format!("stored witness view is invalid: {error}"))
            })
        })
        .collect::<AppResult<_>>()?;
    let now = OffsetDateTime::now_utc();
    for view in &views {
        let evidence = audit_operator_witness_view(domain, now.unix_timestamp(), &operator, &view)
            .map_err(AppError::internal)?;
        if let Some(evidence) = evidence {
            persist_fork(state, domain, &evidence, now).await?;
            return Ok(Some(evidence));
        }
    }
    for (index, left) in views.iter().enumerate() {
        for right in &views[index + 1..] {
            let evidence = audit_witness_views(domain, now.unix_timestamp(), left, right)
                .map_err(AppError::internal)?;
            if let Some(evidence) = evidence {
                persist_fork(state, domain, &evidence, now).await?;
                return Ok(Some(evidence));
            }
        }
    }
    crate::telemetry::fork_event("consistent");
    Ok(None)
}

async fn persist_fork(
    state: &AppState,
    domain: &str,
    evidence: &TransparencyForkEvidenceV1,
    now: OffsetDateTime,
) -> AppResult<()> {
    let value =
        serde_json::to_value(evidence).map_err(|error| AppError::internal(error.to_string()))?;
    // Detection time is operational metadata. The stable digest is over the
    // canonical domain and the two original signed statements, so a scheduled
    // audit does not mint a new evidence record every minute.
    let digest_input = json!({
        "domain": domain,
        "operatorStatement": evidence.operator_statement,
        "witnessStatement": evidence.witness_statement,
    });
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&digest_input).map_err(|error| AppError::internal(error.to_string()))?,
    ));
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO chat_transparency_fork_evidence
         (evidence_digest, domain, evidence, detected_at)
         VALUES ($1,$2,$3,$4) ON CONFLICT (evidence_digest) DO NOTHING",
    )
    .bind(&digest)
    .bind(domain)
    .bind(&value)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let acknowledged: Option<OffsetDateTime> = sqlx::query_scalar(
        "SELECT acknowledged_at FROM chat_transparency_fork_evidence
         WHERE evidence_digest = $1",
    )
    .bind(&digest)
    .fetch_one(&mut *tx)
    .await?;
    if acknowledged.is_some() {
        tx.commit().await?;
        return Ok(());
    }
    let newly_blocked: Option<bool> = sqlx::query_scalar(
        "UPDATE chat_transparency_monitor_cursors SET blocked = true,
         warning = false, failure_class = 'fork', evidence_digest = $2, updated_at = $3
         WHERE domain = $1 AND (blocked = false OR evidence_digest IS DISTINCT FROM $2)
         RETURNING true",
    )
    .bind(domain)
    .bind(&digest)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    if newly_blocked.is_some() {
        crate::federation::insert_system_audit(
            &mut tx,
            "chat.transparency.fork_detected",
            json!({ "domain": domain, "evidenceDigest": digest }),
            now,
        )
        .await?;
    }
    tx.commit().await?;
    if newly_blocked.is_some() {
        crate::telemetry::fork_event("detected");
        tracing::error!(
            domain,
            evidence_digest = digest,
            "transparency fork detected"
        );
    }
    Ok(())
}
