//! Administrative MLS health and cryptographic-state inspection.
//!
//! These views intentionally omit usernames, ciphertext, capabilities, sender
//! certificates, mailbox contents, and sender/recipient correlations.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kutup_chat_proto::MlsOrderingServicePolicyV1;
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::active_policy;
use crate::error::{AppError, AppResult};
use crate::middleware::AdminUser;
use crate::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminMlsStatusV1 {
    enabled: bool,
    advertised: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<MlsOrderingServicePolicyV1>,
    conversations: MlsConversationCountsV1,
    pending_control_deliveries: u64,
    pending_anonymous_deliveries: u64,
    receiving_authority_bootstraps: u64,
    rejected_authority_bootstraps: u64,
    receiving_participant_bootstraps: u64,
    rejected_participant_bootstraps: u64,
    pending_invitations: u64,
    unacknowledged_consensus_evidence: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MlsConversationCountsV1 {
    total: u64,
    pending: u64,
    active: u64,
    blocked: u64,
    closed: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminMlsConversationV1 {
    conversation_id: Uuid,
    kind: u16,
    status: String,
    incarnation: u64,
    incarnation_status: String,
    suite: u16,
    roster_commitment: String,
    member_count: u32,
    genesis_participant_domains: Value,
    participant_domains: Value,
    authority_set_sequence: u64,
    authority_set: Value,
    owner_set_sequence: Option<u64>,
    owner_set: Option<Value>,
    genesis_hash: String,
    last_finalized_height: u64,
    last_finalized_epoch: u64,
    last_block_hash: Option<String>,
    local_members: MlsLocalMemberCountsV1,
    pending_control_deliveries: u64,
    consensus_evidence: Vec<AdminMlsEvidenceV1>,
    audit_events: Vec<AdminMlsAuditEventV1>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MlsLocalMemberCountsV1 {
    active: u64,
    pending: u64,
    rejected: u64,
    removed: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminMlsEvidenceV1 {
    evidence_digest: String,
    failure_class: String,
    detected_at: i64,
    acknowledged_at: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminMlsAuditEventV1 {
    event_type: String,
    incarnation: Option<u64>,
    evidence_digest: Option<String>,
    details: Value,
    occurred_at: i64,
}

#[derive(sqlx::FromRow)]
struct MlsConversationRow {
    kind: i16,
    conversation_status: String,
    incarnation: i64,
    incarnation_status: String,
    suite: i16,
    roster_commitment: String,
    member_count: i32,
    genesis_participant_domains: Value,
    participant_domains: Value,
    authority_set_sequence: i64,
    authority_set: Value,
    owner_set_sequence: Option<i64>,
    owner_set: Option<Value>,
    genesis_hash: String,
    last_finalized_height: i64,
    last_finalized_epoch: i64,
    last_block_hash: Option<String>,
}

pub(crate) async fn status(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Response> {
    let policy = if state.mls_ordering.is_some() {
        Some(active_policy(&state).await?)
    } else {
        None
    };
    let conversation_counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*),
                COUNT(*) FILTER (WHERE status = 'pending'),
                COUNT(*) FILTER (WHERE status = 'active'),
                COUNT(*) FILTER (WHERE status = 'blocked'),
                COUNT(*) FILTER (WHERE status = 'closed')
         FROM chat_mls_conversations",
    )
    .fetch_one(&state.pool)
    .await?;
    let operational_counts: (i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM chat_mls_control_outbox WHERE state = 'pending'),
            (SELECT COUNT(*) FROM chat_mls_federation_outbox WHERE state = 'pending'),
            (SELECT COUNT(*) FROM chat_mls_authority_bootstraps WHERE state = 'receiving'),
            (SELECT COUNT(*) FROM chat_mls_authority_bootstraps WHERE state = 'rejected'),
            (SELECT COUNT(*) FROM chat_mls_participant_bootstraps WHERE state = 'receiving'),
            (SELECT COUNT(*) FROM chat_mls_participant_bootstraps WHERE state = 'rejected'),
            (SELECT COUNT(*) FROM chat_mls_local_members
             WHERE membership_status = 'pending' AND removed_epoch IS NULL),
            (SELECT COUNT(*) FROM chat_mls_consensus_evidence
             WHERE acknowledged_at IS NULL)",
    )
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(AdminMlsStatusV1 {
        enabled: policy.is_some(),
        // This milestone keeps the browser capability absent until browser and
        // two-server E2E gates pass.
        advertised: false,
        policy,
        conversations: MlsConversationCountsV1 {
            total: checked_count(conversation_counts.0)?,
            pending: checked_count(conversation_counts.1)?,
            active: checked_count(conversation_counts.2)?,
            blocked: checked_count(conversation_counts.3)?,
            closed: checked_count(conversation_counts.4)?,
        },
        pending_control_deliveries: checked_count(operational_counts.0)?,
        pending_anonymous_deliveries: checked_count(operational_counts.1)?,
        receiving_authority_bootstraps: checked_count(operational_counts.2)?,
        rejected_authority_bootstraps: checked_count(operational_counts.3)?,
        receiving_participant_bootstraps: checked_count(operational_counts.4)?,
        rejected_participant_bootstraps: checked_count(operational_counts.5)?,
        pending_invitations: checked_count(operational_counts.6)?,
        unacknowledged_consensus_evidence: checked_count(operational_counts.7)?,
    })
    .into_response())
}

pub(crate) async fn conversation(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(conversation_id): Path<Uuid>,
) -> AppResult<Response> {
    let row: Option<MlsConversationRow> = sqlx::query_as(
        "SELECT c.kind, c.status AS conversation_status,
                i.incarnation, i.status AS incarnation_status, i.suite,
                i.roster_commitment, i.member_count,
                i.genesis_participant_domains, i.participant_domains,
                i.authority_set_sequence, i.authority_set,
                i.owner_set_sequence, i.owner_set, i.genesis_hash,
                i.last_finalized_height, i.last_finalized_epoch,
                i.last_block_hash
         FROM chat_mls_conversations c
         JOIN chat_mls_incarnations i
           ON i.conversation_id = c.conversation_id
          AND i.incarnation = c.current_incarnation
         WHERE c.conversation_id = $1",
    )
    .bind(conversation_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some(row) = row else {
        return Err(AppError::not_found("MLS conversation not found"));
    };
    let member_counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
            COUNT(*) FILTER (
                WHERE membership_status = 'active' AND removed_epoch IS NULL
            ),
            COUNT(*) FILTER (
                WHERE membership_status = 'pending' AND removed_epoch IS NULL
            ),
            COUNT(*) FILTER (
                WHERE membership_status = 'rejected' AND removed_epoch IS NULL
            ),
            COUNT(*) FILTER (WHERE removed_epoch IS NOT NULL)
         FROM chat_mls_local_members
         WHERE conversation_id = $1 AND incarnation = $2",
    )
    .bind(conversation_id)
    .bind(row.incarnation)
    .fetch_one(&state.pool)
    .await?;
    let pending_control: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat_mls_control_outbox
         WHERE conversation_id = $1 AND incarnation = $2 AND state = 'pending'",
    )
    .bind(conversation_id)
    .bind(row.incarnation)
    .fetch_one(&state.pool)
    .await?;
    let evidence_rows: Vec<(String, String, OffsetDateTime, Option<OffsetDateTime>)> =
        sqlx::query_as(
            "SELECT evidence_digest, failure_class, detected_at, acknowledged_at
             FROM chat_mls_consensus_evidence
             WHERE conversation_id = $1 AND incarnation = $2
             ORDER BY detected_at DESC, evidence_digest
             LIMIT 100",
        )
        .bind(conversation_id)
        .bind(row.incarnation)
        .fetch_all(&state.pool)
        .await?;
    let audit_rows: Vec<(String, Option<i64>, Option<String>, Value, OffsetDateTime)> =
        sqlx::query_as(
            "SELECT event_type, incarnation, evidence_digest, details, occurred_at
             FROM chat_mls_admin_audit_events
             WHERE conversation_id = $1
             ORDER BY occurred_at DESC, id
             LIMIT 100",
        )
        .bind(conversation_id)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(AdminMlsConversationV1 {
        conversation_id,
        kind: checked_u16(row.kind, "conversation kind")?,
        status: row.conversation_status,
        incarnation: checked_u64(row.incarnation, "incarnation")?,
        incarnation_status: row.incarnation_status,
        suite: checked_u16(row.suite, "suite")?,
        roster_commitment: row.roster_commitment,
        member_count: u32::try_from(row.member_count)
            .map_err(|_| AppError::internal("stored MLS member count is invalid"))?,
        genesis_participant_domains: row.genesis_participant_domains,
        participant_domains: row.participant_domains,
        authority_set_sequence: checked_u64(row.authority_set_sequence, "authority set sequence")?,
        authority_set: row.authority_set,
        owner_set_sequence: row
            .owner_set_sequence
            .map(|value| checked_u64(value, "owner set sequence"))
            .transpose()?,
        owner_set: row.owner_set,
        genesis_hash: row.genesis_hash,
        last_finalized_height: checked_u64(row.last_finalized_height, "finalized height")?,
        last_finalized_epoch: checked_u64(row.last_finalized_epoch, "finalized epoch")?,
        last_block_hash: row.last_block_hash,
        local_members: MlsLocalMemberCountsV1 {
            active: checked_count(member_counts.0)?,
            pending: checked_count(member_counts.1)?,
            rejected: checked_count(member_counts.2)?,
            removed: checked_count(member_counts.3)?,
        },
        pending_control_deliveries: checked_count(pending_control)?,
        consensus_evidence: evidence_rows
            .into_iter()
            .map(
                |(evidence_digest, failure_class, detected_at, acknowledged_at)| {
                    AdminMlsEvidenceV1 {
                        evidence_digest,
                        failure_class,
                        detected_at: detected_at.unix_timestamp(),
                        acknowledged_at: acknowledged_at.map(|value| value.unix_timestamp()),
                    }
                },
            )
            .collect(),
        audit_events: audit_rows
            .into_iter()
            .map(
                |(event_type, incarnation, evidence_digest, details, occurred_at)| {
                    Ok(AdminMlsAuditEventV1 {
                        event_type,
                        incarnation: incarnation
                            .map(|value| checked_u64(value, "audit incarnation"))
                            .transpose()?,
                        evidence_digest,
                        details,
                        occurred_at: occurred_at.unix_timestamp(),
                    })
                },
            )
            .collect::<AppResult<Vec<_>>>()?,
    })
    .into_response())
}

fn checked_count(value: i64) -> AppResult<u64> {
    checked_u64(value, "row count")
}

fn checked_u64(value: i64, field: &str) -> AppResult<u64> {
    u64::try_from(value).map_err(|_| AppError::internal(format!("stored MLS {field} is invalid")))
}

fn checked_u16(value: i16, field: &str) -> AppResult<u16> {
    u16::try_from(value).map_err(|_| AppError::internal(format!("stored MLS {field} is invalid")))
}
