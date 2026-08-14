//! Authenticated acceptance and rejection of identified MLS invitations.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    AccountAddress, MlsInvitationFeedbackDecisionV1, MlsInvitationFeedbackV1,
    PendingMlsInvitationV1, RespondMlsInvitationResponseV1, RespondMlsInvitationV1,
    MLS_INVITATION_FEEDBACK_VERSION,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::active_policy;
use super::invitation_feedback::persist_invitation_feedback;
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::telemetry;
use crate::AppState;

type InvitationResponseRow = (String, Option<OffsetDateTime>, i64, Option<String>, String);

pub(crate) async fn list_invitations(
    State(state): State<AppState>,
    auth: AuthUser,
) -> AppResult<Response> {
    active_policy(&state).await?;
    let local_domain = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?
        .server_name();
    let user_id = trusted_uuid(&auth.user_id)?;
    expire_invitations(&state, user_id, local_domain).await?;
    let rows: Vec<(Uuid, i64, Vec<u8>, i64, OffsetDateTime)> = sqlx::query_as(
        "SELECT m.conversation_id, m.incarnation, i.mls_group_id,
                m.joined_epoch, m.invitation_expires_at
         FROM chat_mls_local_members m
         JOIN chat_mls_incarnations i
           ON i.conversation_id = m.conversation_id
          AND i.incarnation = m.incarnation
         WHERE m.user_id = $1 AND m.membership_status = 'pending'
           AND m.removed_epoch IS NULL AND m.invitation_expires_at > now()
         ORDER BY m.invitation_expires_at, m.conversation_id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let invitations = rows
        .into_iter()
        .map(
            |(conversation_id, incarnation, mls_group_id, invited_epoch, expires_at)| {
                let invitation = PendingMlsInvitationV1 {
                    conversation_id,
                    incarnation: u64::try_from(incarnation)
                        .map_err(|_| AppError::internal("stored MLS incarnation is invalid"))?,
                    mls_group_id: STANDARD.encode(mls_group_id),
                    invited_epoch: u64::try_from(invited_epoch).map_err(|_| {
                        AppError::internal("stored MLS invitation epoch is invalid")
                    })?,
                    expires_at: expires_at.unix_timestamp(),
                };
                invitation.validate(now).map_err(|error| {
                    AppError::internal(format!("stored MLS invitation is invalid: {error}"))
                })?;
                Ok(invitation)
            },
        )
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(invitations).into_response())
}

pub(crate) async fn respond_invitation(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(request): Json<RespondMlsInvitationV1>,
) -> AppResult<Response> {
    active_policy(&state).await?;
    request.validate().map_err(AppError::bad_request)?;
    let local_domain = state
        .federation
        .as_ref()
        .ok_or_else(|| AppError::not_found("MLS federation unavailable"))?
        .server_name()
        .to_owned();
    let user_id = trusted_uuid(&auth.user_id)?;
    let mut tx = state.pool.begin().await?;
    let row: Option<InvitationResponseRow> = sqlx::query_as(
        "SELECT m.membership_status, m.invitation_expires_at, m.joined_epoch,
                m.invited_by_domain, u.username
         FROM chat_mls_local_members m
         JOIN users u ON u.id = m.user_id
         WHERE m.conversation_id = $1 AND m.incarnation = $2
           AND m.user_id = $3 AND m.removed_epoch IS NULL
         FOR UPDATE",
    )
    .bind(request.conversation_id)
    .bind(request.incarnation as i64)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (status, expires_at, invited_epoch, invited_by_domain, username) =
        row.ok_or_else(|| AppError::not_found("MLS invitation not found"))?;
    let requested_status = if request.accept { "active" } else { "rejected" };
    if status == requested_status {
        tx.commit().await?;
        return Ok(Json(RespondMlsInvitationResponseV1 {
            conversation_id: request.conversation_id,
            incarnation: request.incarnation,
            status,
            idempotent: true,
        })
        .into_response());
    }
    if status != "pending" {
        return Err(AppError::conflict(
            "MLS invitation already has a different terminal decision",
        ));
    }
    if expires_at.is_none_or(|expires_at| expires_at <= OffsetDateTime::now_utc()) {
        let feedback = invitation_feedback(
            request.conversation_id,
            request.incarnation,
            &username,
            &local_domain,
            invited_epoch,
            MlsInvitationFeedbackDecisionV1::Expired,
        )?;
        sqlx::query(
            "UPDATE chat_mls_local_members
             SET membership_status = 'rejected', invitation_expires_at = NULL
             WHERE conversation_id = $1 AND incarnation = $2
               AND user_id = $3 AND removed_epoch IS NULL
               AND membership_status = 'pending'",
        )
        .bind(request.conversation_id)
        .bind(request.incarnation as i64)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        delete_invitation_mailbox(
            &mut tx,
            user_id,
            request.conversation_id,
            request.incarnation,
        )
        .await?;
        insert_invitation_audit(
            &mut tx,
            request.conversation_id,
            request.incarnation,
            "invitation_reject",
            "expired",
        )
        .await?;
        persist_invitation_feedback(
            &mut tx,
            &local_domain,
            invited_by_domain
                .as_deref()
                .ok_or_else(|| AppError::internal("pending MLS invitation has no origin"))?,
            &feedback,
        )
        .await?;
        tx.commit().await?;
        telemetry::mls_control_event("invitation_expire", "rejected");
        return Err(AppError::conflict("MLS invitation has expired"));
    }
    sqlx::query(
        "UPDATE chat_mls_local_members
         SET membership_status = $4, invitation_expires_at = NULL
         WHERE conversation_id = $1 AND incarnation = $2
           AND user_id = $3 AND removed_epoch IS NULL
           AND membership_status = 'pending'",
    )
    .bind(request.conversation_id)
    .bind(request.incarnation as i64)
    .bind(user_id)
    .bind(requested_status)
    .execute(&mut *tx)
    .await?;
    if !request.accept {
        let feedback = invitation_feedback(
            request.conversation_id,
            request.incarnation,
            &username,
            &local_domain,
            invited_epoch,
            MlsInvitationFeedbackDecisionV1::Rejected,
        )?;
        delete_invitation_mailbox(
            &mut tx,
            user_id,
            request.conversation_id,
            request.incarnation,
        )
        .await?;
        persist_invitation_feedback(
            &mut tx,
            &local_domain,
            invited_by_domain
                .as_deref()
                .ok_or_else(|| AppError::internal("pending MLS invitation has no origin"))?,
            &feedback,
        )
        .await?;
    }
    insert_invitation_audit(
        &mut tx,
        request.conversation_id,
        request.incarnation,
        if request.accept {
            "invitation_accept"
        } else {
            "invitation_reject"
        },
        requested_status,
    )
    .await?;
    tx.commit().await?;
    telemetry::mls_control_event(
        "respond_invitation",
        if request.accept {
            "accepted"
        } else {
            "rejected"
        },
    );
    Ok(Json(RespondMlsInvitationResponseV1 {
        conversation_id: request.conversation_id,
        incarnation: request.incarnation,
        status: requested_status.to_owned(),
        idempotent: false,
    })
    .into_response())
}

async fn expire_invitations(state: &AppState, user_id: Uuid, local_domain: &str) -> AppResult<()> {
    let mut tx = state.pool.begin().await?;
    let conversations: Vec<(Uuid, i64, i64, String, String)> = sqlx::query_as(
        "WITH expired AS (
             UPDATE chat_mls_local_members
             SET membership_status = 'rejected', invitation_expires_at = NULL
             WHERE user_id = $1 AND membership_status = 'pending'
               AND removed_epoch IS NULL AND invitation_expires_at <= now()
             RETURNING conversation_id, incarnation, joined_epoch,
                       invited_by_domain, user_id
         )
         SELECT expired.conversation_id, expired.incarnation,
                expired.joined_epoch, expired.invited_by_domain, users.username
         FROM expired
         JOIN users ON users.id = expired.user_id",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    for (conversation_id, incarnation, invited_epoch, invited_by_domain, username) in conversations
    {
        let incarnation = u64::try_from(incarnation)
            .map_err(|_| AppError::internal("stored MLS incarnation is invalid"))?;
        delete_invitation_mailbox(&mut tx, user_id, conversation_id, incarnation).await?;
        insert_invitation_audit(
            &mut tx,
            conversation_id,
            incarnation,
            "invitation_reject",
            "expired",
        )
        .await?;
        let feedback = invitation_feedback(
            conversation_id,
            incarnation,
            &username,
            local_domain,
            invited_epoch,
            MlsInvitationFeedbackDecisionV1::Expired,
        )?;
        persist_invitation_feedback(&mut tx, local_domain, &invited_by_domain, &feedback).await?;
    }
    tx.commit().await?;
    Ok(())
}

fn invitation_feedback(
    conversation_id: Uuid,
    incarnation: u64,
    username: &str,
    local_domain: &str,
    invited_epoch: i64,
    decision: MlsInvitationFeedbackDecisionV1,
) -> AppResult<MlsInvitationFeedbackV1> {
    let member: AccountAddress = format!("{username}@{local_domain}")
        .parse()
        .map_err(|_| AppError::internal("stored MLS invitation account is invalid"))?;
    let feedback = MlsInvitationFeedbackV1 {
        protocol_version: MLS_INVITATION_FEEDBACK_VERSION,
        conversation_id,
        incarnation,
        member,
        invited_epoch: u64::try_from(invited_epoch)
            .map_err(|_| AppError::internal("stored MLS invitation epoch is invalid"))?,
        decision,
        decided_at: OffsetDateTime::now_utc().unix_timestamp(),
    };
    feedback.validate().map_err(|error| {
        AppError::internal(format!(
            "stored MLS invitation feedback is invalid: {error}"
        ))
    })?;
    Ok(feedback)
}

async fn insert_invitation_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    conversation_id: Uuid,
    incarnation: u64,
    event_type: &str,
    decision: &str,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO chat_mls_admin_audit_events
             (event_type, conversation_id, incarnation, details)
         VALUES ($1,$2,$3,jsonb_build_object('userDecision', $4::text))",
    )
    .bind(event_type)
    .bind(conversation_id)
    .bind(
        i64::try_from(incarnation)
            .map_err(|_| AppError::bad_request("MLS incarnation is out of range"))?,
    )
    .bind(decision)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn delete_invitation_mailbox(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    conversation_id: Uuid,
    incarnation: u64,
) -> AppResult<()> {
    sqlx::query(
        "DELETE FROM chat_mls_mailbox
         WHERE recipient_user_id = $1 AND conversation_id = $2
           AND incarnation = $3
           AND delivery_kind = 'membership_control'",
    )
    .bind(user_id)
    .bind(conversation_id)
    .bind(
        i64::try_from(incarnation)
            .map_err(|_| AppError::bad_request("MLS incarnation is out of range"))?,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}
