//! Authenticated acceptance and rejection of identified MLS invitations.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    PendingMlsInvitationV1, RespondMlsInvitationResponseV1, RespondMlsInvitationV1,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::active_policy;
use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::telemetry;
use crate::AppState;

pub(crate) async fn list_invitations(
    State(state): State<AppState>,
    auth: AuthUser,
) -> AppResult<Response> {
    active_policy(&state).await?;
    let user_id = trusted_uuid(&auth.user_id)?;
    expire_invitations(&state, user_id).await?;
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
    let user_id = trusted_uuid(&auth.user_id)?;
    let mut tx = state.pool.begin().await?;
    let row: Option<(String, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT membership_status, invitation_expires_at
         FROM chat_mls_local_members
         WHERE conversation_id = $1 AND incarnation = $2
           AND user_id = $3 AND removed_epoch IS NULL
         FOR UPDATE",
    )
    .bind(request.conversation_id)
    .bind(request.incarnation as i64)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (status, expires_at) =
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
        delete_invitation_mailbox(
            &mut tx,
            user_id,
            request.conversation_id,
            request.incarnation,
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

async fn expire_invitations(state: &AppState, user_id: Uuid) -> AppResult<()> {
    let mut tx = state.pool.begin().await?;
    let conversations: Vec<(Uuid, i64)> = sqlx::query_as(
        "UPDATE chat_mls_local_members
         SET membership_status = 'rejected', invitation_expires_at = NULL
         WHERE user_id = $1 AND membership_status = 'pending'
           AND removed_epoch IS NULL AND invitation_expires_at <= now()
         RETURNING conversation_id, incarnation",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    for (conversation_id, incarnation) in conversations {
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
    }
    tx.commit().await?;
    Ok(())
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
