//! Calendar sharing (docs/plans/calendar-e3.md, E3b): members and
//! invitations, key generations and the rotation that removes a member,
//! links as their owner manages them, tombstones, and busy times.
//!
//! Only the owner shares. The server never holds a passphrase: each
//! generation's is shared on account keys (`CalendarShareEnvelopeV1`), and
//! every envelope the owner hands over is checked against its binding
//! (calendar, generation, owner, member, incarnations) and the owner's
//! account signature before it is stored. A pending invitation holds its
//! invitee's share of every live generation in `calendar_member_shares`
//! (keyed by calendar, account and generation, beside the members'; nothing
//! there refers to the member row), so a rotation while it waits gives the
//! invitee the new generation too, and an accept hands over every one.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::calendar::{self as cal, SealedMetadataV1};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::calendar_busy::{BusyBlock, BusyList};
use crate::error::{AppError, AppResult};
use crate::handlers::calendar::{
    b64, coded, crypto, instant, keys_of, limited, member_permissions, owners_of, CalendarKeyView,
    CalendarOwnerView, AVAILABILITY, MAX_SHARE_B64, OWNER, READ, SUPER_OWNER, WRITE,
};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthAccount;
use crate::site_settings::{
    CALENDAR_BUSY_WINDOW_DAYS, CALENDAR_INVITATION_DAYS, CALENDAR_KEY_GENERATIONS,
    CALENDAR_LINKS_PER_CALENDAR, CALENDAR_MEMBERS_PER_CALENDAR, CALENDAR_QUERY_LINKS_ALLOWED,
};
use crate::AppState;

/// Proton's two presets (`ShareCalendarModal`): the only permissions a
/// member is given.
pub const PRESET_EDIT: i32 = WRITE | READ | AVAILABILITY;
pub const PRESET_VIEW: i32 = READ | AVAILABILITY;

fn preset(permissions: i32) -> AppResult<i32> {
    if permissions == PRESET_EDIT || permissions == PRESET_VIEW {
        Ok(permissions)
    } else {
        Err(coded(
            AppError::bad_request("a member is given one of the two presets"),
            "invalidPermissions",
        ))
    }
}

/// Busy-times questions per account (`calendar.rate.busy`).
pub(crate) static BUSY: std::sync::LazyLock<crate::ratelimit::RateLimiter> =
    std::sync::LazyLock::new(|| {
        crate::ratelimit::RateLimiter::registered(crate::ratelimit::Limit::CalendarBusy)
    });

// ----- shared pieces -----

/// What a share's binding names of an account: its ref, its incarnation
/// (hex) and its signing key.
struct Party {
    reference: kutup_crypto::account_ref::AccountRef,
    incarnation: String,
    signing: Vec<u8>,
}

async fn party(
    state: &AppState,
    conn: &mut sqlx::PgConnection,
    account: Uuid,
) -> AppResult<Option<Party>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT encode(account_incarnation_id, 'hex'), COALESCE(kutup_b64(drive_signing_public_key), '')
           FROM accounts WHERE id = $1 AND state = 'active'",
    )
    .bind(account)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((incarnation, signing)) = row else {
        return Ok(None);
    };
    Ok(Some(Party {
        reference: crate::account_ids::local(&state.config.chat_server_name, account)?,
        incarnation,
        signing: STANDARD.decode(signing).unwrap_or_default(),
    }))
}

/// Checks one member's share of generation `generation` (`base64`): from
/// `owner` to `member`, for this calendar, signed by the owner. Answers its
/// bytes as stored.
fn check_share(
    calendar: Uuid,
    generation: i32,
    owner: &Party,
    member: &Party,
    share: &str,
) -> AppResult<Vec<u8>> {
    if share.len() > MAX_SHARE_B64 {
        return Err(AppError::bad_request("a passphrase share is too large"));
    }
    let envelope = cal::CalendarShareEnvelopeV1::decode_b64(share)
        .map_err(|_| AppError::bad_request("a passphrase share does not parse"))?;
    let generation = u32::try_from(generation)
        .map_err(|_| AppError::bad_request("a key generation is positive"))?;
    envelope
        .verify_binding_and_signature(
            &calendar.to_string(),
            generation,
            &owner.reference,
            &owner.incarnation,
            &owner.signing,
            &member.reference,
            &member.incarnation,
        )
        .map_err(|_| {
            coded(
                AppError::bad_request(
                    "a passphrase share is not the owner's, for this member, calendar and generation",
                ),
                "shareNotBound",
            )
        })?;
    envelope.encode().map_err(crypto)
}

/// The calendar locked for a sharing change by its owner: answers the
/// owner, the newest generation and every live one. 404 for a calendar the
/// caller isn't a member of, 403 for a member who isn't its owner.
async fn owned_calendar(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    calendar: Uuid,
) -> AppResult<(i32, Vec<i32>)> {
    let found: Option<(i32, i32)> = sqlx::query_as(
        "SELECT m.permissions, c.key_generation FROM calendars c
           JOIN calendar_members m ON m.calendar_id = c.id AND m.account_id = $2
          WHERE c.id = $1
          FOR UPDATE OF c",
    )
    .bind(calendar)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((permissions, newest)) = found else {
        return Err(AppError::not_found("not found"));
    };
    if permissions & SUPER_OWNER == 0 {
        return Err(AppError::forbidden("only the owner shares a calendar"));
    }
    let generations: Vec<i32> = sqlx::query_scalar(
        "SELECT key_generation FROM calendar_keys WHERE calendar_id = $1 ORDER BY key_generation",
    )
    .bind(calendar)
    .fetch_all(&mut **tx)
    .await?;
    Ok((newest, generations))
}

/// Charges `delta` bytes of a calendar to its owner's pool (a positive one
/// within the quota) and its row: what a calendar's delete gives back.
async fn charge(
    tx: &mut Transaction<'_, Postgres>,
    calendar: Uuid,
    owner: Uuid,
    delta: i64,
) -> AppResult<()> {
    if delta == 0 {
        return Ok(());
    }
    if delta > 0 {
        crate::storage_pool::charge_within_quota(tx, owner, delta).await?;
    } else {
        crate::storage_pool::charge(&mut **tx, crate::storage_pool::Payer::Account(owner), delta)
            .await?;
    }
    sqlx::query("UPDATE calendars SET bytes = GREATEST(bytes + $2, 0) WHERE id = $1")
        .bind(calendar)
        .bind(delta)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn calendar_owner(tx: &mut Transaction<'_, Postgres>, calendar: Uuid) -> AppResult<Uuid> {
    Ok(
        sqlx::query_scalar("SELECT owner_account_id FROM calendars WHERE id = $1")
            .bind(calendar)
            .fetch_one(&mut **tx)
            .await?,
    )
}

/// Drops an account's shares of a calendar, giving their bytes back.
async fn drop_shares(
    tx: &mut Transaction<'_, Postgres>,
    calendar: Uuid,
    account: Uuid,
) -> AppResult<()> {
    let freed: Option<i64> = sqlx::query_scalar(
        "WITH gone AS (DELETE FROM calendar_member_shares
                        WHERE calendar_id = $1 AND account_id = $2 RETURNING share)
         SELECT SUM(octet_length(share))::bigint FROM gone",
    )
    .bind(calendar)
    .bind(account)
    .fetch_one(&mut **tx)
    .await?;
    let owner = calendar_owner(tx, calendar).await?;
    charge(tx, calendar, owner, -freed.unwrap_or(0)).await
}

/// A member leaves a calendar (removed, or by its own choice): its row, its
/// shares, its alarms, reminders and recompute requests go, and it is told
/// once by a tombstone.
async fn remove_member(
    tx: &mut Transaction<'_, Postgres>,
    calendar: Uuid,
    account: Uuid,
    reason: &str,
) -> AppResult<()> {
    sqlx::query("DELETE FROM calendar_members WHERE calendar_id = $1 AND account_id = $2")
        .bind(calendar)
        .bind(account)
        .execute(&mut **tx)
        .await?;
    drop_shares(tx, calendar, account).await?;
    sqlx::query(
        "DELETE FROM calendar_alarms a USING calendar_events e
          WHERE a.event_id = e.id AND e.calendar_id = $1 AND a.account_id = $2",
    )
    .bind(calendar)
    .bind(account)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "DELETE FROM calendar_event_reminders r USING calendar_events e
          WHERE r.event_id = e.id AND e.calendar_id = $1 AND r.account_id = $2",
    )
    .bind(calendar)
    .bind(account)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM calendar_alarm_recomputes WHERE calendar_id = $1 AND account_id = $2")
        .bind(calendar)
        .bind(account)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO calendar_member_tombstones (calendar_id, account_id, reason)
         VALUES ($1, $2, $3)
         ON CONFLICT (calendar_id, account_id)
            DO UPDATE SET reason = EXCLUDED.reason, created_at = now()",
    )
    .bind(calendar)
    .bind(account)
    .bind(reason)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Marks a calendar's key as due for rotation: someone who held its
/// passphrase no longer may (left, or read an invitation that then went).
/// The owner's app rotates it the next time it loads the calendar
/// (docs/plans/calendar-e3.md, "Review fixes", T1).
async fn rotation_due(tx: &mut Transaction<'_, Postgres>, calendar: Uuid) -> AppResult<()> {
    sqlx::query("UPDATE calendars SET rotation_due = true WHERE id = $1")
        .bind(calendar)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn address_of(state: &AppState, username: &str) -> String {
    format!("{username}@{}", state.config.chat_server_name)
}

// ----- key generations -----

#[derive(Debug, Serialize, ToSchema)]
pub struct KeyList {
    pub keys: Vec<CalendarKeyView>,
}

/// `GET /api/v1/calendar/calendars/{id}/keys` — every key generation the
/// caller holds a share of, oldest first.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/calendars/{id}/keys",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    responses((status = 200, body = KeyList), (status = 404))
)]
pub async fn keys(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
) -> AppResult<Json<KeyList>> {
    let user_id = trusted_uuid(&user.account_id)?;
    let mut conn = state.pool.acquire().await?;
    member_permissions(&mut conn, user_id, id).await?;
    let keys = keys_of(&mut *conn, user_id, &[id]).await?;
    Ok(Json(KeyList {
        keys: keys.into_iter().map(|(_, key)| key).collect(),
    }))
}

// ----- members and invitations: the owner's side -----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    pub account_id: Uuid,
    /// Their address now.
    pub address: String,
    pub permissions: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub added_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SentInvitationView {
    pub id: Uuid,
    pub account_id: Uuid,
    pub address: String,
    pub permissions: i32,
    /// `pending` or `declined`.
    pub state: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Sharing {
    pub members: Vec<MemberView>,
    pub invitations: Vec<SentInvitationView>,
}

/// `GET /api/v1/calendar/calendars/{id}/members` — the members (not the
/// owner) and the invitations not accepted (expired ones left out), of
/// active accounts only: a suspended or closing account is given no new key
/// (a rotation drops what it held). The owner's only.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/calendars/{id}/members",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    responses((status = 200, body = Sharing), (status = 403), (status = 404))
)]
pub async fn members(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Sharing>> {
    let user_id = trusted_uuid(&user.account_id)?;
    let mut conn = state.pool.acquire().await?;
    if member_permissions(&mut conn, user_id, id).await? & OWNER == 0 {
        return Err(AppError::forbidden(
            "only the owner lists a calendar's members",
        ));
    }
    let members: Vec<(Uuid, String, i32, time::OffsetDateTime)> = sqlx::query_as(
        "SELECT m.account_id, u.username, m.permissions, m.created_at
           FROM calendar_members m JOIN accounts u ON u.id = m.account_id
          WHERE m.calendar_id = $1 AND m.account_id <> $2 AND u.state = 'active'
          ORDER BY m.created_at, m.account_id",
    )
    .bind(id)
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    type Invitation = (
        Uuid,
        Uuid,
        String,
        i32,
        String,
        time::OffsetDateTime,
        time::OffsetDateTime,
    );
    let invitations: Vec<Invitation> = sqlx::query_as(
        "SELECT i.id, i.invitee_account_id, u.username, i.permissions, i.state,
                i.created_at, i.expires_at
           FROM calendar_invitations i JOIN accounts u ON u.id = i.invitee_account_id
          WHERE i.calendar_id = $1 AND (i.state <> 'pending' OR i.expires_at > now())
            AND u.state = 'active'
          ORDER BY i.created_at, i.id",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(Sharing {
        members: members
            .into_iter()
            .map(|(account_id, username, permissions, added_at)| MemberView {
                account_id,
                address: address_of(&state, &username),
                permissions,
                added_at,
            })
            .collect(),
        invitations: invitations
            .into_iter()
            .map(
                |(id, account_id, username, permissions, state_, created_at, expires_at)| {
                    SentInvitationView {
                        id,
                        account_id,
                        address: address_of(&state, &username),
                        permissions,
                        state: state_,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect(),
    }))
}

/// One generation's share of the passphrase.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationShare {
    pub key_generation: i32,
    /// `CalendarShareEnvelopeV1`, base64.
    pub share: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvitationCreate {
    /// The invitee, an account of this server (same server only, plan Q-2).
    pub account_id: Uuid,
    /// The incarnation the owner's pins confirmed (hex): the shares are
    /// sealed to it.
    pub incarnation_id: String,
    pub permissions: i32,
    /// One share for every live key generation.
    pub shares: Vec<GenerationShare>,
}

/// `POST /api/v1/calendar/calendars/{id}/invitations` — the owner invites an
/// account with one of the presets, handing over its share of every live
/// key generation.
#[utoipa::path(
    post,
    path = "/api/v1/calendar/calendars/{id}/invitations",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    request_body = InvitationCreate,
    responses(
        (status = 201, body = SentInvitationView),
        (status = 400, description = "A share or the permissions don't check"),
        (status = 403, description = "Only the owner shares"),
        (status = 409, description = "Already a member or invited, or the member limit"),
    )
)]
pub async fn invite(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
    Json(input): Json<InvitationCreate>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    let permissions = preset(input.permissions)?;
    if input.account_id == user_id {
        return Err(coded(
            AppError::bad_request("a calendar is already its owner's"),
            "selfShare",
        ));
    }
    let mut tx = state.pool.begin().await?;
    let (_, generations) = owned_calendar(&mut tx, user_id, id).await?;
    let owner = party(&state, &mut tx, user_id)
        .await?
        .ok_or_else(|| AppError::conflict("account identity is unavailable"))?;
    let Some(member) = party(&state, &mut tx, input.account_id).await? else {
        return Err(coded(
            AppError::not_found("no such account"),
            "recipientNotFound",
        ));
    };
    if member.incarnation != input.incarnation_id.to_ascii_lowercase() {
        return Err(coded(
            AppError::conflict("the person's identity changed; look them up again"),
            "identityChanged",
        ));
    }
    let already: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM calendar_members WHERE calendar_id = $1 AND account_id = $2)
             OR EXISTS (SELECT 1 FROM calendar_invitations WHERE calendar_id = $1
                           AND invitee_account_id = $2 AND state = 'pending' AND expires_at > now())",
    )
    .bind(id)
    .bind(input.account_id)
    .fetch_one(&mut *tx)
    .await?;
    if already {
        return Err(coded(
            AppError::conflict("this person already has the calendar or an invitation"),
            "alreadyShared",
        ));
    }
    let taken: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM calendar_members WHERE calendar_id = $1 AND account_id <> $2)
              + (SELECT COUNT(*) FROM calendar_invitations
                  WHERE calendar_id = $1 AND state = 'pending' AND expires_at > now())",
    )
    .bind(id)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    let most = CALENDAR_MEMBERS_PER_CALENDAR
        .load_for(&mut *tx, user_id)
        .await?;
    if taken >= most {
        return Err(coded(
            AppError::conflict(format!("a calendar has at most {most} members")),
            "memberLimit",
        ));
    }
    // One share for each live generation, no more, no fewer.
    let mut named: Vec<i32> = input.shares.iter().map(|s| s.key_generation).collect();
    named.sort_unstable();
    if named != generations {
        return Err(coded(
            AppError::bad_request("an invitation holds one share of every key generation"),
            "sharesIncomplete",
        ));
    }
    let shares: Vec<(i32, Vec<u8>)> = input
        .shares
        .iter()
        .map(|s| {
            Ok((
                s.key_generation,
                check_share(id, s.key_generation, &owner, &member, &s.share)?,
            ))
        })
        .collect::<AppResult<_>>()?;
    // A declined or expired invitation, and what it held, makes way.
    sqlx::query(
        "DELETE FROM calendar_invitations WHERE calendar_id = $1 AND invitee_account_id = $2",
    )
    .bind(id)
    .bind(input.account_id)
    .execute(&mut *tx)
    .await?;
    drop_shares(&mut tx, id, input.account_id).await?;
    let days = CALENDAR_INVITATION_DAYS.load(&mut *tx).await?;
    let incarnation = hex::decode(&member.incarnation)
        .map_err(|_| AppError::internal("a stored incarnation is not hex"))?;
    let (invitation, created_at, expires_at): (Uuid, time::OffsetDateTime, time::OffsetDateTime) =
        sqlx::query_as(
            "INSERT INTO calendar_invitations (calendar_id, invitee_account_id, invitee_incarnation_id,
                 invited_by_account_id, permissions, state, expires_at)
             VALUES ($1, $2, $3, $4, $5, 'pending', now() + make_interval(days => $6))
             RETURNING id, created_at, expires_at",
        )
        .bind(id)
        .bind(input.account_id)
        .bind(&incarnation)
        .bind(user_id)
        .bind(permissions)
        .bind(days as i32)
        .fetch_one(&mut *tx)
        .await?;
    let mut bytes = 0i64;
    for (generation, share) in &shares {
        bytes += share.len() as i64;
        sqlx::query(
            "INSERT INTO calendar_member_shares (calendar_id, account_id, key_generation, share)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(input.account_id)
        .bind(generation)
        .bind(share)
        .execute(&mut *tx)
        .await?;
    }
    charge(&mut tx, id, user_id, bytes).await?;
    let username: String = sqlx::query_scalar("SELECT username FROM accounts WHERE id = $1")
        .bind(input.account_id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(SentInvitationView {
            id: invitation,
            account_id: input.account_id,
            address: address_of(&state, &username),
            permissions,
            state: "pending".into(),
            created_at,
            expires_at,
        }),
    )
        .into_response())
}

/// `DELETE /api/v1/calendar/calendars/{id}/invitations/{invitationId}` — the
/// owner takes an invitation back (its shares with it).
#[utoipa::path(
    delete,
    path = "/api/v1/calendar/calendars/{id}/invitations/{invitationId}",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path), ("invitationId" = Uuid, Path)),
    responses((status = 204), (status = 403), (status = 404))
)]
pub async fn revoke(
    State(state): State<AppState>,
    user: AuthAccount,
    Path((id, invitation)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    let mut tx = state.pool.begin().await?;
    owned_calendar(&mut tx, user_id, id).await?;
    let invitee: Option<(Uuid, bool)> = sqlx::query_as(
        "DELETE FROM calendar_invitations WHERE id = $1 AND calendar_id = $2
         RETURNING invitee_account_id, fetched_at IS NOT NULL",
    )
    .bind(invitation)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((invitee, fetched)) = invitee else {
        return Err(AppError::not_found("not found"));
    };
    drop_shares(&mut tx, id, invitee).await?;
    // The invitee read its shares: the key is theirs to know until rotated.
    if fetched {
        rotation_due(&mut tx, id).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberChange {
    pub permissions: i32,
}

/// `PATCH /api/v1/calendar/calendars/{id}/members/{accountId}` — the owner
/// gives a member the other preset; their alarms are worked out again.
#[utoipa::path(
    patch,
    path = "/api/v1/calendar/calendars/{id}/members/{accountId}",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path), ("accountId" = Uuid, Path)),
    request_body = MemberChange,
    responses((status = 204), (status = 400), (status = 403), (status = 404))
)]
pub async fn change_member(
    State(state): State<AppState>,
    user: AuthAccount,
    Path((id, account)): Path<(Uuid, String)>,
    Json(input): Json<MemberChange>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    let account = Uuid::parse_str(&account).map_err(|_| AppError::not_found("not found"))?;
    let permissions = preset(input.permissions)?;
    let mut tx = state.pool.begin().await?;
    owned_calendar(&mut tx, user_id, id).await?;
    if account == user_id {
        return Err(AppError::bad_request(
            "the owner keeps the owner's permissions",
        ));
    }
    let changed = sqlx::query(
        "UPDATE calendar_members SET permissions = $3 WHERE calendar_id = $1 AND account_id = $2",
    )
    .bind(id)
    .bind(account)
    .bind(permissions)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(AppError::not_found("not found"));
    }
    crate::calendar_alarms::queue_recompute(&mut tx, account, Some(id))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/v1/calendar/calendars/{id}/members/me` — a member leaves a
/// calendar someone else owns. (The owner removes a member by rotating the
/// key: `keys/rotate`.)
#[utoipa::path(
    delete,
    path = "/api/v1/calendar/calendars/{id}/members/me",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    responses((status = 204), (status = 400, description = "An owner deletes, never leaves"), (status = 404))
)]
pub async fn leave(
    State(state): State<AppState>,
    user: AuthAccount,
    Path((id, who)): Path<(Uuid, String)>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    if who != "me" {
        return Err(AppError::not_found("not found"));
    }
    let mut tx = state.pool.begin().await?;
    let permissions: Option<i32> = sqlx::query_scalar(
        "SELECT m.permissions FROM calendars c
           JOIN calendar_members m ON m.calendar_id = c.id AND m.account_id = $2
          WHERE c.id = $1 FOR UPDATE OF c",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    match permissions {
        None => return Err(AppError::not_found("not found")),
        Some(permissions) if permissions & SUPER_OWNER != 0 => {
            return Err(AppError::bad_request(
                "an owner deletes a calendar, never leaves it",
            ))
        }
        Some(_) => {}
    }
    remove_member(&mut tx, id, user_id, "left").await?;
    rotation_due(&mut tx, id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- rotation -----

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberShare {
    pub account_id: Uuid,
    pub share: String,
}

/// A full or query link carried to the new generation.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkCarried {
    pub id: Uuid,
    /// The new generation's passphrase sealed under the link's secret.
    pub passphrase: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rotation {
    /// The member removed by this rotation; none for a rotation that is
    /// due (someone left, or an invitation they had read went).
    pub remove_account_id: Option<Uuid>,
    /// The generation this one follows: refused when another came first.
    pub from_key_generation: i32,
    pub key_generation: i32,
    pub public_key: String,
    pub locked_secret_key: String,
    /// The owner's own share of the new passphrase.
    pub own_share: String,
    /// One for every member who stays and every pending invitation.
    pub member_shares: Vec<MemberShare>,
    /// The name and description, sealed to the new key.
    #[schema(value_type = Object)]
    pub metadata: SealedMetadataV1,
    /// Every full and query link, carried over.
    pub links: Vec<LinkCarried>,
    /// Keyed links deleted in the same transaction instead of carried over
    /// (the owner makes them again under fresh secrets once this succeeds).
    #[serde(default)]
    pub remove_links: Vec<Uuid>,
}

/// The largest owner's link-secret envelope taken, in base64 (the column
/// holds 4096 bytes).
const MAX_OWNER_SECRET_B64: usize = 4096 / 3 * 4 + 4;

/// A keyed link's access proof as the wire carries it: base64url, 32 bytes.
pub(crate) fn access_proof(text: &str) -> Option<[u8; 32]> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    if text.len() > 64 {
        return None;
    }
    URL_SAFE_NO_PAD.decode(text.trim()).ok()?.try_into().ok()
}

/// What the server keeps of an access proof: its SHA-256.
pub(crate) fn proof_digest(proof: &[u8; 32]) -> [u8; 32] {
    kutup_crypto::primitives::hash(kutup_crypto::primitives::Suite::V1, proof).into()
}

/// The largest link passphrase envelope taken, in base64 (the column holds
/// 256 bytes).
const MAX_LINK_SEALED_B64: usize = 256 / 3 * 4 + 4;

fn link_sealed(value: &str, what: &str) -> AppResult<Vec<u8>> {
    if value.len() > MAX_LINK_SEALED_B64 {
        return Err(AppError::bad_request(format!("{what} is too large")));
    }
    let bytes = b64(value, what)?;
    if bytes.is_empty() || bytes[0] != kutup_crypto::calendar_link::CALENDAR_LINK_VERSION {
        return Err(AppError::bad_request(format!(
            "{what} is not a link envelope"
        )));
    }
    Ok(bytes)
}

/// `POST /api/v1/calendar/calendars/{id}/keys/rotate` — the owner removes a
/// member (or, with none named, carries out a rotation that is due) and
/// moves the calendar to a new key generation, in one
/// transaction (plan §2, "Decisions"): the new key, everyone else's shares,
/// the name and every keyed link all written before the generation becomes
/// the newest, and the member removed in the same commit. A crash halfway
/// leaves the old generation current.
#[utoipa::path(
    post,
    path = "/api/v1/calendar/calendars/{id}/keys/rotate",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    request_body = Rotation,
    responses(
        (status = 204),
        (status = 400, description = "A key, share, name or link doesn't check"),
        (status = 403, description = "Only the owner rotates"),
        (status = 409, description = "Another generation came first, or the generation limit"),
    )
)]
pub async fn rotate(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
    Json(input): Json<Rotation>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    let public_key = b64(&input.public_key, "public key")?;
    let locked = b64(&input.locked_secret_key, "locked secret key")?;
    let fingerprint = cal::inspect_calendar_public_key(&public_key).map_err(crypto)?;
    cal::inspect_locked_calendar_key(&locked, &public_key).map_err(crypto)?;
    let metadata = input.metadata.to_sealed().map_err(crypto)?;
    if metadata.signature.len() > 4096
        || cal::key_packet_key_id(&metadata.key_packet).map_err(crypto)?
            != cal::encryption_key_id(&public_key).map_err(crypto)?
    {
        return Err(AppError::bad_request(
            "the metadata is not to the new calendar key",
        ));
    }
    let mut tx = state.pool.begin().await?;
    let (newest, generations) = owned_calendar(&mut tx, user_id, id).await?;
    if input.from_key_generation != newest {
        return Err(coded(
            AppError::conflict("another key generation came first; reload the calendar"),
            "keyGenerationBehind",
        ));
    }
    if input.key_generation != newest + 1 {
        return Err(AppError::bad_request(
            "the new generation follows the newest",
        ));
    }
    let most = CALENDAR_KEY_GENERATIONS.load(&mut *tx).await?;
    if generations.len() as i64 >= most {
        return Err(coded(
            AppError::conflict(format!(
                "this calendar has reached {most} key generations, the most a calendar keeps; \
                 nobody can be removed from it until an administrator raises the limit"
            )),
            "keyGenerationLimit",
        ));
    }
    if let Some(removed) = input.remove_account_id {
        if removed == user_id {
            return Err(AppError::bad_request("the owner is never removed"));
        }
        let is_member: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM calendar_members WHERE calendar_id = $1 AND account_id = $2)",
        )
        .bind(id)
        .bind(removed)
        .fetch_one(&mut *tx)
        .await?;
        if !is_member {
            return Err(AppError::not_found("no such member"));
        }
    }
    let leaving: Vec<Uuid> = std::iter::once(user_id)
        .chain(input.remove_account_id)
        .collect();
    // An account that isn't active (suspended, closing) gets nothing new:
    // it is left out, and what it held of the calendar goes. Its pending
    // invitation goes with it.
    let inactive: Vec<Uuid> = sqlx::query_scalar(
        "SELECT m.account_id FROM calendar_members m JOIN accounts u ON u.id = m.account_id
          WHERE m.calendar_id = $1 AND u.state <> 'active' AND m.account_id <> ALL($2)
         UNION
         SELECT i.invitee_account_id FROM calendar_invitations i
           JOIN accounts u ON u.id = i.invitee_account_id
          WHERE i.calendar_id = $1 AND u.state <> 'active'",
    )
    .bind(id)
    .bind(&leaving)
    .fetch_all(&mut *tx)
    .await?;
    // Who stays: every other active member and every pending invitation to
    // an active account.
    let mut staying: Vec<Uuid> = sqlx::query_scalar(
        "SELECT m.account_id FROM calendar_members m JOIN accounts u ON u.id = m.account_id
          WHERE m.calendar_id = $1 AND m.account_id <> ALL($2) AND u.state = 'active'
         UNION
         SELECT i.invitee_account_id FROM calendar_invitations i
           JOIN accounts u ON u.id = i.invitee_account_id
          WHERE i.calendar_id = $1 AND i.state = 'pending' AND i.expires_at > now()
            AND i.invitee_account_id <> ALL($2) AND u.state = 'active'",
    )
    .bind(id)
    .bind(&leaving)
    .fetch_all(&mut *tx)
    .await?;
    staying.sort_unstable();
    let mut named: Vec<Uuid> = input.member_shares.iter().map(|s| s.account_id).collect();
    named.sort_unstable();
    if named != staying {
        return Err(coded(
            AppError::bad_request(
                "a rotation gives a share to every member who stays and every pending invitation",
            ),
            "sharesIncomplete",
        ));
    }
    let owner = party(&state, &mut tx, user_id)
        .await?
        .ok_or_else(|| AppError::conflict("account identity is unavailable"))?;
    let own_share = check_share(id, input.key_generation, &owner, &owner, &input.own_share)?;
    let mut shares = vec![(user_id, own_share)];
    for share in &input.member_shares {
        let member = party(&state, &mut tx, share.account_id)
            .await?
            .ok_or_else(|| AppError::bad_request("a member's account is not active"))?;
        shares.push((
            share.account_id,
            check_share(id, input.key_generation, &owner, &member, &share.share)?,
        ));
    }
    // Every keyed link, carried over: one entry each.
    let keyed: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM calendar_links WHERE calendar_id = $1 AND kind <> 'busy' ORDER BY id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let mut carried: Vec<Uuid> = input
        .links
        .iter()
        .map(|l| l.id)
        .chain(input.remove_links.iter().copied())
        .collect();
    carried.sort_unstable();
    if carried != keyed {
        return Err(coded(
            AppError::bad_request("a rotation carries every keyed link over, or removes it"),
            "linksIncomplete",
        ));
    }
    let links: Vec<(Uuid, Vec<u8>)> = input
        .links
        .iter()
        .map(|link| Ok((link.id, link_sealed(&link.passphrase, "a link passphrase")?)))
        .collect::<AppResult<_>>()?;
    let old_metadata: i64 = sqlx::query_scalar(
        "SELECT (octet_length(metadata_key_packet) + octet_length(metadata_data_packet)
                 + octet_length(metadata_signature))::bigint FROM calendars WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    // The member leaves first: its shares' bytes come back before the new
    // ones are charged.
    if let Some(removed) = input.remove_account_id {
        remove_member(&mut tx, id, removed, "removed").await?;
    }
    // Links replaced: gone in the same commit as the new key.
    for link in &input.remove_links {
        let freed = link_bytes(&mut tx, id, *link).await?.unwrap_or(0);
        sqlx::query("DELETE FROM calendar_links WHERE id = $1 AND calendar_id = $2")
            .bind(link)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        charge(&mut tx, id, user_id, -freed).await?;
    }
    for account in &inactive {
        sqlx::query(
            "DELETE FROM calendar_invitations WHERE calendar_id = $1 AND invitee_account_id = $2",
        )
        .bind(id)
        .bind(account)
        .execute(&mut *tx)
        .await?;
        drop_shares(&mut tx, id, *account).await?;
    }
    sqlx::query(
        "INSERT INTO calendar_keys (calendar_id, key_generation, public_key, fingerprint, locked_secret_key)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(input.key_generation)
    .bind(&public_key)
    .bind(hex::encode(fingerprint))
    .bind(&locked)
    .execute(&mut *tx)
    .await
    .map_err(|error| match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            AppError::conflict("this key is in use")
        }
        _ => error.into(),
    })?;
    let mut bytes = (public_key.len() + locked.len()) as i64;
    for (account, share) in &shares {
        bytes += share.len() as i64;
        sqlx::query(
            "INSERT INTO calendar_member_shares (calendar_id, account_id, key_generation, share)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(account)
        .bind(input.key_generation)
        .bind(share)
        .execute(&mut *tx)
        .await?;
    }
    for (link, passphrase) in &links {
        bytes += passphrase.len() as i64;
        sqlx::query(
            "INSERT INTO calendar_link_passphrases (link_id, calendar_id, key_generation, passphrase)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(link)
        .bind(id)
        .bind(input.key_generation)
        .bind(passphrase)
        .execute(&mut *tx)
        .await?;
    }
    let new_metadata =
        (metadata.key_packet.len() + metadata.data_packet.len() + metadata.signature.len()) as i64;
    bytes += new_metadata - old_metadata;
    // The new generation becomes the newest last, with everything above.
    sqlx::query(
        "UPDATE calendars SET key_generation = $2, metadata_key_packet = $3,
                metadata_data_packet = $4, metadata_signature = $5, rotation_due = false,
                updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(input.key_generation)
    .bind(&metadata.key_packet)
    .bind(&metadata.data_packet)
    .bind(&metadata.signature)
    .execute(&mut *tx)
    .await?;
    charge(&mut tx, id, user_id, bytes).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- invitations: the invitee's side -----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReceivedInvitationView {
    pub id: Uuid,
    pub calendar_id: Uuid,
    pub owner: CalendarOwnerView,
    pub permissions: i32,
    #[schema(value_type = Object)]
    pub metadata: SealedMetadataV1,
    /// The invitee's share of every key generation, oldest first.
    pub keys: Vec<CalendarKeyView>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReceivedInvitations {
    pub invitations: Vec<ReceivedInvitationView>,
}

/// `GET /api/v1/calendar/invitations` — the caller's pending invitations.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/invitations",
    tag = "calendar",
    security(("BearerAuth" = [])),
    responses((status = 200, body = ReceivedInvitations))
)]
pub async fn invitations(
    State(state): State<AppState>,
    user: AuthAccount,
) -> AppResult<Json<ReceivedInvitations>> {
    let user_id = trusted_uuid(&user.account_id)?;
    type Row = (
        Uuid,
        Uuid,
        Uuid,
        i32,
        Vec<u8>,
        Vec<u8>,
        String,
        time::OffsetDateTime,
        time::OffsetDateTime,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT i.id, i.calendar_id, c.owner_account_id, i.permissions,
                c.metadata_key_packet, c.metadata_data_packet, c.metadata_signature,
                i.created_at, i.expires_at
           FROM calendar_invitations i JOIN calendars c ON c.id = i.calendar_id
          WHERE i.invitee_account_id = $1 AND i.state = 'pending' AND i.expires_at > now()
          ORDER BY i.created_at DESC, i.id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    // Read: from now on, the invitee may hold the key (T1).
    let ids: Vec<Uuid> = rows.iter().map(|row| row.0).collect();
    sqlx::query(
        "UPDATE calendar_invitations SET fetched_at = now() WHERE id = ANY($1) AND fetched_at IS NULL",
    )
    .bind(&ids)
    .execute(&state.pool)
    .await?;
    let calendars: Vec<Uuid> = rows.iter().map(|row| row.1).collect();
    let keys = keys_of(&state.pool, user_id, &calendars).await?;
    let owner_ids: Vec<Uuid> = rows.iter().map(|row| row.2).collect();
    let owners = owners_of(&state, &owner_ids).await?;
    let mut out = Vec::new();
    for (
        id,
        calendar,
        owner,
        permissions,
        key_packet,
        data_packet,
        signature,
        created_at,
        expires_at,
    ) in rows
    {
        let Some(owner) = owners.iter().find(|o| o.account_id == owner).cloned() else {
            continue;
        };
        out.push(ReceivedInvitationView {
            id,
            calendar_id: calendar,
            owner,
            permissions,
            metadata: SealedMetadataV1 {
                key_packet: STANDARD.encode(key_packet),
                data_packet: STANDARD.encode(data_packet),
                signature,
            },
            keys: keys
                .iter()
                .filter(|(c, _)| *c == calendar)
                .map(|(_, key)| key.clone())
                .collect(),
            created_at,
            expires_at,
        });
    }
    Ok(Json(ReceivedInvitations { invitations: out }))
}

/// The caller's pending invitation, locked with its calendar.
async fn own_invitation(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    invitation: Uuid,
) -> AppResult<(Uuid, i32)> {
    let calendar: Option<Uuid> = sqlx::query_scalar(
        "SELECT calendar_id FROM calendar_invitations
          WHERE id = $1 AND invitee_account_id = $2 AND state = 'pending' AND expires_at > now()",
    )
    .bind(invitation)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(calendar) = calendar else {
        return Err(AppError::not_found("not found"));
    };
    // The calendar first, as every sharing change locks it.
    sqlx::query("SELECT id FROM calendars WHERE id = $1 FOR UPDATE")
        .bind(calendar)
        .execute(&mut **tx)
        .await?;
    let permissions: Option<i32> = sqlx::query_scalar(
        "SELECT permissions FROM calendar_invitations
          WHERE id = $1 AND state = 'pending' AND expires_at > now() FOR UPDATE",
    )
    .bind(invitation)
    .fetch_optional(&mut **tx)
    .await?;
    let permissions = permissions.ok_or_else(|| AppError::not_found("not found"))?;
    Ok((calendar, permissions))
}

/// `POST /api/v1/calendar/invitations/{id}/accept` — the invitee joins: its
/// shares of every generation become a member's. The client files its
/// `calendarSettings` record first.
#[utoipa::path(
    post,
    path = "/api/v1/calendar/invitations/{id}/accept",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    responses((status = 204), (status = 404), (status = 409, description = "A key generation's share is missing"))
)]
pub async fn accept(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(invitation): Path<Uuid>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    let mut tx = state.pool.begin().await?;
    let (calendar, permissions) = own_invitation(&mut tx, user_id, invitation).await?;
    let missing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM calendar_keys k WHERE k.calendar_id = $1 AND NOT EXISTS (
             SELECT 1 FROM calendar_member_shares s WHERE s.calendar_id = k.calendar_id
                AND s.key_generation = k.key_generation AND s.account_id = $2)",
    )
    .bind(calendar)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if missing > 0 {
        return Err(coded(
            AppError::conflict("the invitation lacks a key generation; ask for a new one"),
            "sharesIncomplete",
        ));
    }
    sqlx::query(
        "INSERT INTO calendar_members (calendar_id, account_id, permissions) VALUES ($1, $2, $3)",
    )
    .bind(calendar)
    .bind(user_id)
    .bind(permissions)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM calendar_invitations WHERE id = $1")
        .bind(invitation)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM calendar_member_tombstones WHERE calendar_id = $1 AND account_id = $2",
    )
    .bind(calendar)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    crate::calendar_alarms::queue_recompute(&mut tx, user_id, Some(calendar))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/calendar/invitations/{id}/decline` — the invitee says no:
/// the owner sees it declined, and its shares go.
#[utoipa::path(
    post,
    path = "/api/v1/calendar/invitations/{id}/decline",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    responses((status = 204), (status = 404))
)]
pub async fn decline(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(invitation): Path<Uuid>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    let mut tx = state.pool.begin().await?;
    let (calendar, _) = own_invitation(&mut tx, user_id, invitation).await?;
    let fetched: bool = sqlx::query_scalar(
        "UPDATE calendar_invitations SET state = 'declined' WHERE id = $1
         RETURNING fetched_at IS NOT NULL",
    )
    .bind(invitation)
    .fetch_one(&mut *tx)
    .await?;
    drop_shares(&mut tx, calendar, user_id).await?;
    // Declined after reading its shares: the key is rotated (T1).
    if fetched {
        rotation_due(&mut tx, calendar).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sweeps invitations past their expiry (and declined ones as old), with
/// what they held. Answers how many went.
pub async fn sweep_invitations(pool: &sqlx::PgPool) -> anyhow::Result<u64> {
    let expired: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(
        "SELECT i.id, i.calendar_id, i.invitee_account_id FROM calendar_invitations i
          WHERE i.expires_at < now() LIMIT 1000",
    )
    .fetch_all(pool)
    .await?;
    let mut swept = 0;
    for (id, calendar, invitee) in expired {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT id FROM calendars WHERE id = $1 FOR UPDATE")
            .bind(calendar)
            .execute(&mut *tx)
            .await?;
        let gone: Option<bool> = sqlx::query_scalar(
            "DELETE FROM calendar_invitations WHERE id = $1 AND expires_at < now()
             RETURNING fetched_at IS NOT NULL AND state = 'pending'",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        // Expired after it was read: the key is rotated (T1).
        if gone == Some(true) {
            rotation_due(&mut tx, calendar)
                .await
                .map_err(|error| anyhow::anyhow!(error.message))?;
        }
        let gone = u64::from(gone.is_some());
        let member: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM calendar_members WHERE calendar_id = $1 AND account_id = $2)",
        )
        .bind(calendar)
        .bind(invitee)
        .fetch_one(&mut *tx)
        .await?;
        if gone > 0 && !member {
            drop_shares(&mut tx, calendar, invitee)
                .await
                .map_err(|error| anyhow::anyhow!(error.message))?;
        }
        tx.commit().await?;
        swept += gone;
    }
    Ok(swept)
}

// ----- tombstones -----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TombstoneView {
    pub calendar_id: Uuid,
    /// `removed`, `left` or `deleted`.
    pub reason: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Tombstones {
    pub tombstones: Vec<TombstoneView>,
}

/// `GET /api/v1/calendar/tombstones` — the calendars the caller stopped
/// being a member of, each told once (plan §1): the client drops their
/// settings records, then the tombstone.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/tombstones",
    tag = "calendar",
    security(("BearerAuth" = [])),
    responses((status = 200, body = Tombstones))
)]
pub async fn tombstones(
    State(state): State<AppState>,
    user: AuthAccount,
) -> AppResult<Json<Tombstones>> {
    let user_id = trusted_uuid(&user.account_id)?;
    let rows: Vec<(Uuid, String, time::OffsetDateTime)> = sqlx::query_as(
        "SELECT calendar_id, reason, created_at FROM calendar_member_tombstones
          WHERE account_id = $1 ORDER BY created_at, calendar_id LIMIT 500",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(Tombstones {
        tombstones: rows
            .into_iter()
            .map(|(calendar_id, reason, created_at)| TombstoneView {
                calendar_id,
                reason,
                created_at,
            })
            .collect(),
    }))
}

/// `DELETE /api/v1/calendar/tombstones/{calendarId}` — read; gone.
#[utoipa::path(
    delete,
    path = "/api/v1/calendar/tombstones/{calendarId}",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("calendarId" = Uuid, Path)),
    responses((status = 204))
)]
pub async fn delete_tombstone(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(calendar): Path<Uuid>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.account_id)?;
    sqlx::query(
        "DELETE FROM calendar_member_tombstones WHERE calendar_id = $1 AND account_id = $2",
    )
    .bind(calendar)
    .bind(user_id)
    .execute(&state.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- links: the owner's side -----

/// One generation's passphrase, sealed for a keyed link.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationSealed {
    pub key_generation: i32,
    pub sealed: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LinkView {
    pub id: Uuid,
    /// `full`, `query` or `busy`.
    pub kind: String,
    /// A keyed link's secret, sealed by the owner to its own account key
    /// (`CalendarLinkSecretEnvelopeV1`, base64); none on a busy link.
    pub secret: Option<String>,
    /// The owner's label, sealed to the calendar key and signed.
    #[schema(value_type = Option<Object>)]
    pub purpose: Option<SealedMetadataV1>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LinkList {
    pub links: Vec<LinkView>,
}

type LinkRow = (
    Uuid,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    time::OffsetDateTime,
);

const LINK_COLUMNS: &str = "id, kind, secret, purpose_key_packet,
    purpose_data_packet, purpose_signature, created_at";

fn link_view(row: LinkRow) -> LinkView {
    let (id, kind, secret, key_packet, data_packet, signature, created_at) = row;
    LinkView {
        id,
        kind,
        secret: secret.map(|secret| STANDARD.encode(secret)),
        purpose: match (key_packet, data_packet, signature) {
            (Some(key_packet), Some(data_packet), Some(signature)) => Some(SealedMetadataV1 {
                key_packet: STANDARD.encode(key_packet),
                data_packet: STANDARD.encode(data_packet),
                signature,
            }),
            _ => None,
        },
        created_at,
    }
}

async fn owner_only(state: &AppState, user_id: Uuid, calendar: Uuid) -> AppResult<()> {
    let mut conn = state.pool.acquire().await?;
    if member_permissions(&mut conn, user_id, calendar).await? & SUPER_OWNER == 0 {
        return Err(AppError::forbidden("only the owner manages links"));
    }
    Ok(())
}

/// `GET /api/v1/calendar/calendars/{id}/links` — the owner's links.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/calendars/{id}/links",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    responses((status = 200, body = LinkList), (status = 403), (status = 404))
)]
pub async fn links(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
) -> AppResult<Json<LinkList>> {
    let user_id = trusted_uuid(&user.account_id)?;
    owner_only(&state, user_id, id).await?;
    let rows: Vec<LinkRow> = sqlx::query_as(&format!(
        "SELECT {LINK_COLUMNS} FROM calendar_links WHERE calendar_id = $1 ORDER BY created_at, id"
    ))
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(LinkList {
        links: rows.into_iter().map(link_view).collect(),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkCreate {
    /// A fresh UUID v4 the client draws: the envelopes are bound to it.
    pub id: Uuid,
    /// `full`, `query` or `busy`.
    pub kind: String,
    /// A keyed link's secret, sealed by the owner to its own account key
    /// (`CalendarLinkSecretEnvelopeV1`, base64): bound to the link, signed
    /// by the owner, opened by nobody else.
    pub secret: Option<String>,
    /// A keyed link's copy of every generation's passphrase.
    pub passphrases: Option<Vec<GenerationSealed>>,
    /// A keyed link's access proof (base64url, 32 bytes), which its page
    /// shows; the server keeps its SHA-256.
    pub access_proof: Option<String>,
    #[schema(value_type = Option<Object>)]
    pub purpose: Option<SealedMetadataV1>,
}

/// `POST /api/v1/calendar/calendars/{id}/links` — the owner makes a link.
#[utoipa::path(
    post,
    path = "/api/v1/calendar/calendars/{id}/links",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    request_body = LinkCreate,
    responses(
        (status = 201, body = LinkView),
        (status = 400, description = "An envelope doesn't check"),
        (status = 403, description = "Only the owner, while public sharing is on; query links off"),
        (status = 409, description = "The link limit, or the id is in use"),
    )
)]
pub async fn create_link(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
    Json(input): Json<LinkCreate>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    if input.id.get_version_num() != 4 {
        return Err(AppError::bad_request("a link's id is a UUID v4"));
    }
    let keyed = match input.kind.as_str() {
        "full" | "query" => true,
        "busy" => false,
        _ => return Err(AppError::bad_request("a link is full, query or busy")),
    };
    crate::public_sharing::ensure_may_share(&state.pool, user_id).await?;
    if input.kind == "query" && CALENDAR_QUERY_LINKS_ALLOWED.load(&state.pool).await? == 0 {
        return Err(coded(
            AppError::forbidden("this server does not allow links with the key in the address"),
            "queryLinksOff",
        ));
    }
    let purpose = input
        .purpose
        .as_ref()
        .map(|purpose| purpose.to_sealed().map_err(crypto))
        .transpose()?;
    let mut tx = state.pool.begin().await?;
    let (newest, generations) = owned_calendar(&mut tx, user_id, id).await?;
    if let Some(purpose) = &purpose {
        let public_key: Vec<u8> = sqlx::query_scalar(
            "SELECT public_key FROM calendar_keys WHERE calendar_id = $1 AND key_generation = $2",
        )
        .bind(id)
        .bind(newest)
        .fetch_one(&mut *tx)
        .await?;
        if purpose.signature.is_empty()
            || purpose.signature.len() > 4096
            || purpose.data_packet.len() > 4096
            || purpose.key_packet.len() > 1024
            || cal::key_packet_key_id(&purpose.key_packet).map_err(crypto)?
                != cal::encryption_key_id(&public_key).map_err(crypto)?
        {
            return Err(AppError::bad_request(
                "the purpose is not to the calendar key",
            ));
        }
    }
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM calendar_links WHERE calendar_id = $1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let most = CALENDAR_LINKS_PER_CALENDAR
        .load_for(&mut *tx, user_id)
        .await?;
    if count >= most {
        return Err(coded(
            AppError::conflict(format!("a calendar has at most {most} links")),
            "linkLimit",
        ));
    }
    let (secret, passphrases, proof_hash) = if keyed {
        let secret = input
            .secret
            .as_ref()
            .ok_or_else(|| AppError::bad_request("a keyed link carries its sealed secret"))?;
        if secret.len() > MAX_OWNER_SECRET_B64 {
            return Err(AppError::bad_request("the link secret is too large"));
        }
        let envelope =
            kutup_crypto::calendar_link::CalendarLinkSecretEnvelopeV1::decode_b64(secret)
                .map_err(|_| AppError::bad_request("the link secret does not parse"))?;
        let owner = party(&state, &mut tx, user_id)
            .await?
            .ok_or_else(|| AppError::conflict("account identity is unavailable"))?;
        envelope
            .verify_binding_and_signature(
                &input.id.to_string(),
                kutup_crypto::calendar_link::OWNER_SECRET_VERSION,
                &owner.reference,
                &owner.incarnation,
                &owner.signing,
                &owner.reference,
                &owner.incarnation,
            )
            .map_err(|_| {
                coded(
                    AppError::bad_request("the link secret is not the owner's own, for this link"),
                    "shareNotBound",
                )
            })?;
        let proof = input
            .access_proof
            .as_deref()
            .and_then(access_proof)
            .ok_or_else(|| AppError::bad_request("a keyed link carries its access proof"))?;
        let passphrases = input
            .passphrases
            .as_ref()
            .ok_or_else(|| AppError::bad_request("a keyed link carries every passphrase"))?;
        let mut named: Vec<i32> = passphrases.iter().map(|p| p.key_generation).collect();
        named.sort_unstable();
        if named != generations {
            return Err(coded(
                AppError::bad_request("a keyed link holds every key generation's passphrase"),
                "sharesIncomplete",
            ));
        }
        let passphrases: Vec<(i32, Vec<u8>)> = passphrases
            .iter()
            .map(|p| {
                Ok((
                    p.key_generation,
                    link_sealed(&p.sealed, "a link passphrase")?,
                ))
            })
            .collect::<AppResult<_>>()?;
        (
            Some(envelope.encode().map_err(crypto)?),
            passphrases,
            Some(proof_digest(&proof).to_vec()),
        )
    } else {
        if input.secret.is_some() || input.passphrases.is_some() || input.access_proof.is_some() {
            return Err(AppError::bad_request("a busy link carries no key"));
        }
        (None, Vec::new(), None)
    };
    let row: LinkRow = sqlx::query_as(&format!(
        "INSERT INTO calendar_links (id, calendar_id, kind, secret, access_proof_hash,
             purpose_key_packet, purpose_data_packet, purpose_signature, created_by_account_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING {LINK_COLUMNS}"
    ))
    .bind(input.id)
    .bind(id)
    .bind(&input.kind)
    .bind(secret.clone())
    .bind(proof_hash)
    .bind(purpose.as_ref().map(|p| p.key_packet.clone()))
    .bind(purpose.as_ref().map(|p| p.data_packet.clone()))
    .bind(purpose.as_ref().map(|p| p.signature.clone()))
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            coded(AppError::conflict("this link id is in use"), "linkExists")
        }
        _ => error.into(),
    })?;
    let mut bytes = secret.as_ref().map_or(0, Vec::len) as i64
        + purpose.as_ref().map_or(0, |p| {
            p.key_packet.len() + p.data_packet.len() + p.signature.len()
        }) as i64;
    for (generation, sealed) in &passphrases {
        bytes += sealed.len() as i64;
        sqlx::query(
            "INSERT INTO calendar_link_passphrases (link_id, calendar_id, key_generation, passphrase)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(input.id)
        .bind(id)
        .bind(generation)
        .bind(sealed)
        .execute(&mut *tx)
        .await?;
    }
    charge(&mut tx, id, user_id, bytes).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(link_view(row))).into_response())
}

/// The bytes a link holds (its secret, purpose and passphrase copies), or
/// none for a link that isn't the calendar's.
async fn link_bytes(
    tx: &mut Transaction<'_, Postgres>,
    calendar: Uuid,
    link: Uuid,
) -> AppResult<Option<i64>> {
    Ok(sqlx::query_scalar(
        "SELECT (COALESCE(octet_length(l.secret), 0)
                 + COALESCE(octet_length(l.purpose_key_packet), 0)
                 + COALESCE(octet_length(l.purpose_data_packet), 0)
                 + COALESCE(octet_length(l.purpose_signature), 0)
                 + COALESCE((SELECT SUM(octet_length(p.passphrase))
                               FROM calendar_link_passphrases p WHERE p.link_id = l.id), 0))::bigint
           FROM calendar_links l WHERE l.id = $1 AND l.calendar_id = $2",
    )
    .bind(link)
    .bind(calendar)
    .fetch_optional(&mut **tx)
    .await?)
}

/// `DELETE /api/v1/calendar/calendars/{id}/links/{linkId}` — the owner
/// deletes a link: it opens nothing from then on.
#[utoipa::path(
    delete,
    path = "/api/v1/calendar/calendars/{id}/links/{linkId}",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path), ("linkId" = Uuid, Path)),
    responses((status = 204), (status = 403), (status = 404))
)]
pub async fn delete_link(
    State(state): State<AppState>,
    user: AuthAccount,
    Path((id, link)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    let mut tx = state.pool.begin().await?;
    owned_calendar(&mut tx, user_id, id).await?;
    let freed = link_bytes(&mut tx, id, link).await?;
    let Some(freed) = freed else {
        return Err(AppError::not_found("not found"));
    };
    sqlx::query("DELETE FROM calendar_links WHERE id = $1")
        .bind(link)
        .execute(&mut *tx)
        .await?;
    charge(&mut tx, id, user_id, -freed).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- busy times -----

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct BusyQuery {
    /// The person's address.
    pub address: String,
    /// The window, RFC 3339.
    pub start: String,
    pub end: String,
}

/// `GET /api/v1/calendar/busy?address&start&end` — when a person is busy
/// (plan §4, Q-3): from the calendars they own that share busy times, and only to
/// someone of their organization (Proton's rule). Anyone else, or an
/// address that is no one's, is answered nothing, never an error that would
/// tell which.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/busy",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(BusyQuery),
    responses((status = 200, body = BusyList), (status = 400), (status = 429))
)]
pub async fn busy(
    State(state): State<AppState>,
    user: AuthAccount,
    Query(query): Query<BusyQuery>,
) -> AppResult<Json<BusyList>> {
    let user_id = trusted_uuid(&user.account_id)?;
    if !BUSY.allow(&user_id.to_string()) {
        return Err(AppError::too_many_requests("too many busy-times questions")
            .with_details(serde_json::json!({ "code": "rateLimited" })));
    }
    let (start, end) = (instant(&query.start, "start")?, instant(&query.end, "end")?);
    let days = CALENDAR_BUSY_WINDOW_DAYS.load(&state.pool).await?;
    if end <= start || end - start > time::Duration::days(days) {
        return Err(coded(
            AppError::bad_request(format!("the window is up to {days} days, end after start")),
            "busyWindowTooLong",
        ));
    }
    let nothing = || Ok(Json(BusyList { busy: Vec::new() }));
    let address = query.address.trim();
    if address.is_empty() || address.len() > 320 {
        return nothing();
    }
    let Some(found) = crate::handlers::mail_keys::lookup_address(&state, address).await? else {
        return nothing();
    };
    let Some(person) = found
        .account_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
    else {
        return nothing();
    };
    if person != user_id {
        let together: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM organization_members a
                              JOIN organization_members b ON b.organization_id = a.organization_id
                             WHERE a.account_id = $1 AND b.account_id = $2
                               AND a.state = 1 AND b.state = 1)",
        )
        .bind(user_id)
        .bind(person)
        .fetch_one(&state.pool)
        .await?;
        if !together {
            return nothing();
        }
    }
    // Only the person's own calendars: a calendar someone else shares with
    // them is that owner's to show, never theirs.
    let calendars: Vec<Uuid> = sqlx::query_scalar(
        "SELECT m.calendar_id FROM calendar_members m JOIN calendars c ON c.id = m.calendar_id
          WHERE m.account_id = $1 AND c.owner_account_id = $1 AND m.share_busy",
    )
    .bind(person)
    .fetch_all(&state.pool)
    .await?;
    let busy: Vec<BusyBlock> =
        crate::calendar_busy::blocks(&state.pool, &calendars, start, end).await?;
    Ok(Json(BusyList { busy }))
}

// ----- compaction -----
//
// Each removal (or due rotation) adds a key generation, up to
// `calendar.key_generations`. The owner's app compacts a calendar before it
// gets there (docs/plans/calendar-e3.md, "Compaction"): every event still
// under an older generation has its two key packets sealed again to the
// newest key (the same session keys, so its parts and their signatures stay
// as they are), as does every link purpose; then the generations nothing
// needs any more are pruned, with their shares and link copies, in one
// transaction that checks first that nothing still names them.

/// The most events one rewrap takes, and one stale listing answers.
const COMPACTION_BATCH: usize = 100;

/// The key ID each generation's key packets name.
async fn generation_key_ids(
    tx: &mut Transaction<'_, Postgres>,
    calendar: Uuid,
) -> AppResult<Vec<(i32, [u8; 8])>> {
    let keys: Vec<(i32, Vec<u8>)> = sqlx::query_as(
        "SELECT key_generation, public_key FROM calendar_keys WHERE calendar_id = $1
          ORDER BY key_generation",
    )
    .bind(calendar)
    .fetch_all(&mut **tx)
    .await?;
    keys.into_iter()
        .map(|(generation, public_key)| {
            cal::encryption_key_id(&public_key)
                .map(|id| (generation, id))
                .map_err(|_| AppError::internal("a stored calendar key does not parse"))
        })
        .collect()
}

/// The key ID a stored key packet names; none for one that doesn't parse.
fn packet_key_id(packet: &[u8]) -> Option<[u8; 8]> {
    cal::key_packet_key_id(packet).ok()
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StaleEvent {
    pub id: Uuid,
    /// The stored revision, which the rewrap names as its base.
    pub revision: i64,
    #[schema(value_type = Object)]
    pub event: kutup_crypto::calendar::SealedEventV1,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StaleEvents {
    /// The newest generation, which the rewrap seals to.
    pub key_generation: i32,
    /// Generations the calendar holds, oldest first.
    pub generations: Vec<i32>,
    /// Events still under an older generation (at most a batch).
    pub events: Vec<StaleEvent>,
    /// More remain after these.
    pub more: bool,
}

/// `GET /api/v1/calendar/calendars/{id}/events/stale` — the owner's events
/// still under an older key generation, a batch at a time.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/calendars/{id}/events/stale",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    responses((status = 200, body = StaleEvents), (status = 403), (status = 404))
)]
pub async fn stale_events(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
) -> AppResult<Json<StaleEvents>> {
    let user_id = trusted_uuid(&user.account_id)?;
    let mut tx = state.pool.begin().await?;
    let (newest, generations) = owned_calendar(&mut tx, user_id, id).await?;
    let ids = generation_key_ids(&mut tx, id).await?;
    let newest_id = ids
        .iter()
        .find(|(generation, _)| *generation == newest)
        .map(|(_, key)| *key)
        .ok_or_else(|| AppError::internal("the newest key generation is missing"))?;
    let packets: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT id, shared_key_packet FROM calendar_events WHERE calendar_id = $1 ORDER BY id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let stale: Vec<Uuid> = packets
        .into_iter()
        .filter(|(_, packet)| packet_key_id(packet) != Some(newest_id))
        .map(|(event, _)| event)
        .collect();
    let more = stale.len() > COMPACTION_BATCH;
    let batch: Vec<Uuid> = stale.into_iter().take(COMPACTION_BATCH).collect();
    let rows: Vec<crate::handlers::calendar::EventRow> = sqlx::query_as(&format!(
        "{} WHERE e.calendar_id = $1 AND e.id = ANY($2) ORDER BY e.id",
        crate::handlers::calendar::event_view_sql(3)
    ))
    .bind(id)
    .bind(&batch)
    .bind(Uuid::nil())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(StaleEvents {
        key_generation: newest,
        generations,
        events: rows
            .into_iter()
            .map(crate::handlers::calendar::event_view)
            .map(|view| StaleEvent {
                id: view.id,
                revision: view.revision,
                event: view.event,
            })
            .collect(),
        more,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewrappedEvent {
    pub id: Uuid,
    pub base_revision: i64,
    pub shared_key_packet: String,
    pub calendar_key_packet: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewrappedPurpose {
    pub link_id: Uuid,
    pub key_packet: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rewrap {
    /// The newest generation the packets are sealed to: refused when
    /// another came first.
    pub key_generation: i32,
    #[serde(default)]
    pub events: Vec<RewrappedEvent>,
    #[serde(default)]
    pub purposes: Vec<RewrappedPurpose>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RewrapResult {
    pub id: Uuid,
    pub status: u16,
    pub code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RewrapResults {
    pub results: Vec<RewrapResult>,
}

/// A rewrapped key packet: canonical base64, at most 1024 bytes, to the
/// newest key.
fn rewrapped(value: &str, newest: [u8; 8]) -> AppResult<Vec<u8>> {
    if value.len() > 1024 / 3 * 4 + 4 {
        return Err(AppError::bad_request("a key packet is too large"));
    }
    let packet = b64(value, "key packet")?;
    if packet.is_empty() || packet_key_id(&packet) != Some(newest) {
        return Err(coded(
            AppError::bad_request("a key packet is not to the calendar's newest key"),
            "notNewestKey",
        ));
    }
    Ok(packet)
}

/// `POST /api/v1/calendar/calendars/{id}/events/rewrap` — the owner moves
/// events (and link purposes) to the newest key generation: their key
/// packets sealed again, nothing else changed. Each event names the
/// revision it was read at, as an update does (`409 revisionConflict`
/// otherwise), and its revision goes up by one.
#[utoipa::path(
    post,
    path = "/api/v1/calendar/calendars/{id}/events/rewrap",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    request_body = Rewrap,
    responses(
        (status = 200, body = RewrapResults),
        (status = 400),
        (status = 403),
        (status = 409, description = "Another key generation came first"),
    )
)]
pub async fn rewrap(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
    Json(input): Json<Rewrap>,
) -> AppResult<Json<RewrapResults>> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    if input.events.len() > COMPACTION_BATCH || input.purposes.len() > COMPACTION_BATCH {
        return Err(AppError::bad_request(format!(
            "a rewrap takes at most {COMPACTION_BATCH} events and purposes"
        )));
    }
    let mut tx = state.pool.begin().await?;
    let (newest, _) = owned_calendar(&mut tx, user_id, id).await?;
    if input.key_generation != newest {
        return Err(coded(
            AppError::conflict("the calendar's key changed; reload it"),
            "keyRotated",
        ));
    }
    let newest_id = generation_key_ids(&mut tx, id)
        .await?
        .into_iter()
        .find(|(generation, _)| *generation == newest)
        .map(|(_, key)| key)
        .ok_or_else(|| AppError::internal("the newest key generation is missing"))?;
    let mut results = Vec::new();
    let mut event_bytes = 0i64;
    for change in &input.events {
        let packets = rewrapped(&change.shared_key_packet, newest_id)
            .and_then(|shared| Ok((shared, rewrapped(&change.calendar_key_packet, newest_id)?)));
        let (shared, own) = match packets {
            Ok(packets) => packets,
            Err(error) => {
                results.push(RewrapResult {
                    id: change.id,
                    status: error.status.as_u16(),
                    code: error
                        .details
                        .as_ref()
                        .and_then(|d| d.get("code"))
                        .and_then(|c| c.as_str())
                        .map(str::to_owned),
                });
                continue;
            }
        };
        let current: Option<(i64, i64)> = sqlx::query_as(
            "SELECT revision, (octet_length(shared_key_packet) + octet_length(calendar_key_packet))::bigint
               FROM calendar_events WHERE id = $1 AND calendar_id = $2 FOR UPDATE",
        )
        .bind(change.id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((revision, old)) = current else {
            results.push(RewrapResult {
                id: change.id,
                status: 404,
                code: None,
            });
            continue;
        };
        if revision != change.base_revision {
            results.push(RewrapResult {
                id: change.id,
                status: 409,
                code: Some("revisionConflict".into()),
            });
            continue;
        }
        let delta = (shared.len() + own.len()) as i64 - old;
        sqlx::query(
            "UPDATE calendar_events SET shared_key_packet = $2, calendar_key_packet = $3,
                    revision = revision + 1, bytes = GREATEST(bytes + $4, 0), modified_at = now()
              WHERE id = $1",
        )
        .bind(change.id)
        .bind(&shared)
        .bind(&own)
        .bind(delta)
        .execute(&mut *tx)
        .await?;
        event_bytes += delta;
        results.push(RewrapResult {
            id: change.id,
            status: 200,
            code: None,
        });
    }
    // Events' bytes are the events' own (not the calendar row's).
    if event_bytes > 0 {
        crate::storage_pool::charge_within_quota(&mut tx, user_id, event_bytes).await?;
    } else if event_bytes < 0 {
        crate::storage_pool::charge(
            &mut *tx,
            crate::storage_pool::Payer::Account(user_id),
            event_bytes,
        )
        .await?;
    }
    for purpose in &input.purposes {
        let packet = rewrapped(&purpose.key_packet, newest_id)?;
        let old: Option<i64> = sqlx::query_scalar(
            "SELECT octet_length(purpose_key_packet)::bigint FROM calendar_links
              WHERE id = $1 AND calendar_id = $2 AND purpose_key_packet IS NOT NULL FOR UPDATE",
        )
        .bind(purpose.link_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(old) = old else {
            return Err(AppError::not_found("no such link purpose"));
        };
        sqlx::query("UPDATE calendar_links SET purpose_key_packet = $2 WHERE id = $1")
            .bind(purpose.link_id)
            .bind(&packet)
            .execute(&mut *tx)
            .await?;
        charge(&mut tx, id, user_id, packet.len() as i64 - old).await?;
    }
    tx.commit().await?;
    Ok(Json(RewrapResults { results }))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prune {
    /// Older generations to drop.
    pub generations: Vec<i32>,
}

/// `POST /api/v1/calendar/calendars/{id}/keys/prune` — the owner drops key
/// generations nothing needs any more: refused (`409 generationInUse`)
/// while an event or a link purpose still names one; the newest is never
/// pruned. Their shares and link copies go with them, in one transaction.
#[utoipa::path(
    post,
    path = "/api/v1/calendar/calendars/{id}/keys/prune",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    request_body = Prune,
    responses((status = 204), (status = 400), (status = 403), (status = 409))
)]
pub async fn prune(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(id): Path<Uuid>,
    Json(input): Json<Prune>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    let mut tx = state.pool.begin().await?;
    let (newest, generations) = owned_calendar(&mut tx, user_id, id).await?;
    if input.generations.is_empty()
        || input
            .generations
            .iter()
            .any(|g| *g >= newest || !generations.contains(g))
    {
        return Err(AppError::bad_request(
            "only older generations the calendar holds are pruned",
        ));
    }
    let doomed: Vec<[u8; 8]> = generation_key_ids(&mut tx, id)
        .await?
        .into_iter()
        .filter(|(generation, _)| input.generations.contains(generation))
        .map(|(_, key)| key)
        .collect();
    let packets: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT shared_key_packet, calendar_key_packet FROM calendar_events WHERE calendar_id = $1",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let purposes: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT purpose_key_packet FROM calendar_links
          WHERE calendar_id = $1 AND purpose_key_packet IS NOT NULL",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    // Anything that doesn't name a key the server can read counts as
    // naming a doomed one: never pruned from under it.
    let in_use = |packet: &[u8]| packet_key_id(packet).is_none_or(|key| doomed.contains(&key));
    if packets
        .iter()
        .any(|(shared, own)| in_use(shared) || in_use(own))
        || purposes.iter().any(|packet| in_use(packet))
    {
        return Err(coded(
            AppError::conflict("an event or a link still uses an older key; compact it first"),
            "generationInUse",
        ));
    }
    let freed: i64 = sqlx::query_scalar(
        "SELECT (COALESCE((SELECT SUM(octet_length(public_key) + octet_length(locked_secret_key))
                             FROM calendar_keys WHERE calendar_id = $1 AND key_generation = ANY($2)), 0)
               + COALESCE((SELECT SUM(octet_length(share)) FROM calendar_member_shares
                            WHERE calendar_id = $1 AND key_generation = ANY($2)), 0)
               + COALESCE((SELECT SUM(octet_length(passphrase)) FROM calendar_link_passphrases
                            WHERE calendar_id = $1 AND key_generation = ANY($2)), 0))::bigint",
    )
    .bind(id)
    .bind(&input.generations)
    .fetch_one(&mut *tx)
    .await?;
    // The shares and the links' copies go with their generation (their
    // foreign keys cascade).
    sqlx::query("DELETE FROM calendar_keys WHERE calendar_id = $1 AND key_generation = ANY($2)")
        .bind(id)
        .bind(&input.generations)
        .execute(&mut *tx)
        .await?;
    charge(&mut tx, id, user_id, -freed).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
