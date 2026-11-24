//! Calendar invitations (docs/plans/calendar-e4.md): the attendee rows and
//! Kutup invitees an organizer's event carries, attendees' answers, the
//! invitations a Kutup attendee lists, adopting one into a calendar, and
//! the account's invitation settings.
//!
//! What the server sees and keeps (§7): the number of attendees, each
//! one's keyed token (`HMAC` under the event's shared session key: the
//! server can't tell whose it is), whether they are optional, when they
//! last answered, and which Kutup accounts and addresses on this server
//! were invited (so the event reaches them, Proton's
//! `AddedProtonAttendees`). Names, addresses and answers are sealed under
//! the shared session key. The server checks who may write each row:
//!
//! - the attendee list, by the organizer only (the owner of the event's
//!   home calendar, who signed ORGANIZER with its own address);
//! - an answer, by the organizer (an outside reply) or by the Kutup
//!   invitee whose token it is, and never one older than the stored one;
//! - an adopted copy, by an invitee, into a calendar they own.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use kutup_crypto::calendar::{self as cal, EventPartV1};
use kutup_crypto::calendar_event::SharedSigned;
use kutup_crypto::calendar_recurrence::{Rule, Series};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::calendar::{
    b64, coded, crypto, event_view, event_view_sql, limited, member_permissions, EventRow,
    EventView, WRITE,
};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthAccount;
use crate::site_settings::{
    CALENDAR_ATTENDEES_PER_EVENT, CALENDAR_EVENTS_PAGE, CALENDAR_EVENTS_PER_CALENDAR,
    CALENDAR_INVITATIONS_PER_ACCOUNT,
};
use crate::AppState;

/// An event's attendee rows as JSON, for [`event_view_sql`]: token and
/// answer in hex, read back by [`attendee_rows`].
pub(crate) const ATTENDEE_ROWS_SQL: &str = "COALESCE((SELECT json_agg(json_build_object(
            'token', encode(t.token, 'hex'), 'optional', t.optional,
            'answer', encode(t.answer, 'hex'), 'answerUpdatedAt', t.answer_updated_at)
            ORDER BY t.token)
          FROM calendar_event_attendees t WHERE t.shared_event_id = se.id), '[]'::json)";

/// One attendee's row as a reader gets it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttendeeRowView {
    /// base64url.
    pub token: String,
    pub optional: bool,
    /// The sealed answer (base64), once given.
    pub answer: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub answer_updated_at: Option<time::OffsetDateTime>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttendeeRowJson {
    token: String,
    optional: bool,
    answer: Option<String>,
    answer_updated_at: Option<String>,
}

pub(crate) fn attendee_rows(value: serde_json::Value) -> Vec<AttendeeRowView> {
    let rows: Vec<AttendeeRowJson> = serde_json::from_value(value).unwrap_or_default();
    rows.into_iter()
        .filter_map(|row| {
            Some(AttendeeRowView {
                token: URL_SAFE_NO_PAD.encode(hex::decode(row.token).ok()?),
                optional: row.optional,
                answer: row
                    .answer
                    .and_then(|answer| hex::decode(answer).ok())
                    .map(|answer| STANDARD.encode(answer)),
                answer_updated_at: row.answer_updated_at.and_then(|at| {
                    time::OffsetDateTime::parse(&at, &time::format_description::well_known::Rfc3339)
                        .ok()
                }),
            })
        })
        .collect()
}

fn token(value: &str) -> AppResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .filter(|bytes| bytes.len() == kutup_crypto::calendar_invitation::TOKEN_LEN)
        .ok_or_else(|| AppError::bad_request("a token is 32 bytes, base64url"))
}

// ----- the organizer's attendees, on an events sync -----

/// One attendee row the organizer lists.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttendeeIn {
    pub token: String,
    #[serde(default)]
    pub optional: bool,
}

/// A Kutup attendee on this server the event reaches at once: their
/// address, the shared session key to its key, and their token.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InviteeIn {
    pub address: String,
    pub key_packet: String,
    pub token: String,
}

/// What an event with an ORGANIZER carries on a create or an update: the
/// whole attendee list, each time.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvitationIn {
    #[schema(value_type = Object)]
    pub attendees: EventPartV1,
    pub rows: Vec<AttendeeIn>,
    #[serde(default)]
    pub invitees: Vec<InviteeIn>,
    /// The update moved the event (its SEQUENCE went up): every answer is
    /// asked again (Proton's reset of the attendees' PARTSTAT).
    #[serde(default)]
    pub reset_answers: bool,
}

/// An invitation checked before the calendar is locked.
pub(crate) struct CheckedInvitation {
    attendees: (Vec<u8>, String),
    rows: Vec<(Vec<u8>, bool)>,
    /// (account, address, key packet, token)
    invitees: Vec<(Uuid, Uuid, Vec<u8>, Vec<u8>)>,
    reset_answers: bool,
}

impl CheckedInvitation {
    pub(crate) fn bytes(&self) -> i64 {
        (self.attendees.0.len() + self.attendees.1.len()) as i64
    }
}

/// Checks an invitation: its rows within `calendar.attendees_per_event`,
/// each token once, each invitee an active address on this server (not the
/// organizer's own account) whose key the key packet is to, and one of the
/// rows.
pub(crate) async fn check_invitation(
    state: &AppState,
    organizer: Uuid,
    invitation: &InvitationIn,
) -> AppResult<CheckedInvitation> {
    let most = CALENDAR_ATTENDEES_PER_EVENT.load(&state.pool).await?;
    if invitation.rows.is_empty() || invitation.rows.len() as i64 > most {
        return Err(coded(
            AppError::bad_request(format!("an invitation has 1 to {most} attendees")),
            "tooManyAttendees",
        ));
    }
    let data = b64(&invitation.attendees.data, "the attendee part")?;
    if data.is_empty() || data.len() > cal::MAX_DATA_PACKET_LEN {
        return Err(AppError::bad_request("the attendee part is too large"));
    }
    let signature = invitation.attendees.signature.clone();
    if signature.is_empty() || signature.len() > 4096 {
        return Err(AppError::bad_request(
            "the attendee part's signature is invalid",
        ));
    }
    let mut rows = Vec::with_capacity(invitation.rows.len());
    for row in &invitation.rows {
        let token = token(&row.token)?;
        if rows.iter().any(|(seen, _)| *seen == token) {
            return Err(AppError::bad_request("an attendee is listed once"));
        }
        rows.push((token, row.optional));
    }
    if invitation.invitees.len() > rows.len() {
        return Err(AppError::bad_request("every invitee is an attendee"));
    }
    let mut invitees = Vec::with_capacity(invitation.invitees.len());
    for invitee in &invitation.invitees {
        let token = token(&invitee.token)?;
        if !rows.iter().any(|(row, _)| *row == token) {
            return Err(AppError::bad_request("every invitee is an attendee"));
        }
        let packet = b64(&invitee.key_packet, "an invitee's key packet")?;
        let packet_id = cal::key_packet_key_id(&packet).map_err(crypto)?;
        let found: Option<(Uuid, Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT a.id, a.account_id, a.domain_id FROM mail_addresses a
               JOIN accounts u ON u.id = a.account_id
              WHERE a.folded = kutup_address_folded($1) AND a.disabled_at IS NULL
                AND a.state = 'active' AND u.state = 'active'",
        )
        .bind(invitee.address.trim())
        .fetch_optional(&state.pool)
        .await?;
        let unknown = || {
            coded(
                AppError::bad_request("an invitee is not an address on this server"),
                "inviteeUnknown",
            )
        };
        let (address_id, account_id, domain_id) = found.ok_or_else(unknown)?;
        if let Some(domain_id) = domain_id {
            if !crate::mail::domains::usable_for(state, account_id, domain_id).await? {
                return Err(unknown());
            }
        }
        if account_id == organizer {
            return Err(coded(
                AppError::bad_request("self invitation not allowed"),
                "selfInvitation",
            ));
        }
        if invitees
            .iter()
            .any(|(seen, _, _, _): &(Uuid, Uuid, Vec<u8>, Vec<u8>)| *seen == account_id)
        {
            return Err(AppError::bad_request("an invitee is listed once"));
        }
        let keys: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT public_key FROM mail_address_keys WHERE address_id = $1 AND NOT is_forwarding",
        )
        .bind(address_id)
        .fetch_all(&state.pool)
        .await?;
        let to_a_key = keys
            .iter()
            .any(|key| cal::encryption_key_id(key).is_ok_and(|id| id == packet_id));
        if !to_a_key {
            return Err(coded(
                AppError::bad_request("an invitee's key packet is not to their address key"),
                "inviteeKey",
            ));
        }
        invitees.push((account_id, address_id, packet, token));
    }
    Ok(CheckedInvitation {
        attendees: (data, signature),
        rows,
        invitees,
        reset_answers: invitation.reset_answers,
    })
}

/// Removes the adopted copies of a shared event in the calendars of the
/// accounts not in `keep` (attendees removed, or the event gone), giving
/// back what each held. Every calendar's alarms for them go with the rows.
async fn drop_copies(
    tx: &mut Transaction<'_, Postgres>,
    shared_id: Uuid,
    keep: &[Uuid],
) -> AppResult<()> {
    let gone: Vec<(Uuid, Uuid, i64)> = sqlx::query_as(
        "DELETE FROM calendar_events e USING calendars c, calendar_shared_events se
          WHERE e.shared_event_id = $1 AND c.id = e.calendar_id AND se.id = e.shared_event_id
            AND e.calendar_id <> se.home_calendar_id AND NOT (c.owner_account_id = ANY($2))
          RETURNING e.id, c.owner_account_id, e.bytes",
    )
    .bind(shared_id)
    .bind(keep)
    .fetch_all(&mut **tx)
    .await?;
    for (_, owner, bytes) in gone {
        crate::storage_pool::charge(
            &mut **tx,
            crate::storage_pool::Payer::Account(owner),
            -bytes,
        )
        .await?;
    }
    Ok(())
}

/// Every adopted copy of a shared event, for its home's delete: their
/// owners get back what they held (the rows go with the shared row).
pub(crate) async fn refund_copies(
    tx: &mut Transaction<'_, Postgres>,
    shared_id: Uuid,
) -> AppResult<()> {
    drop_copies(tx, shared_id, &[]).await
}

/// Writes an invitation's attendee part, rows and invitees on its shared
/// row: answers kept for the tokens that stay (unless reset), the rows of
/// people removed gone with their invitee rows and adopted copies. `None`:
/// the event has no attendees (any it had are removed).
pub(crate) async fn write_invitation(
    tx: &mut Transaction<'_, Postgres>,
    shared_id: Uuid,
    invitation: Option<&CheckedInvitation>,
) -> AppResult<()> {
    let empty = CheckedInvitation {
        attendees: (Vec::new(), String::new()),
        rows: Vec::new(),
        invitees: Vec::new(),
        reset_answers: false,
    };
    let invitation = invitation.unwrap_or(&empty);
    let (part, signature) = if invitation.rows.is_empty() {
        (None, None)
    } else {
        (
            Some(invitation.attendees.0.clone()),
            Some(invitation.attendees.1.clone()),
        )
    };
    sqlx::query(
        "UPDATE calendar_shared_events SET attendees_encrypted = $2,
                attendees_encrypted_signature = $3
          WHERE id = $1",
    )
    .bind(shared_id)
    .bind(part)
    .bind(signature)
    .execute(&mut **tx)
    .await?;
    let tokens: Vec<Vec<u8>> = invitation.rows.iter().map(|(t, _)| t.clone()).collect();
    let accounts: Vec<Uuid> = invitation.invitees.iter().map(|(a, ..)| *a).collect();
    // People removed lose their copy first, then their rows (and with an
    // attendee row, its invitee row).
    drop_copies(tx, shared_id, &accounts).await?;
    sqlx::query(
        "DELETE FROM calendar_event_invitees
          WHERE shared_event_id = $1 AND NOT (invitee_account_id = ANY($2))",
    )
    .bind(shared_id)
    .bind(&accounts)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "DELETE FROM calendar_event_attendees WHERE shared_event_id = $1 AND NOT (token = ANY($2))",
    )
    .bind(shared_id)
    .bind(&tokens)
    .execute(&mut **tx)
    .await?;
    if invitation.reset_answers {
        sqlx::query(
            "UPDATE calendar_event_attendees SET answer = NULL, answer_updated_at = NULL
              WHERE shared_event_id = $1",
        )
        .bind(shared_id)
        .execute(&mut **tx)
        .await?;
    }
    for (token, optional) in &invitation.rows {
        sqlx::query(
            "INSERT INTO calendar_event_attendees (shared_event_id, token, optional)
             VALUES ($1, $2, $3)
             ON CONFLICT (shared_event_id, token) DO UPDATE SET optional = EXCLUDED.optional",
        )
        .bind(shared_id)
        .bind(token)
        .bind(optional)
        .execute(&mut **tx)
        .await?;
    }
    let most = CALENDAR_INVITATIONS_PER_ACCOUNT.load(&mut **tx).await?;
    for (account, address, packet, token) in &invitation.invitees {
        let existing: Option<bool> = sqlx::query_scalar(
            "SELECT true FROM calendar_event_invitees
              WHERE shared_event_id = $1 AND invitee_account_id = $2",
        )
        .bind(shared_id)
        .bind(account)
        .fetch_optional(&mut **tx)
        .await?;
        if existing.is_none() {
            // An account takes at most `calendar.invitations_per_account`
            // invitations at once: past it, the event doesn't appear in
            // their calendar (the invitation mail still comes).
            let held: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM calendar_event_invitees WHERE invitee_account_id = $1",
            )
            .bind(account)
            .fetch_one(&mut **tx)
            .await?;
            if held >= most {
                continue;
            }
        }
        sqlx::query(
            "INSERT INTO calendar_event_invitees
                 (shared_event_id, invitee_account_id, invitee_address_id, key_packet, token)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (shared_event_id, invitee_account_id) DO UPDATE
                SET invitee_address_id = EXCLUDED.invitee_address_id,
                    key_packet = EXCLUDED.key_packet, token = EXCLUDED.token",
        )
        .bind(shared_id)
        .bind(account)
        .bind(address)
        .bind(packet)
        .bind(token)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// After the organizer changed a shared event: every adopted copy's alarms
/// follow its new times.
pub(crate) async fn recompute_copies(
    tx: &mut Transaction<'_, Postgres>,
    shared_id: Uuid,
) -> AppResult<()> {
    let copies: Vec<Uuid> = sqlx::query_scalar(
        "SELECT e.id FROM calendar_events e JOIN calendar_shared_events se ON se.id = e.shared_event_id
          WHERE e.shared_event_id = $1 AND e.calendar_id <> se.home_calendar_id",
    )
    .bind(shared_id)
    .fetch_all(&mut **tx)
    .await?;
    for copy in copies {
        crate::calendar_alarms::recompute(tx, copy)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    Ok(())
}

// ----- answers -----

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnswerIn {
    /// The sealed answer (base64): sealed under the shared session key,
    /// bound to this event and token, signed by its writer.
    pub answer: String,
    /// When it was given (an outside reply: its DTSTAMP), RFC 3339.
    pub updated_at: String,
}

/// How far ahead of the server's clock an answer's time may be.
const ANSWER_SKEW: time::Duration = time::Duration::days(1);

/// `PUT /api/v1/calendar/shared-events/{id}/attendees/{token}` — writes an
/// attendee's sealed answer: by the organizer (the owner of the event's
/// home calendar, for an outside reply), or by the Kutup invitee whose
/// token it is. One older than the stored one is `409 answerStale`.
#[utoipa::path(
    put,
    path = "/api/v1/calendar/shared-events/{id}/attendees/{token}",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path), ("token" = String, Path)),
    request_body = AnswerIn,
    responses((status = 204), (status = 400), (status = 404), (status = 409))
)]
pub async fn answer(
    State(state): State<AppState>,
    user: AuthAccount,
    Path((id, token_text)): Path<(Uuid, String)>,
    Json(input): Json<AnswerIn>,
) -> AppResult<StatusCode> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    let token = token(&token_text)?;
    let answer = b64(&input.answer, "the answer")?;
    if answer.is_empty() || answer.len() > kutup_crypto::calendar_invitation::MAX_SEALED_ANSWER_LEN
    {
        return Err(AppError::bad_request("the answer is 1 to 4096 bytes"));
    }
    let at = crate::handlers::calendar::instant(&input.updated_at, "updatedAt")?
        .replace_nanosecond(0)
        .expect("zero is in range");
    if at > time::OffsetDateTime::now_utc() + ANSWER_SKEW {
        return Err(AppError::bad_request("updatedAt is in the future"));
    }
    let mut tx = state.pool.begin().await?;
    // The organizer, or the invitee holding this token: anyone else is
    // told the row doesn't exist.
    let allowed: Option<bool> = sqlx::query_scalar(
        "SELECT true FROM calendar_shared_events se
           JOIN calendars c ON c.id = se.home_calendar_id
          WHERE se.id = $1
            AND (c.owner_account_id = $2
                 OR EXISTS (SELECT 1 FROM calendar_event_invitees i
                             WHERE i.shared_event_id = se.id AND i.invitee_account_id = $2
                               AND i.token = $3))",
    )
    .bind(id)
    .bind(user_id)
    .bind(&token)
    .fetch_optional(&mut *tx)
    .await?;
    if allowed.is_none() {
        return Err(AppError::not_found("not found"));
    }
    let stored: Option<Option<time::OffsetDateTime>> = sqlx::query_scalar(
        "SELECT answer_updated_at FROM calendar_event_attendees
          WHERE shared_event_id = $1 AND token = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(&token)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(stored) = stored else {
        return Err(AppError::not_found("not found"));
    };
    if stored.is_some_and(|stored| stored > at) {
        return Err(coded(
            AppError::conflict("a newer answer is stored"),
            "answerStale",
        ));
    }
    sqlx::query(
        "UPDATE calendar_event_attendees SET answer = $3, answer_updated_at = $4
          WHERE shared_event_id = $1 AND token = $2",
    )
    .bind(id)
    .bind(&token)
    .bind(&answer)
    .bind(at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- a Kutup attendee's invitations -----

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct InvitationsQuery {
    /// The `next` of the previous page.
    pub after_id: Option<Uuid>,
}

/// An invitation as its Kutup attendee lists it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InvitedEventView {
    pub shared_event_id: Uuid,
    pub uid: String,
    /// The organizer's address: verify the shared parts against its keys.
    pub author_address: Option<String>,
    /// The address this account was invited at.
    pub address: String,
    /// The shared session key to that address's key.
    pub key_packet: String,
    /// This account's own token.
    pub token: String,
    #[schema(value_type = Object)]
    pub shared_signed: EventPartV1,
    #[schema(value_type = Object)]
    pub shared_encrypted: EventPartV1,
    #[schema(value_type = Option<Object>)]
    pub attendees: Option<EventPartV1>,
    #[serde(with = "time::serde::rfc3339")]
    pub start_utc: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub end_utc: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub range_end_utc: Option<time::OffsetDateTime>,
    pub sequence: i32,
    /// The account's own copies: `[calendarId, eventId]`.
    pub copies: Vec<(Uuid, Uuid)>,
    pub attendee_rows: Vec<AttendeeRowView>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InvitedEventPage {
    pub events: Vec<InvitedEventView>,
    pub next: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct InvitedRow {
    id: Uuid,
    uid: String,
    author_address: Option<String>,
    address: String,
    key_packet: Vec<u8>,
    token: Vec<u8>,
    shared_signed: String,
    shared_signed_signature: String,
    shared_encrypted: Vec<u8>,
    shared_encrypted_signature: String,
    attendees_encrypted: Option<Vec<u8>>,
    attendees_encrypted_signature: Option<String>,
    start_utc: time::OffsetDateTime,
    end_utc: time::OffsetDateTime,
    range_end_utc: Option<time::OffsetDateTime>,
    sequence: i32,
    copies: serde_json::Value,
    attendee_rows: serde_json::Value,
}

/// `GET /api/v1/calendar/invitations/events` — the events this account was
/// invited to by Kutup organizers on this server (§6), with what it needs
/// to open them, its own copies and every answer row, paged by id.
#[utoipa::path(
    get,
    path = "/api/v1/calendar/invitations/events",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(InvitationsQuery),
    responses((status = 200, body = InvitedEventPage))
)]
pub async fn invitations(
    State(state): State<AppState>,
    user: AuthAccount,
    Query(query): Query<InvitationsQuery>,
) -> AppResult<Json<InvitedEventPage>> {
    let user_id = trusted_uuid(&user.account_id)?;
    let limit = CALENDAR_EVENTS_PAGE.load(&state.pool).await?;
    let mut rows: Vec<InvitedRow> = sqlx::query_as(&format!(
        "SELECT se.id, se.uid, oa.address AS author_address, ia.address, i.key_packet, i.token,
                se.shared_signed, se.shared_signed_signature,
                se.shared_encrypted, se.shared_encrypted_signature,
                se.attendees_encrypted, se.attendees_encrypted_signature,
                se.start_utc, se.end_utc, se.range_end_utc, se.sequence,
                COALESCE((SELECT json_agg(json_build_array(e.calendar_id, e.id))
                            FROM calendar_events e JOIN calendars c ON c.id = e.calendar_id
                           WHERE e.shared_event_id = se.id AND c.owner_account_id = $1),
                         '[]'::json) AS copies,
                {ATTENDEE_ROWS_SQL} AS attendee_rows
           FROM calendar_event_invitees i
           JOIN calendar_shared_events se ON se.id = i.shared_event_id
           JOIN mail_addresses ia ON ia.id = i.invitee_address_id
           LEFT JOIN mail_addresses oa ON oa.id = se.author_address_id
          WHERE i.invitee_account_id = $1 AND ($2::uuid IS NULL OR se.id > $2)
          ORDER BY se.id
          LIMIT $3"
    ))
    .bind(user_id)
    .bind(query.after_id)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;
    let next = (rows.len() as i64 > limit).then(|| {
        rows.truncate(limit as usize);
        rows.last().map(|row| row.id)
    });
    let events = rows
        .into_iter()
        .map(|row| InvitedEventView {
            shared_event_id: row.id,
            uid: row.uid,
            author_address: row.author_address,
            address: row.address,
            key_packet: STANDARD.encode(row.key_packet),
            token: URL_SAFE_NO_PAD.encode(row.token),
            shared_signed: EventPartV1 {
                data: STANDARD.encode(row.shared_signed.as_bytes()),
                signature: row.shared_signed_signature,
            },
            shared_encrypted: EventPartV1 {
                data: STANDARD.encode(row.shared_encrypted),
                signature: row.shared_encrypted_signature,
            },
            attendees: row
                .attendees_encrypted
                .zip(row.attendees_encrypted_signature)
                .map(|(data, signature)| EventPartV1 {
                    data: STANDARD.encode(data),
                    signature,
                }),
            start_utc: row.start_utc,
            end_utc: row.end_utc,
            range_end_utc: row.range_end_utc,
            sequence: row.sequence,
            copies: serde_json::from_value(row.copies).unwrap_or_default(),
            attendee_rows: attendee_rows(row.attendee_rows),
        })
        .collect();
    Ok(Json(InvitedEventPage {
        events,
        next: next.flatten(),
    }))
}

// ----- adopting an invitation into a calendar -----

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdoptIn {
    /// The new row's id (a UUID v4 the client drew, so a retry answers the
    /// row it made).
    pub id: Uuid,
    pub shared_event_id: Uuid,
    /// The attendee's address whose key signed the calendar parts.
    pub address_id: Uuid,
    pub shared_key_packet: String,
    pub calendar_key_packet: String,
    #[schema(value_type = Object)]
    pub calendar_signed: EventPartV1,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub calendar_encrypted: Option<EventPartV1>,
}

/// `POST /api/v1/calendar/calendars/{id}/events/adopt` — an invitee's own
/// copy of an event they were invited to, in a calendar they own (Q-6:
/// never one shared with them): its key packets to the calendar's newest
/// key and its calendar parts, signed by the invitee's address. One copy
/// per account.
#[utoipa::path(
    post,
    path = "/api/v1/calendar/calendars/{id}/events/adopt",
    tag = "calendar",
    security(("BearerAuth" = [])),
    params(("id" = Uuid, Path)),
    request_body = AdoptIn,
    responses((status = 200, body = EventView), (status = 400), (status = 403), (status = 404), (status = 409))
)]
pub async fn adopt(
    State(state): State<AppState>,
    user: AuthAccount,
    Path(calendar): Path<Uuid>,
    Json(input): Json<AdoptIn>,
) -> AppResult<Json<EventView>> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    if input.id.get_version_num() != 4 {
        return Err(AppError::bad_request("an event's id is a UUID v4"));
    }
    let shared_packet = b64(&input.shared_key_packet, "the shared key packet")?;
    let own_packet = b64(&input.calendar_key_packet, "the calendar key packet")?;
    let signed = input.calendar_signed.to_part().map_err(crypto)?;
    let encrypted = input
        .calendar_encrypted
        .as_ref()
        .map(EventPartV1::to_part)
        .transpose()
        .map_err(crypto)?;
    let author_keys = {
        let mut conn = state.pool.acquire().await?;
        crate::handlers::calendar::address_keys(&mut conn, user_id, input.address_id).await?
    };
    let mut tx = state.pool.begin().await?;
    let calendar_row: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT c.owner_account_id, k.public_key FROM calendars c
           JOIN calendar_keys k ON k.calendar_id = c.id AND k.key_generation = c.key_generation
          WHERE c.id = $1 FOR UPDATE OF c",
    )
    .bind(calendar)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((owner, public_key)) = calendar_row else {
        return Err(AppError::not_found("not found"));
    };
    if member_permissions(&mut tx, user_id, calendar).await? & WRITE == 0 || owner != user_id {
        return Err(AppError::forbidden(
            "an invitation goes into a calendar of your own",
        ));
    }
    let shared: Option<(String, String)> = sqlx::query_as(
        "SELECT se.uid, se.shared_signed FROM calendar_event_invitees i
           JOIN calendar_shared_events se ON se.id = i.shared_event_id
          WHERE i.shared_event_id = $1 AND i.invitee_account_id = $2",
    )
    .bind(input.shared_event_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((uid, shared_signed)) = shared else {
        return Err(AppError::not_found("not found"));
    };
    let keys: Vec<&[u8]> = author_keys.iter().map(Vec::as_slice).collect();
    let own = kutup_crypto::calendar_invitation::check_adopted_parts(
        &signed,
        &shared_packet,
        &own_packet,
        &uid,
        &keys,
    )
    .map_err(crypto)?;
    let newest = cal::encryption_key_id(&public_key).map_err(crypto)?;
    for packet in [&shared_packet, &own_packet] {
        if cal::key_packet_key_id(packet).map_err(crypto)? != newest {
            return Err(coded(
                AppError::conflict("the event is not to the calendar's newest key; reload it"),
                "keyRotated",
            ));
        }
    }
    if let Some(part) = &encrypted {
        if part.data.is_empty() || part.data.len() > cal::MAX_DATA_PACKET_LEN {
            return Err(AppError::bad_request("the calendar part is too large"));
        }
    }
    // The attendee's own EXDATEs remove occurrences of the series, and
    // only those (as on the organizer's calendar).
    if !own.exdates.is_empty() {
        let parent = SharedSigned::parse(&shared_signed)
            .map_err(|_| AppError::internal("a stored event doesn't parse"))?;
        let rule = parent
            .rrule
            .as_deref()
            .map(Rule::parse)
            .transpose()
            .map_err(crypto)?;
        let Some(rule) = rule else {
            return Err(coded(
                AppError::bad_request("an EXDATE removes an occurrence of a repeating event"),
                "exdateNotAnOccurrence",
            ));
        };
        let bare = Series::new(&parent.dtstart, parent.dtend.as_ref(), Some(&rule), &[])
            .map_err(crypto)?;
        if !bare.occurs_at_all(&own.exdates).map_err(crypto)? {
            return Err(coded(
                AppError::bad_request("an EXDATE is not an occurrence of the series"),
                "exdateNotAnOccurrence",
            ));
        }
    }
    let held: Option<Uuid> = sqlx::query_scalar(
        "SELECT e.id FROM calendar_events e JOIN calendars c ON c.id = e.calendar_id
          WHERE e.shared_event_id = $1 AND c.owner_account_id = $2",
    )
    .bind(input.shared_event_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(held) = held {
        if held == input.id {
            // A retry of an adopt that landed.
            tx.commit().await?;
            return view(&state, held, user_id).await.map(Json);
        }
        return Err(coded(
            AppError::conflict("the event is in one of your calendars already"),
            "alreadyAdopted",
        ));
    }
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM calendar_events WHERE calendar_id = $1")
            .bind(calendar)
            .fetch_one(&mut *tx)
            .await?;
    if count >= CALENDAR_EVENTS_PER_CALENDAR.load(&state.pool).await? {
        return Err(coded(
            AppError::conflict("this calendar is full"),
            "eventLimit",
        ));
    }
    let bytes = (shared_packet.len()
        + own_packet.len()
        + signed.data.len()
        + signed.signature.len()
        + encrypted
            .as_ref()
            .map_or(0, |part| part.data.len() + part.signature.len())) as i64;
    crate::storage_pool::charge_within_quota(&mut tx, owner, bytes).await?;
    let text = String::from_utf8(signed.data.clone()).expect("checked as text");
    sqlx::query(
        "INSERT INTO calendar_events (id, calendar_id, shared_event_id,
             shared_key_packet, calendar_key_packet,
             calendar_signed, calendar_signed_signature,
             calendar_encrypted, calendar_encrypted_signature,
             revision, bytes, author_address_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, $10, $11)",
    )
    .bind(input.id)
    .bind(calendar)
    .bind(input.shared_event_id)
    .bind(&shared_packet)
    .bind(&own_packet)
    .bind(text)
    .bind(&signed.signature)
    .bind(encrypted.as_ref().map(|part| part.data.clone()))
    .bind(encrypted.as_ref().map(|part| part.signature.clone()))
    .bind(bytes)
    .bind(input.address_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => coded(
            AppError::conflict("another event has this id"),
            "eventIdTaken",
        ),
        _ => error.into(),
    })?;
    crate::calendar_alarms::recompute(&mut tx, input.id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    tx.commit().await?;
    view(&state, input.id, user_id).await.map(Json)
}

async fn view(state: &AppState, id: Uuid, user_id: Uuid) -> AppResult<EventView> {
    let row: EventRow = sqlx::query_as(&format!("{} WHERE e.id = $1", event_view_sql(2)))
        .bind(id)
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;
    Ok(event_view(row))
}

// ----- the account's invitation settings -----

/// Proton's `InviteLocale` and `AutoImportInvite`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InviteSettings {
    /// `en` or `tr`; none: the app's language.
    pub invite_locale: Option<String>,
    /// Received invitations go into the default calendar at once, marked
    /// as pending ("Add to calendar and mark as pending").
    pub auto_add: bool,
}

/// `GET /api/v1/calendar/settings/invitations`
#[utoipa::path(
    get,
    path = "/api/v1/calendar/settings/invitations",
    tag = "calendar",
    security(("BearerAuth" = [])),
    responses((status = 200, body = InviteSettings))
)]
pub async fn settings(
    State(state): State<AppState>,
    user: AuthAccount,
) -> AppResult<Json<InviteSettings>> {
    let user_id = trusted_uuid(&user.account_id)?;
    let row: Option<(Option<String>, bool)> = sqlx::query_as(
        "SELECT invite_locale, auto_add FROM calendar_invite_settings WHERE account_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let (invite_locale, auto_add) = row.unwrap_or((None, true));
    Ok(Json(InviteSettings {
        invite_locale,
        auto_add,
    }))
}

/// `PUT /api/v1/calendar/settings/invitations`
#[utoipa::path(
    put,
    path = "/api/v1/calendar/settings/invitations",
    tag = "calendar",
    security(("BearerAuth" = [])),
    request_body = InviteSettings,
    responses((status = 200, body = InviteSettings), (status = 400))
)]
pub async fn update_settings(
    State(state): State<AppState>,
    user: AuthAccount,
    Json(input): Json<InviteSettings>,
) -> AppResult<Json<InviteSettings>> {
    let user_id = trusted_uuid(&user.account_id)?;
    limited(user_id)?;
    if input
        .invite_locale
        .as_deref()
        .is_some_and(|locale| !matches!(locale, "en" | "tr"))
    {
        return Err(AppError::bad_request("the language is en or tr"));
    }
    sqlx::query(
        "INSERT INTO calendar_invite_settings (account_id, invite_locale, auto_add)
         VALUES ($1, $2, $3)
         ON CONFLICT (account_id) DO UPDATE
            SET invite_locale = EXCLUDED.invite_locale, auto_add = EXCLUDED.auto_add,
                updated_at = now()",
    )
    .bind(user_id)
    .bind(&input.invite_locale)
    .bind(input.auto_add)
    .execute(&state.pool)
    .await?;
    Ok(Json(input))
}
