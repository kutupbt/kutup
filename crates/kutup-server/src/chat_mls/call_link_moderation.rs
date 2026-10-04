//! Running a meeting (docs/chat-calls.md, "Hosts"): seats, hosts, and what
//! hosts do.
//!
//! Until here this server only minted tokens to enter an SFU room. Removing
//! a participant, muting one, stopping a screen share and ending a meeting
//! act on the SFU itself, as the room's administrator, through LiveKit's
//! room service API.
//!
//! **Seats.** A browser joins under a random SFU identity, and binds it to a
//! secret only it holds. A token for an identity is minted only to the
//! holder of its seat secret, so nobody can take another participant's
//! identity (and with it their role, or their place in the room). A browser
//! that reconnects presents the same seat and is the same participant.
//!
//! **Hosts.** Two kinds:
//!
//! - the **owner**, who presents the host token only their account can
//!   derive. They may do everything;
//! - a **co-host**: a participant the owner named, or the longest-present
//!   participant when the meeting was left without a host. They prove who
//!   they are with their own SFU token (which this server minted, so it can
//!   check it) and may let people in, turn them away, lock the meeting, and
//!   act on participants who are not hosts.
//!
//! **Removing someone** does not change the meeting's keys: they still hold
//! the link. It disconnects them at the SFU and turns the waiting room on,
//! so they cannot come straight back in. The SFU token they hold cannot be
//! withdrawn either, so their seat is remembered as removed and they are
//! removed again whenever they are found back in the room (`tend`).
//!
//! **Ending the meeting** starts a new sitting: the SFU room is named after
//! the room id and the sitting, so every token of the ended one opens
//! nothing.

use std::sync::LazyLock;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::call_links::{admitted, hex32, require_sfu, Admitted};
use crate::error::{AppError, AppResult};
use crate::AppState;

pub(super) const OWNER: i16 = 1;
pub(super) const CO_HOST: i16 = 2;
/// A seat nobody asked a token for in this long is forgotten; a removed one
/// this long after it was last removed. Longer than any SFU token lasts.
const FORGET_SEAT_SECONDS: i64 = 24 * 60 * 60;
/// How long a meeting stays without a host before the longest-present
/// participant is made a co-host: long enough for a host to reload the page.
const HOSTLESS_GRACE_SECONDS: i64 = 20;
/// An SFU admin token is used at once.
const ADMIN_TOKEN_TTL_SECONDS: i64 = 60;

static SFU_API: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build the SFU API client")
});

/// The SFU room of one sitting of a meeting.
pub(super) fn sfu_room(room_id: &str, sitting: i64) -> String {
    format!("{room_id}.{sitting}")
}

// --- Seats ------------------------------------------------------------------

/// How someone asking for a seat comes to the meeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Entry {
    /// The owner, with the host token: always comes in.
    Owner,
    /// A host let them in from the waiting room: a lock does not stop them.
    Admitted,
    /// The link alone lets people in (no waiting room), unless it is locked.
    Open,
    /// The meeting has a waiting room: only a seat already held comes back.
    Returning,
}

/// What a seat says about the token to mint for it.
#[derive(Debug, Clone, Default)]
pub(super) struct Seat {
    /// A host stopped this participant sharing their screen.
    pub no_screen: bool,
}

/// Take, or come back to, the seat of `participant_id`.
///
/// - Someone else's seat (another secret) is refused: `409`.
/// - A removed seat is refused: `410`.
/// - A new seat needs a way in: `403` with a waiting room, `423` when the
///   meeting is locked.
pub(super) async fn claim_seat(
    state: &AppState,
    meeting: &Admitted,
    room_id: &str,
    participant_id: &str,
    seat_hash: &[u8; 32],
    entry: Entry,
    account: Option<&str>,
) -> AppResult<Seat> {
    let existing: Option<(Vec<u8>, bool, bool)> = sqlx::query_as(
        "SELECT seat_hash, removed_at IS NOT NULL, no_screen FROM chat_call_link_seats
         WHERE room_id = $1 AND participant_id = $2",
    )
    .bind(room_id)
    .bind(participant_id)
    .fetch_optional(&state.pool)
    .await?;
    if let Some((stored, removed, no_screen)) = existing {
        let stored: [u8; 32] = stored.as_slice().try_into().unwrap_or([0u8; 32]);
        if !kutup_chat_proto::constant_time_capability_hash_eq(seat_hash, &stored) {
            return Err(AppError::conflict("this participant identity is taken"));
        }
        if removed {
            return Err(AppError::new(
                StatusCode::GONE,
                "a host removed this participant from the meeting",
            ));
        }
        sqlx::query(
            "UPDATE chat_call_link_seats
             SET last_minted_at = NOW(), account = $3,
                 role = CASE WHEN $4 THEN $5 ELSE role END
             WHERE room_id = $1 AND participant_id = $2",
        )
        .bind(room_id)
        .bind(participant_id)
        .bind(account)
        .bind(entry == Entry::Owner)
        .bind(OWNER)
        .execute(&state.pool)
        .await?;
        return Ok(Seat { no_screen });
    }
    match entry {
        Entry::Owner | Entry::Admitted => {}
        Entry::Returning => {
            return Err(AppError::forbidden(
                "this meeting has a waiting room: knock and wait to be admitted",
            ))
        }
        Entry::Open if meeting.locked => {
            return Err(AppError::new(
                StatusCode::LOCKED,
                "a host locked this meeting",
            ))
        }
        Entry::Open => {}
    }
    sqlx::query(
        "DELETE FROM chat_call_link_seats
         WHERE room_id = $1 AND COALESCE(removed_at, last_minted_at) < NOW() - make_interval(secs => $2)",
    )
    .bind(room_id)
    .bind(FORGET_SEAT_SECONDS as f64)
    .execute(&state.pool)
    .await?;
    let taken = sqlx::query(
        "INSERT INTO chat_call_link_seats (room_id, participant_id, seat_hash, role, account)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(room_id)
    .bind(participant_id)
    .bind(seat_hash.as_slice())
    .bind((entry == Entry::Owner).then_some(OWNER))
    .bind(account)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if taken == 0 {
        return Err(AppError::conflict("this participant identity is taken"));
    }
    Ok(Seat::default())
}

// --- Who is asking ----------------------------------------------------------

/// How a request says who is asking: the owner's host token, or a
/// participant's own SFU token.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostCredentials {
    pub room_id: String,
    /// The link's access token (standard base64, 32 bytes).
    pub access_token: String,
    /// The owner's host token (standard base64, 32 bytes).
    #[serde(default)]
    pub host_token: Option<String>,
    /// The asking participant's SFU token, as this server minted it.
    #[serde(default)]
    pub sfu_token: Option<String>,
}

/// Who is asking, once their credentials held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Asker {
    Owner,
    /// A participant, by the identity in their SFU token, and their role.
    Participant {
        id: String,
        co_host: bool,
    },
    /// A holder of the link who showed no further credential.
    Holder,
}

impl Asker {
    pub fn is_host(&self) -> bool {
        matches!(self, Self::Owner | Self::Participant { co_host: true, .. })
    }

    /// Whether this host may act on a participant with `target` role
    /// (remove, mute, stop sharing). Nobody acts on the owner; the owner on
    /// anyone else; a co-host only on those who are not hosts.
    fn may_act_on(&self, target: Option<i16>) -> bool {
        match (self, target) {
            (_, Some(OWNER)) => false,
            (Self::Owner, _) => true,
            (Self::Participant { co_host: true, .. }, None) => true,
            _ => false,
        }
    }
}

#[derive(Deserialize)]
struct SfuVideoClaim {
    #[serde(default)]
    room: String,
}

#[derive(Deserialize)]
struct SfuClaims {
    sub: String,
    video: SfuVideoClaim,
}

/// The participant an SFU token names, if this server minted it for this
/// sitting of the meeting and it has not expired.
fn sfu_participant(state: &AppState, sfu_room: &str, token: &str) -> Option<String> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_issuer(&[&state.config.chat_sfu_api_key]);
    validation.set_required_spec_claims(&["exp", "sub", "iss"]);
    let claims = jsonwebtoken::decode::<SfuClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(state.config.chat_sfu_api_secret.as_bytes()),
        &validation,
    )
    .ok()?
    .claims;
    (claims.video.room == sfu_room && kutup_chat_proto::validate_room_id(&claims.sub).is_ok())
        .then_some(claims.sub)
}

/// The meeting and who is asking about it. A wrong access token is answered
/// like an unknown room; a wrong host or SFU token leaves a mere holder, as
/// does the token of a seat that was removed.
pub(super) async fn asker(
    state: &AppState,
    credentials: &HostCredentials,
) -> AppResult<(Admitted, Asker)> {
    let meeting = admitted(state, &credentials.room_id, &credentials.access_token).await?;
    if meeting.is_host(credentials.host_token.as_deref())? {
        return Ok((meeting, Asker::Owner));
    }
    let room = sfu_room(&credentials.room_id, meeting.sitting);
    let Some(id) = credentials
        .sfu_token
        .as_deref()
        .and_then(|token| sfu_participant(state, &room, token))
    else {
        return Ok((meeting, Asker::Holder));
    };
    let seat: Option<Option<i16>> = sqlx::query_scalar(
        "SELECT role FROM chat_call_link_seats
         WHERE room_id = $1 AND participant_id = $2 AND removed_at IS NULL",
    )
    .bind(&credentials.room_id)
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(match seat {
        Some(role) => (
            meeting,
            Asker::Participant {
                id,
                co_host: role == Some(CO_HOST),
            },
        ),
        None => (meeting, Asker::Holder),
    })
}

/// The meeting, for one of its hosts. Anyone else is answered like an
/// unknown room.
pub(super) async fn host(
    state: &AppState,
    credentials: &HostCredentials,
) -> AppResult<(Admitted, Asker)> {
    let (meeting, asker) = asker(state, credentials).await?;
    if asker.is_host() {
        Ok((meeting, asker))
    } else {
        Err(AppError::not_found("this call link does not work"))
    }
}

async fn owner(state: &AppState, credentials: &HostCredentials) -> AppResult<Admitted> {
    match asker(state, credentials).await? {
        (meeting, Asker::Owner) => Ok(meeting),
        _ => Err(AppError::not_found("this call link does not work")),
    }
}

/// The role of a participant's seat: `None` when they have no seat (or it
/// was removed), `Some(None)` when they are not a host.
async fn seat_role(
    state: &AppState,
    room_id: &str,
    participant_id: &str,
) -> AppResult<Option<Option<i16>>> {
    Ok(sqlx::query_scalar(
        "SELECT role FROM chat_call_link_seats
         WHERE room_id = $1 AND participant_id = $2 AND removed_at IS NULL",
    )
    .bind(room_id)
    .bind(participant_id)
    .fetch_optional(&state.pool)
    .await?)
}

// --- The SFU's room service -------------------------------------------------

#[derive(Serialize, Default)]
struct AdminGrant<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    room: Option<&'a str>,
    #[serde(rename = "roomAdmin", skip_serializing_if = "std::ops::Not::not")]
    room_admin: bool,
    #[serde(rename = "roomCreate", skip_serializing_if = "std::ops::Not::not")]
    room_create: bool,
}

#[derive(Serialize)]
struct AdminClaims<'a> {
    iss: &'a str,
    nbf: i64,
    exp: i64,
    video: AdminGrant<'a>,
}

/// Where the SFU's API is: `CHAT_SFU_API_URL`, or the browsers' WebSocket
/// URL with `ws` read as `http`.
fn sfu_api_base(state: &AppState) -> String {
    let configured = state.config.chat_sfu_api_url.trim();
    let base = if configured.is_empty() {
        let url = state.config.chat_sfu_url.trim();
        url.strip_prefix("wss://")
            .map(|rest| format!("https://{rest}"))
            .or_else(|| {
                url.strip_prefix("ws://")
                    .map(|rest| format!("http://{rest}"))
            })
            .unwrap_or_else(|| url.to_owned())
    } else {
        configured.to_owned()
    };
    base.trim_end_matches('/').to_owned()
}

/// Call one method of LiveKit's room service. A room or participant that
/// is already gone counts as done.
async fn room_service<T: Serialize>(
    state: &AppState,
    method: &str,
    grant: AdminGrant<'_>,
    body: &T,
) -> AppResult<()> {
    room_service_answer(state, method, grant, body)
        .await
        .map(|_| ())
}

/// Call one method of LiveKit's room service and return what it answered;
/// `None` when the room or participant is not there.
async fn room_service_answer<T: Serialize>(
    state: &AppState,
    method: &str,
    grant: AdminGrant<'_>,
    body: &T,
) -> AppResult<Option<serde_json::Value>> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &AdminClaims {
            iss: &state.config.chat_sfu_api_key,
            nbf: now - 10,
            exp: now + ADMIN_TOKEN_TTL_SECONDS,
            video: grant,
        },
        &jsonwebtoken::EncodingKey::from_secret(state.config.chat_sfu_api_secret.as_bytes()),
    )
    .map_err(|error| AppError::internal(format!("sign SFU admin token: {error}")))?;
    let unreachable = |error: String| {
        tracing::warn!(%error, method, "the SFU's room service could not be reached");
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "the call server could not be reached",
        )
    };
    let response = SFU_API
        .post(format!(
            "{}/twirp/livekit.RoomService/{method}",
            sfu_api_base(state)
        ))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .map_err(|error| unreachable(error.to_string()))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status.is_success() {
        return response
            .json()
            .await
            .map(Some)
            .map_err(|error| unreachable(error.to_string()));
    }
    let detail = response.text().await.unwrap_or_default();
    Err(unreachable(format!("{status}: {detail}")))
}

/// The identities in an SFU answer to `ListParticipants`.
fn identities(answer: &serde_json::Value) -> Vec<&str> {
    answer["participants"]
        .as_array()
        .map(|participants| {
            participants
                .iter()
                .filter_map(|participant| participant["identity"].as_str())
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Serialize)]
struct RoomParticipant<'a> {
    room: &'a str,
    identity: &'a str,
}

#[derive(Serialize)]
struct RoomName<'a> {
    room: &'a str,
}

#[derive(Serialize)]
struct MuteTrack<'a> {
    room: &'a str,
    identity: &'a str,
    track_sid: &'a str,
    muted: bool,
}

#[derive(Serialize)]
struct Permission<'a> {
    can_subscribe: bool,
    can_publish: bool,
    can_publish_data: bool,
    /// Empty means every source.
    can_publish_sources: &'a [&'a str],
}

#[derive(Serialize)]
struct UpdateParticipant<'a> {
    room: &'a str,
    identity: &'a str,
    permission: Permission<'a>,
}

fn room_admin(room: &str) -> AdminGrant<'_> {
    AdminGrant {
        room: Some(room),
        room_admin: true,
        ..AdminGrant::default()
    }
}

/// The sources a participant stopped from sharing their screen may still
/// publish, as an SFU token names them and as the room service does.
pub(super) const TOKEN_SOURCES_WITHOUT_SCREEN: &[&str] = &["camera", "microphone"];
const SOURCES_WITHOUT_SCREEN: &[&str] = &["CAMERA", "MICROPHONE"];

async fn disconnect(state: &AppState, room: &str, participant_id: &str) -> AppResult<()> {
    room_service(
        state,
        "RemoveParticipant",
        room_admin(room),
        &RoomParticipant {
            room,
            identity: participant_id,
        },
    )
    .await
}

/// Delete an SFU room, disconnecting everyone in it.
pub(super) async fn delete_sfu_room(state: &AppState, room: &str) -> AppResult<()> {
    room_service(
        state,
        "DeleteRoom",
        AdminGrant {
            room_create: true,
            ..AdminGrant::default()
        },
        &RoomName { room },
    )
    .await
}

/// Who is in the meeting's SFU room; `None` when there is no such room now.
async fn participants(state: &AppState, room: &str) -> AppResult<Option<serde_json::Value>> {
    room_service_answer(
        state,
        "ListParticipants",
        room_admin(room),
        &RoomName { room },
    )
    .await
}

/// Whether a `ListParticipants` entry is allowed to publish a screen: no
/// list of sources means every source.
fn may_share_screen(participant: &serde_json::Value) -> bool {
    participant["permission"]["canPublishSources"]
        .as_array()
        .is_none_or(|sources| {
            sources.is_empty() || sources.iter().any(|source| source == "SCREEN_SHARE")
        })
}

async fn stop_screen_share(state: &AppState, room: &str, identity: &str) -> AppResult<()> {
    room_service(
        state,
        "UpdateParticipant",
        room_admin(room),
        &UpdateParticipant {
            room,
            identity,
            permission: Permission {
                can_subscribe: true,
                can_publish: true,
                can_publish_data: true,
                can_publish_sources: SOURCES_WITHOUT_SCREEN,
            },
        },
    )
    .await
}

/// The microphone tracks in a `ListParticipants` entry that are not muted.
fn open_microphones(participant: &serde_json::Value) -> Vec<&str> {
    participant["tracks"]
        .as_array()
        .map(|tracks| {
            tracks
                .iter()
                .filter(|track| {
                    track["source"] == "MICROPHONE" && track["muted"].as_bool() != Some(true)
                })
                .filter_map(|track| track["sid"].as_str())
                .collect()
        })
        .unwrap_or_default()
}

/// Look after a meeting that is on, whenever someone in it asks who its
/// hosts are (every browser does when the people in the room change, and
/// again while there is no host) or a host looks at who is waiting:
///
/// - whoever was removed and is back in the room, with the SFU token they
///   still hold, is removed again;
/// - whoever a host stopped from sharing their screen and is back with an
///   SFU token from before that (which still allows it) is stopped again;
/// - when no host has been in the room for a while, the participant who has
///   been there longest becomes a co-host, so the meeting is not left with
///   nobody to let people in.
///
/// Returns whether the meeting is without a host right now. A failure is
/// logged and tried again at the next question.
pub(super) async fn tend(state: &AppState, room_id: &str, meeting: &Admitted) -> bool {
    let outcome: AppResult<bool> = async {
        let room = sfu_room(room_id, meeting.sitting);
        let Some(answer) = participants(state, &room).await? else {
            return Ok(false);
        };
        let present = identities(&answer);
        // Who in the room the SFU lets share a screen right now.
        let sharers: Vec<&str> = answer["participants"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|participant| may_share_screen(participant))
            .filter_map(|participant| participant["identity"].as_str())
            .collect();
        // participant_id, role, removed, no_screen
        let seats: Vec<(String, Option<i16>, bool, bool)> = sqlx::query_as(
            "SELECT participant_id, role, removed_at IS NOT NULL, no_screen FROM chat_call_link_seats
             WHERE room_id = $1 ORDER BY issued_at, participant_id",
        )
        .bind(room_id)
        .fetch_all(&state.pool)
        .await?;
        let mut hosted = false;
        // Present and not a host, longest-seated first.
        let mut others = Vec::new();
        for (id, role, removed, no_screen) in &seats {
            if !present.contains(&id.as_str()) {
                continue;
            }
            if *no_screen && !*removed && sharers.contains(&id.as_str()) {
                stop_screen_share(state, &room, id).await?;
            }
            if *removed {
                tracing::info!(room_id, "a removed participant was back in the meeting");
                // Remembered from now, so they are kept out while they keep trying.
                sqlx::query(
                    "UPDATE chat_call_link_seats SET removed_at = NOW()
                     WHERE room_id = $1 AND participant_id = $2",
                )
                .bind(room_id)
                .bind(id)
                .execute(&state.pool)
                .await?;
                disconnect(state, &room, id).await?;
            } else if role.is_some() {
                hosted = true;
            } else {
                others.push(id);
            }
        }
        if hosted || others.is_empty() {
            if meeting.hostless_since.is_some() {
                sqlx::query("UPDATE chat_call_links SET hostless_since = NULL WHERE room_id = $1")
                    .bind(room_id)
                    .execute(&state.pool)
                    .await?;
            }
            return Ok(false);
        }
        let now = OffsetDateTime::now_utc();
        match meeting.hostless_since {
            Some(since) if (now - since).whole_seconds() >= HOSTLESS_GRACE_SECONDS => {
                sqlx::query(
                    "UPDATE chat_call_link_seats SET role = $3
                     WHERE room_id = $1 AND participant_id = $2 AND role IS NULL AND removed_at IS NULL",
                )
                .bind(room_id)
                .bind(others[0])
                .bind(CO_HOST)
                .execute(&state.pool)
                .await?;
                sqlx::query("UPDATE chat_call_links SET hostless_since = NULL WHERE room_id = $1")
                    .bind(room_id)
                    .execute(&state.pool)
                    .await?;
                tracing::info!(room_id, "a meeting without a host: its longest-present participant is now a co-host");
                Ok(false)
            }
            Some(_) => Ok(true),
            None => {
                sqlx::query(
                    "UPDATE chat_call_links SET hostless_since = NOW()
                     WHERE room_id = $1 AND hostless_since IS NULL",
                )
                .bind(room_id)
                .execute(&state.pool)
                .await?;
                Ok(true)
            }
        }
    }
    .await;
    outcome.unwrap_or_else(|error| {
        tracing::warn!(?error, room_id, "could not look after the meeting");
        false
    })
}

// --- Routes -----------------------------------------------------------------

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MeetingRole {
    pub participant_id: String,
    /// `owner` or `coHost`.
    pub role: &'static str,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MeetingRoles {
    /// The asker's own role, when they showed a credential that carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub me: Option<&'static str>,
    pub roles: Vec<MeetingRole>,
    /// Nobody new comes in.
    pub locked: bool,
    /// Joiners wait to be let in.
    pub waiting_room: bool,
    /// No host is in the meeting right now. If it stays so, its
    /// longest-present participant becomes a co-host: ask again shortly.
    pub no_host: bool,
}

fn role_name(role: i16) -> &'static str {
    if role == OWNER {
        "owner"
    } else {
        "coHost"
    }
}

/// Who the meeting's hosts are and how it is set, for anyone holding the
/// link, and the asker's own role.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/roles",
    tag = "chat",
    operation_id = "getChatCallLinkRoles",
    request_body = HostCredentials,
    responses(
        (status = 200, description = "The meeting's hosts", body = MeetingRoles),
        (status = 404, description = "No such link, or the wrong access token"),
        (status = 429, description = "Too many requests"),
    )
)]
pub(crate) async fn roles(
    State(state): State<AppState>,
    Json(credentials): Json<HostCredentials>,
) -> AppResult<Json<MeetingRoles>> {
    let (meeting, _) = asker(&state, &credentials).await?;
    let no_host = tend(&state, &credentials.room_id, &meeting).await;
    // Asked again: looking after the meeting may have changed the roles.
    let (meeting, asker) = asker(&state, &credentials).await?;
    let rows: Vec<(String, i16)> = sqlx::query_as(
        "SELECT participant_id, role FROM chat_call_link_seats
         WHERE room_id = $1 AND role IS NOT NULL AND removed_at IS NULL
         ORDER BY role, issued_at",
    )
    .bind(&credentials.room_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(MeetingRoles {
        me: match asker {
            Asker::Owner => Some("owner"),
            Asker::Participant { co_host: true, .. } => Some("coHost"),
            _ => None,
        },
        roles: rows
            .into_iter()
            .map(|(participant_id, role)| MeetingRole {
                participant_id,
                role: role_name(role),
            })
            .collect(),
        locked: meeting.locked,
        waiting_room: meeting.waiting_room,
        no_host,
    }))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetCoHostRequest {
    pub room_id: String,
    pub access_token: String,
    /// The owner's host token (standard base64, 32 bytes).
    pub host_token: String,
    pub participant_id: String,
    pub enabled: bool,
}

/// Make a participant a co-host, or stop them being one. The owner only.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/co-hosts",
    tag = "chat",
    operation_id = "setChatCallLinkCoHost",
    request_body = SetCoHostRequest,
    responses(
        (status = 204, description = "Set"),
        (status = 404, description = "No such link or participant, or not the owner"),
        (status = 409, description = "That participant is the owner"),
    )
)]
pub(crate) async fn set_co_host(
    State(state): State<AppState>,
    Json(request): Json<SetCoHostRequest>,
) -> AppResult<StatusCode> {
    hex32("participantId", &request.participant_id)?;
    owner(
        &state,
        &HostCredentials {
            room_id: request.room_id.clone(),
            access_token: request.access_token.clone(),
            host_token: Some(request.host_token.clone()),
            sfu_token: None,
        },
    )
    .await?;
    match seat_role(&state, &request.room_id, &request.participant_id).await? {
        None => {
            return Err(AppError::not_found(
                "nobody in the meeting has that identity",
            ))
        }
        Some(Some(OWNER)) => {
            return Err(AppError::conflict(
                "that participant is the meeting's owner",
            ))
        }
        Some(_) => {}
    }
    sqlx::query(
        "UPDATE chat_call_link_seats SET role = $3
         WHERE room_id = $1 AND participant_id = $2 AND role IS DISTINCT FROM $4",
    )
    .bind(&request.room_id)
    .bind(&request.participant_id)
    .bind(request.enabled.then_some(CO_HOST))
    .bind(OWNER)
    .execute(&state.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A host's request about one participant.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoveParticipantRequest {
    pub room_id: String,
    pub access_token: String,
    /// The owner's host token, or
    #[serde(default)]
    pub host_token: Option<String>,
    /// a co-host's own SFU token.
    #[serde(default)]
    pub sfu_token: Option<String>,
    pub participant_id: String,
}

/// The meeting and the asking host, when that host may act on `target`.
async fn host_over(
    state: &AppState,
    credentials: HostCredentials,
    target: &str,
) -> AppResult<(Admitted, Asker)> {
    hex32("participantId", target)?;
    let (meeting, asker) = host(state, &credentials).await?;
    let role = seat_role(state, &credentials.room_id, target)
        .await?
        .flatten();
    if !asker.may_act_on(role) {
        return Err(AppError::forbidden(
            "a co-host cannot do that to a host, and nobody can to the owner",
        ));
    }
    Ok((meeting, asker))
}

/// Remove a participant from the meeting, as a host. The waiting room is
/// turned on, so they cannot come straight back in with the link.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/participants/remove",
    tag = "chat",
    operation_id = "removeChatCallLinkParticipant",
    request_body = RemoveParticipantRequest,
    responses(
        (status = 204, description = "Removed, and the waiting room is on"),
        (status = 403, description = "A co-host cannot remove a host"),
        (status = 404, description = "No such link, or not one of its hosts"),
        (status = 502, description = "The call server could not be reached"),
    )
)]
pub(crate) async fn remove_participant(
    State(state): State<AppState>,
    Json(request): Json<RemoveParticipantRequest>,
) -> AppResult<StatusCode> {
    require_sfu(&state)?;
    let room_id = &request.room_id;
    let (meeting, _) = host_over(
        &state,
        HostCredentials {
            room_id: room_id.clone(),
            access_token: request.access_token.clone(),
            host_token: request.host_token.clone(),
            sfu_token: request.sfu_token.clone(),
        },
        &request.participant_id,
    )
    .await?;
    // The door first: once it is shut, disconnecting them is final.
    sqlx::query(
        "UPDATE chat_call_links SET waiting_room = TRUE
         WHERE room_id = $1 AND host_token_hash IS NOT NULL",
    )
    .bind(room_id)
    .execute(&state.pool)
    .await?;
    // Their seat mints no more tokens, and the SFU token they hold is
    // answered by removing them again if they come back (`tend`).
    sqlx::query(
        "UPDATE chat_call_link_seats SET removed_at = NOW(), role = NULL
         WHERE room_id = $1 AND participant_id = $2",
    )
    .bind(room_id)
    .bind(&request.participant_id)
    .execute(&state.pool)
    .await?;
    // Nor does the knock they came in by.
    sqlx::query(
        "UPDATE chat_call_link_knocks SET status = 2 WHERE room_id = $1 AND participant_id = $2",
    )
    .bind(room_id)
    .bind(&request.participant_id)
    .execute(&state.pool)
    .await?;
    disconnect(
        &state,
        &sfu_room(room_id, meeting.sitting),
        &request.participant_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuteRequest {
    pub room_id: String,
    pub access_token: String,
    #[serde(default)]
    pub host_token: Option<String>,
    #[serde(default)]
    pub sfu_token: Option<String>,
    /// Whom to mute; left out, everyone who is not a host.
    #[serde(default)]
    pub participant_id: Option<String>,
}

/// Mute a participant's microphone, or everyone's who is not a host. They
/// can turn it back on themselves: a host mutes, and never unmutes.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/participants/mute",
    tag = "chat",
    operation_id = "muteChatCallLinkParticipant",
    request_body = MuteRequest,
    responses(
        (status = 204, description = "Muted"),
        (status = 403, description = "A co-host cannot mute a host"),
        (status = 404, description = "No such link, or not one of its hosts"),
        (status = 502, description = "The call server could not be reached"),
    )
)]
pub(crate) async fn mute(
    State(state): State<AppState>,
    Json(request): Json<MuteRequest>,
) -> AppResult<StatusCode> {
    require_sfu(&state)?;
    let room_id = &request.room_id;
    let credentials = HostCredentials {
        room_id: room_id.clone(),
        access_token: request.access_token.clone(),
        host_token: request.host_token.clone(),
        sfu_token: request.sfu_token.clone(),
    };
    let (meeting, hosts) = match &request.participant_id {
        Some(target) => (host_over(&state, credentials, target).await?.0, Vec::new()),
        None => {
            let (meeting, _) = host(&state, &credentials).await?;
            let hosts: Vec<String> = sqlx::query_scalar(
                "SELECT participant_id FROM chat_call_link_seats
                 WHERE room_id = $1 AND role IS NOT NULL AND removed_at IS NULL",
            )
            .bind(room_id)
            .fetch_all(&state.pool)
            .await?;
            (meeting, hosts)
        }
    };
    let room = sfu_room(room_id, meeting.sitting);
    let Some(answer) = participants(&state, &room).await? else {
        return Ok(StatusCode::NO_CONTENT);
    };
    for participant in answer["participants"].as_array().into_iter().flatten() {
        let Some(identity) = participant["identity"].as_str() else {
            continue;
        };
        let wanted = match &request.participant_id {
            Some(target) => target == identity,
            None => !hosts.iter().any(|host| host == identity),
        };
        if !wanted {
            continue;
        }
        for track_sid in open_microphones(participant) {
            room_service(
                &state,
                "MutePublishedTrack",
                room_admin(&room),
                &MuteTrack {
                    room: &room,
                    identity,
                    track_sid,
                    muted: true,
                },
            )
            .await?;
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScreenShareRequest {
    pub room_id: String,
    pub access_token: String,
    #[serde(default)]
    pub host_token: Option<String>,
    #[serde(default)]
    pub sfu_token: Option<String>,
    pub participant_id: String,
    /// Whether this participant may share their screen.
    pub allowed: bool,
}

/// Stop a participant sharing their screen (what they are sharing ends, and
/// they cannot start again), or allow it again.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/participants/screen",
    tag = "chat",
    operation_id = "setChatCallLinkScreenShare",
    request_body = ScreenShareRequest,
    responses(
        (status = 204, description = "Set"),
        (status = 403, description = "A co-host cannot do that to a host"),
        (status = 404, description = "No such link, or not one of its hosts"),
        (status = 502, description = "The call server could not be reached"),
    )
)]
pub(crate) async fn set_screen_share(
    State(state): State<AppState>,
    Json(request): Json<ScreenShareRequest>,
) -> AppResult<StatusCode> {
    require_sfu(&state)?;
    let room_id = &request.room_id;
    let (meeting, _) = host_over(
        &state,
        HostCredentials {
            room_id: room_id.clone(),
            access_token: request.access_token.clone(),
            host_token: request.host_token.clone(),
            sfu_token: request.sfu_token.clone(),
        },
        &request.participant_id,
    )
    .await?;
    // Kept with the seat, so a token minted when they reconnect says the same.
    sqlx::query(
        "UPDATE chat_call_link_seats SET no_screen = $3
         WHERE room_id = $1 AND participant_id = $2",
    )
    .bind(room_id)
    .bind(&request.participant_id)
    .bind(!request.allowed)
    .execute(&state.pool)
    .await?;
    let room = sfu_room(room_id, meeting.sitting);
    if request.allowed {
        room_service(
            &state,
            "UpdateParticipant",
            room_admin(&room),
            &UpdateParticipant {
                room: &room,
                identity: &request.participant_id,
                permission: Permission {
                    can_subscribe: true,
                    can_publish: true,
                    can_publish_data: true,
                    can_publish_sources: &[],
                },
            },
        )
        .await?;
    } else {
        stop_screen_share(&state, &room, &request.participant_id).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LockRequest {
    pub room_id: String,
    pub access_token: String,
    #[serde(default)]
    pub host_token: Option<String>,
    #[serde(default)]
    pub sfu_token: Option<String>,
    pub locked: bool,
}

/// Lock the meeting (nobody new comes in, not even by knocking; whoever is
/// waiting is turned away) or unlock it. Someone already in it can still
/// reconnect, and the owner always comes in.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/lock",
    tag = "chat",
    operation_id = "lockChatCallLink",
    request_body = LockRequest,
    responses(
        (status = 204, description = "Set"),
        (status = 404, description = "No such link, or not one of its hosts"),
    )
)]
pub(crate) async fn lock(
    State(state): State<AppState>,
    Json(request): Json<LockRequest>,
) -> AppResult<StatusCode> {
    host(
        &state,
        &HostCredentials {
            room_id: request.room_id.clone(),
            access_token: request.access_token.clone(),
            host_token: request.host_token.clone(),
            sfu_token: request.sfu_token.clone(),
        },
    )
    .await?;
    sqlx::query("UPDATE chat_call_links SET locked = $2 WHERE room_id = $1")
        .bind(&request.room_id)
        .bind(request.locked)
        .execute(&state.pool)
        .await?;
    if request.locked {
        sqlx::query(
            "UPDATE chat_call_link_knocks SET status = 2 WHERE room_id = $1 AND status = 0",
        )
        .bind(&request.room_id)
        .execute(&state.pool)
        .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// End the meeting for everyone in it, as its owner. The link keeps working
/// for another time: a new sitting, which the tokens of this one do not open.
#[utoipa::path(
    post,
    path = "/api/chat/call-links/end",
    tag = "chat",
    operation_id = "endChatCallLinkMeeting",
    request_body = HostCredentials,
    responses(
        (status = 204, description = "Everyone is disconnected"),
        (status = 404, description = "No such link, or not its owner"),
        (status = 502, description = "The call server could not be reached"),
    )
)]
pub(crate) async fn end(
    State(state): State<AppState>,
    Json(credentials): Json<HostCredentials>,
) -> AppResult<StatusCode> {
    require_sfu(&state)?;
    owner(&state, &credentials).await?;
    let room_id = &credentials.room_id;
    let mut tx = state.pool.begin().await?;
    // The sitting that ends, read as it is replaced.
    let ended: i64 = sqlx::query_scalar(
        "UPDATE chat_call_links
         SET sitting = sitting + 1, locked = FALSE, hostless_since = NULL
         WHERE room_id = $1 RETURNING sitting - 1",
    )
    .bind(room_id)
    .fetch_one(&mut *tx)
    .await?;
    // Nobody keeps a seat or a role, and no knock of this sitting, waiting
    // or let in, gets a token now.
    sqlx::query("DELETE FROM chat_call_link_seats WHERE room_id = $1")
        .bind(room_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE chat_call_link_knocks SET status = 2 WHERE room_id = $1")
        .bind(room_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    delete_sfu_room(&state, &sfu_room(room_id, ended)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn co_host() -> Asker {
        Asker::Participant {
            id: "a".into(),
            co_host: true,
        }
    }

    #[test]
    fn only_the_owner_and_co_hosts_are_hosts() {
        assert!(Asker::Owner.is_host());
        assert!(co_host().is_host());
        assert!(!Asker::Participant {
            id: "a".into(),
            co_host: false
        }
        .is_host());
        assert!(!Asker::Holder.is_host());
    }

    #[test]
    fn a_co_host_acts_only_on_those_who_are_not_hosts() {
        assert!(Asker::Owner.may_act_on(None));
        assert!(Asker::Owner.may_act_on(Some(CO_HOST)));
        assert!(!Asker::Owner.may_act_on(Some(OWNER)));
        assert!(co_host().may_act_on(None));
        assert!(!co_host().may_act_on(Some(CO_HOST)));
        assert!(!co_host().may_act_on(Some(OWNER)));
        assert!(!Asker::Holder.may_act_on(None));
    }

    #[test]
    fn each_sitting_has_its_own_sfu_room() {
        assert_eq!(sfu_room("ab", 0), "ab.0");
        assert_ne!(sfu_room("ab", 0), sfu_room("ab", 1));
    }

    #[test]
    fn identities_and_open_microphones_are_read_from_a_participant_list() {
        let answer = serde_json::json!({
            "participants": [
                { "identity": "aa", "tracks": [
                    { "sid": "TR_mic", "source": "MICROPHONE" },
                    { "sid": "TR_cam", "source": "CAMERA" },
                    { "sid": "TR_off", "source": "MICROPHONE", "muted": true },
                ] },
                { "sid": "PA_x" },
                { "identity": "bb" },
            ]
        });
        assert_eq!(identities(&answer), ["aa", "bb"]);
        assert!(identities(&serde_json::json!({})).is_empty());
        assert_eq!(open_microphones(&answer["participants"][0]), ["TR_mic"]);
        // No list of sources means every source.
        assert!(may_share_screen(&answer["participants"][0]));
        assert!(may_share_screen(
            &serde_json::json!({ "permission": { "canPublishSources": ["CAMERA", "SCREEN_SHARE"] } })
        ));
        assert!(!may_share_screen(
            &serde_json::json!({ "permission": { "canPublishSources": ["CAMERA", "MICROPHONE"] } })
        ));
        assert!(open_microphones(&answer["participants"][2]).is_empty());
    }

    #[test]
    fn admin_requests_carry_only_what_a_call_needs() {
        assert_eq!(
            serde_json::to_value(room_admin("room")).unwrap(),
            serde_json::json!({ "room": "room", "roomAdmin": true })
        );
        let end = serde_json::to_value(AdminGrant {
            room_create: true,
            ..AdminGrant::default()
        })
        .unwrap();
        assert_eq!(end, serde_json::json!({ "roomCreate": true }));
        let stop = serde_json::to_value(Permission {
            can_subscribe: true,
            can_publish: true,
            can_publish_data: true,
            can_publish_sources: SOURCES_WITHOUT_SCREEN,
        })
        .unwrap();
        assert_eq!(
            stop["can_publish_sources"],
            serde_json::json!(["CAMERA", "MICROPHONE"])
        );
    }
}
