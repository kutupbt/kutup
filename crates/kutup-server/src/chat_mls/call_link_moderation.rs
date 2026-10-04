//! Running a meeting (docs/chat-calls.md, "Hosts"): who its hosts are,
//! removing someone, and ending it for everyone.
//!
//! Until here this server only minted tokens to enter an SFU room. Removing
//! a participant and ending a meeting act on the SFU itself, as the room's
//! administrator, through LiveKit's room service API.
//!
//! Two kinds of host:
//!
//! - the **owner**, who presents the host token only their account can
//!   derive. They may do everything;
//! - a **co-host**, a participant the owner named for this stay in the
//!   meeting. They prove who they are with their own SFU token (which this
//!   server minted, so it can check it) and may let people in, turn them
//!   away, and remove participants who are not hosts.
//!
//! Removing someone does not change the meeting's keys: they still hold the
//! link. It disconnects them at the SFU and turns the waiting room on, so
//! they cannot come straight back in. The SFU token they hold cannot be
//! withdrawn either, so the removed identity is remembered and removed
//! again whenever it is found back in the room (`keep_removed_out`).

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
/// Roles of stays that ended long ago are swept when a new one is recorded.
const FORGET_ROLES_SECONDS: i64 = 24 * 60 * 60;
/// A removed identity is remembered this long after it was last removed:
/// longer than any SFU token it could hold stays valid.
const REMEMBER_REMOVED_SECONDS: i64 = 24 * 60 * 60;
/// An SFU admin token is used at once.
const ADMIN_TOKEN_TTL_SECONDS: i64 = 60;

static SFU_API: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build the SFU API client")
});

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

/// The participant an SFU token names, if this server minted it for `room_id`
/// and it has not expired.
fn sfu_participant(state: &AppState, room_id: &str, token: &str) -> Option<String> {
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
    (claims.video.room == room_id && kutup_chat_proto::validate_room_id(&claims.sub).is_ok())
        .then_some(claims.sub)
}

/// The meeting and who is asking about it. A wrong access token is answered
/// like an unknown room; a wrong host or SFU token leaves a mere holder.
pub(super) async fn asker(
    state: &AppState,
    credentials: &HostCredentials,
) -> AppResult<(Admitted, Asker)> {
    let meeting = admitted(state, &credentials.room_id, &credentials.access_token).await?;
    if meeting.is_host(credentials.host_token.as_deref())? {
        return Ok((meeting, Asker::Owner));
    }
    let Some(id) = credentials
        .sfu_token
        .as_deref()
        .and_then(|token| sfu_participant(state, &credentials.room_id, token))
    else {
        return Ok((meeting, Asker::Holder));
    };
    let role: Option<i16> = sqlx::query_scalar(
        "SELECT role FROM chat_call_link_roles WHERE room_id = $1 AND participant_id = $2",
    )
    .bind(&credentials.room_id)
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?;
    Ok((
        meeting,
        Asker::Participant {
            id,
            co_host: role == Some(CO_HOST),
        },
    ))
}

/// The meeting, for one of its hosts. Anyone else is answered like an
/// unknown room.
pub(super) async fn host(state: &AppState, credentials: &HostCredentials) -> AppResult<Asker> {
    let (_, asker) = asker(state, credentials).await?;
    if asker.is_host() {
        Ok(asker)
    } else {
        Err(AppError::not_found("this call link does not work"))
    }
}

async fn owner(state: &AppState, credentials: &HostCredentials) -> AppResult<()> {
    match asker(state, credentials).await?.1 {
        Asker::Owner => Ok(()),
        _ => Err(AppError::not_found("this call link does not work")),
    }
}

/// Record that the owner joined under `participant_id`.
pub(super) async fn record_owner(
    state: &AppState,
    room_id: &str,
    participant_id: &str,
) -> AppResult<()> {
    sqlx::query(
        "DELETE FROM chat_call_link_roles
         WHERE room_id = $1 AND created_at < NOW() - make_interval(secs => $2)",
    )
    .bind(room_id)
    .bind(FORGET_ROLES_SECONDS as f64)
    .execute(&state.pool)
    .await?;
    sqlx::query(
        "INSERT INTO chat_call_link_roles (room_id, participant_id, role) VALUES ($1, $2, $3)
         ON CONFLICT (room_id, participant_id) DO UPDATE SET role = EXCLUDED.role",
    )
    .bind(room_id)
    .bind(participant_id)
    .bind(OWNER)
    .execute(&state.pool)
    .await?;
    Ok(())
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

async fn disconnect(state: &AppState, room_id: &str, participant_id: &str) -> AppResult<()> {
    room_service(
        state,
        "RemoveParticipant",
        AdminGrant {
            room: Some(room_id),
            room_admin: true,
            ..AdminGrant::default()
        },
        &RoomParticipant {
            room: room_id,
            identity: participant_id,
        },
    )
    .await
}

/// Remove again whoever was removed from this meeting and is back in its
/// room: the SFU token they held still let them connect. Run whenever
/// someone in the meeting asks who its hosts are (every browser does when
/// the people in the room change) or a host looks at who is waiting, so it
/// needs no host present. It costs one query for a meeting nobody was
/// removed from. A failure is logged and tried again at the next question.
pub(super) async fn keep_removed_out(state: &AppState, room_id: &str) {
    let outcome: AppResult<()> = async {
        let removed: Vec<String> = sqlx::query_scalar(
            "SELECT participant_id FROM chat_call_link_removed
             WHERE room_id = $1 AND removed_at > NOW() - make_interval(secs => $2)",
        )
        .bind(room_id)
        .bind(REMEMBER_REMOVED_SECONDS as f64)
        .fetch_all(&state.pool)
        .await?;
        if removed.is_empty() {
            return Ok(());
        }
        let Some(answer) = room_service_answer(
            state,
            "ListParticipants",
            AdminGrant {
                room: Some(room_id),
                room_admin: true,
                ..AdminGrant::default()
            },
            &RoomName { room: room_id },
        )
        .await?
        else {
            return Ok(());
        };
        for identity in identities(&answer) {
            if !removed.iter().any(|id| id == identity) {
                continue;
            }
            tracing::info!(room_id, "a removed participant was back in the meeting");
            // Remembered from now, so they are kept out while they keep trying.
            sqlx::query(
                "UPDATE chat_call_link_removed SET removed_at = NOW()
                 WHERE room_id = $1 AND participant_id = $2",
            )
            .bind(room_id)
            .bind(identity)
            .execute(&state.pool)
            .await?;
            disconnect(state, room_id, identity).await?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = outcome {
        tracing::warn!(?error, room_id, "could not keep removed participants out");
    }
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
}

fn role_name(role: i16) -> &'static str {
    if role == OWNER {
        "owner"
    } else {
        "coHost"
    }
}

/// Who the meeting's hosts are, for anyone holding the link, and the
/// asker's own role.
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
    let (_, asker) = asker(&state, &credentials).await?;
    keep_removed_out(&state, &credentials.room_id).await;
    let rows: Vec<(String, i16)> = sqlx::query_as(
        "SELECT participant_id, role FROM chat_call_link_roles
         WHERE room_id = $1 ORDER BY role, created_at",
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
        (status = 404, description = "No such link, or not its owner"),
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
    let room_id = &request.room_id;
    if request.enabled {
        let changed = sqlx::query(
            "INSERT INTO chat_call_link_roles (room_id, participant_id, role) VALUES ($1, $2, $3)
             ON CONFLICT (room_id, participant_id) DO UPDATE SET role = EXCLUDED.role
             WHERE chat_call_link_roles.role <> $4",
        )
        .bind(room_id)
        .bind(&request.participant_id)
        .bind(CO_HOST)
        .bind(OWNER)
        .execute(&state.pool)
        .await?
        .rows_affected();
        if changed == 0 {
            return Err(AppError::conflict(
                "that participant is the meeting's owner",
            ));
        }
    } else {
        sqlx::query(
            "DELETE FROM chat_call_link_roles
             WHERE room_id = $1 AND participant_id = $2 AND role = $3",
        )
        .bind(room_id)
        .bind(&request.participant_id)
        .bind(CO_HOST)
        .execute(&state.pool)
        .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

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
    hex32("participantId", &request.participant_id)?;
    let asker = host(
        &state,
        &HostCredentials {
            room_id: request.room_id.clone(),
            access_token: request.access_token.clone(),
            host_token: request.host_token.clone(),
            sfu_token: request.sfu_token.clone(),
        },
    )
    .await?;
    let room_id = &request.room_id;
    let target: Option<i16> = sqlx::query_scalar(
        "SELECT role FROM chat_call_link_roles WHERE room_id = $1 AND participant_id = $2",
    )
    .bind(room_id)
    .bind(&request.participant_id)
    .fetch_optional(&state.pool)
    .await?;
    let may = match (&asker, target) {
        // Nobody removes the owner; the owner leaves or ends the meeting.
        (_, Some(OWNER)) => false,
        (Asker::Owner, _) => true,
        (_, Some(_)) => false,
        (_, None) => true,
    };
    if !may {
        return Err(AppError::forbidden("a host cannot be removed by a co-host"));
    }
    // The door first: once it is shut, disconnecting them is final.
    sqlx::query(
        "UPDATE chat_call_links SET waiting_room = TRUE
         WHERE room_id = $1 AND host_token_hash IS NOT NULL",
    )
    .bind(room_id)
    .execute(&state.pool)
    .await?;
    sqlx::query("DELETE FROM chat_call_link_roles WHERE room_id = $1 AND participant_id = $2")
        .bind(room_id)
        .bind(&request.participant_id)
        .execute(&state.pool)
        .await?;
    // Someone who was let in could collect a fresh SFU token with the ticket
    // of that knock: it now says they were turned away.
    sqlx::query(
        "UPDATE chat_call_link_knocks SET status = 2 WHERE room_id = $1 AND participant_id = $2",
    )
    .bind(room_id)
    .bind(&request.participant_id)
    .execute(&state.pool)
    .await?;
    // Their SFU token still works: remember the identity, to remove it again
    // if it comes back.
    sqlx::query(
        "DELETE FROM chat_call_link_removed
         WHERE room_id = $1 AND removed_at < NOW() - make_interval(secs => $2)",
    )
    .bind(room_id)
    .bind(REMEMBER_REMOVED_SECONDS as f64)
    .execute(&state.pool)
    .await?;
    sqlx::query(
        "INSERT INTO chat_call_link_removed (room_id, participant_id) VALUES ($1, $2)
         ON CONFLICT (room_id, participant_id) DO UPDATE SET removed_at = NOW()",
    )
    .bind(room_id)
    .bind(&request.participant_id)
    .execute(&state.pool)
    .await?;
    disconnect(&state, room_id, &request.participant_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// End the meeting for everyone in it, as its owner. The link keeps working
/// for another time; whoever was waiting is turned away.
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
    // Waiting or already let in: no knock of this sitting gets a token now.
    sqlx::query("UPDATE chat_call_link_knocks SET status = 2 WHERE room_id = $1")
        .bind(room_id)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM chat_call_link_roles WHERE room_id = $1")
        .bind(room_id)
        .execute(&state.pool)
        .await?;
    room_service(
        &state,
        "DeleteRoom",
        AdminGrant {
            room_create: true,
            ..AdminGrant::default()
        },
        &RoomName { room: room_id },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_owner_and_co_hosts_are_hosts() {
        assert!(Asker::Owner.is_host());
        assert!(Asker::Participant {
            id: "a".into(),
            co_host: true
        }
        .is_host());
        assert!(!Asker::Participant {
            id: "a".into(),
            co_host: false
        }
        .is_host());
        assert!(!Asker::Holder.is_host());
    }

    #[test]
    fn a_co_host_removes_only_those_who_are_not_hosts() {
        // The rule of `remove_participant`, spelled out.
        let may = |asker: &Asker, target: Option<i16>| match (asker, target) {
            (_, Some(OWNER)) => false,
            (Asker::Owner, _) => true,
            (_, Some(_)) => false,
            (_, None) => true,
        };
        let co_host = Asker::Participant {
            id: "a".into(),
            co_host: true,
        };
        assert!(may(&Asker::Owner, None));
        assert!(may(&Asker::Owner, Some(CO_HOST)));
        assert!(!may(&Asker::Owner, Some(OWNER)));
        assert!(may(&co_host, None));
        assert!(!may(&co_host, Some(CO_HOST)));
        assert!(!may(&co_host, Some(OWNER)));
    }

    #[test]
    fn identities_are_read_from_a_participant_list() {
        let answer = serde_json::json!({
            "participants": [{ "identity": "aa", "state": "ACTIVE" }, { "sid": "PA_x" }, { "identity": "bb" }]
        });
        assert_eq!(identities(&answer), ["aa", "bb"]);
        assert!(identities(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn admin_grants_carry_only_what_a_call_needs() {
        let remove = serde_json::to_value(AdminGrant {
            room: Some("room"),
            room_admin: true,
            ..AdminGrant::default()
        })
        .unwrap();
        assert_eq!(
            remove,
            serde_json::json!({ "room": "room", "roomAdmin": true })
        );
        let end = serde_json::to_value(AdminGrant {
            room_create: true,
            ..AdminGrant::default()
        })
        .unwrap();
        assert_eq!(end, serde_json::json!({ "roomCreate": true }));
    }
}
