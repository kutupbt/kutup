//! Profile keys handed over through Drive shares (docs/plans/unified-profile.md).
//!
//! Someone who shares a folder, or is shared one, gives the other person the
//! key to their end-to-end encrypted profile, so Drive can show a name and a
//! picture instead of an address. The key travels in a
//! [`ProfileKeyEnvelopeV1`]: sealed to the recipient's Drive key and signed by
//! the sender, so this server stores and forwards it without reading it. It
//! is accepted only between two people with a share between them, in either
//! direction; one key per pair, whatever the number of shared folders. People
//! are their server and account id (docs/plans/account-ids.md), never their
//! names: a rename on either side changes nothing here.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::profile_key_share::{ProfileKeyEnvelopeV1, ProfileKeyParties};
use kutup_federation_proto::FederationFeature;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::drive_federation::{configured_stack, gateway_error, signed_app_error, signed_json};
use crate::error::{AppError, AppResult};
use crate::federation::FederationRequestSpec;
use crate::handlers::chat::canonical_profile_version;
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

const JSON_CONTENT_TYPE: &str = "application/json";
const FED_PATH: &str = "/api/fed/drive/profile-keys";
const MAX_ENVELOPE_CHARS: usize = 2048;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutProfileKeyRequest {
    /// The person the key is for: their server and account id.
    pub recipient_server: String,
    pub recipient_account_id: String,
    /// Base64 `ProfileKeyEnvelopeV1`.
    pub envelope: String,
    /// The version the key opens, so the sender can tell when it is stale.
    pub profile_version: String,
}

/// Someone you share a folder with, either way round.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrivePerson {
    /// Who they are: their server and account id.
    pub server: String,
    pub account_id: String,
    /// Their address now, to show (`user@server`).
    pub account: String,
    /// On this server; the keys below are then filled in. For someone on
    /// another server, look them up through `/api/drive/federation/users`.
    pub local: bool,
    pub account_incarnation_id: Option<String>,
    /// Their Drive HPKE key, to seal them your profile key.
    pub drive_public_key: Option<String>,
    /// Their Drive signing key, to check the profile key they gave you.
    pub drive_signing_public_key: Option<String>,
    /// Their profile key, sealed to you (`ProfileKeyEnvelopeV1`), if they gave it.
    pub received_envelope: Option<String>,
    /// The version of the profile key you last gave them.
    pub sent_profile_version: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrivePeopleResponse {
    pub people: Vec<DrivePerson>,
}

/// Server-to-server delivery of a profile key to someone on this server.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedProfileKey {
    #[schema(value_type = Object)]
    pub sender: AccountRef,
    #[schema(value_type = Object)]
    pub recipient: AccountRef,
    pub envelope: String,
    pub profile_version: String,
}

struct LocalUser {
    id: Uuid,
    incarnation: String,
    signing_public_key: String,
}

fn decode_envelope(envelope: &str) -> AppResult<ProfileKeyEnvelopeV1> {
    if envelope.len() > MAX_ENVELOPE_CHARS {
        return Err(AppError::bad_request("invalid profile key envelope"));
    }
    ProfileKeyEnvelopeV1::decode_b64(envelope)
        .map_err(|_| AppError::bad_request("invalid profile key envelope"))
}

async fn local_user(pool: &PgPool, id: Uuid) -> AppResult<Option<LocalUser>> {
    let row: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, account_incarnation_id, drive_signing_public_key
         FROM users WHERE id = $1 AND is_active = true",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(id, incarnation, signing)| {
        signing.map(|signing_public_key| LocalUser {
            id,
            incarnation,
            signing_public_key,
        })
    }))
}

fn account_uuid(person: &AccountRef) -> Uuid {
    Uuid::parse_str(&person.account_id).expect("an AccountRef holds a canonical UUID")
}

/// Whether two local people share a folder or a file, either way round.
async fn local_pair_shares(pool: &PgPool, a: Uuid, b: Uuid) -> AppResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM collection_shares cs
            JOIN collections c ON c.id = cs.collection_id AND c.deleted_at IS NULL
            WHERE (c.owner_user_id = $1 AND cs.recipient_user_id = $2)
               OR (c.owner_user_id = $2 AND cs.recipient_user_id = $1))
         OR EXISTS (
            SELECT 1 FROM file_shares fs
            JOIN files f ON f.id = fs.file_id AND f.deleted_at IS NULL
            JOIN collections c ON c.id = f.collection_id AND c.deleted_at IS NULL
            WHERE (c.owner_user_id = $1 AND fs.recipient_user_id = $2)
               OR (c.owner_user_id = $2 AND fs.recipient_user_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await?)
}

/// Whether a local person and someone on another server share a folder,
/// either way round: matched by their account id, never their name.
async fn remote_pair_shares(pool: &PgPool, local: Uuid, remote: &AccountRef) -> AppResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM federated_outgoing_shares s
            JOIN collections c ON c.id = s.collection_id AND c.deleted_at IS NULL
            WHERE s.sharer_user_id = $1 AND s.recipient_domain = $2 AND s.recipient_account_id = $3)
         OR EXISTS (
            SELECT 1 FROM federated_incoming_shares
            WHERE user_id = $1 AND remote_domain = $2 AND owner_user_id = $3)",
    )
    .bind(local)
    .bind(&remote.server)
    .bind(account_uuid(remote))
    .fetch_one(pool)
    .await?)
}

async fn store(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    direction: &str,
    peer: &AccountRef,
    peer_incarnation_id: &str,
    envelope: &str,
    profile_version: &str,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO drive_profile_keys
             (user_id, direction, peer_server, peer_account_id, peer_incarnation_id, envelope,
              profile_version)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (user_id, direction, peer_server, peer_account_id) DO UPDATE SET
             peer_incarnation_id = EXCLUDED.peer_incarnation_id,
             envelope = EXCLUDED.envelope,
             profile_version = EXCLUDED.profile_version,
             updated_at = now()",
    )
    .bind(user_id)
    .bind(direction)
    .bind(&peer.server)
    .bind(account_uuid(peer))
    .bind(peer_incarnation_id)
    .bind(envelope)
    .bind(profile_version)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `GET /api/drive/people` — everyone you share a folder with or who
/// shares one with you, with what you need to exchange profile keys, and
/// the keys exchanged so far.
#[utoipa::path(
    get,
    path = "/api/drive/people",
    tag = "drive",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "People you share with", body = DrivePeopleResponse))
)]
pub async fn list_people(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<DrivePeopleResponse>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let domain = state.config.chat_server_name.as_str();
    type LocalRow = (Uuid, String, String, String, Option<String>);
    let local: Vec<LocalRow> = sqlx::query_as(
        "SELECT u.id, u.username, u.account_incarnation_id, u.public_key, u.drive_signing_public_key
         FROM users u
         WHERE u.is_active = true AND u.username IS NOT NULL AND u.id <> $1 AND u.id IN (
             SELECT cs.recipient_user_id FROM collection_shares cs
             JOIN collections c ON c.id = cs.collection_id AND c.deleted_at IS NULL
             WHERE c.owner_user_id = $1
             UNION
             SELECT c.owner_user_id FROM collection_shares cs
             JOIN collections c ON c.id = cs.collection_id AND c.deleted_at IS NULL
             WHERE cs.recipient_user_id = $1
             UNION
             SELECT fs.recipient_user_id FROM file_shares fs
             JOIN files f ON f.id = fs.file_id AND f.deleted_at IS NULL
             JOIN collections c ON c.id = f.collection_id AND c.deleted_at IS NULL
             WHERE c.owner_user_id = $1
             UNION
             SELECT c.owner_user_id FROM file_shares fs
             JOIN files f ON f.id = fs.file_id AND f.deleted_at IS NULL
             JOIN collections c ON c.id = f.collection_id AND c.deleted_at IS NULL
             WHERE fs.recipient_user_id = $1)
         ORDER BY u.username",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    // Remote people by (server, account id), with the address each share
    // last named them by (kept current by rename announces), to show.
    let remote: Vec<(String, Uuid, String)> = sqlx::query_as(
        "SELECT DISTINCT ON (server, account_id) server, account_id, account FROM (
             SELECT s.recipient_domain AS server, s.recipient_account_id AS account_id,
                    s.recipient_username || '@' || s.recipient_domain AS account
               FROM federated_outgoing_shares s
               JOIN collections c ON c.id = s.collection_id AND c.deleted_at IS NULL
              WHERE s.sharer_user_id = $1
             UNION ALL
             SELECT remote_domain, owner_user_id, owner_account
               FROM federated_incoming_shares WHERE user_id = $1) people
         ORDER BY server, account_id, account",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let exchanged: Vec<(String, String, Uuid, String, String)> = sqlx::query_as(
        "SELECT direction, peer_server, peer_account_id, envelope, profile_version
         FROM drive_profile_keys WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let mut received = std::collections::HashMap::new();
    let mut sent = std::collections::HashMap::new();
    for (direction, server, account_id, envelope, version) in exchanged {
        if direction == "received" {
            received.insert((server, account_id), envelope);
        } else {
            sent.insert((server, account_id), version);
        }
    }
    let mut people: Vec<DrivePerson> = local
        .into_iter()
        .map(|(id, username, incarnation, public_key, signing)| {
            let key = (domain.to_owned(), id);
            DrivePerson {
                received_envelope: received.remove(&key),
                sent_profile_version: sent.remove(&key),
                server: domain.to_owned(),
                account_id: id.to_string(),
                account: format!("{username}@{domain}"),
                local: true,
                account_incarnation_id: Some(incarnation),
                drive_public_key: Some(public_key),
                drive_signing_public_key: signing,
            }
        })
        .collect();
    people.extend(remote.into_iter().map(|(server, account_id, account)| {
        let key = (server.clone(), account_id);
        DrivePerson {
            received_envelope: received.remove(&key),
            sent_profile_version: sent.remove(&key),
            server,
            account_id: account_id.to_string(),
            account,
            local: false,
            account_incarnation_id: None,
            drive_public_key: None,
            drive_signing_public_key: None,
        }
    }));
    people.sort_by(|a, b| a.account.cmp(&b.account));
    Ok(Json(DrivePeopleResponse { people }))
}

/// `PUT /api/drive/profile-keys` — give someone you share a folder with
/// (either way round) your profile key. Delivered to their server when
/// they are on another one; `404` when there is no share between you.
#[utoipa::path(
    put,
    path = "/api/drive/profile-keys",
    tag = "drive",
    security(("BearerAuth" = [])),
    request_body = PutProfileKeyRequest,
    responses(
        (status = 204, description = "Stored or delivered"),
        (status = 404, description = "No share with that person")
    )
)]
pub async fn put_profile_key(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<PutProfileKeyRequest>,
) -> AppResult<Response> {
    if !canonical_profile_version(&request.profile_version) {
        return Err(AppError::bad_request("invalid profile version"));
    }
    let me = local_user(&state.pool, trusted_uuid(&user.user_id)?)
        .await?
        .ok_or_else(|| AppError::conflict("account identity is unavailable"))?;
    let local_domain = state.config.chat_server_name.as_str();
    let mine = crate::account_ids::local(local_domain, me.id)?;
    let recipient =
        crate::account_ids::remote(&request.recipient_server, &request.recipient_account_id)?;
    if recipient == mine {
        return Err(AppError::bad_request("a profile key goes to someone else"));
    }

    // Sealed by me, now, to the named person, and signed by my Drive key.
    let envelope = decode_envelope(&request.envelope)?;
    let signing = STANDARD
        .decode(&me.signing_public_key)
        .map_err(|_| AppError::conflict("account identity is unavailable"))?;
    let recipient_incarnation = hex::encode(envelope.recipient_incarnation_id);
    envelope
        .verify(
            &ProfileKeyParties {
                sender: &mine,
                sender_incarnation_id: &me.incarnation,
                recipient: &recipient,
                recipient_incarnation_id: &recipient_incarnation,
            },
            &signing,
        )
        .map_err(|_| AppError::bad_request("profile key envelope does not match"))?;

    if recipient.server == local_domain {
        let other = local_user(&state.pool, account_uuid(&recipient))
            .await?
            .filter(|other| other.incarnation == recipient_incarnation)
            .ok_or_else(|| AppError::not_found("no share with that person"))?;
        if !local_pair_shares(&state.pool, me.id, other.id).await? {
            return Err(AppError::not_found("no share with that person"));
        }
        let mut tx = state.pool.begin().await?;
        store(
            &mut tx,
            me.id,
            "sent",
            &recipient,
            &recipient_incarnation,
            &request.envelope,
            &request.profile_version,
        )
        .await?;
        store(
            &mut tx,
            other.id,
            "received",
            &mine,
            &me.incarnation,
            &request.envelope,
            &request.profile_version,
        )
        .await?;
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    if !remote_pair_shares(&state.pool, me.id, &recipient).await? {
        return Err(AppError::not_found("no share with that person"));
    }
    let federation = configured_stack(&state)?;
    let body = serde_json::to_vec(&FederatedProfileKey {
        sender: mine,
        recipient: recipient.clone(),
        envelope: request.envelope.clone(),
        profile_version: request.profile_version.clone(),
    })
    .map_err(|error| AppError::internal(format!("serialize profile key: {error}")))?;
    let response = federation
        .send(
            &recipient.server,
            FederationRequestSpec {
                feature: FederationFeature::DriveV1,
                method: Method::PUT,
                path: FED_PATH.into(),
                query: None,
                content_type: JSON_CONTENT_TYPE.into(),
                body,
                request_id: Uuid::new_v4().to_string(),
                extra_headers: Vec::new(),
                response_limit: 16 * 1024,
            },
        )
        .await
        .map_err(gateway_error)?;
    match response.status {
        StatusCode::OK => {}
        StatusCode::NOT_FOUND => return Err(AppError::not_found("no share with that person")),
        status => {
            return Err(AppError::new(
                StatusCode::BAD_GATEWAY,
                format!("their server refused the profile key ({status})"),
            ))
        }
    }
    let mut conn = state.pool.acquire().await?;
    store(
        &mut conn,
        me.id,
        "sent",
        &recipient,
        &recipient_incarnation,
        &request.envelope,
        &request.profile_version,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Signed server-to-server delivery of a profile key from someone on the
/// calling server to someone here they share a folder with. The recipient's
/// client checks the sender's signature; this server checks the parties.
#[utoipa::path(
    put,
    path = "/api/fed/drive/profile-keys",
    tag = "drive federation",
    request_body = FederatedProfileKey,
    responses(
        (status = 200, description = "Stored"),
        (status = 401, description = "Invalid federation request signature"),
        (status = 404, description = "No share between them")
    )
)]
pub async fn receive_profile_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "PUT",
            FED_PATH,
            None,
            &body,
            FederationFeature::DriveV1,
        )
        .await?;
    let result: AppResult<()> = async {
        let delivery: FederatedProfileKey = serde_json::from_slice(&body)
            .map_err(|_| AppError::bad_request("invalid profile key"))?;
        if !canonical_profile_version(&delivery.profile_version) {
            return Err(AppError::bad_request("invalid profile version"));
        }
        if delivery.sender.server != authenticated.origin()
            || delivery.recipient.server != state.config.chat_server_name
        {
            return Err(AppError::forbidden("profile key is for another server"));
        }
        let not_shared = || AppError::not_found("no share between them");
        let recipient = local_user(&state.pool, account_uuid(&delivery.recipient))
            .await?
            .ok_or_else(not_shared)?;
        let envelope = decode_envelope(&delivery.envelope)?;
        if envelope.sender != delivery.sender
            || envelope.recipient != delivery.recipient
            || hex::encode(envelope.recipient_incarnation_id) != recipient.incarnation
        {
            return Err(AppError::bad_request("profile key envelope does not match"));
        }
        if !remote_pair_shares(&state.pool, recipient.id, &delivery.sender).await? {
            return Err(not_shared());
        }
        let mut conn = state.pool.acquire().await?;
        store(
            &mut conn,
            recipient.id,
            "received",
            &delivery.sender,
            &hex::encode(envelope.sender_incarnation_id),
            &delivery.envelope,
            &delivery.profile_version,
        )
        .await
    }
    .await;
    match result {
        Ok(()) => signed_json(federation, &authenticated, StatusCode::OK, &json!({})),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}
