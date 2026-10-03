//! Profile keys handed over through Drive shares (docs/plans/unified-profile.md).
//!
//! Someone who shares a folder, or is shared one, gives the other person the
//! key to their end-to-end encrypted profile, so Drive can show a name and a
//! picture instead of an address. The key travels in a
//! [`ProfileKeyEnvelopeV1`]: sealed to the recipient's Drive key and signed by
//! the sender, so this server stores and forwards it without reading it. It
//! is accepted only between two people with a share between them, in either
//! direction; one key per pair, whatever the number of shared folders.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::profile_key_share::{ProfileKeyEnvelopeV1, ProfileKeyParties};
use kutup_federation_proto::FederationFeature;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::drive_federation::{
    canonical_domain, canonical_username, configured_stack, gateway_error, signed_app_error,
    signed_json,
};
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
#[serde(rename_all = "camelCase")]
pub struct PutProfileKeyRequest {
    /// Canonical `user@server` of the person the key is for.
    pub recipient_account: String,
    /// Base64 `ProfileKeyEnvelopeV1`.
    pub envelope: String,
    /// The version the key opens, so the sender can tell when it is stale.
    pub profile_version: String,
}

/// Someone you share a folder with, either way round.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrivePerson {
    /// Canonical `user@server`.
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
    pub sender_account: String,
    pub recipient_account: String,
    pub envelope: String,
    pub profile_version: String,
}

struct LocalUser {
    id: Uuid,
    username: String,
    incarnation: String,
    signing_public_key: String,
}

fn split_account(account: &str) -> AppResult<(&str, &str)> {
    let (username, domain) = account
        .rsplit_once('@')
        .ok_or_else(|| AppError::bad_request("invalid account"))?;
    Ok((canonical_username(username)?, canonical_domain(domain)?))
}

fn decode_envelope(envelope: &str) -> AppResult<ProfileKeyEnvelopeV1> {
    if envelope.len() > MAX_ENVELOPE_CHARS {
        return Err(AppError::bad_request("invalid profile key envelope"));
    }
    ProfileKeyEnvelopeV1::decode_b64(envelope)
        .map_err(|_| AppError::bad_request("invalid profile key envelope"))
}

async fn local_user_by_id(pool: &PgPool, id: Uuid) -> AppResult<LocalUser> {
    let row: Option<(Uuid, Option<String>, String, Option<String>)> = sqlx::query_as(
        "SELECT id, username, account_incarnation_id, drive_signing_public_key
         FROM users WHERE id = $1 AND is_active = true",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    match row {
        Some((id, Some(username), incarnation, Some(signing_public_key))) => Ok(LocalUser {
            id,
            username,
            incarnation,
            signing_public_key,
        }),
        _ => Err(AppError::conflict("account identity is unavailable")),
    }
}

async fn local_user_by_name(pool: &PgPool, username: &str) -> AppResult<Option<LocalUser>> {
    let row: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, account_incarnation_id, drive_signing_public_key
         FROM users WHERE username = $1 AND is_active = true",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(id, incarnation, signing)| {
        signing.map(|signing_public_key| LocalUser {
            id,
            username: username.to_owned(),
            incarnation,
            signing_public_key,
        })
    }))
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
/// either way round.
async fn remote_pair_shares(
    pool: &PgPool,
    local: Uuid,
    remote_username: &str,
    remote_domain: &str,
) -> AppResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM federated_outgoing_shares s
            JOIN collections c ON c.id = s.collection_id AND c.deleted_at IS NULL
            WHERE s.sharer_user_id = $1 AND s.recipient_username = $2 AND s.recipient_domain = $3)
         OR EXISTS (
            SELECT 1 FROM federated_incoming_shares
            WHERE user_id = $1 AND remote_domain = $3 AND owner_account = $4)",
    )
    .bind(local)
    .bind(remote_username)
    .bind(remote_domain)
    .bind(format!("{remote_username}@{remote_domain}"))
    .fetch_one(pool)
    .await?)
}

async fn store(
    pool: &PgPool,
    user_id: Uuid,
    direction: &str,
    peer_account: &str,
    envelope: &str,
    profile_version: &str,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO drive_profile_keys (user_id, direction, peer_account, envelope, profile_version)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id, direction, peer_account) DO UPDATE SET
             envelope = EXCLUDED.envelope,
             profile_version = EXCLUDED.profile_version,
             updated_at = now()",
    )
    .bind(user_id)
    .bind(direction)
    .bind(peer_account)
    .bind(envelope)
    .bind(profile_version)
    .execute(pool)
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
    type LocalRow = (String, String, String, Option<String>);
    let local: Vec<LocalRow> = sqlx::query_as(
        "SELECT u.username, u.account_incarnation_id, u.public_key, u.drive_signing_public_key
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
    let remote: Vec<String> = sqlx::query_scalar(
        "SELECT s.recipient_username || '@' || s.recipient_domain FROM federated_outgoing_shares s
         JOIN collections c ON c.id = s.collection_id AND c.deleted_at IS NULL
         WHERE s.sharer_user_id = $1
         UNION
         SELECT owner_account FROM federated_incoming_shares WHERE user_id = $1
         ORDER BY 1",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let exchanged: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT direction, peer_account, envelope, profile_version
         FROM drive_profile_keys WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let mut received = std::collections::HashMap::new();
    let mut sent = std::collections::HashMap::new();
    for (direction, peer, envelope, version) in exchanged {
        if direction == "received" {
            received.insert(peer, envelope);
        } else {
            sent.insert(peer, version);
        }
    }
    let mut people: Vec<DrivePerson> = local
        .into_iter()
        .map(|(username, incarnation, public_key, signing)| {
            let account = format!("{username}@{domain}");
            DrivePerson {
                received_envelope: received.remove(&account),
                sent_profile_version: sent.remove(&account),
                account,
                local: true,
                account_incarnation_id: Some(incarnation),
                drive_public_key: Some(public_key),
                drive_signing_public_key: signing,
            }
        })
        .collect();
    people.extend(remote.into_iter().map(|account| DrivePerson {
        received_envelope: received.remove(&account),
        sent_profile_version: sent.remove(&account),
        account,
        local: false,
        account_incarnation_id: None,
        drive_public_key: None,
        drive_signing_public_key: None,
    }));
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
    let me = local_user_by_id(&state.pool, trusted_uuid(&user.user_id)?).await?;
    let local_domain = state.config.chat_server_name.as_str();
    let my_account = format!("{}@{local_domain}", me.username);
    let (username, domain) = split_account(&request.recipient_account)?;
    let recipient_account = format!("{username}@{domain}");
    if recipient_account == my_account {
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
                sender_account: &my_account,
                sender_incarnation_id: &me.incarnation,
                recipient_account: &recipient_account,
                recipient_incarnation_id: &recipient_incarnation,
            },
            &signing,
        )
        .map_err(|_| AppError::bad_request("profile key envelope does not match"))?;

    if domain == local_domain {
        let recipient = local_user_by_name(&state.pool, username)
            .await?
            .filter(|recipient| recipient.incarnation == recipient_incarnation)
            .ok_or_else(|| AppError::not_found("no share with that person"))?;
        if !local_pair_shares(&state.pool, me.id, recipient.id).await? {
            return Err(AppError::not_found("no share with that person"));
        }
        let mut tx = state.pool.begin().await?;
        for (user_id, direction, peer) in [
            (me.id, "sent", recipient_account.as_str()),
            (recipient.id, "received", my_account.as_str()),
        ] {
            sqlx::query(
                "INSERT INTO drive_profile_keys (user_id, direction, peer_account, envelope, profile_version)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (user_id, direction, peer_account) DO UPDATE SET
                     envelope = EXCLUDED.envelope,
                     profile_version = EXCLUDED.profile_version,
                     updated_at = now()",
            )
            .bind(user_id)
            .bind(direction)
            .bind(peer)
            .bind(&request.envelope)
            .bind(&request.profile_version)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    if !remote_pair_shares(&state.pool, me.id, username, domain).await? {
        return Err(AppError::not_found("no share with that person"));
    }
    let federation = configured_stack(&state)?;
    let body = serde_json::to_vec(&FederatedProfileKey {
        sender_account: my_account,
        recipient_account: recipient_account.clone(),
        envelope: request.envelope.clone(),
        profile_version: request.profile_version.clone(),
    })
    .map_err(|error| AppError::internal(format!("serialize profile key: {error}")))?;
    let response = federation
        .send(
            domain,
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
    store(
        &state.pool,
        me.id,
        "sent",
        &recipient_account,
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
        let (sender_username, sender_domain) = split_account(&delivery.sender_account)?;
        let (recipient_username, recipient_domain) = split_account(&delivery.recipient_account)?;
        if sender_domain != authenticated.origin()
            || recipient_domain != state.config.chat_server_name
        {
            return Err(AppError::forbidden("profile key is for another server"));
        }
        let not_shared = || AppError::not_found("no share between them");
        let recipient = local_user_by_name(&state.pool, recipient_username)
            .await?
            .ok_or_else(not_shared)?;
        let envelope = decode_envelope(&delivery.envelope)?;
        if envelope.sender_account != delivery.sender_account
            || envelope.recipient_account != delivery.recipient_account
            || hex::encode(envelope.recipient_incarnation_id) != recipient.incarnation
        {
            return Err(AppError::bad_request("profile key envelope does not match"));
        }
        if !remote_pair_shares(&state.pool, recipient.id, sender_username, sender_domain).await? {
            return Err(not_shared());
        }
        store(
            &state.pool,
            recipient.id,
            "received",
            &delivery.sender_account,
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
