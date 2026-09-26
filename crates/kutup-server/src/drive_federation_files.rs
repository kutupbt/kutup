//! Sharing one file with someone on another server
//! (docs/plans/drive-file-sharing.md, slice 2), over the same signed
//! federation stack and capability pattern as folder invites
//! (`drive_federation`): the owner's server issues a capability for that
//! file alone; the recipient's server keeps it and relays reads for its
//! user. The browser never holds the capability.
//!
//! Reads only for now: the file's record and key, its content, and the saved
//! state of a note or place list. Editing across servers waits for the live
//! editing relay to federate.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::named_share::FileShareEnvelopeV1;
use kutup_federation_proto::{content_digest_sha256_from_digest, FederationFeature};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio_util::io::ReaderStream;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::drive_federation::{
    canonical_domain, canonical_public_key, canonical_username, capability_hash, configured_stack,
    drive_spec, ensure_ciphertext_digest, ensure_version_digest, gateway_error, signed_app_error,
    signed_json, validate_capability, FederatedDriveFile, JSON_CONTENT_TYPE,
    MAX_DIRECTORY_RESPONSE_BYTES, MAX_DRIVE_OBJECT_BYTES, OCTET_STREAM_CONTENT_TYPE,
    SHARE_CAPABILITY_HEADER,
};
use crate::error::{AppError, AppResult};
use crate::federation::{AuthenticatedFederationRequest, FederationDirection, FederationStack};
use crate::handlers::{random_token, trusted_uuid};
use crate::middleware::AuthUser;
use crate::AppState;

/// A note's or place list's saved state is bounded well below this.
const MAX_STATE_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateFederatedFileShareRequest {
    pub recipient_username: String,
    pub recipient_server: String,
    /// `FileShareEnvelopeV1` sealed to the remote account's Drive key.
    pub share_envelope: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateFederatedFileShareResponse {
    pub invite_url: String,
}

/// What the owner's server tells the recipient's about a file invite.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileInviteResponse {
    pub source_server: String,
    pub recipient_username: String,
    pub file: FederatedDriveFile,
    pub share_envelope: String,
    /// The generation the envelope opens.
    pub key_generation: i32,
    pub owner_user_id: Uuid,
    pub owner_account: String,
    pub owner_incarnation_id: String,
    pub owner_signing_public_key: String,
}

/// A note's or place list's latest saved state, sealed under the file key of
/// `key_generation`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileStateResponse {
    pub key_generation: i32,
    /// Base64.
    pub state: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptFederatedFileShareRequest {
    pub server: String,
    pub capability: String,
}

/// An accepted file from another server, as stored here.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct IncomingFileShare {
    pub id: Uuid,
    pub remote_domain: String,
    pub remote_file_id: Uuid,
    pub owner_account: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// An accepted file as it is now on its owner's server, checked.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IncomingFileShareNow {
    pub id: Uuid,
    pub remote_domain: String,
    pub file: FederatedDriveFile,
    pub share_envelope: String,
    pub key_generation: i32,
    pub owner_user_id: Uuid,
    pub owner_account: String,
    pub owner_incarnation_id: String,
    pub owner_signing_public_key: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

// ------------------------------------------------------------- owner's side

/// `POST /api/files/{id}/federated-shares` — share one of your files with
/// someone on another server. Returns an invite link (the capability only in
/// its fragment); only its hash is kept.
#[utoipa::path(
    post,
    path = "/api/files/{id}/federated-shares",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("id" = String, Path, description = "File id")),
    request_body = CreateFederatedFileShareRequest,
    responses((status = 201, description = "Domain-bound file invite", body = CreateFederatedFileShareResponse))
)]
pub async fn create_federated_file_share(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(request): Json<CreateFederatedFileShareRequest>,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let recipient_username = canonical_username(&request.recipient_username)?;
    let recipient_domain = canonical_domain(&request.recipient_server)?;
    if recipient_domain == federation.server_name() {
        return Err(AppError::bad_request(
            "that account is on this server: share with them here",
        ));
    }
    federation
        .resolve_peer(
            recipient_domain,
            FederationFeature::DriveV1,
            FederationDirection::Outbound,
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(gateway_error)?;
    let owner = trusted_uuid(&user.user_id)?;
    let file_id = Uuid::parse_str(&id).map_err(|_| AppError::not_found("not found"))?;
    let generation: Option<i32> = sqlx::query_scalar(
        "SELECT f.key_generation FROM files f JOIN collections c ON c.id = f.collection_id
         WHERE f.id = $1 AND c.owner_user_id = $2 AND f.deleted_at IS NULL AND c.deleted_at IS NULL",
    )
    .bind(file_id)
    .bind(owner)
    .fetch_optional(&state.pool)
    .await?;
    let Some(generation) = generation else {
        return Err(AppError::forbidden("only the owner shares this file"));
    };
    let sender: (Option<String>, String, String) = sqlx::query_as(
        "SELECT username, account_incarnation_id, drive_signing_public_key FROM users WHERE id = $1",
    )
    .bind(owner)
    .fetch_one(&state.pool)
    .await?;
    let sender_username = sender
        .0
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::conflict("sender identity is unavailable"))?;
    let envelope = FileShareEnvelopeV1::decode_b64(&request.share_envelope)
        .map_err(|_| AppError::bad_request("invalid file share"))?;
    let recipient_incarnation = hex::encode(envelope.recipient_incarnation_id);
    envelope
        .verify_binding_and_signature(
            &file_id.to_string(),
            u32::try_from(generation).map_err(|_| AppError::conflict("invalid key generation"))?,
            &format!("{sender_username}@{}", federation.server_name()),
            &sender.1,
            &canonical_public_key(&sender.2)?,
            &format!("{recipient_username}@{recipient_domain}"),
            &recipient_incarnation,
        )
        .map_err(|_| {
            AppError::bad_request("the file share does not match the file or the person")
        })?;

    let capability = random_token(32);
    sqlx::query(
        "INSERT INTO federated_outgoing_file_shares
            (file_id, sharer_user_id, recipient_username, recipient_domain,
             recipient_incarnation_id, share_envelope, key_generation, capability_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(file_id)
    .bind(owner)
    .bind(recipient_username)
    .bind(recipient_domain)
    .bind(&recipient_incarnation)
    .bind(&request.share_envelope)
    .bind(generation)
    .bind(capability_hash(&capability))
    .execute(&state.pool)
    .await?;
    let invite_url = format!(
        "{}/invite#server={}&capability={}&kind=file",
        state.config.server_url.trim_end_matches('/'),
        federation.server_name(),
        capability
    );
    Ok((
        StatusCode::CREATED,
        Json(CreateFederatedFileShareResponse { invite_url }),
    )
        .into_response())
}

struct OutgoingFileShare {
    file_id: Uuid,
    recipient_username: String,
    share_envelope: String,
    key_generation: i32,
}

/// The file share a signed request's capability names, when its file is live
/// and the request comes from the server it was issued to.
async fn outgoing_file_share(
    state: &AppState,
    authenticated: &AuthenticatedFederationRequest,
    headers: &HeaderMap,
) -> AppResult<OutgoingFileShare> {
    let capability = headers
        .get(SHARE_CAPABILITY_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::not_found("Drive share not found"))?;
    validate_capability(capability).map_err(|_| AppError::not_found("Drive share not found"))?;
    let row: Option<(Uuid, String, String, i32)> = sqlx::query_as(
        "SELECT s.file_id, s.recipient_username, s.share_envelope, s.key_generation
         FROM federated_outgoing_file_shares s
         JOIN files f ON f.id = s.file_id AND f.deleted_at IS NULL
         JOIN collections c ON c.id = f.collection_id AND c.deleted_at IS NULL
         WHERE s.capability_hash = $1 AND s.recipient_domain = $2",
    )
    .bind(capability_hash(capability))
    .bind(authenticated.origin())
    .fetch_optional(&state.pool)
    .await?;
    let (file_id, recipient_username, share_envelope, key_generation) =
        row.ok_or_else(|| AppError::not_found("Drive share not found"))?;
    Ok(OutgoingFileShare {
        file_id,
        recipient_username,
        share_envelope,
        key_generation,
    })
}

async fn federated_file(state: &AppState, file_id: Uuid) -> AppResult<FederatedDriveFile> {
    sqlx::query_as(&format!(
        "SELECT f.id, f.collection_id, f.uploader_user_id, f.metadata_envelope,
                f.file_key_envelope, f.key_epoch, f.key_generation, f.metadata_revision,
                f.encrypted_size_bytes, f.created_at, f.updated_at, f.original_key_generation,
                {} AS key_history, {} AS content_key_generation
         FROM files f WHERE f.id = $1 AND f.deleted_at IS NULL",
        crate::models::FILE_KEY_HISTORY_SQL,
        crate::models::CONTENT_KEY_GENERATION_SQL
    ))
    .bind(file_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("file not found"))
}

/// A signed, capability-authorized read: authenticate the calling server,
/// find the file share its capability names, run `read`; every error is
/// answered signed.
macro_rules! signed_read {
    ($state:expr, $headers:expr, $path:literal, |$federation:ident, $authenticated:ident, $share:ident| $read:block) => {{
        let $federation = configured_stack(&$state)?;
        let $authenticated = $federation
            .authenticate_inbound(
                &$headers,
                "GET",
                $path,
                None,
                &[],
                FederationFeature::DriveV1,
            )
            .await?;
        let result: AppResult<Response> = async {
            let $share = outgoing_file_share(&$state, &$authenticated, &$headers).await?;
            $read
        }
        .await;
        match result {
            Ok(response) => Ok(response),
            Err(error) => signed_app_error($federation, &$authenticated, error),
        }
    }};
}

/// `GET /api/fed/drive/file-invite` — the file behind a capability, its key
/// sealed to the recipient, and its owner's identity. Signed.
#[utoipa::path(
    get,
    path = "/api/fed/drive/file-invite",
    tag = "drive federation",
    responses((status = 200, description = "Signed capability-authorized file invite", body = FileInviteResponse))
)]
pub async fn get_file_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    signed_read!(
        state,
        headers,
        "/api/fed/drive/file-invite",
        |federation, authenticated, share| {
            let file = federated_file(&state, share.file_id).await?;
            let owner: (Uuid, Option<String>, String, Option<String>) = sqlx::query_as(
            "SELECT u.id, u.username, u.account_incarnation_id, u.drive_signing_public_key
             FROM files f JOIN collections c ON c.id = f.collection_id JOIN users u ON u.id = c.owner_user_id
             WHERE f.id = $1",
        )
        .bind(share.file_id)
        .fetch_one(&state.pool)
        .await?;
            let (owner_user_id, username, incarnation, signing) = owner;
            let unavailable = || AppError::conflict("owner identity is unavailable");
            signed_json(
                federation,
                &authenticated,
                StatusCode::OK,
                &FileInviteResponse {
                    source_server: federation.server_name().to_owned(),
                    recipient_username: share.recipient_username,
                    file,
                    share_envelope: share.share_envelope,
                    key_generation: share.key_generation,
                    owner_user_id,
                    owner_account: format!(
                        "{}@{}",
                        username.ok_or_else(unavailable)?,
                        federation.server_name()
                    ),
                    owner_incarnation_id: incarnation,
                    owner_signing_public_key: signing.ok_or_else(unavailable)?,
                },
            )
        }
    )
}

/// `GET /api/fed/drive/file-content` — the file as it is now (its latest
/// whole-file version, else the upload), as a signed encrypted stream.
#[utoipa::path(
    get,
    path = "/api/fed/drive/file-content",
    tag = "drive federation",
    responses((status = 200, description = "Signed encrypted file stream"))
)]
pub async fn get_file_content(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    signed_read!(
        state,
        headers,
        "/api/fed/drive/file-content",
        |federation, authenticated, share| {
            let stored_digest: Option<String> =
                sqlx::query_scalar("SELECT ciphertext_sha256 FROM files WHERE id = $1")
                    .bind(share.file_id)
                    .fetch_one(&state.pool)
                    .await?;
            let content = crate::file_content::current_content(&state.pool, share.file_id)
                .await?
                .ok_or_else(|| AppError::not_found("file not found"))?;
            let digest = match content.version {
                None => match stored_digest {
                    Some(digest) => digest,
                    None => ensure_ciphertext_digest(&state, share.file_id, &content.path).await?,
                },
                Some(version) => ensure_version_digest(&state, version, &content).await?,
            };
            let digest: [u8; 32] = hex::decode(&digest)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| AppError::internal("invalid stored digest"))?;
            let (object, size) = content
                .open(&state.storage)
                .await
                .map_err(|error| AppError::internal(format!("read Drive object: {error}")))?;
            if size != content.size {
                return Err(AppError::internal(
                    "Drive object size does not match metadata",
                ));
            }
            federation.signed_stream_response(
                &authenticated,
                StatusCode::OK,
                OCTET_STREAM_CONTENT_TYPE,
                &content_digest_sha256_from_digest(&digest),
                size as u64,
                Body::from_stream(ReaderStream::new(object.into_async_read())),
            )
        }
    )
}

/// `GET /api/fed/drive/file-state` — a note's or place list's latest saved
/// state (their edits are not whole-file versions). `404` when none. Signed.
#[utoipa::path(
    get,
    path = "/api/fed/drive/file-state",
    tag = "drive federation",
    responses((status = 200, description = "Signed saved state", body = FileStateResponse))
)]
pub async fn get_file_state(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    signed_read!(
        state,
        headers,
        "/api/fed/drive/file-state",
        |federation, authenticated, share| {
            let body = saved_state(&state, share.file_id).await?;
            signed_json(federation, &authenticated, StatusCode::OK, &body)
        }
    )
}

// --------------------------------------------------------- recipient's side

/// The owner's server's current invite for a capability, checked: meant for
/// this account, sealed to it by the named owner, for the file it names.
async fn fetch_verified_file_invite(
    federation: &FederationStack,
    server: &str,
    capability: &str,
    local_username: &str,
    local_incarnation: &str,
) -> AppResult<FileInviteResponse> {
    let response = federation
        .send(
            server,
            drive_spec(
                Method::GET,
                "/api/fed/drive/file-invite".into(),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                Some(capability),
                MAX_DIRECTORY_RESPONSE_BYTES,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            if response.status == StatusCode::NOT_FOUND {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_GATEWAY
            },
            "the shared file is unavailable",
        ));
    }
    let invite: FileInviteResponse = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid file invite"))?;
    if invite.source_server != server || invite.recipient_username != local_username {
        return Err(AppError::forbidden(
            "this file invite is for another account or server",
        ));
    }
    if !invite.owner_account.ends_with(&format!("@{server}")) {
        return Err(AppError::forbidden("the file's owner identity is invalid"));
    }
    FileShareEnvelopeV1::decode_b64(&invite.share_envelope)
        .and_then(|envelope| {
            envelope.verify_binding_and_signature(
                &invite.file.id.to_string(),
                u32::try_from(invite.key_generation).unwrap_or(0),
                &invite.owner_account,
                &invite.owner_incarnation_id,
                &canonical_public_key(&invite.owner_signing_public_key)
                    .map_err(|_| kutup_crypto::CryptoError::InvalidInput("key".into()))?,
                &format!("{}@{}", local_username, federation.server_name()),
                local_incarnation,
            )
        })
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid file share"))?;
    Ok(invite)
}

async fn local_identity(state: &AppState, user_id: Uuid) -> AppResult<(String, String)> {
    sqlx::query_as(
        "SELECT username, account_incarnation_id FROM users WHERE id = $1 AND is_active = true",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("unauthorized"))
}

/// `POST /api/drive/federation/file-shares` — accept a file invite from
/// another server (its capability is kept here, never given to the browser).
#[utoipa::path(
    post,
    path = "/api/drive/federation/file-shares",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    request_body = AcceptFederatedFileShareRequest,
    responses((status = 201, description = "Accepted", body = IncomingFileShare))
)]
pub async fn accept_file_share(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<AcceptFederatedFileShareRequest>,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let server = canonical_domain(&request.server)?;
    validate_capability(&request.capability)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let (username, incarnation) = local_identity(&state, user_id).await?;
    let invite = fetch_verified_file_invite(
        federation,
        server,
        &request.capability,
        &username,
        &incarnation,
    )
    .await?;
    let row: IncomingFileShare = sqlx::query_as(
        "INSERT INTO federated_incoming_file_shares
            (user_id, remote_domain, remote_capability, capability_hash, remote_file_id,
             owner_user_id, owner_account, owner_incarnation_id, owner_signing_public_key)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (user_id, remote_domain, capability_hash) DO UPDATE SET
             remote_file_id = EXCLUDED.remote_file_id
         RETURNING id, remote_domain, remote_file_id, owner_account, created_at",
    )
    .bind(user_id)
    .bind(server)
    .bind(&request.capability)
    .bind(capability_hash(&request.capability))
    .bind(invite.file.id)
    .bind(invite.owner_user_id)
    .bind(&invite.owner_account)
    .bind(&invite.owner_incarnation_id)
    .bind(&invite.owner_signing_public_key)
    .fetch_one(&state.pool)
    .await?;
    Ok((StatusCode::CREATED, Json(row)).into_response())
}

/// `GET /api/drive/federation/file-shares` — files accepted from other servers.
#[utoipa::path(
    get,
    path = "/api/drive/federation/file-shares",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Accepted files", body = Vec<IncomingFileShare>))
)]
pub async fn list_file_shares(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<IncomingFileShare>>> {
    let user_id = trusted_uuid(&user.user_id)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT id, remote_domain, remote_file_id, owner_account, created_at
             FROM federated_incoming_file_shares WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&state.pool)
        .await?,
    ))
}

struct IncomingSecret {
    id: Uuid,
    remote_domain: String,
    remote_capability: String,
    remote_file_id: Uuid,
    owner_user_id: Uuid,
    owner_incarnation_id: String,
    owner_signing_public_key: String,
    created_at: OffsetDateTime,
}

async fn incoming(state: &AppState, user: &AuthUser, id: &str) -> AppResult<IncomingSecret> {
    let user_id = trusted_uuid(&user.user_id)?;
    let id = Uuid::parse_str(id).map_err(|_| AppError::not_found("share not found"))?;
    type Row = (
        Uuid,
        String,
        String,
        Uuid,
        Uuid,
        String,
        String,
        OffsetDateTime,
    );
    let row: Row = sqlx::query_as(
        "SELECT id, remote_domain, remote_capability, remote_file_id, owner_user_id,
                owner_incarnation_id, owner_signing_public_key, created_at
         FROM federated_incoming_file_shares WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("share not found"))?;
    Ok(IncomingSecret {
        id: row.0,
        remote_domain: row.1,
        remote_capability: row.2,
        remote_file_id: row.3,
        owner_user_id: row.4,
        owner_incarnation_id: row.5,
        owner_signing_public_key: row.6,
        created_at: row.7,
    })
}

/// `GET /api/drive/federation/file-shares/{id}` — the file as it is now on
/// its owner's server, its key sealed to this account, checked. The owner
/// must be the one first accepted.
#[utoipa::path(
    get,
    path = "/api/drive/federation/file-shares/{id}",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    responses((status = 200, description = "The file now", body = IncomingFileShareNow), (status = 404, description = "No longer shared"))
)]
pub async fn get_file_share(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let share = incoming(&state, &user, &id).await?;
    let (username, incarnation) = local_identity(&state, trusted_uuid(&user.user_id)?).await?;
    let invite = fetch_verified_file_invite(
        federation,
        &share.remote_domain,
        &share.remote_capability,
        &username,
        &incarnation,
    )
    .await?;
    if invite.file.id != share.remote_file_id
        || invite.owner_user_id != share.owner_user_id
        || invite.owner_incarnation_id != share.owner_incarnation_id
        || invite.owner_signing_public_key != share.owner_signing_public_key
    {
        return Err(AppError::conflict(
            "the shared file's owner identity changed; accept the invite again",
        ));
    }
    Ok(Json(IncomingFileShareNow {
        id: share.id,
        remote_domain: share.remote_domain,
        file: invite.file,
        share_envelope: invite.share_envelope,
        key_generation: invite.key_generation,
        owner_user_id: invite.owner_user_id,
        owner_account: invite.owner_account,
        owner_incarnation_id: invite.owner_incarnation_id,
        owner_signing_public_key: invite.owner_signing_public_key,
        created_at: share.created_at,
    })
    .into_response())
}

/// `GET /api/drive/federation/file-shares/{id}/content` — the file's content,
/// relayed from its owner's server (still encrypted).
#[utoipa::path(
    get,
    path = "/api/drive/federation/file-shares/{id}/content",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    responses((status = 200, description = "The encrypted content"))
)]
pub async fn proxy_file_content(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let share = incoming(&state, &user, &id).await?;
    let response = configured_stack(&state)?
        .send_streamed(
            &share.remote_domain,
            drive_spec(
                Method::GET,
                "/api/fed/drive/file-content".into(),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                Some(&share.remote_capability),
                MAX_DRIVE_OBJECT_BYTES,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    Response::builder()
        .status(response.status)
        .header(header::CONTENT_TYPE, response.content_type)
        .header(header::CONTENT_LENGTH, response.content_length)
        .body(Body::from_stream(ReaderStream::new(response.file)))
        .map_err(|error| AppError::internal(error.to_string()))
}

/// `GET /api/drive/federation/file-shares/{id}/state` — a note's or place
/// list's saved state, relayed. `404` when none.
#[utoipa::path(
    get,
    path = "/api/drive/federation/file-shares/{id}/state",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    responses((status = 200, description = "The saved state", body = FileStateResponse))
)]
pub async fn proxy_file_state(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let share = incoming(&state, &user, &id).await?;
    let response = configured_stack(&state)?
        .send(
            &share.remote_domain,
            drive_spec(
                Method::GET,
                "/api/fed/drive/file-state".into(),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                Some(&share.remote_capability),
                MAX_STATE_RESPONSE_BYTES,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    Ok((
        response.status,
        [(header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
        response.body,
    )
        .into_response())
}

/// `DELETE /api/drive/federation/file-shares/{id}` — stop seeing a file
/// shared from another server.
#[utoipa::path(
    delete,
    path = "/api/drive/federation/file-shares/{id}",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("id" = String, Path)),
    responses((status = 204, description = "Removed"))
)]
pub async fn remove_file_share(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let share = incoming(&state, &user, &id).await?;
    sqlx::query("DELETE FROM federated_incoming_file_shares WHERE id = $1")
        .bind(share.id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The latest saved Yjs state of `file_id`, as a response body.
async fn saved_state(state: &AppState, file_id: Uuid) -> AppResult<FileStateResponse> {
    let latest: Option<(String, String, i32)> = sqlx::query_as(
        "SELECT storage_path, s3_version_id, key_generation FROM file_versions
         WHERE file_id = $1 AND kind = 'yjs' AND size_bytes > 0
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(file_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((path, s3_version_id, key_generation)) = latest else {
        return Err(AppError::not_found("no saved state"));
    };
    let (object, _) = if s3_version_id.is_empty() {
        state.storage.get_object(&path).await
    } else {
        state
            .storage
            .get_object_version(&path, &s3_version_id)
            .await
    }
    .map_err(|_| AppError::internal("storage"))?;
    let bytes = object
        .collect()
        .await
        .map_err(|_| AppError::internal("storage"))?
        .into_bytes();
    Ok(FileStateResponse {
        key_generation,
        state: STANDARD.encode(bytes),
    })
}

/// `GET /api/fed/drive/files/{fileId}/state` — a note's or place list's saved
/// state in a folder shared with the calling server's user. Signed.
#[utoipa::path(
    get,
    path = "/api/fed/drive/files/{fileId}/state",
    tag = "drive federation",
    params(("fileId" = String, Path)),
    responses((status = 200, description = "Signed saved state", body = FileStateResponse))
)]
pub async fn get_folder_file_state(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let path = format!("/api/fed/drive/files/{file_id}/state");
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            &path,
            None,
            &[],
            FederationFeature::DriveV1,
        )
        .await?;
    let result: AppResult<Response> = async {
        let share =
            crate::drive_federation::outgoing_share(&state, &authenticated, &headers, false).await?;
        let file_id =
            Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("file not found"))?;
        let in_folder: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM files WHERE id = $1 AND collection_id = $2 AND deleted_at IS NULL)",
        )
        .bind(file_id)
        .bind(share.collection_id)
        .fetch_one(&state.pool)
        .await?;
        if !in_folder {
            return Err(AppError::not_found("file not found"));
        }
        let body = saved_state(&state, file_id).await?;
        signed_json(federation, &authenticated, StatusCode::OK, &body)
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

/// `GET /api/drive/federation/shares/{shareId}/files/{fileId}/state` — a
/// note's or place list's saved state in a folder on another server, relayed.
#[utoipa::path(
    get,
    path = "/api/drive/federation/shares/{shareId}/files/{fileId}/state",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("shareId" = String, Path), ("fileId" = String, Path)),
    responses((status = 200, description = "The saved state", body = FileStateResponse))
)]
pub async fn proxy_folder_file_state(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, file_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let share = crate::drive_federation::incoming_share(&state, &user, &share_id).await?;
    let file_id = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("file not found"))?;
    let response = configured_stack(&state)?
        .send(
            &share.remote_domain,
            drive_spec(
                Method::GET,
                format!("/api/fed/drive/files/{file_id}/state"),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                Some(&share.remote_capability),
                MAX_STATE_RESPONSE_BYTES,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    Ok((
        response.status,
        [(header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
        response.body,
    )
        .into_response())
}
