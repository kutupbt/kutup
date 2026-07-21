//! Drive feature adapter for the unified federation v2 stack.
//!
//! Server identity, discovery, admission, pinning, replay protection, HTTP
//! signatures, and SSRF-safe routing belong to `FederationStack`. This module
//! owns only Drive account lookup and per-share capability authorization.

use std::io::Write as _;

use aws_sdk_s3::primitives::ByteStream;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::stream;
use kutup_federation_proto::{
    content_digest_sha256_from_digest, validate_server_name, FederationFeature,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;
use time::OffsetDateTime;
use tokio::io::AsyncReadExt as _;
use tokio_util::io::ReaderStream;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::federation::{
    AuthenticatedFederationRequest, FederationDirection, FederationRequestSpec, FederationStack,
};
use crate::handlers::{random_token, trusted_uuid};
use crate::middleware::AuthUser;
use crate::AppState;

const JSON_CONTENT_TYPE: &str = "application/json";
const OCTET_STREAM_CONTENT_TYPE: &str = "application/octet-stream";
const SHARE_CAPABILITY_HEADER: &str = "kutup-share-capability";
const MAX_DIRECTORY_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_LIST_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_DRIVE_OBJECT_BYTES: usize = 10 * 1024 * 1024 * 1024;
const MAX_MULTIPART_FIELD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDriveUserQuery {
    pub server: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteDriveUserResponse {
    pub username: String,
    pub server: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateFederatedShareRequest {
    pub recipient_username: String,
    pub recipient_server: String,
    pub encrypted_collection_key: String,
    pub can_upload: bool,
    pub can_delete: bool,
    pub upload_quota_bytes: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateFederatedShareResponse {
    pub invite_url: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveInviteResponse {
    pub source_server: String,
    pub recipient_username: String,
    pub wrapped_key: String,
    pub encrypted_name: String,
    pub name_nonce: String,
    pub can_upload: bool,
    pub can_delete: bool,
    pub upload_quota_bytes: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AcceptFederatedShareRequest {
    pub server: String,
    pub capability: String,
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct IncomingDriveShare {
    pub id: Uuid,
    pub remote_domain: String,
    pub encrypted_collection_key: String,
    pub encrypted_name: String,
    pub name_nonce: String,
    pub can_upload: bool,
    pub can_delete: bool,
    pub upload_quota_bytes: Option<i64>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedDriveFile {
    pub id: Uuid,
    pub collection_id: Uuid,
    pub uploader_user_id: Uuid,
    pub encrypted_metadata: String,
    pub metadata_nonce: String,
    pub encrypted_file_key: String,
    pub file_key_nonce: String,
    pub encrypted_size_bytes: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FederatedDriveUploadResponse {
    pub id: Uuid,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct OutgoingShare {
    id: Uuid,
    collection_id: Uuid,
    sharer_user_id: Uuid,
    recipient_username: String,
    can_upload: bool,
    can_delete: bool,
    upload_quota_bytes: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct IncomingShareSecret {
    remote_domain: String,
    remote_capability: String,
}

#[derive(Debug)]
struct ParsedUpload {
    encrypted_metadata: String,
    metadata_nonce: String,
    encrypted_file_key: String,
    file_key_nonce: String,
    file: NamedTempFile,
    size: i64,
    digest: String,
}

fn configured_stack(state: &AppState) -> AppResult<&FederationStack> {
    state
        .federation
        .as_deref()
        .ok_or_else(|| AppError::bad_request("Drive federation is not configured"))
}

fn canonical_username(username: &str) -> AppResult<&str> {
    if username.is_empty()
        || username.len() > 64
        || !username.is_ascii()
        || !username.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(AppError::bad_request("invalid canonical username"));
    }
    Ok(username)
}

fn canonical_domain(domain: &str) -> AppResult<&str> {
    validate_server_name(domain).map_err(|error| AppError::bad_request(error.to_string()))?;
    Ok(domain)
}

fn capability_header(capability: &str) -> AppResult<(HeaderName, HeaderValue)> {
    validate_capability(capability)?;
    let value = HeaderValue::from_str(capability)
        .map_err(|_| AppError::bad_request("invalid Drive share capability"))?;
    Ok((HeaderName::from_static(SHARE_CAPABILITY_HEADER), value))
}

fn validate_capability(capability: &str) -> AppResult<()> {
    if !(32..=256).contains(&capability.len())
        || !capability
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
    {
        return Err(AppError::bad_request("invalid Drive share capability"));
    }
    Ok(())
}

fn capability_hash(capability: &str) -> String {
    hex::encode(Sha256::digest(capability.as_bytes()))
}

fn gateway_error(error: anyhow::Error) -> AppError {
    if error
        .downcast_ref::<crate::federation::FederationAdmissionError>()
        .is_some()
    {
        AppError::forbidden(error.to_string())
    } else {
        AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("federation transport failed: {error}"),
        )
    }
}

fn drive_spec(
    method: Method,
    path: String,
    content_type: String,
    body: Vec<u8>,
    capability: Option<&str>,
    response_limit: usize,
) -> AppResult<FederationRequestSpec> {
    let extra_headers = capability
        .map(capability_header)
        .transpose()?
        .into_iter()
        .collect();
    Ok(FederationRequestSpec {
        feature: FederationFeature::DriveV1,
        method,
        path,
        query: None,
        content_type,
        body,
        request_id: Uuid::new_v4().to_string(),
        extra_headers,
        response_limit,
    })
}

fn stable_mutation_request_id(operation: &str, scope: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"kutup-drive-federation-operation-v1\0");
    digest.update(operation.as_bytes());
    for value in scope {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    format!("{operation}-{}", hex::encode(digest.finalize()))
}

/// Local authenticated lookup of a remote Drive account through the pinned,
/// signed federation transport.
#[utoipa::path(
    get,
    path = "/api/drive/federation/users/{username}",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(
        ("username" = String, Path, description = "Remote canonical username"),
        ("server" = String, Query, description = "Remote canonical server domain")
    ),
    responses(
        (status = 200, description = "Authenticated remote Drive account", body = RemoteDriveUserResponse),
        (status = 404, description = "Remote account not found")
    )
)]
pub async fn fetch_remote_user(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(username): Path<String>,
    Query(query): Query<RemoteDriveUserQuery>,
) -> AppResult<Response> {
    let username = canonical_username(&username)?;
    let server = canonical_domain(&query.server)?;
    let federation = configured_stack(&state)?;
    let response = federation
        .send(
            server,
            drive_spec(
                Method::GET,
                format!("/api/fed/drive/users/{username}"),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                None,
                MAX_DIRECTORY_RESPONSE_BYTES,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    if response.status == StatusCode::NOT_FOUND {
        return Err(AppError::not_found("remote Drive user not found"));
    }
    if response.status != StatusCode::OK {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            format!("remote Drive directory returned {}", response.status),
        ));
    }
    let remote: RemoteDriveUserResponse = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid remote Drive user"))?;
    if remote.username != username || remote.server != server || remote.public_key.is_empty() {
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "remote Drive directory returned the wrong account",
        ));
    }
    Ok(Json(remote).into_response())
}

/// Create a domain-bound outgoing share and return its bearer capability only
/// inside a URL fragment. The plaintext capability is never stored locally.
#[utoipa::path(
    post,
    path = "/api/collections/{collectionId}/federated-shares",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("collectionId" = String, Path, description = "Owned collection id")),
    request_body = CreateFederatedShareRequest,
    responses((status = 201, description = "Domain-bound federated invite", body = CreateFederatedShareResponse))
)]
pub async fn create_federated_share(
    State(state): State<AppState>,
    user: AuthUser,
    Path(collection_id): Path<String>,
    Json(request): Json<CreateFederatedShareRequest>,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let recipient_username = canonical_username(&request.recipient_username)?;
    let recipient_domain = canonical_domain(&request.recipient_server)?;
    if request.encrypted_collection_key.is_empty()
        || request.upload_quota_bytes.is_some_and(|quota| quota < 0)
    {
        return Err(AppError::bad_request("invalid federated share"));
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
    let collection_id =
        Uuid::parse_str(&collection_id).map_err(|_| AppError::forbidden("forbidden"))?;
    let actual_owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT owner_user_id FROM collections WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(collection_id)
    .fetch_optional(&state.pool)
    .await?;
    if actual_owner != Some(owner) {
        return Err(AppError::forbidden("forbidden"));
    }

    let capability = random_token(32);
    let hash = capability_hash(&capability);
    sqlx::query(
        "INSERT INTO federated_outgoing_shares
            (collection_id, sharer_user_id, recipient_username,
             recipient_domain, encrypted_collection_key, capability_hash,
             can_upload, can_delete, upload_quota_bytes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(collection_id)
    .bind(owner)
    .bind(recipient_username)
    .bind(recipient_domain)
    .bind(&request.encrypted_collection_key)
    .bind(hash)
    .bind(request.can_upload)
    .bind(request.can_delete)
    .bind(request.upload_quota_bytes)
    .execute(&state.pool)
    .await?;

    let invite_url = format!(
        "{}/invite#server={}&capability={}",
        state.config.server_url.trim_end_matches('/'),
        federation.server_name(),
        capability
    );
    Ok((
        StatusCode::CREATED,
        Json(CreateFederatedShareResponse { invite_url }),
    )
        .into_response())
}

/// Signed server-to-server Drive account lookup.
#[utoipa::path(
    get,
    path = "/api/fed/drive/users/{username}",
    tag = "drive federation",
    params(("username" = String, Path)),
    responses((status = 200, description = "Signed local Drive account", body = RemoteDriveUserResponse))
)]
pub async fn get_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let path = format!("/api/fed/drive/users/{username}");
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
        let username = match canonical_username(&username) {
            Ok(username) => username,
            Err(error) => return signed_app_error(federation, &authenticated, error),
        };
        let public_key: Option<String> = sqlx::query_scalar(
            "SELECT public_key FROM users WHERE username = $1 AND is_active = true",
        )
        .bind(username)
        .fetch_optional(&state.pool)
        .await?;
        let Some(public_key) = public_key else {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::not_found("Drive user not found"),
            );
        };
        signed_json(
            federation,
            &authenticated,
            StatusCode::OK,
            &RemoteDriveUserResponse {
                username: username.to_owned(),
                server: federation.server_name().to_owned(),
                public_key,
            },
        )
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

/// Accept an invite on the recipient server after fetching its metadata over
/// the pinned remote identity and confirming the intended local username.
#[utoipa::path(
    post,
    path = "/api/drive/federation/shares",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    request_body = AcceptFederatedShareRequest,
    responses((status = 201, description = "Incoming federated share accepted", body = IncomingDriveShare))
)]
pub async fn accept_incoming_share(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<AcceptFederatedShareRequest>,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let server = canonical_domain(&request.server)?;
    validate_capability(&request.capability)?;
    let user_id = trusted_uuid(&user.user_id)?;
    let local_username: Option<String> =
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1 AND is_active = true")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    let local_username = local_username.ok_or_else(|| AppError::unauthorized("unauthorized"))?;
    let response = federation
        .send(
            server,
            drive_spec(
                Method::GET,
                "/api/fed/drive/invite".into(),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                Some(&request.capability),
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
            "federated Drive invite is unavailable",
        ));
    }
    let invite: DriveInviteResponse = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "invalid Drive invite"))?;
    if invite.source_server != server || invite.recipient_username != local_username {
        return Err(AppError::forbidden(
            "federated Drive invite is intended for another account or server",
        ));
    }
    let hash = capability_hash(&request.capability);
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO federated_incoming_shares
            (user_id, remote_domain, remote_capability, capability_hash,
             encrypted_collection_key, encrypted_name, name_nonce,
             can_upload, can_delete, upload_quota_bytes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (user_id, remote_domain, capability_hash) DO UPDATE SET
             encrypted_collection_key = EXCLUDED.encrypted_collection_key,
             encrypted_name = EXCLUDED.encrypted_name,
             name_nonce = EXCLUDED.name_nonce,
             can_upload = EXCLUDED.can_upload,
             can_delete = EXCLUDED.can_delete,
             upload_quota_bytes = EXCLUDED.upload_quota_bytes
         RETURNING id",
    )
    .bind(user_id)
    .bind(server)
    .bind(&request.capability)
    .bind(hash)
    .bind(&invite.wrapped_key)
    .bind(&invite.encrypted_name)
    .bind(&invite.name_nonce)
    .bind(invite.can_upload)
    .bind(invite.can_delete)
    .bind(invite.upload_quota_bytes)
    .fetch_one(&state.pool)
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(IncomingDriveShare {
            id,
            remote_domain: server.to_owned(),
            encrypted_collection_key: invite.wrapped_key,
            encrypted_name: invite.encrypted_name,
            name_nonce: invite.name_nonce,
            can_upload: invite.can_upload,
            can_delete: invite.can_delete,
            upload_quota_bytes: invite.upload_quota_bytes,
            created_at: OffsetDateTime::now_utc(),
        }),
    )
        .into_response())
}

#[utoipa::path(
    get,
    path = "/api/drive/federation/shares",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Incoming federated shares", body = Vec<IncomingDriveShare>))
)]
pub async fn list_incoming_shares(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let rows: Vec<IncomingDriveShare> = sqlx::query_as(
        "SELECT id, remote_domain, encrypted_collection_key, encrypted_name,
                  name_nonce, can_upload, can_delete, upload_quota_bytes, created_at
           FROM federated_incoming_shares
           WHERE user_id = $1 ORDER BY created_at ASC",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows).into_response())
}

#[utoipa::path(
    delete,
    path = "/api/drive/federation/shares/{shareId}",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("shareId" = String, Path)),
    responses((status = 204, description = "Incoming share removed"))
)]
pub async fn remove_incoming_share(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let share_id = Uuid::parse_str(&share_id).map_err(|_| AppError::not_found("not found"))?;
    let result =
        sqlx::query("DELETE FROM federated_incoming_shares WHERE id = $1 AND user_id = $2")
            .bind(share_id)
            .bind(user_id)
            .execute(&state.pool)
            .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found("share not found"));
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn incoming_share(
    state: &AppState,
    user: &AuthUser,
    share_id: &str,
) -> AppResult<IncomingShareSecret> {
    let user_id = trusted_uuid(&user.user_id)?;
    let share_id = Uuid::parse_str(share_id).map_err(|_| AppError::not_found("share not found"))?;
    sqlx::query_as(
        "SELECT remote_domain, remote_capability
         FROM federated_incoming_shares WHERE id = $1 AND user_id = $2",
    )
    .bind(share_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("share not found"))
}

#[utoipa::path(
    get,
    path = "/api/drive/federation/shares/{shareId}/files",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("shareId" = String, Path)),
    responses((status = 200, description = "Verified remote file list", body = Vec<FederatedDriveFile>))
)]
pub async fn proxy_list_files(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> AppResult<Response> {
    let share = incoming_share(&state, &user, &share_id).await?;
    let response = configured_stack(&state)?
        .send(
            &share.remote_domain,
            drive_spec(
                Method::GET,
                "/api/fed/drive/files".into(),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                Some(&share.remote_capability),
                MAX_LIST_RESPONSE_BYTES,
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

#[utoipa::path(
    get,
    path = "/api/drive/federation/shares/{shareId}/files/{fileId}/content",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("shareId" = String, Path), ("fileId" = String, Path)),
    responses((status = 200, description = "Digest-verified encrypted file stream"))
)]
pub async fn proxy_download(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, file_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let share = incoming_share(&state, &user, &share_id).await?;
    let file_id = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("file not found"))?;
    let response = configured_stack(&state)?
        .send_streamed(
            &share.remote_domain,
            drive_spec(
                Method::GET,
                format!("/api/fed/drive/files/{file_id}/content"),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                Some(&share.remote_capability),
                MAX_DRIVE_OBJECT_BYTES,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    let stream = ReaderStream::new(response.file);
    Response::builder()
        .status(response.status)
        .header(header::CONTENT_TYPE, response.content_type)
        .header(header::CONTENT_LENGTH, response.content_length)
        .body(Body::from_stream(stream))
        .map_err(|error| AppError::internal(error.to_string()))
}

#[utoipa::path(
    post,
    path = "/api/drive/federation/shares/{shareId}/files",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("shareId" = String, Path)),
    request_body(content = Vec<u8>, content_type = "multipart/form-data"),
    responses((status = 201, description = "Remote encrypted file stored", body = FederatedDriveUploadResponse))
)]
pub async fn proxy_upload(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let share = incoming_share(&state, &user, &share_id).await?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::bad_request("multipart content type required"))?
        .to_owned();
    if !content_type.starts_with("multipart/form-data;") {
        return Err(AppError::bad_request("multipart content type required"));
    }
    let content_type = canonical_multipart_content_type(&content_type)?;
    let request_id = stable_mutation_request_id(
        "upload",
        &[user.user_id.as_bytes(), share_id.as_bytes(), &body],
    );
    let mut spec = drive_spec(
        Method::POST,
        "/api/fed/drive/files".into(),
        content_type,
        body.to_vec(),
        Some(&share.remote_capability),
        MAX_DIRECTORY_RESPONSE_BYTES,
    )?;
    spec.request_id = request_id;
    let response = configured_stack(&state)?
        .send(&share.remote_domain, spec)
        .await
        .map_err(gateway_error)?;
    Ok((
        response.status,
        [(header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
        response.body,
    )
        .into_response())
}

fn canonical_multipart_content_type(value: &str) -> AppResult<String> {
    let boundary = multer::parse_boundary(value)
        .map_err(|_| AppError::bad_request("invalid multipart form"))?;
    // Federation signature inputs deliberately reject optional whitespace.
    // Reconstruct the media type using a token boundary so the value signed by
    // the proxy is byte-for-byte the value sent to the peer.
    if boundary.is_empty() || boundary.len() > 70 || !boundary.bytes().all(is_http_token_byte) {
        return Err(AppError::bad_request("invalid multipart boundary"));
    }
    Ok(format!("multipart/form-data;boundary={boundary}"))
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[utoipa::path(
    delete,
    path = "/api/drive/federation/shares/{shareId}/files/{fileId}",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("shareId" = String, Path), ("fileId" = String, Path)),
    responses((status = 204, description = "Remote encrypted file deleted"))
)]
pub async fn proxy_delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, file_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let share = incoming_share(&state, &user, &share_id).await?;
    let file_id = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("file not found"))?;
    let mut spec = drive_spec(
        Method::DELETE,
        format!("/api/fed/drive/files/{file_id}"),
        JSON_CONTENT_TYPE.into(),
        Vec::new(),
        Some(&share.remote_capability),
        MAX_DIRECTORY_RESPONSE_BYTES,
    )?;
    spec.request_id = stable_mutation_request_id(
        "delete",
        &[
            user.user_id.as_bytes(),
            share_id.as_bytes(),
            file_id.as_bytes(),
        ],
    );
    let response = configured_stack(&state)?
        .send(&share.remote_domain, spec)
        .await
        .map_err(gateway_error)?;
    Ok((
        response.status,
        [(header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
        response.body,
    )
        .into_response())
}

#[utoipa::path(
    get,
    path = "/api/fed/drive/invite",
    tag = "drive federation",
    responses((status = 200, description = "Signed capability-authorized invite", body = DriveInviteResponse))
)]
pub async fn get_invite(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            "/api/fed/drive/invite",
            None,
            &[],
            FederationFeature::DriveV1,
        )
        .await?;
    let result: AppResult<Response> = async {
        let share = match outgoing_share(&state, &authenticated, &headers, false).await {
            Ok(share) => share,
            Err(error) => return signed_app_error(federation, &authenticated, error),
        };
        let collection: Option<(String, String, String)> = sqlx::query_as(
            "SELECT c.encrypted_name, c.name_nonce, s.encrypted_collection_key
         FROM collections c
         JOIN federated_outgoing_shares s ON s.collection_id = c.id
         WHERE s.id = $1 AND c.deleted_at IS NULL",
        )
        .bind(share.id)
        .fetch_optional(&state.pool)
        .await?;
        let Some((encrypted_name, name_nonce, wrapped_key)) = collection else {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::not_found("Drive invite not found"),
            );
        };
        signed_json(
            federation,
            &authenticated,
            StatusCode::OK,
            &DriveInviteResponse {
                source_server: federation.server_name().to_owned(),
                recipient_username: share.recipient_username,
                wrapped_key,
                encrypted_name,
                name_nonce,
                can_upload: share.can_upload,
                can_delete: share.can_delete,
                upload_quota_bytes: share.upload_quota_bytes,
            },
        )
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

#[utoipa::path(
    get,
    path = "/api/fed/drive/files",
    tag = "drive federation",
    responses((status = 200, description = "Signed capability-authorized file list", body = Vec<FederatedDriveFile>))
)]
pub async fn list_files(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            "/api/fed/drive/files",
            None,
            &[],
            FederationFeature::DriveV1,
        )
        .await?;
    let result: AppResult<Response> = async {
        let share = match outgoing_share(&state, &authenticated, &headers, false).await {
            Ok(share) => share,
            Err(error) => return signed_app_error(federation, &authenticated, error),
        };
        let files: Vec<FederatedDriveFile> = sqlx::query_as(
            "SELECT id, collection_id, uploader_user_id, encrypted_metadata,
                metadata_nonce, encrypted_file_key, file_key_nonce,
                encrypted_size_bytes, created_at, updated_at
         FROM files WHERE collection_id = $1 AND deleted_at IS NULL
         ORDER BY created_at DESC",
        )
        .bind(share.collection_id)
        .fetch_all(&state.pool)
        .await?;
        signed_json(federation, &authenticated, StatusCode::OK, &files)
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

#[utoipa::path(
    get,
    path = "/api/fed/drive/files/{fileId}/content",
    tag = "drive federation",
    params(("fileId" = String, Path)),
    responses((status = 200, description = "Signed encrypted file stream"))
)]
pub async fn download_file(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let path = format!("/api/fed/drive/files/{file_id}/content");
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
        let share = match outgoing_share(&state, &authenticated, &headers, false).await {
            Ok(share) => share,
            Err(error) => return signed_app_error(federation, &authenticated, error),
        };
        let file_id = match Uuid::parse_str(&file_id) {
            Ok(file_id) => file_id,
            Err(_) => {
                return signed_app_error(
                    federation,
                    &authenticated,
                    AppError::not_found("file not found"),
                )
            }
        };
        let file: Option<(String, i64, Option<String>)> = sqlx::query_as(
            "SELECT storage_path, encrypted_size_bytes, ciphertext_sha256
         FROM files WHERE id = $1 AND collection_id = $2 AND deleted_at IS NULL",
        )
        .bind(file_id)
        .bind(share.collection_id)
        .fetch_optional(&state.pool)
        .await?;
        let Some((storage_path, size, stored_digest)) = file else {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::not_found("file not found"),
            );
        };
        let digest = match stored_digest {
            Some(digest) => digest,
            None => match ensure_ciphertext_digest(&state, file_id, &storage_path).await {
                Ok(digest) => digest,
                Err(error) => return signed_app_error(federation, &authenticated, error),
            },
        };
        let decoded =
            hex::decode(&digest).map_err(|_| AppError::internal("invalid stored digest"))?;
        let digest: [u8; 32] = decoded
            .try_into()
            .map_err(|_| AppError::internal("invalid stored digest"))?;
        let content_digest = content_digest_sha256_from_digest(&digest);
        let (object, object_size) = state
            .storage
            .get_object(&storage_path)
            .await
            .map_err(|error| AppError::internal(format!("read Drive object: {error}")))?;
        if object_size != size {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::internal("Drive object size does not match metadata"),
            );
        }
        let stream = ReaderStream::new(object.into_async_read());
        federation.signed_stream_response(
            &authenticated,
            StatusCode::OK,
            OCTET_STREAM_CONTENT_TYPE,
            &content_digest,
            object_size as u64,
            Body::from_stream(stream),
        )
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

#[utoipa::path(
    post,
    path = "/api/fed/drive/files",
    tag = "drive federation",
    request_body(content = Vec<u8>, content_type = "multipart/form-data"),
    responses((status = 201, description = "Idempotent encrypted upload", body = FederatedDriveUploadResponse))
)]
pub async fn upload_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "POST",
            "/api/fed/drive/files",
            None,
            &body,
            FederationFeature::DriveV1,
        )
        .await?;
    let result: AppResult<Response> = async {
        let share = match outgoing_share(&state, &authenticated, &headers, true).await {
            Ok(share) => share,
            Err(error) => return signed_app_error(federation, &authenticated, error),
        };
        if !share.can_upload {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::forbidden("upload not permitted"),
            );
        }
        let content_type = match headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            Some(value) => value,
            None => {
                return signed_app_error(
                    federation,
                    &authenticated,
                    AppError::bad_request("multipart content type required"),
                )
            }
        };
        let parsed = match parse_upload(content_type, body).await {
            Ok(parsed) => parsed,
            Err(error) => return signed_app_error(federation, &authenticated, error),
        };
        let metadata = authenticated.replay_metadata()?;
        let operation = "upload";
        let mut tx = state.pool.begin().await?;
        lock_drive_mutation(&mut tx, metadata.origin(), metadata.request_id()).await?;
        if let Some(response) = prior_mutation(
            &mut tx,
            metadata.origin(),
            metadata.request_id(),
            metadata.request_hash(),
            operation,
        )
        .await?
        {
            tx.rollback().await?;
            return federation.signed_response(
                &authenticated,
                response.0,
                JSON_CONTENT_TYPE,
                response.1,
            );
        }
        let used: i64 = sqlx::query_scalar(
            "SELECT upload_used_bytes FROM federated_outgoing_shares WHERE id = $1 FOR UPDATE",
        )
        .bind(share.id)
        .fetch_one(&mut *tx)
        .await?;
        if share
            .upload_quota_bytes
            .is_some_and(|quota| used.saturating_add(parsed.size) > quota)
        {
            tx.rollback().await?;
            return signed_app_error(
                federation,
                &authenticated,
                AppError::new(StatusCode::PAYLOAD_TOO_LARGE, "share quota exceeded"),
            );
        }

        let file_id = Uuid::new_v4();
        let storage_path = format!("fed/{}/{}/{}", share.id, share.collection_id, file_id);
        let object = ByteStream::from_path(parsed.file.path())
            .await
            .map_err(|error| AppError::internal(format!("read upload: {error}")))?;
        state
            .storage
            .upload(&storage_path, object, parsed.size)
            .await
            .map_err(|error| AppError::internal(format!("store Drive upload: {error}")))?;
        let response_body = serde_json::to_vec(&FederatedDriveUploadResponse { id: file_id })
            .map_err(|error| AppError::internal(error.to_string()))?;
        let result: AppResult<()> = async {
            sqlx::query(
                "INSERT INTO files
                (id, collection_id, uploader_user_id, encrypted_metadata,
                 metadata_nonce, encrypted_file_key, file_key_nonce,
                 storage_path, encrypted_size_bytes, ciphertext_sha256)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            )
            .bind(file_id)
            .bind(share.collection_id)
            .bind(share.sharer_user_id)
            .bind(&parsed.encrypted_metadata)
            .bind(&parsed.metadata_nonce)
            .bind(&parsed.encrypted_file_key)
            .bind(&parsed.file_key_nonce)
            .bind(&storage_path)
            .bind(parsed.size)
            .bind(&parsed.digest)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE federated_outgoing_shares
             SET upload_used_bytes = upload_used_bytes + $1 WHERE id = $2",
            )
            .bind(parsed.size)
            .bind(share.id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id = $2",
            )
            .bind(parsed.size)
            .bind(share.sharer_user_id)
            .execute(&mut *tx)
            .await?;
            record_mutation(
                &mut tx,
                metadata.origin(),
                metadata.request_id(),
                metadata.request_hash(),
                share.id,
                operation,
                StatusCode::CREATED,
                &response_body,
            )
            .await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            let _ = state.storage.delete(&storage_path).await;
            return signed_app_error(federation, &authenticated, error);
        }
        federation.signed_response(
            &authenticated,
            StatusCode::CREATED,
            JSON_CONTENT_TYPE,
            response_body,
        )
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

#[utoipa::path(
    delete,
    path = "/api/fed/drive/files/{fileId}",
    tag = "drive federation",
    params(("fileId" = String, Path)),
    responses((status = 204, description = "Idempotent encrypted file deletion"))
)]
pub async fn delete_file(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let path = format!("/api/fed/drive/files/{file_id}");
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "DELETE",
            &path,
            None,
            &[],
            FederationFeature::DriveV1,
        )
        .await?;
    let result: AppResult<Response> = async {
    let share = match outgoing_share(&state, &authenticated, &headers, true).await {
        Ok(share) => share,
        Err(error) => return signed_app_error(federation, &authenticated, error),
    };
    if !share.can_delete {
        return signed_app_error(
            federation,
            &authenticated,
            AppError::forbidden("delete not permitted"),
        );
    }
    let file_id = match Uuid::parse_str(&file_id) {
        Ok(file_id) => file_id,
        Err(_) => {
            return signed_app_error(
                federation,
                &authenticated,
                AppError::not_found("file not found"),
            )
        }
    };
    let metadata = authenticated.replay_metadata()?;
    let operation = "delete";
    let mut tx = state.pool.begin().await?;
    lock_drive_mutation(&mut tx, metadata.origin(), metadata.request_id()).await?;
    if let Some(response) = prior_mutation(
        &mut tx,
        metadata.origin(),
        metadata.request_id(),
        metadata.request_hash(),
        operation,
    )
    .await?
    {
        tx.rollback().await?;
        return federation.signed_response(
            &authenticated,
            response.0,
            JSON_CONTENT_TYPE,
            response.1,
        );
    }
    let file: Option<(String, i64)> = sqlx::query_as(
        "SELECT storage_path, encrypted_size_bytes FROM files
         WHERE id = $1 AND collection_id = $2 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(file_id)
    .bind(share.collection_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((storage_path, size)) = file else {
        tx.rollback().await?;
        return signed_app_error(
            federation,
            &authenticated,
            AppError::not_found("file not found"),
        );
    };
    sqlx::query("DELETE FROM files WHERE id = $1")
        .bind(file_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE federated_outgoing_shares
         SET upload_used_bytes = GREATEST(0, upload_used_bytes - $1) WHERE id = $2",
    )
    .bind(size)
    .bind(share.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1) WHERE id = $2",
    )
    .bind(size)
    .bind(share.sharer_user_id)
    .execute(&mut *tx)
    .await?;
    record_mutation(
        &mut tx,
        metadata.origin(),
        metadata.request_id(),
        metadata.request_hash(),
        share.id,
        operation,
        StatusCode::NO_CONTENT,
        &[],
    )
    .await?;
    tx.commit().await?;
    if let Err(error) = state.storage.delete(&storage_path).await {
        tracing::warn!(%error, %storage_path, "deleted federated Drive row but object cleanup failed");
    }
    federation.signed_response(
        &authenticated,
        StatusCode::NO_CONTENT,
        JSON_CONTENT_TYPE,
        Vec::new(),
    )
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

async fn outgoing_share(
    state: &AppState,
    authenticated: &AuthenticatedFederationRequest,
    headers: &HeaderMap,
    _mutation: bool,
) -> AppResult<OutgoingShare> {
    let capability = headers
        .get(SHARE_CAPABILITY_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::not_found("Drive share not found"))?;
    validate_capability(capability).map_err(|_| AppError::not_found("Drive share not found"))?;
    let hash = capability_hash(capability);
    sqlx::query_as(
        "SELECT s.id, s.collection_id, s.sharer_user_id, s.recipient_username,
                s.can_upload, s.can_delete, s.upload_quota_bytes
         FROM federated_outgoing_shares s
         JOIN collections c ON c.id = s.collection_id AND c.deleted_at IS NULL
         WHERE s.capability_hash = $1 AND s.recipient_domain = $2",
    )
    .bind(hash)
    .bind(authenticated.origin())
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Drive share not found"))
}

async fn parse_upload(content_type: &str, body: Bytes) -> AppResult<ParsedUpload> {
    let boundary = multer::parse_boundary(content_type)
        .map_err(|_| AppError::bad_request("invalid multipart form"))?;
    let body_stream = stream::once(async move { Ok::<Bytes, std::io::Error>(body) });
    let mut multipart = multer::Multipart::new(body_stream, boundary);
    let mut encrypted_metadata = None;
    let mut metadata_nonce = None;
    let mut encrypted_file_key = None;
    let mut file_key_nonce = None;
    let mut uploaded_file = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::bad_request("invalid multipart form"))?
    {
        match field.name() {
            Some("encryptedMetadata") => {
                encrypted_metadata = Some(limited_field_text(field).await?)
            }
            Some("metadataNonce") => metadata_nonce = Some(limited_field_text(field).await?),
            Some("encryptedFileKey") => encrypted_file_key = Some(limited_field_text(field).await?),
            Some("fileKeyNonce") => file_key_nonce = Some(limited_field_text(field).await?),
            Some("file") => {
                if uploaded_file.is_some() {
                    return Err(AppError::bad_request("only one file may be uploaded"));
                }
                let mut file = NamedTempFile::new()
                    .map_err(|error| AppError::internal(format!("create temp file: {error}")))?;
                let mut size = 0_i64;
                let mut digest = Sha256::new();
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|_| AppError::bad_request("invalid uploaded file"))?
                {
                    size = size.checked_add(chunk.len() as i64).ok_or_else(|| {
                        AppError::new(StatusCode::PAYLOAD_TOO_LARGE, "file too large")
                    })?;
                    digest.update(&chunk);
                    file.write_all(&chunk).map_err(|error| {
                        AppError::internal(format!("write upload temp file: {error}"))
                    })?;
                }
                uploaded_file = Some((file, size, hex::encode(digest.finalize())));
            }
            _ => {}
        }
    }
    let (file, size, digest) =
        uploaded_file.ok_or_else(|| AppError::bad_request("no file provided"))?;
    let required = |value: Option<String>, name: &str| {
        value
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::bad_request(format!("{name} required")))
    };
    Ok(ParsedUpload {
        encrypted_metadata: required(encrypted_metadata, "encryptedMetadata")?,
        metadata_nonce: required(metadata_nonce, "metadataNonce")?,
        encrypted_file_key: required(encrypted_file_key, "encryptedFileKey")?,
        file_key_nonce: required(file_key_nonce, "fileKeyNonce")?,
        file,
        size,
        digest,
    })
}

async fn limited_field_text(field: multer::Field<'_>) -> AppResult<String> {
    let bytes = field
        .bytes()
        .await
        .map_err(|_| AppError::bad_request("invalid multipart field"))?;
    if bytes.len() > MAX_MULTIPART_FIELD_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "multipart metadata field too large",
        ));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| AppError::bad_request("multipart metadata must be UTF-8"))
}

async fn ensure_ciphertext_digest(
    state: &AppState,
    file_id: Uuid,
    storage_path: &str,
) -> AppResult<String> {
    let (object, _) = state
        .storage
        .get_object(storage_path)
        .await
        .map_err(|error| AppError::internal(format!("read Drive object for digest: {error}")))?;
    let mut reader = object.into_async_read();
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut digest = Sha256::new();
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|error| AppError::internal(format!("hash Drive object: {error}")))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let digest = hex::encode(digest.finalize());
    sqlx::query(
        "UPDATE files SET ciphertext_sha256 = $2
         WHERE id = $1 AND ciphertext_sha256 IS NULL",
    )
    .bind(file_id)
    .bind(&digest)
    .execute(&state.pool)
    .await?;
    Ok(digest)
}

pub fn spawn_digest_backfill(state: AppState) {
    if state.federation.is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            let rows: Result<Vec<(Uuid, String)>, sqlx::Error> = sqlx::query_as(
                "SELECT id, storage_path FROM files
                 WHERE ciphertext_sha256 IS NULL AND deleted_at IS NULL
                 ORDER BY created_at, id LIMIT 10",
            )
            .fetch_all(&state.pool)
            .await;
            match rows {
                Ok(rows) => {
                    for (file_id, storage_path) in rows {
                        if let Err(error) =
                            ensure_ciphertext_digest(&state, file_id, &storage_path).await
                        {
                            tracing::warn!(%error, %file_id, "Drive ciphertext digest backfill failed");
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "Drive ciphertext digest backfill query failed")
                }
            }
        }
    });
}

async fn lock_drive_mutation(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    origin: &str,
    request_id: &str,
) -> AppResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(drive_mutation_lock_key(origin, request_id))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn drive_mutation_lock_key(origin: &str, request_id: &str) -> String {
    // PostgreSQL text cannot contain NUL. A decimal length prefix keeps the
    // pair unambiguous without relying on a delimiter accepted by either
    // validated federation field.
    format!("{}:{origin}{request_id}", origin.len())
}

async fn prior_mutation(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    origin: &str,
    request_id: &str,
    request_hash: &str,
    operation: &str,
) -> AppResult<Option<(StatusCode, Vec<u8>)>> {
    let row: Option<(String, String, i16, String, Vec<u8>)> = sqlx::query_as(
        "SELECT request_hash, operation, response_status,
                response_content_type, response_body
         FROM drive_federation_mutations
         WHERE origin = $1 AND request_id = $2",
    )
    .bind(origin)
    .bind(request_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((prior_hash, prior_operation, status, content_type, body)) = row else {
        return Ok(None);
    };
    if prior_hash != request_hash || prior_operation != operation {
        return Err(AppError::conflict(
            "federation request ID was reused for another Drive mutation",
        ));
    }
    if content_type != JSON_CONTENT_TYPE {
        return Err(AppError::internal(
            "stored Drive mutation has invalid content type",
        ));
    }
    let status = StatusCode::from_u16(status as u16)
        .map_err(|_| AppError::internal("stored Drive mutation has invalid status"))?;
    Ok(Some((status, body)))
}

#[allow(clippy::too_many_arguments)]
async fn record_mutation(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    origin: &str,
    request_id: &str,
    request_hash: &str,
    share_id: Uuid,
    operation: &str,
    status: StatusCode,
    body: &[u8],
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO drive_federation_mutations
            (origin, request_id, request_hash, share_id, operation,
             response_status, response_content_type, response_body)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(origin)
    .bind(request_id)
    .bind(request_hash)
    .bind(share_id)
    .bind(operation)
    .bind(status.as_u16() as i16)
    .bind(JSON_CONTENT_TYPE)
    .bind(body)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn signed_json<T: Serialize>(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    status: StatusCode,
    value: &T,
) -> AppResult<Response> {
    let body = serde_json::to_vec(value).map_err(|error| {
        AppError::internal(format!("serialize Drive federation response: {error}"))
    })?;
    federation.signed_response(authenticated, status, JSON_CONTENT_TYPE, body)
}

fn signed_app_error(
    federation: &FederationStack,
    authenticated: &AuthenticatedFederationRequest,
    error: AppError,
) -> AppResult<Response> {
    let message = if error.status.is_server_error() {
        tracing::error!(status = %error.status, error = %error.message, "Drive federation request failed");
        "internal server error".to_owned()
    } else {
        error.message
    };
    signed_json(
        federation,
        authenticated,
        error.status,
        &json!({ "error": message }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_and_canonical_identifiers_fail_closed() {
        assert!(canonical_username("alice_1").is_ok());
        assert!(canonical_username("Alice").is_err());
        assert!(canonical_username("-alice").is_err());
        assert!(canonical_domain("drive.example").is_ok());
        assert!(canonical_domain("https://drive.example").is_err());
        assert!(validate_capability("abcdefghijklmnopqrstuvwxyzABCDEFG0123456789").is_ok());
        assert!(validate_capability("short").is_err());
        assert!(validate_capability(&format!("{} ", "a".repeat(32))).is_err());
    }

    #[test]
    fn stable_mutation_ids_bind_operation_scope_and_exact_body() {
        let first = stable_mutation_request_id("upload", &[b"user", b"share", b"ciphertext"]);
        let retry = stable_mutation_request_id("upload", &[b"user", b"share", b"ciphertext"]);
        assert_eq!(first, retry);
        assert_ne!(
            first,
            stable_mutation_request_id("upload", &[b"user", b"share", b"changed"])
        );
        assert_ne!(
            retry,
            stable_mutation_request_id("delete", &[b"user", b"share", b"ciphertext"])
        );
        assert!(first.len() <= 128);
    }

    #[test]
    fn mutation_lock_keys_are_postgres_safe_and_unambiguous() {
        let first = drive_mutation_lock_key("a.test", "bc");
        let second = drive_mutation_lock_key("a.testb", "c");
        assert_ne!(first, second);
        assert!(!first.contains('\0'));
        assert_eq!(first, "6:a.testbc");
    }

    #[test]
    fn multipart_content_type_is_canonical_for_federation_signatures() {
        assert_eq!(
            canonical_multipart_content_type(
                "multipart/form-data; boundary=----WebKitFormBoundary123"
            )
            .unwrap(),
            "multipart/form-data;boundary=----WebKitFormBoundary123"
        );
        assert!(canonical_multipart_content_type(
            "multipart/form-data; boundary=\"boundary with spaces\""
        )
        .is_err());
    }

    #[tokio::test]
    async fn multipart_upload_hashes_exact_ciphertext() {
        let boundary = "kutup-drive-test-boundary";
        let ciphertext = b"encrypted bytes, not plaintext";
        let mut body = Vec::new();
        for (name, value) in [
            ("encryptedMetadata", "metadata"),
            ("metadataNonce", "metadata-nonce"),
            ("encryptedFileKey", "wrapped-file-key"),
            ("fileKeyNonce", "file-key-nonce"),
        ] {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"ciphertext\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(ciphertext);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let upload = parse_upload(
            &format!("multipart/form-data; boundary={boundary}"),
            Bytes::from(body),
        )
        .await
        .unwrap();
        assert_eq!(upload.size, ciphertext.len() as i64);
        assert_eq!(upload.digest, hex::encode(Sha256::digest(ciphertext)));
        assert_eq!(upload.encrypted_metadata, "metadata");
    }
}
