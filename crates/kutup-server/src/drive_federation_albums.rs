//! Albums shared with people on other servers (docs/plans/photos.md, slice
//! 5), over the folder-invite stack (`drive_federation`): the owner's server
//! issues a capability for the album; the recipient's server keeps it and
//! relays reads for its user. An album holds references, so its photos live
//! in other folders: these routes list the album's items (each photo's key
//! sealed under the album key) and serve their thumbnails; content comes
//! through the folder route, which also reaches album items.
//!
//! View only: a person on another server does not add photos.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kutup_crypto::thumbnail::ThumbnailVariant;
use kutup_federation_proto::{content_digest_sha256_from_digest, FederationFeature};
use reqwest::Method;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use tokio_util::io::ReaderStream;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::drive_federation::{
    configured_stack, drive_spec, gateway_error, incoming_share, outgoing_share, signed_app_error,
    signed_json, FederatedDriveFile, JSON_CONTENT_TYPE, MAX_LIST_RESPONSE_BYTES,
    OCTET_STREAM_CONTENT_TYPE,
};
use crate::error::{AppError, AppResult};
use crate::handlers::file_thumbnails::thumbnail_storage_path;
use crate::middleware::AuthUser;
use crate::AppState;

/// Thumbnails are small pictures; anything larger is refused on the way in.
const MAX_THUMBNAIL_BYTES: usize = 4 * 1024 * 1024;

/// A photo in an album shared across servers.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FederatedAlbumItem {
    file: FederatedDriveFile,
    thumbnails: crate::models::FileThumbnails,
    /// The file key of `keyGeneration`, under the album key of `albumEpoch`.
    file_key_envelope: String,
    key_generation: i32,
    album_epoch: i32,
}

/// Whether a share of `collection` reaches `file`: a file in the folder, or
/// a photo in the album.
pub(crate) async fn share_reaches(
    pool: &sqlx::PgPool,
    collection: Uuid,
    file: Uuid,
) -> AppResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM files WHERE id = $1 AND deleted_at IS NULL AND (collection_id = $2
             OR id IN (SELECT file_id FROM album_items WHERE album_id = $2)))",
    )
    .bind(file)
    .bind(collection)
    .fetch_one(pool)
    .await?)
}

/// `GET /api/fed/drive/album` — the shared album's photos. Signed.
#[utoipa::path(
    get,
    path = "/api/fed/drive/album",
    tag = "drive federation",
    responses((status = 200, description = "Signed capability-authorized album items", body = Vec<FederatedAlbumItem>))
)]
pub async fn album_items(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let authenticated = federation
        .authenticate_inbound(
            &headers,
            "GET",
            "/api/fed/drive/album",
            None,
            &[],
            FederationFeature::DriveV1,
        )
        .await?;
    let result: AppResult<Response> = async {
        let share = outgoing_share(&state, &authenticated, &headers, false).await?;
        let is_album: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM collections WHERE id = $1 AND kind = 'album')",
        )
        .bind(share.collection_id)
        .fetch_one(&state.pool)
        .await?;
        if !is_album {
            return Err(AppError::not_found("not an album"));
        }
        let files: Vec<FederatedDriveFile> = sqlx::query_as(&format!(
            "SELECT f.id, f.collection_id, f.uploader_user_id, f.metadata_envelope,
                f.file_key_envelope, f.key_epoch, f.key_generation, f.metadata_revision,
                f.encrypted_size_bytes, f.created_at, f.updated_at, f.original_key_generation,
                {} AS key_history, {} AS content_key_generation
             FROM files f
             WHERE f.id IN (SELECT file_id FROM album_items WHERE album_id = $1)
               AND f.deleted_at IS NULL
             ORDER BY f.created_at DESC",
            crate::models::FILE_KEY_HISTORY_SQL,
            crate::models::CONTENT_KEY_GENERATION_SQL
        ))
        .bind(share.collection_id)
        .fetch_all(&state.pool)
        .await?;
        #[derive(sqlx::FromRow)]
        struct Item {
            file_id: Uuid,
            file_key_envelope: String,
            key_generation: i32,
            album_epoch: i32,
            thumb_sm: Option<OffsetDateTime>,
            thumb_lg: Option<OffsetDateTime>,
            thumb_sm_generation: Option<i32>,
            thumb_lg_generation: Option<i32>,
        }
        let items: Vec<Item> = sqlx::query_as(
            "SELECT i.file_id, i.file_key_envelope, i.key_generation, i.album_epoch,
                    sm.updated_at AS thumb_sm, lg.updated_at AS thumb_lg,
                    sm.key_generation AS thumb_sm_generation, lg.key_generation AS thumb_lg_generation
             FROM album_items i
             LEFT JOIN file_thumbnails sm ON sm.file_id = i.file_id AND sm.variant = 'sm'
             LEFT JOIN file_thumbnails lg ON lg.file_id = i.file_id AND lg.variant = 'lg'
             WHERE i.album_id = $1",
        )
        .bind(share.collection_id)
        .fetch_all(&state.pool)
        .await?;
        let mut by_file: std::collections::HashMap<Uuid, Item> =
            items.into_iter().map(|i| (i.file_id, i)).collect();
        let out: Vec<FederatedAlbumItem> = files
            .into_iter()
            .filter_map(|file| {
                let item = by_file.remove(&file.id)?;
                Some(FederatedAlbumItem {
                    file,
                    thumbnails: crate::models::FileThumbnails {
                        sm: item.thumb_sm,
                        lg: item.thumb_lg,
                        sm_key_generation: item.thumb_sm_generation,
                        lg_key_generation: item.thumb_lg_generation,
                    },
                    file_key_envelope: item.file_key_envelope,
                    key_generation: item.key_generation,
                    album_epoch: item.album_epoch,
                })
            })
            .collect();
        signed_json(federation, &authenticated, StatusCode::OK, &out)
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

/// `GET /api/fed/drive/files/{fileId}/thumbnails/{variant}` — a thumbnail of
/// a file the share reaches (sealed under the file key). Signed.
#[utoipa::path(
    get,
    path = "/api/fed/drive/files/{fileId}/thumbnails/{variant}",
    tag = "drive federation",
    params(("fileId" = String, Path), ("variant" = String, Path, description = "sm or lg")),
    responses((status = 200, description = "Signed sealed thumbnail"))
)]
pub async fn thumbnail(
    State(state): State<AppState>,
    Path((file_id, variant)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let federation = configured_stack(&state)?;
    let path = format!("/api/fed/drive/files/{file_id}/thumbnails/{variant}");
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
        let share = outgoing_share(&state, &authenticated, &headers, false).await?;
        let file_id =
            Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("file not found"))?;
        let variant = ThumbnailVariant::try_from(variant.as_str())
            .map_err(|_| AppError::not_found("not found"))?;
        if !share_reaches(&state.pool, share.collection_id, file_id).await? {
            return Err(AppError::not_found("file not found"));
        }
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM file_thumbnails WHERE file_id = $1 AND variant = $2)",
        )
        .bind(file_id)
        .bind(variant.as_str())
        .fetch_one(&state.pool)
        .await?;
        if !exists {
            return Err(AppError::not_found("not found"));
        }
        let (object, _) = state
            .storage
            .get_object(&thumbnail_storage_path(file_id, variant))
            .await
            .map_err(|_| AppError::not_found("not found"))?;
        let bytes = object
            .collect()
            .await
            .map_err(|error| AppError::internal(format!("read thumbnail: {error}")))?
            .into_bytes();
        if bytes.len() > MAX_THUMBNAIL_BYTES {
            return Err(AppError::internal("thumbnail too large"));
        }
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        federation.signed_stream_response(
            &authenticated,
            StatusCode::OK,
            OCTET_STREAM_CONTENT_TYPE,
            &content_digest_sha256_from_digest(&digest),
            bytes.len() as u64,
            Body::from(bytes),
        )
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => signed_app_error(federation, &authenticated, error),
    }
}

/// `GET /api/drive/federation/shares/{shareId}/album` — the photos of an
/// album on another server, relayed.
#[utoipa::path(
    get,
    path = "/api/drive/federation/shares/{shareId}/album",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("shareId" = String, Path)),
    responses((status = 200, description = "Verified remote album items", body = Vec<FederatedAlbumItem>))
)]
pub async fn proxy_album_items(
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
                "/api/fed/drive/album".into(),
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

/// `GET /api/drive/federation/shares/{shareId}/files/{fileId}/thumbnails/{variant}`
/// — a thumbnail from another server, relayed (still sealed).
#[utoipa::path(
    get,
    path = "/api/drive/federation/shares/{shareId}/files/{fileId}/thumbnails/{variant}",
    tag = "drive federation",
    security(("BearerAuth" = [])),
    params(("shareId" = String, Path), ("fileId" = String, Path), ("variant" = String, Path)),
    responses((status = 200, description = "Digest-verified sealed thumbnail"))
)]
pub async fn proxy_thumbnail(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, file_id, variant)): Path<(String, String, String)>,
) -> AppResult<Response> {
    let share = incoming_share(&state, &user, &share_id).await?;
    let file_id = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("file not found"))?;
    let variant = ThumbnailVariant::try_from(variant.as_str())
        .map_err(|_| AppError::not_found("not found"))?;
    let response = configured_stack(&state)?
        .send_streamed(
            &share.remote_domain,
            drive_spec(
                Method::GET,
                format!(
                    "/api/fed/drive/files/{file_id}/thumbnails/{}",
                    variant.as_str()
                ),
                JSON_CONTENT_TYPE.into(),
                Vec::new(),
                Some(&share.remote_capability),
                MAX_THUMBNAIL_BYTES,
            )?,
        )
        .await
        .map_err(gateway_error)?;
    let mut builder = Response::builder()
        .status(response.status)
        .header(header::CONTENT_TYPE, response.content_type)
        .header(header::CONTENT_LENGTH, response.content_length);
    if response.status == StatusCode::OK {
        // Addressed with ?v={updatedAt} like local thumbnails: never changes meaning.
        builder = builder.header(
            header::CACHE_CONTROL,
            "private, max-age=31536000, immutable",
        );
    }
    builder
        .body(Body::from_stream(ReaderStream::new(response.file)))
        .map_err(|error| AppError::internal(error.to_string()))
}
