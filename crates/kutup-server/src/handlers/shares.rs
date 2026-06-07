//! Public-share handlers — mirrors `backend/handlers/shares.go`.
//!
//! A public share is a tokenised link to a collection or file. The link key never reaches
//! the server (it lives only in the URL `#fragment`); we store the collection key already
//! wrapped with that link key, so the stored ciphertext is useless without the fragment.
//! Read endpoints are anonymous — the token is the capability.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::random_token;
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateShareRequest {
    /// "collection" or "file".
    share_type: String,
    target_id: String,
    encrypted_collection_key: String,
    encrypted_collection_key_nonce: String,
    expires_in_hours: Option<i64>,
}

/// `POST /api/share` — mirrors `CreatePublicShare`. The link key is never sent here.
pub async fn create_public_share(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateShareRequest>,
) -> AppResult<Response> {
    let user_id =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::internal("invalid user id"))?;

    if !user_owns_target(&state, user_id, &req.share_type, &req.target_id).await {
        return Err(AppError::forbidden("forbidden"));
    }

    let token = random_token(32);
    let expires_at: Option<OffsetDateTime> = req
        .expires_in_hours
        .map(|h| OffsetDateTime::now_utc() + time::Duration::hours(h));

    // target_id is a uuid column; bind a parsed Uuid (a bad id ⇒ forbidden was already
    // ruled out by user_owns_target, which returns false on a non-owned/invalid id).
    let target_uuid =
        Uuid::parse_str(&req.target_id).map_err(|_| AppError::forbidden("forbidden"))?;

    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO public_shares (share_type, target_id, token,
                                      encrypted_collection_key, encrypted_collection_key_nonce,
                                      expires_at)
           VALUES ($1,$2,$3,$4,$5,$6)
           RETURNING id"#,
    )
    .bind(&req.share_type)
    .bind(target_uuid)
    .bind(&token)
    .bind(&req.encrypted_collection_key)
    .bind(&req.encrypted_collection_key_nonce)
    .bind(expires_at)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    Ok((StatusCode::CREATED, Json(json!({"id": id, "token": token}))).into_response())
}

/// Encrypted key material for a public share. Field order mirrors the Go response struct
/// (not alphabetical); the nullable key fields serialise as `null` when unset.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicShareResponse {
    id: Uuid,
    share_type: String,
    target_id: Uuid,
    encrypted_collection_key: Option<String>,
    encrypted_collection_key_nonce: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    expires_at: Option<OffsetDateTime>,
}

/// `GET /api/share/{token}` — mirrors `GetPublicShare`. Anonymous.
pub async fn get_public_share(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> AppResult<Response> {
    type ShareRow = (
        Uuid,
        String,
        Uuid,
        Option<String>,
        Option<String>,
        Option<OffsetDateTime>,
    );
    let row: Option<ShareRow> = sqlx::query_as(
        r#"SELECT id, share_type, target_id,
                  encrypted_collection_key, encrypted_collection_key_nonce, expires_at
           FROM public_shares WHERE token = $1"#,
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((id, share_type, target_id, eck, eckn, expires_at)) = row else {
        return Err(AppError::not_found("not found"));
    };
    if let Some(exp) = expires_at {
        if OffsetDateTime::now_utc() > exp {
            return Err(AppError::new(StatusCode::GONE, "link expired"));
        }
    }
    Ok(Json(PublicShareResponse {
        id,
        share_type,
        target_id,
        encrypted_collection_key: eck,
        encrypted_collection_key_nonce: eckn,
        expires_at,
    })
    .into_response())
}

/// One file in a public-collection share. Field order mirrors the Go struct; `created_at`
/// is the Postgres timestamp rendered as the same text Go's `time.Time` JSON produces.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicFileRow {
    id: Uuid,
    collection_id: Uuid,
    encrypted_metadata: String,
    metadata_nonce: String,
    encrypted_file_key: String,
    file_key_nonce: String,
    encrypted_size_bytes: i64,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

/// `GET /api/share/{token}/files` — mirrors `ListPublicShareFiles`. Anonymous.
pub async fn list_public_share_files(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> AppResult<Response> {
    let meta: Option<(Uuid, String, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT target_id, share_type, expires_at FROM public_shares WHERE token = $1",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((target_id, share_type, expires_at)) = meta else {
        return Err(AppError::not_found("not found"));
    };
    if let Some(exp) = expires_at {
        if OffsetDateTime::now_utc() > exp {
            return Err(AppError::new(StatusCode::GONE, "link expired"));
        }
    }
    if share_type != "collection" {
        return Err(AppError::bad_request("not a collection share"));
    }

    type PubFileTuple = (
        Uuid,
        Uuid,
        String,
        String,
        String,
        String,
        i64,
        OffsetDateTime,
    );
    let rows: Vec<PubFileTuple> = sqlx::query_as(
        r#"SELECT id, collection_id, encrypted_metadata, metadata_nonce,
                  encrypted_file_key, file_key_nonce, encrypted_size_bytes, created_at
           FROM files WHERE collection_id = $1 ORDER BY created_at DESC"#,
    )
    .bind(target_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    let files: Vec<PublicFileRow> = rows
        .into_iter()
        .map(
            |(id, collection_id, em, mn, efk, fkn, size, created_at)| PublicFileRow {
                id,
                collection_id,
                encrypted_metadata: em,
                metadata_nonce: mn,
                encrypted_file_key: efk,
                file_key_nonce: fkn,
                encrypted_size_bytes: size,
                created_at,
            },
        )
        .collect();
    Ok(Json(files).into_response())
}

/// `GET /api/share/{token}/download/{fileId}` — mirrors `DownloadPublicShareFile`. Returns a
/// presigned S3 URL. Anonymous.
pub async fn download_public_share_file(
    State(state): State<AppState>,
    Path((token, file_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let meta: Option<(Uuid, String, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT target_id, share_type, expires_at FROM public_shares WHERE token = $1",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((target_id, share_type, expires_at)) = meta else {
        return Err(AppError::not_found("not found"));
    };
    if let Some(exp) = expires_at {
        if OffsetDateTime::now_utc() > exp {
            return Err(AppError::new(StatusCode::GONE, "link expired"));
        }
    }

    let fid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
    let file: Option<(String, Uuid)> =
        sqlx::query_as("SELECT storage_path, collection_id FROM files WHERE id = $1")
            .bind(fid)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
    let Some((storage_path, coll_id)) = file else {
        return Err(AppError::not_found("not found"));
    };

    if share_type == "collection" && coll_id != target_id {
        return Err(AppError::forbidden("forbidden"));
    }
    if share_type == "file" && fid != target_id {
        return Err(AppError::forbidden("forbidden"));
    }

    let url = state
        .storage
        .presigned_download(&storage_path)
        .await
        .map_err(|_| AppError::internal("internal error"))?;
    Ok(Json(json!({ "url": url })).into_response())
}

/// Verifies the caller owns the share target — mirrors `userOwnsTarget`.
async fn user_owns_target(
    state: &AppState,
    user_id: Uuid,
    share_type: &str,
    target_id: &str,
) -> bool {
    let Ok(tid) = Uuid::parse_str(target_id) else {
        return false;
    };
    let sql = match share_type {
        "collection" => "SELECT COUNT(*) FROM collections WHERE id = $1 AND owner_user_id = $2",
        "file" => "SELECT COUNT(*) FROM files WHERE id = $1 AND uploader_user_id = $2",
        _ => return false,
    };
    let count: i64 = sqlx::query_scalar(sql)
        .bind(tid)
        .bind(user_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    count > 0
}
