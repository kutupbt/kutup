//! Federation public endpoints — mirrors `backend/handlers/federation.go`.
//!
//! These are the endpoints a *remote* kutup server calls during federated sharing. There is
//! no JWT here — the per-share `access_token` is the capability. The server still only ever
//! handles ciphertext (encrypted metadata + file blobs).

use std::io::Write;

use aws_sdk_s3::primitives::ByteStream;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tempfile::NamedTempFile;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::octet_stream_response;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct UserQuery {
    username: Option<String>,
}

/// `GET /api/fed/users?username=…` — mirrors `GetUserByUsername`. Rate-limited (60/min/IP)
/// by the route layer. Returns the recipient's public key for wrapping the collection key.
pub async fn get_user_by_username(
    State(state): State<AppState>,
    Query(q): Query<UserQuery>,
) -> AppResult<Response> {
    let username = q.username.unwrap_or_default();
    if username.is_empty() {
        return Err(AppError::bad_request("username required"));
    }
    let pubkey: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM users WHERE username = $1 AND is_active = true")
            .bind(&username)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
    match pubkey {
        Some(pk) => Ok(Json(json!({ "publicKey": pk })).into_response()),
        None => Err(AppError::not_found("user not found")),
    }
}

/// Invite metadata for a federated share. Keys are alphabetical, matching Go's marshalled
/// `fiber.Map`.
#[derive(Debug, Serialize)]
struct InviteResponse {
    #[serde(rename = "canDelete")]
    can_delete: bool,
    #[serde(rename = "canUpload")]
    can_upload: bool,
    #[serde(rename = "encryptedName")]
    encrypted_name: String,
    #[serde(rename = "nameNonce")]
    name_nonce: String,
    #[serde(rename = "uploadQuotaBytes")]
    upload_quota_bytes: Option<i64>,
    #[serde(rename = "wrappedKey")]
    wrapped_key: String,
}

/// `GET /api/fed/invites/{token}` — mirrors `GetInvite`. The token is the auth.
pub async fn get_invite(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> AppResult<Response> {
    let row: Option<(String, String, String, bool, bool, Option<i64>)> = sqlx::query_as(
        r#"SELECT fos.encrypted_collection_key, c.encrypted_name, c.name_nonce,
                  fos.can_upload, fos.can_delete, fos.upload_quota_bytes
           FROM federated_outgoing_shares fos
           JOIN collections c ON c.id = fos.collection_id
           WHERE fos.access_token = $1"#,
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((wrapped_key, encrypted_name, name_nonce, can_upload, can_delete, quota)) = row else {
        return Err(AppError::not_found("invite not found"));
    };
    Ok(Json(InviteResponse {
        can_delete,
        can_upload,
        encrypted_name,
        name_nonce,
        upload_quota_bytes: quota,
        wrapped_key,
    })
    .into_response())
}

/// One file in a federated share. Field order mirrors the Go struct.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FedFileRow {
    id: Uuid,
    collection_id: Uuid,
    uploader_user_id: Uuid,
    encrypted_metadata: String,
    metadata_nonce: String,
    encrypted_file_key: String,
    file_key_nonce: String,
    encrypted_size_bytes: i64,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

/// `GET /api/fed/shares/{token}/files` — mirrors `ListShareFiles`.
pub async fn list_share_files(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> AppResult<Response> {
    let coll_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT collection_id FROM federated_outgoing_shares WHERE access_token = $1",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(coll_id) = coll_id else {
        return Err(AppError::forbidden("forbidden"));
    };

    type FedFileTuple = (
        Uuid,
        Uuid,
        Uuid,
        String,
        String,
        String,
        String,
        i64,
        OffsetDateTime,
        OffsetDateTime,
    );
    let rows: Vec<FedFileTuple> = sqlx::query_as(
        r#"SELECT id, collection_id, uploader_user_id, encrypted_metadata, metadata_nonce,
                  encrypted_file_key, file_key_nonce, encrypted_size_bytes, created_at, updated_at
           FROM files WHERE collection_id = $1 ORDER BY created_at DESC"#,
    )
    .bind(coll_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| AppError::internal("internal error"))?;

    let files: Vec<FedFileRow> = rows
        .into_iter()
        .map(
            |(id, cid, uid, em, mn, efk, fkn, size, created, updated)| FedFileRow {
                id,
                collection_id: cid,
                uploader_user_id: uid,
                encrypted_metadata: em,
                metadata_nonce: mn,
                encrypted_file_key: efk,
                file_key_nonce: fkn,
                encrypted_size_bytes: size,
                created_at: created,
                updated_at: updated,
            },
        )
        .collect();
    Ok(Json(files).into_response())
}

/// `GET /api/fed/shares/{token}/files/{fileId}/download` — mirrors `DownloadShareFile`.
pub async fn download_share_file(
    State(state): State<AppState>,
    Path((token, file_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let coll_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT collection_id FROM federated_outgoing_shares WHERE access_token = $1",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(coll_id) = coll_id else {
        return Err(AppError::forbidden("forbidden"));
    };
    let fid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT storage_path, encrypted_size_bytes FROM files WHERE id = $1 AND collection_id = $2",
    )
    .bind(fid)
    .bind(coll_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((storage_path, _size)) = row else {
        return Err(AppError::not_found("not found"));
    };
    let (body, size) = state
        .storage
        .get_object(&storage_path)
        .await
        .map_err(|_| AppError::internal("internal error"))?;
    Ok(octet_stream_response(body, size, &[]))
}

/// `POST /api/fed/shares/{token}/files` — mirrors `UploadShareFile`. Multipart upload from a
/// remote server; the file blob is stored under `fed/{shareId}/{collectionId}/{fileId}`.
pub async fn upload_share_file(
    State(state): State<AppState>,
    Path(token): Path<String>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    let share: Option<(Uuid, Uuid, Uuid, bool, Option<i64>)> = sqlx::query_as(
        r#"SELECT id, collection_id, sharer_user_id, can_upload, upload_quota_bytes
           FROM federated_outgoing_shares WHERE access_token = $1"#,
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((share_id, coll_id, sharer_id, can_upload, share_quota)) = share else {
        return Err(AppError::forbidden("forbidden"));
    };
    if !can_upload {
        return Err(AppError::forbidden("upload not permitted"));
    }

    // Collect the form fields + spool the file part to a temp file (to learn its size).
    let mut enc_metadata = String::new();
    let mut metadata_nonce = String::new();
    let mut enc_file_key = String::new();
    let mut file_key_nonce = String::new();
    let mut tmp: Option<(NamedTempFile, i64)> = None;
    loop {
        let field = multipart
            .next_field()
            .await
            .map_err(|_| AppError::bad_request("invalid multipart form"))?;
        let Some(mut field) = field else { break };
        match field.name() {
            Some("encryptedMetadata") => enc_metadata = field.text().await.unwrap_or_default(),
            Some("metadataNonce") => metadata_nonce = field.text().await.unwrap_or_default(),
            Some("encryptedFileKey") => enc_file_key = field.text().await.unwrap_or_default(),
            Some("fileKeyNonce") => file_key_nonce = field.text().await.unwrap_or_default(),
            Some("file") => {
                let mut f = NamedTempFile::new().map_err(|_| AppError::internal("temp file"))?;
                let mut size: i64 = 0;
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|_| AppError::bad_request("no file provided"))?
                {
                    f.write_all(&chunk)
                        .map_err(|_| AppError::internal("temp write"))?;
                    size += chunk.len() as i64;
                }
                tmp = Some((f, size));
            }
            _ => {}
        }
    }
    let Some((tmp_file, file_size)) = tmp else {
        return Err(AppError::bad_request("no file provided"));
    };

    let file_id = Uuid::new_v4();
    let storage_path = format!("fed/{share_id}/{coll_id}/{file_id}");

    // Upload to S3 first; on any subsequent failure we delete the orphan.
    let body = ByteStream::from_path(tmp_file.path())
        .await
        .map_err(|_| AppError::internal("read upload"))?;
    if state
        .storage
        .upload(&storage_path, body, file_size)
        .await
        .is_err()
    {
        return Err(AppError::internal("storage error"));
    }

    // FOR UPDATE on the share row to make the quota check + counter bump atomic.
    let mut tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(_) => {
            let _ = state.storage.delete(&storage_path).await;
            return Err(AppError::internal("internal error"));
        }
    };
    if let Some(quota) = share_quota {
        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE(upload_used_bytes, 0) FROM federated_outgoing_shares WHERE id = $1 FOR UPDATE",
        )
        .bind(share_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
        if used + file_size > quota {
            let _ = state.storage.delete(&storage_path).await;
            return Err(AppError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "share quota exceeded",
            ));
        }
    }

    let ins = sqlx::query(
        r#"INSERT INTO files (id, collection_id, uploader_user_id,
                              encrypted_metadata, metadata_nonce,
                              encrypted_file_key, file_key_nonce,
                              storage_path, encrypted_size_bytes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"#,
    )
    .bind(file_id)
    .bind(coll_id)
    .bind(sharer_id)
    .bind(&enc_metadata)
    .bind(&metadata_nonce)
    .bind(&enc_file_key)
    .bind(&file_key_nonce)
    .bind(&storage_path)
    .bind(file_size)
    .execute(&mut *tx)
    .await;
    if ins.is_err() {
        let _ = state.storage.delete(&storage_path).await;
        return Err(AppError::internal("internal error"));
    }

    let _ = sqlx::query(
        "UPDATE federated_outgoing_shares SET upload_used_bytes = upload_used_bytes + $1 WHERE id = $2",
    )
    .bind(file_size)
    .bind(share_id)
    .execute(&mut *tx)
    .await;
    let _ =
        sqlx::query("UPDATE users SET storage_used_bytes = storage_used_bytes + $1 WHERE id = $2")
            .bind(file_size)
            .bind(sharer_id)
            .execute(&mut *tx)
            .await;

    if tx.commit().await.is_err() {
        let _ = state.storage.delete(&storage_path).await;
        return Err(AppError::internal("internal error"));
    }

    Ok((StatusCode::CREATED, Json(json!({ "id": file_id }))).into_response())
}

/// `DELETE /api/fed/shares/{token}/files/{fileId}` — mirrors `DeleteShareFile`.
pub async fn delete_share_file(
    State(state): State<AppState>,
    Path((token, file_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let share: Option<(Uuid, Uuid, Uuid, bool)> = sqlx::query_as(
        r#"SELECT id, collection_id, sharer_user_id, can_delete
           FROM federated_outgoing_shares WHERE access_token = $1"#,
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((share_id, coll_id, sharer_id, can_delete)) = share else {
        return Err(AppError::forbidden("forbidden"));
    };
    if !can_delete {
        return Err(AppError::forbidden("delete not permitted"));
    }
    let fid = Uuid::parse_str(&file_id).map_err(|_| AppError::not_found("not found"))?;
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT storage_path, encrypted_size_bytes FROM files WHERE id = $1 AND collection_id = $2",
    )
    .bind(fid)
    .bind(coll_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some((storage_path, file_size)) = row else {
        return Err(AppError::not_found("not found"));
    };

    if sqlx::query("DELETE FROM files WHERE id = $1")
        .bind(fid)
        .execute(&state.pool)
        .await
        .is_err()
    {
        return Err(AppError::internal("internal error"));
    }
    let _ = sqlx::query(
        "UPDATE federated_outgoing_shares SET upload_used_bytes = GREATEST(0, upload_used_bytes - $1) WHERE id = $2",
    )
    .bind(file_size)
    .bind(share_id)
    .execute(&state.pool)
    .await;
    let _ = sqlx::query(
        "UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $1) WHERE id = $2",
    )
    .bind(file_size)
    .bind(sharer_id)
    .execute(&state.pool)
    .await;
    let _ = state.storage.delete(&storage_path).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}
