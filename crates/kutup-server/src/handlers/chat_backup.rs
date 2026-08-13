//! Always-on continuous E2EE Chat-history storage.
//!
//! This handler owns only opaque ciphertext, typed public headers, account and
//! device authorization, append ordering, idempotency, and dedicated Chat
//! quota. Archive plaintext is never accepted as an API field.

use aws_sdk_s3::primitives::ByteStream;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    chat_backup_media_reference_set_digest, AppendChatBackupSegmentRequestV1,
    ChatBackupBaseReceiptV1, ChatBackupManifestCommitReceiptV1, ChatBackupManifestV1,
    ChatBackupMediaReconciliationReceiptV1, ChatBackupMediaReferenceV1, ChatBackupSegmentPageV1,
    ChatBackupSegmentReceiptV1, ChatBackupSignerAuthorizationV1, ChatBackupStatusV1,
    ChatBackupStorageUsageV1, ChatBackupWireSegmentV1, CommitChatBackupManifestRequestV1,
    CopyChatBackupMediaRequestV1, ProvisionChatBackupRequestV1, ReconcileChatBackupMediaRequestV1,
    StageChatBackupBaseRequestV1, UploadChatBackupMediaRequestV1,
    MAX_CHAT_BACKUP_BASE_CIPHERTEXT_BYTES, MAX_CHAT_BACKUP_PAGE_SEGMENTS,
};
use kutup_crypto::account_envelope::{self, AccountEnvelopePurpose};
use kutup_crypto::chat_backup::{
    self, ChatBackupObjectPurposeV1, ChatBackupProtectionDomainV1, ChatBackupSuiteId,
};
use kutup_crypto::chat_backup_media::{
    self, ChatBackupMediaContextV1, CHAT_BACKUP_MEDIA_HEADER_BYTES,
};
use kutup_crypto::stream::{StreamEncryptor, CHUNK_SIZE, TAG_FINAL, TAG_MESSAGE};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use tempfile::NamedTempFile;
use time::OffsetDateTime;
use tokio::io::AsyncReadExt as _;
use uuid::Uuid;

use super::trusted_uuid;
use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::AppState;

const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
// A small, server-owned overdraft prevents a full account from deadlocking:
// deletion tombstones must be appendable before compaction can release their
// message/media bytes. It is never available to media uploads.
const OPERATIONAL_MESSAGE_HEADROOM_BYTES: i64 = 1024 * 1024;

fn base_storage_path(
    user_id: Uuid,
    backup_id: Uuid,
    object_id: Uuid,
    ciphertext_digest: &str,
) -> String {
    // Include the verified digest so two hostile concurrent uploads cannot
    // share, overwrite, and then delete the same staged object path.
    format!("chat-backup/{user_id}/{backup_id}/bases/{object_id}/{ciphertext_digest}")
}

fn media_storage_path(user_id: Uuid, backup_id: Uuid, media_id: &str, operation: Uuid) -> String {
    format!("chat-backup/{user_id}/{backup_id}/media/{media_id}/{operation}")
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct SegmentPageQuery {
    after: Option<u64>,
    limit: Option<u16>,
}

fn canonical_uuid(field: &str, value: &str) -> AppResult<Uuid> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| AppError::bad_request(format!("invalid {field}")))?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(AppError::bad_request(format!("invalid {field}")));
    }
    Ok(parsed)
}

fn canonical_hex_32(field: &str, value: &str) -> AppResult<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::bad_request(format!("invalid {field}")));
    }
    hex::decode(value)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| AppError::bad_request(format!("invalid {field}")))
}

fn request_digest<T: serde::Serialize>(value: &T) -> AppResult<String> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| AppError::internal(format!("encode Chat backup request: {error}")))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

#[utoipa::path(post, path = "/api/chat/backup", tag = "chat-backup",
    security(("BearerAuth" = [])), request_body = ProvisionChatBackupRequestV1,
    responses((status = 201, body = ChatBackupStatusV1), (status = 200, body = ChatBackupStatusV1)))]
pub async fn provision(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<ProvisionChatBackupRequestV1>,
) -> AppResult<(StatusCode, Json<ChatBackupStatusV1>)> {
    request
        .validate()
        .map_err(|error| AppError::bad_request(format!("invalid Chat backup: {error}")))?;
    let user_id = trusted_uuid(&user.user_id)?;
    let operation_id = canonical_uuid("backup operation id", &request.operation_id)?;
    let backup_incarnation_id = canonical_uuid(
        "backup incarnation id",
        &request.signer_authorization.backup_incarnation_id,
    )?;
    let envelope = account_envelope::decode_canonical_b64(&request.root_envelope)
        .map_err(|_| AppError::bad_request("invalid Chat backup root envelope"))?;
    let envelope_header = account_envelope::inspect(&envelope)
        .map_err(|_| AppError::bad_request("invalid Chat backup root envelope"))?;
    if envelope_header.purpose != AccountEnvelopePurpose::ChatBackupRoot {
        return Err(AppError::bad_request(
            "Chat backup root envelope has the wrong purpose",
        ));
    }
    let digest = request_digest(&request)?;
    let authorization_digest = request
        .signer_authorization
        .digest()
        .map_err(AppError::bad_request)?;

    let mut transaction = state.pool.begin().await?;
    let user_row: (String, String, String, String) = sqlx::query_as(
        "SELECT email,account_incarnation_id,account_authority_public_key,
                account_authority_key_id FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    let (email, account_incarnation_id, authority_public_key, authority_key_id) = user_row;
    if envelope_header.canonical_login_email != email.trim().to_ascii_lowercase() {
        return Err(AppError::bad_request(
            "Chat backup root envelope account binding mismatch",
        ));
    }
    if request.signer_authorization.account_incarnation_id != account_incarnation_id
        || request.signer_authorization.account_authority_key_id != authority_key_id
    {
        return Err(AppError::conflict(
            "Chat backup signer differs from the account identity",
        ));
    }
    let authority_public_key = STANDARD
        .decode(&authority_public_key)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| AppError::internal("stored account authority key is malformed"))?;
    request
        .signer_authorization
        .verify(&authority_public_key)
        .map_err(AppError::bad_request)?;

    if let Some((stored_digest, stored_backup_id)) = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT request_digest,backup_incarnation_id
         FROM chat_backup_provision_operations WHERE user_id=$1 AND operation_id=$2",
    )
    .bind(user_id)
    .bind(operation_id)
    .fetch_optional(&mut *transaction)
    .await?
    {
        if stored_digest != digest || stored_backup_id != backup_incarnation_id {
            return Err(AppError::conflict(
                "Chat backup provision operation changed across retry",
            ));
        }
        transaction.commit().await?;
        return Ok((StatusCode::OK, Json(load_status(&state, user_id).await?)));
    }

    if let Some((stored_backup_id, root_envelope, stored_authorization_digest)) =
        sqlx::query_as::<_, (Uuid, String, String)>(
            "SELECT backup_incarnation_id,root_envelope,signer_authorization_digest
             FROM chat_backups WHERE user_id=$1",
        )
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await?
    {
        if stored_backup_id != backup_incarnation_id
            || root_envelope != request.root_envelope
            || stored_authorization_digest != authorization_digest
        {
            return Err(AppError::conflict(
                "Chat history is already provisioned for this account",
            ));
        }
    } else {
        sqlx::query(
            "INSERT INTO chat_backups
             (user_id,backup_incarnation_id,suite,protection_domain,root_envelope,
              signer_authorization,signer_authorization_digest)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(user_id)
        .bind(backup_incarnation_id)
        .bind(i16::try_from(request.signer_authorization.suite.as_u16()).unwrap_or_default())
        .bind(i16::from(
            request.signer_authorization.protection_domain.as_u8(),
        ))
        .bind(&request.root_envelope)
        .bind(
            serde_json::to_value(&request.signer_authorization).map_err(|error| {
                AppError::internal(format!("encode backup signer authorization: {error}"))
            })?,
        )
        .bind(&authorization_digest)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "INSERT INTO chat_backup_provision_operations
         (user_id,operation_id,request_digest,backup_incarnation_id) VALUES ($1,$2,$3,$4)",
    )
    .bind(user_id)
    .bind(operation_id)
    .bind(&digest)
    .bind(backup_incarnation_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    crate::telemetry::chat_backup_event("provision", "created");
    Ok((
        StatusCode::CREATED,
        Json(load_status(&state, user_id).await?),
    ))
}

#[utoipa::path(get, path = "/api/chat/backup", tag = "chat-backup",
    security(("BearerAuth" = [])), responses((status = 200, body = ChatBackupStatusV1)))]
pub async fn status(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<ChatBackupStatusV1>> {
    Ok(Json(
        load_status(&state, trusted_uuid(&user.user_id)?).await?,
    ))
}

/// Account-lifecycle cleanup. There is intentionally no authenticated Chat
/// backup DELETE route: backup is always on and cannot be disabled separately.
pub async fn purge_for_account(state: &AppState, user_id: Uuid) -> AppResult<()> {
    let mut transaction = state.pool.begin().await?;
    let backup_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT backup_incarnation_id FROM chat_backups WHERE user_id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(backup_id) = backup_id else {
        transaction.commit().await?;
        return Ok(());
    };
    let released: i64 = sqlx::query_scalar(
        "SELECT
           COALESCE((SELECT SUM(ciphertext_bytes)::bigint FROM chat_backup_segments WHERE user_id=$1),0) +
           COALESCE((SELECT SUM(ciphertext_bytes)::bigint FROM chat_backup_bases WHERE user_id=$1),0) +
           COALESCE((SELECT SUM(ciphertext_bytes)::bigint FROM chat_backup_media_objects WHERE user_id=$1),0)",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM chat_backups WHERE user_id=$1")
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE users SET chat_storage_used_bytes=GREATEST(0,chat_storage_used_bytes-$1)
         WHERE id=$2",
    )
    .bind(released)
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let prefix = format!("chat-backup/{user_id}/{backup_id}/");
    if let Err(error) = state.storage.delete_prefix(&prefix).await {
        tracing::warn!("deleted Chat backup left storage objects for orphan cleanup: {error:#}");
    }
    crate::telemetry::chat_backup_event("backup", "deleted");
    Ok(())
}

async fn load_status(state: &AppState, user_id: Uuid) -> AppResult<ChatBackupStatusV1> {
    let (quota, used): (i64, i64) = sqlx::query_as(
        "SELECT chat_storage_quota_bytes,chat_storage_used_bytes FROM users WHERE id=$1",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    let delivery_media_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(logical_bytes),0)::bigint
         FROM chat_media_references WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    let history_media_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(ciphertext_bytes),0)::bigint
         FROM chat_backup_media_objects WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    let message_bytes: i64 = sqlx::query_scalar(
        "SELECT
          COALESCE((SELECT SUM(ciphertext_bytes)::bigint FROM chat_backup_segments WHERE user_id=$1),0) +
          COALESCE((SELECT SUM(ciphertext_bytes)::bigint FROM chat_backup_bases
                    WHERE user_id=$1),0)",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    let storage = ChatBackupStorageUsageV1 {
        quota_bytes: u64::try_from(quota).unwrap_or_default(),
        used_bytes: u64::try_from(used).unwrap_or_default(),
        message_bytes: u64::try_from(message_bytes).unwrap_or_default(),
        delivery_media_bytes: u64::try_from(delivery_media_bytes).unwrap_or_default(),
        history_media_bytes: u64::try_from(history_media_bytes).unwrap_or_default(),
    };
    let backup: Option<(
        String,
        serde_json::Value,
        Option<serde_json::Value>,
        i64,
        Option<OffsetDateTime>,
    )> = sqlx::query_as(
        "SELECT root_envelope,signer_authorization,current_manifest,current_cursor,
                latest_protected_at FROM chat_backups WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((root_envelope, authorization, manifest, cursor, protected_at)) = backup else {
        return Ok(ChatBackupStatusV1 {
            provisioned: false,
            root_envelope: None,
            signer_authorization: None,
            manifest: None,
            current_cursor: 0,
            latest_protected_at_unix: None,
            storage,
        });
    };
    Ok(ChatBackupStatusV1 {
        provisioned: true,
        root_envelope: Some(root_envelope),
        signer_authorization: Some(
            serde_json::from_value::<ChatBackupSignerAuthorizationV1>(authorization).map_err(
                |error| {
                    AppError::internal(format!("stored backup authorization is malformed: {error}"))
                },
            )?,
        ),
        manifest: manifest
            .map(serde_json::from_value::<ChatBackupManifestV1>)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("stored backup manifest is malformed: {error}"))
            })?,
        current_cursor: u64::try_from(cursor).unwrap_or_default(),
        latest_protected_at_unix: protected_at.map(|value| value.unix_timestamp()),
        storage,
    })
}

#[utoipa::path(post, path = "/api/chat/backup/segments", tag = "chat-backup",
    security(("BearerAuth" = [])), request_body = AppendChatBackupSegmentRequestV1,
    responses((status = 200, body = ChatBackupSegmentReceiptV1), (status = 507, description = "Chat storage full")))]
pub async fn append_segment(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<AppendChatBackupSegmentRequestV1>,
) -> AppResult<Json<ChatBackupSegmentReceiptV1>> {
    let ciphertext = request
        .validate()
        .map_err(|error| AppError::bad_request(format!("invalid backup segment: {error}")))?;
    let user_id = trusted_uuid(&user.user_id)?;
    let operation_id = canonical_uuid("backup operation id", &request.operation_id)?;
    let backup_incarnation_id =
        canonical_uuid("backup incarnation id", &request.backup_incarnation_id)?;
    let previous_digest =
        canonical_hex_32("previous segment digest", &request.previous_segment_digest)?;
    let source_device_id = i32::try_from(request.source_device_id)
        .map_err(|_| AppError::bad_request("backup source device exceeds server range"))?;
    let device_sequence = i64::try_from(request.device_sequence)
        .map_err(|_| AppError::bad_request("backup device sequence exceeds server range"))?;
    let manifest_sequence = i64::try_from(request.account_manifest_sequence)
        .map_err(|_| AppError::bad_request("account manifest sequence exceeds server range"))?;
    let header = chat_backup::inspect_object(&ciphertext)
        .map_err(|_| AppError::bad_request("invalid backup segment object"))?;
    if header.context.purpose != ChatBackupObjectPurposeV1::EventSegment
        || Uuid::from_bytes(header.context.object_id) != operation_id
        || Uuid::from_bytes(header.context.backup.backup_incarnation_id) != backup_incarnation_id
        || header.context.source_device_id != request.source_device_id
        || header.context.device_sequence != request.device_sequence
        || header.context.previous_segment_digest != previous_digest
        || header.context.backup.protection_domain != ChatBackupProtectionDomainV1::StandardChat
        || header.suite != ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1
    {
        return Err(AppError::bad_request(
            "backup segment public binding mismatch",
        ));
    }

    let mut transaction = state.pool.begin().await?;
    let backup: (Uuid, i64, i16, i16) = sqlx::query_as(
        "SELECT backup_incarnation_id,current_cursor,suite,protection_domain
         FROM chat_backups WHERE user_id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| AppError::conflict("Chat history is not provisioned"))?;
    if backup.0 != backup_incarnation_id || backup.2 != 1 || backup.3 != 1 {
        return Err(AppError::conflict("backup incarnation or suite changed"));
    }
    let account_incarnation_id: String =
        sqlx::query_scalar("SELECT account_incarnation_id FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_one(&mut *transaction)
            .await?;
    if header.context.backup.account_incarnation_id
        != canonical_hex_32("account incarnation", &account_incarnation_id)?
    {
        return Err(AppError::bad_request(
            "backup segment account incarnation mismatch",
        ));
    }

    if let Some((cursor, digest, acknowledged_at, stored_device, stored_sequence, stored_previous, stored_manifest, stored_bytes)) =
        sqlx::query_as::<_, (i64, String, OffsetDateTime, i32, i64, String, i64, i32)>(
            "SELECT cursor,ciphertext_sha256,acknowledged_at,source_device_id,
                    device_sequence,previous_segment_digest,account_manifest_sequence,ciphertext_bytes
             FROM chat_backup_segments WHERE user_id=$1 AND operation_id=$2",
        )
        .bind(user_id)
        .bind(operation_id)
        .fetch_optional(&mut *transaction)
        .await?
    {
        if digest != request.ciphertext_sha256
            || stored_device != source_device_id
            || stored_sequence != device_sequence
            || stored_previous != request.previous_segment_digest
            || stored_manifest != manifest_sequence
            || stored_bytes != i32::try_from(request.ciphertext_bytes).unwrap_or_default()
        {
            return Err(AppError::conflict(
                "backup segment operation changed across retry",
            ));
        }
        transaction.commit().await?;
        return Ok(Json(ChatBackupSegmentReceiptV1 {
            operation_id: request.operation_id,
            cursor: u64::try_from(cursor).unwrap_or_default(),
            acknowledged_at_unix: acknowledged_at.unix_timestamp(),
            already_stored: true,
        }));
    }

    let current_manifest_sequence: Option<i64> =
        sqlx::query_scalar("SELECT version FROM chat_device_manifests WHERE user_id=$1")
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await?;
    if current_manifest_sequence != Some(manifest_sequence) {
        return Err(AppError::conflict("account manifest sequence changed"));
    }
    let device_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat_devices WHERE user_id=$1 AND device_id=$2)",
    )
    .bind(user_id)
    .bind(source_device_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !device_exists {
        return Err(AppError::forbidden("backup source device is not active"));
    }

    let head: Option<(i64, String)> = sqlx::query_as(
        "SELECT last_device_sequence,last_segment_digest
         FROM chat_backup_device_heads WHERE user_id=$1 AND source_device_id=$2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(source_device_id)
    .fetch_optional(&mut *transaction)
    .await?;
    match head {
        None if request.device_sequence == 1 && request.previous_segment_digest == ZERO_DIGEST => {}
        Some((sequence, digest))
            if request.device_sequence == u64::try_from(sequence).unwrap_or_default() + 1
                && request.previous_segment_digest == digest => {}
        _ => {
            return Err(AppError::conflict(
                "backup device segment chain is not contiguous",
            ))
        }
    }

    let (quota, used): (i64, i64) = sqlx::query_as(
        "SELECT chat_storage_quota_bytes,chat_storage_used_bytes
         FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    let ciphertext_bytes = i64::from(request.ciphertext_bytes);
    let operational_limit = quota.saturating_add(OPERATIONAL_MESSAGE_HEADROOM_BYTES);
    if used
        .checked_add(ciphertext_bytes)
        .is_none_or(|value| value > operational_limit)
    {
        return Err(AppError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "Chat storage full; delete messages or media, or increase storage",
        ));
    }
    let cursor = backup
        .1
        .checked_add(1)
        .ok_or_else(|| AppError::internal("backup cursor exhausted"))?;
    let acknowledged_at = OffsetDateTime::now_utc();
    sqlx::query(
        "INSERT INTO chat_backup_segments
         (user_id,cursor,operation_id,source_device_id,device_sequence,
          previous_segment_digest,account_manifest_sequence,ciphertext_bytes,
          ciphertext_sha256,ciphertext,acknowledged_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(user_id)
    .bind(cursor)
    .bind(operation_id)
    .bind(source_device_id)
    .bind(device_sequence)
    .bind(&request.previous_segment_digest)
    .bind(manifest_sequence)
    .bind(ciphertext_bytes)
    .bind(&request.ciphertext_sha256)
    .bind(&ciphertext)
    .bind(acknowledged_at)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO chat_backup_device_heads
         (user_id,source_device_id,last_device_sequence,last_segment_digest)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (user_id,source_device_id) DO UPDATE SET
           last_device_sequence=EXCLUDED.last_device_sequence,
           last_segment_digest=EXCLUDED.last_segment_digest,
           updated_at=NOW()",
    )
    .bind(user_id)
    .bind(source_device_id)
    .bind(device_sequence)
    .bind(&request.ciphertext_sha256)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE chat_backups SET current_cursor=$1,latest_protected_at=$2,updated_at=NOW()
         WHERE user_id=$3",
    )
    .bind(cursor)
    .bind(acknowledged_at)
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("UPDATE users SET chat_storage_used_bytes=chat_storage_used_bytes+$1 WHERE id=$2")
        .bind(ciphertext_bytes)
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    crate::telemetry::chat_backup_event("segment", "stored");
    Ok(Json(ChatBackupSegmentReceiptV1 {
        operation_id: request.operation_id,
        cursor: u64::try_from(cursor).unwrap_or_default(),
        acknowledged_at_unix: acknowledged_at.unix_timestamp(),
        already_stored: false,
    }))
}

#[utoipa::path(get, path = "/api/chat/backup/segments", tag = "chat-backup",
    security(("BearerAuth" = [])), params(
        ("after" = Option<u64>, Query, description = "Exclusive account backup cursor"),
        ("limit" = Option<u16>, Query, description = "Page size")
    ), responses((status = 200, body = ChatBackupSegmentPageV1)))]
pub async fn list_segments(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<SegmentPageQuery>,
) -> AppResult<Json<ChatBackupSegmentPageV1>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let after = i64::try_from(query.after.unwrap_or(0))
        .map_err(|_| AppError::bad_request("invalid backup cursor"))?;
    let limit = query
        .limit
        .unwrap_or(MAX_CHAT_BACKUP_PAGE_SEGMENTS)
        .clamp(1, MAX_CHAT_BACKUP_PAGE_SEGMENTS);
    let current_cursor: i64 =
        sqlx::query_scalar("SELECT current_cursor FROM chat_backups WHERE user_id=$1")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Chat history is not provisioned"))?;
    let rows: Vec<(
        Uuid,
        i64,
        i32,
        i64,
        String,
        i32,
        String,
        Vec<u8>,
        OffsetDateTime,
    )> = sqlx::query_as(
        "SELECT operation_id,cursor,source_device_id,device_sequence,previous_segment_digest,
                    ciphertext_bytes,ciphertext_sha256,ciphertext,acknowledged_at
             FROM chat_backup_segments WHERE user_id=$1 AND cursor>$2
             ORDER BY cursor LIMIT $3",
    )
    .bind(user_id)
    .bind(after)
    .bind(i64::from(limit) + 1)
    .fetch_all(&state.pool)
    .await?;
    let more = rows.len() > usize::from(limit);
    let segments = rows
        .into_iter()
        .take(usize::from(limit))
        .map(
            |(
                operation_id,
                cursor,
                device,
                sequence,
                previous,
                bytes,
                digest,
                ciphertext,
                acknowledged,
            )| {
                ChatBackupWireSegmentV1 {
                    operation_id: operation_id.hyphenated().to_string(),
                    cursor: u64::try_from(cursor).unwrap_or_default(),
                    source_device_id: u32::try_from(device).unwrap_or_default(),
                    device_sequence: u64::try_from(sequence).unwrap_or_default(),
                    previous_segment_digest: previous,
                    ciphertext_bytes: u32::try_from(bytes).unwrap_or_default(),
                    ciphertext_sha256: digest,
                    ciphertext: STANDARD.encode(ciphertext),
                    acknowledged_at_unix: acknowledged.unix_timestamp(),
                }
            },
        )
        .collect();
    Ok(Json(ChatBackupSegmentPageV1 {
        segments,
        current_cursor: u64::try_from(current_cursor).unwrap_or_default(),
        more,
    }))
}

/// Streams an encrypted base snapshot to object storage. The multipart form
/// contains a canonical `metadata` JSON part and one `ciphertext` file part.
#[utoipa::path(post, path = "/api/chat/backup/bases", tag = "chat-backup",
    security(("BearerAuth" = [])), request_body(
        content = Vec<u8>, content_type = "multipart/form-data",
        description = "Typed metadata and encrypted base ciphertext"
    ), responses((status = 200, body = ChatBackupBaseReceiptV1), (status = 507, description = "Chat storage full")))]
pub async fn stage_base(
    State(state): State<AppState>,
    user: AuthUser,
    mut multipart: Multipart,
) -> AppResult<Json<ChatBackupBaseReceiptV1>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let mut metadata: Option<StageChatBackupBaseRequestV1> = None;
    let mut object: Option<(NamedTempFile, u64, [u8; 32])> = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::bad_request("invalid backup base multipart form"))?
    {
        match field.name().unwrap_or("") {
            "metadata" => {
                if metadata.is_some() {
                    return Err(AppError::bad_request("duplicate backup base metadata"));
                }
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|_| AppError::bad_request("invalid backup base metadata"))?;
                metadata = Some(
                    serde_json::from_slice(&bytes)
                        .map_err(|_| AppError::bad_request("invalid backup base metadata"))?,
                );
            }
            "ciphertext" => {
                if object.is_some() {
                    return Err(AppError::bad_request("duplicate backup base ciphertext"));
                }
                let mut file = NamedTempFile::new()
                    .map_err(|_| AppError::internal("create backup base temp file"))?;
                let mut bytes = 0u64;
                let mut digest = Sha256::new();
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|_| AppError::bad_request("invalid backup base ciphertext"))?
                {
                    bytes = bytes
                        .checked_add(chunk.len() as u64)
                        .ok_or_else(|| AppError::bad_request("backup base is too large"))?;
                    if bytes > MAX_CHAT_BACKUP_BASE_CIPHERTEXT_BYTES {
                        return Err(AppError::new(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "backup base is too large",
                        ));
                    }
                    digest.update(&chunk);
                    file.write_all(&chunk)
                        .map_err(|_| AppError::internal("write backup base temp file"))?;
                }
                object = Some((file, bytes, digest.finalize().into()));
            }
            _ => return Err(AppError::bad_request("unknown backup base multipart field")),
        }
    }
    let metadata = metadata.ok_or_else(|| AppError::bad_request("missing backup base metadata"))?;
    metadata
        .validate()
        .map_err(|error| AppError::bad_request(format!("invalid backup base: {error}")))?;
    let (mut file, measured_bytes, measured_digest) =
        object.ok_or_else(|| AppError::bad_request("missing backup base ciphertext"))?;
    if measured_bytes != metadata.ciphertext_bytes
        || hex::encode(measured_digest) != metadata.ciphertext_sha256
    {
        return Err(AppError::bad_request(
            "backup base ciphertext binding mismatch",
        ));
    }
    let backup_id = canonical_uuid("backup incarnation id", &metadata.backup_incarnation_id)?;
    let object_id = canonical_uuid("backup base object id", &metadata.object_id)?;
    let mut public_header = vec![0u8; chat_backup::CHAT_BACKUP_OBJECT_HEADER_BYTES];
    file.as_file_mut()
        .seek(SeekFrom::Start(0))
        .and_then(|_| file.as_file_mut().read_exact(&mut public_header))
        .map_err(|_| AppError::bad_request("backup base header is truncated"))?;
    let header = chat_backup::inspect_object_header(
        &public_header,
        usize::try_from(measured_bytes)
            .map_err(|_| AppError::bad_request("backup base is too large"))?,
    )
    .map_err(|_| AppError::bad_request("invalid backup base object"))?;
    if header.context.purpose != ChatBackupObjectPurposeV1::BaseSnapshot
        || Uuid::from_bytes(header.context.object_id) != object_id
        || Uuid::from_bytes(header.context.backup.backup_incarnation_id) != backup_id
        || header.context.backup.protection_domain != ChatBackupProtectionDomainV1::StandardChat
        || header.suite != ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1
    {
        return Err(AppError::bad_request("backup base public binding mismatch"));
    }

    let preflight: Option<(Uuid, i64, i64, String)> = sqlx::query_as(
        "SELECT b.backup_incarnation_id,b.current_generation,b.current_cursor,
                u.account_incarnation_id
         FROM chat_backups b JOIN users u ON u.id=b.user_id WHERE b.user_id=$1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((stored_backup_id, current_generation, current_cursor, account_incarnation)) =
        preflight
    else {
        return Err(AppError::conflict("Chat history is not provisioned"));
    };
    if stored_backup_id != backup_id
        || metadata.generation != u64::try_from(current_generation).unwrap_or_default() + 1
        || metadata.covered_cursor > u64::try_from(current_cursor).unwrap_or_default()
        || header.context.backup.account_incarnation_id
            != canonical_hex_32("account incarnation", &account_incarnation)?
    {
        return Err(AppError::conflict(
            "backup base is stale or belongs to another account",
        ));
    }

    if let Some((generation, covered, bytes, digest)) =
        sqlx::query_as::<_, (i64, i64, i64, String)>(
            "SELECT generation,covered_cursor,ciphertext_bytes,ciphertext_sha256
             FROM chat_backup_bases WHERE user_id=$1 AND object_id=$2",
        )
        .bind(user_id)
        .bind(object_id)
        .fetch_optional(&state.pool)
        .await?
    {
        if generation != metadata.generation as i64
            || covered != metadata.covered_cursor as i64
            || bytes != metadata.ciphertext_bytes as i64
            || digest != metadata.ciphertext_sha256
        {
            return Err(AppError::conflict(
                "backup base object changed across retry",
            ));
        }
        return Ok(Json(ChatBackupBaseReceiptV1 {
            object_id: metadata.object_id,
            already_stored: true,
        }));
    }

    let path = base_storage_path(user_id, backup_id, object_id, &metadata.ciphertext_sha256);
    let body = ByteStream::from_path(file.path())
        .await
        .map_err(|_| AppError::internal("read backup base temp file"))?;
    state
        .storage
        .upload(
            &path,
            body,
            i64::try_from(measured_bytes)
                .map_err(|_| AppError::bad_request("backup base is too large"))?,
        )
        .await
        .map_err(|error| {
            tracing::error!("backup base storage upload failed: {error:#}");
            AppError::internal("backup storage error")
        })?;

    let insert_result: AppResult<bool> = async {
        let mut transaction = state.pool.begin().await?;
        let (locked_backup_id, locked_generation, locked_cursor): (Uuid, i64, i64) =
            sqlx::query_as(
                "SELECT backup_incarnation_id,current_generation,current_cursor
                 FROM chat_backups WHERE user_id=$1 FOR UPDATE",
            )
            .bind(user_id)
            .fetch_one(&mut *transaction)
            .await?;
        if locked_backup_id != backup_id
            || metadata.generation != u64::try_from(locked_generation).unwrap_or_default() + 1
            || metadata.covered_cursor > u64::try_from(locked_cursor).unwrap_or_default()
        {
            return Err(AppError::conflict("backup base became stale during upload"));
        }
        let (quota, used): (i64, i64) = sqlx::query_as(
            "SELECT chat_storage_quota_bytes,chat_storage_used_bytes
             FROM users WHERE id=$1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_one(&mut *transaction)
        .await?;
        let charged = i64::try_from(measured_bytes)
            .map_err(|_| AppError::bad_request("backup base is too large"))?;
        // Staging temporarily duplicates the current logical archive. Permit
        // that bounded overlap only when the exact post-CAS footprint fits.
        let reclaimable: i64 =
            if metadata.covered_cursor == u64::try_from(locked_cursor).unwrap_or_default() {
                sqlx::query_scalar(
                    "SELECT
                   COALESCE((SELECT SUM(ciphertext_bytes)::bigint
                             FROM chat_backup_segments
                             WHERE user_id=$1 AND cursor<=$2),0) +
                   COALESCE((SELECT SUM(ciphertext_bytes)::bigint
                             FROM chat_backup_bases
                             WHERE user_id=$1 AND state='committed'),0)",
                )
                .bind(user_id)
                .bind(locked_cursor)
                .fetch_one(&mut *transaction)
                .await?
            } else {
                0
            };
        if used
            .checked_add(charged)
            .is_none_or(|value| value > quota.saturating_add(reclaimable))
        {
            return Err(AppError::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "Chat storage full; delete messages or media, or increase storage",
            ));
        }
        let inserted = sqlx::query(
            "INSERT INTO chat_backup_bases
             (user_id,object_id,generation,covered_cursor,ciphertext_bytes,
              ciphertext_sha256,storage_path)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(object_id)
        .bind(
            i64::try_from(metadata.generation)
                .map_err(|_| AppError::bad_request("generation exceeds server range"))?,
        )
        .bind(
            i64::try_from(metadata.covered_cursor)
                .map_err(|_| AppError::bad_request("cursor exceeds server range"))?,
        )
        .bind(charged)
        .bind(&metadata.ciphertext_sha256)
        .bind(&path)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        if inserted {
            sqlx::query(
                "UPDATE users SET chat_storage_used_bytes=chat_storage_used_bytes+$1 WHERE id=$2",
            )
            .bind(charged)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        } else {
            let existing: Option<(Uuid, i64, i64, String)> = sqlx::query_as(
                "SELECT object_id,covered_cursor,ciphertext_bytes,ciphertext_sha256
                 FROM chat_backup_bases WHERE user_id=$1 AND generation=$2",
            )
            .bind(user_id)
            .bind(i64::try_from(metadata.generation).unwrap_or(i64::MAX))
            .fetch_optional(&mut *transaction)
            .await?;
            if existing
                != Some((
                    object_id,
                    i64::try_from(metadata.covered_cursor).unwrap_or(i64::MAX),
                    charged,
                    metadata.ciphertext_sha256.clone(),
                ))
            {
                return Err(AppError::conflict(
                    "another compacted base already owns this generation",
                ));
            }
        }
        transaction.commit().await?;
        Ok(inserted)
    }
    .await;
    let inserted = match insert_result {
        Ok(value) => value,
        Err(error) => {
            if let Err(delete_error) = state.storage.delete(&path).await {
                tracing::warn!("failed to remove rejected backup base object: {delete_error:#}");
            }
            return Err(error);
        }
    };
    crate::telemetry::chat_backup_event("base", if inserted { "staged" } else { "retried" });
    Ok(Json(ChatBackupBaseReceiptV1 {
        object_id: metadata.object_id,
        already_stored: !inserted,
    }))
}

#[utoipa::path(put, path = "/api/chat/backup/manifest", tag = "chat-backup",
    security(("BearerAuth" = [])), request_body = CommitChatBackupManifestRequestV1,
    responses((status = 200, body = ChatBackupManifestCommitReceiptV1), (status = 409, description = "Restore point changed")))]
pub async fn commit_manifest(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CommitChatBackupManifestRequestV1>,
) -> AppResult<Json<ChatBackupManifestCommitReceiptV1>> {
    request.validate().map_err(|error| {
        AppError::bad_request(format!("invalid backup manifest commit: {error}"))
    })?;
    let user_id = trusted_uuid(&user.user_id)?;
    let base_id = canonical_uuid("backup base object id", &request.manifest.base_object_id)?;
    let manifest_digest = request.manifest.digest().map_err(AppError::bad_request)?;
    let mut transaction = state.pool.begin().await?;
    let row: (i64, i64, String, serde_json::Value, String) = sqlx::query_as(
        "SELECT current_generation,current_cursor,current_manifest_digest,
                signer_authorization,signer_authorization_digest
         FROM chat_backups WHERE user_id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| AppError::conflict("Chat history is not provisioned"))?;
    let (generation, cursor, current_digest, authorization_value, authorization_digest) = row;
    if request.expected_generation != u64::try_from(generation).unwrap_or_default()
        || request.expected_cursor != u64::try_from(cursor).unwrap_or_default()
        || request.expected_manifest_digest != current_digest
    {
        return Err(AppError::conflict(
            "backup restore point changed; compact again",
        ));
    }
    let authorization: ChatBackupSignerAuthorizationV1 =
        serde_json::from_value(authorization_value)
            .map_err(|_| AppError::internal("stored backup authorization is malformed"))?;
    request
        .manifest
        .verify(&authorization)
        .map_err(AppError::bad_request)?;
    if request.manifest.generation != request.expected_generation + 1
        || request.manifest.previous_manifest_digest != request.expected_manifest_digest
        || request.manifest.covered_cursor != request.expected_cursor
        || request.manifest.signer_authorization_digest != authorization_digest
    {
        return Err(AppError::conflict("backup manifest CAS binding mismatch"));
    }
    let staged: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT ciphertext_bytes,covered_cursor,ciphertext_sha256
         FROM chat_backup_bases
         WHERE user_id=$1 AND object_id=$2 AND generation=$3 AND state='staged'
         FOR UPDATE",
    )
    .bind(user_id)
    .bind(base_id)
    .bind(
        i64::try_from(request.manifest.generation)
            .map_err(|_| AppError::bad_request("generation exceeds server range"))?,
    )
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((base_bytes, covered_cursor, base_digest)) = staged else {
        return Err(AppError::conflict("backup base is not staged"));
    };
    if u64::try_from(base_bytes).unwrap_or_default() != request.manifest.base_ciphertext_bytes
        || u64::try_from(covered_cursor).unwrap_or_default() != request.manifest.covered_cursor
        || base_digest != request.manifest.base_ciphertext_sha256
    {
        return Err(AppError::bad_request(
            "backup manifest base binding mismatch",
        ));
    }
    let reconciliation_id: Uuid = sqlx::query_scalar(
        "SELECT operation_id FROM chat_backup_media_reconciliations
         WHERE user_id=$1 AND target_generation=$2 AND reference_set_digest=$3 AND completed=true",
    )
    .bind(user_id)
    .bind(i64::try_from(request.manifest.generation).unwrap_or(i64::MAX))
    .bind(&request.manifest.media_reference_set_digest)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| AppError::conflict("backup media reconciliation is incomplete"))?;
    let mut old_paths: Vec<String> = sqlx::query_scalar(
        "SELECT storage_path FROM chat_backup_bases
         WHERE user_id=$1 AND state='committed' AND object_id<>$2",
    )
    .bind(user_id)
    .bind(base_id)
    .fetch_all(&mut *transaction)
    .await?;
    let released_segments: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(ciphertext_bytes),0)::bigint FROM chat_backup_segments
         WHERE user_id=$1 AND cursor<=$2",
    )
    .bind(user_id)
    .bind(covered_cursor)
    .fetch_one(&mut *transaction)
    .await?;
    let released_bases: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(ciphertext_bytes),0)::bigint FROM chat_backup_bases
         WHERE user_id=$1 AND state='committed' AND object_id<>$2",
    )
    .bind(user_id)
    .bind(base_id)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM chat_backup_media_references WHERE user_id=$1")
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO chat_backup_media_references(user_id,media_id,reference_id)
         SELECT user_id,media_id,reference_id
         FROM chat_backup_media_reconciliation_entries
         WHERE user_id=$1 AND operation_id=$2",
    )
    .bind(user_id)
    .bind(reconciliation_id)
    .execute(&mut *transaction)
    .await?;
    let unreferenced_media: Vec<(String, i64)> = sqlx::query_as(
        "SELECT object.storage_path,object.ciphertext_bytes
         FROM chat_backup_media_objects object
         WHERE object.user_id=$1 AND NOT EXISTS (
           SELECT 1 FROM chat_backup_media_references reference
           WHERE reference.user_id=object.user_id AND reference.media_id=object.media_id
         )",
    )
    .bind(user_id)
    .fetch_all(&mut *transaction)
    .await?;
    let released_media = unreferenced_media
        .iter()
        .fold(0i64, |total, (_, bytes)| total.saturating_add(*bytes));
    old_paths.extend(unreferenced_media.into_iter().map(|(path, _)| path));
    sqlx::query(
        "DELETE FROM chat_backup_media_objects object
         WHERE object.user_id=$1 AND NOT EXISTS (
           SELECT 1 FROM chat_backup_media_references reference
           WHERE reference.user_id=object.user_id AND reference.media_id=object.media_id
         )",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;
    let committed_at = OffsetDateTime::now_utc();
    sqlx::query(
        "UPDATE chat_backup_bases SET state='committed',committed_at=$1,expires_at='infinity'
         WHERE user_id=$2 AND object_id=$3",
    )
    .bind(committed_at)
    .bind(user_id)
    .bind(base_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM chat_backup_segments WHERE user_id=$1 AND cursor<=$2")
        .bind(user_id)
        .bind(covered_cursor)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "DELETE FROM chat_backup_bases WHERE user_id=$1 AND state='committed' AND object_id<>$2",
    )
    .bind(user_id)
    .bind(base_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE chat_backups SET current_generation=$1,current_manifest_digest=$2,
         current_manifest=$3,current_base_object_id=$4,latest_protected_at=$5,updated_at=NOW()
         WHERE user_id=$6",
    )
    .bind(i64::try_from(request.manifest.generation).unwrap_or(i64::MAX))
    .bind(&manifest_digest)
    .bind(
        serde_json::to_value(&request.manifest)
            .map_err(|_| AppError::internal("encode backup manifest"))?,
    )
    .bind(base_id)
    .bind(committed_at)
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE users SET chat_storage_used_bytes=GREATEST(0,chat_storage_used_bytes-$1)
         WHERE id=$2",
    )
    .bind(
        released_segments
            .saturating_add(released_bases)
            .saturating_add(released_media),
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "DELETE FROM chat_backup_media_reconciliations
         WHERE user_id=$1 AND target_generation<=$2",
    )
    .bind(user_id)
    .bind(i64::try_from(request.manifest.generation).unwrap_or(i64::MAX))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    for path in old_paths {
        if let Err(error) = state.storage.delete(&path).await {
            tracing::warn!("failed to remove superseded backup base: {error:#}");
        }
    }
    crate::telemetry::chat_backup_event("manifest", "committed");
    Ok(Json(ChatBackupManifestCommitReceiptV1 {
        generation: request.manifest.generation,
        covered_cursor: request.manifest.covered_cursor,
        manifest_digest,
        committed_at_unix: committed_at.unix_timestamp(),
    }))
}

#[utoipa::path(get, path = "/api/chat/backup/bases/{objectId}", tag = "chat-backup",
    security(("BearerAuth" = [])), params(("objectId" = String, Path)),
    responses((status = 200, description = "Encrypted committed base", content_type = "application/octet-stream")))]
pub async fn download_base(
    State(state): State<AppState>,
    user: AuthUser,
    Path(object_id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let object_id = canonical_uuid("backup base object id", &object_id)?;
    let row: Option<(String, i64, String)> = sqlx::query_as(
        "SELECT base.storage_path,base.ciphertext_bytes,base.ciphertext_sha256
         FROM chat_backups backup JOIN chat_backup_bases base
           ON base.user_id=backup.user_id AND base.object_id=backup.current_base_object_id
         WHERE backup.user_id=$1 AND base.object_id=$2 AND base.state='committed'",
    )
    .bind(user_id)
    .bind(object_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((path, expected_bytes, digest)) = row else {
        return Err(AppError::not_found("backup base not found"));
    };
    let (body, stored_bytes) = state
        .storage
        .get_object(&path)
        .await
        .map_err(|_| AppError::internal("backup storage error"))?;
    if stored_bytes != expected_bytes {
        return Err(AppError::internal("stored backup base length mismatch"));
    }
    Ok(super::octet_stream_response(
        body,
        stored_bytes,
        &[("x-kutup-ciphertext-sha256".parse().expect("header"), digest)],
    ))
}

/// Server-side copy of an account-owned inner Chat-media ciphertext into its
/// backup-specific padded outer encryption. The outer key is never persisted.
#[utoipa::path(post, path = "/api/chat/backup/media/copy", tag = "chat-backup",
    security(("BearerAuth" = [])), request_body = CopyChatBackupMediaRequestV1,
    responses((status = 200, body = kutup_chat_proto::ChatBackupMediaReceiptV1), (status = 507, description = "Chat storage full")))]
pub async fn copy_media(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CopyChatBackupMediaRequestV1>,
) -> AppResult<Json<kutup_chat_proto::ChatBackupMediaReceiptV1>> {
    let outer_key = request
        .validate()
        .map_err(|error| AppError::bad_request(format!("invalid backup media copy: {error}")))?;
    let user_id = trusted_uuid(&user.user_id)?;
    let operation_id = canonical_uuid("backup media operation id", &request.operation_id)?;
    let backup_id = canonical_uuid("backup incarnation id", &request.backup_incarnation_id)?;
    let source_id = canonical_uuid("source attachment id", &request.source_attachment_id)?;
    let reference_id = canonical_uuid("backup media reference id", &request.reference_id)?;
    let media_id = canonical_hex_32("backup media id", &request.media_id)?;
    let request_hash = request_digest(&request)?;

    if let Some((stored_hash, bytes, ciphertext_hash)) = sqlx::query_as::<_, (String, i64, String)>(
        "SELECT operation.request_digest,object.ciphertext_bytes,object.ciphertext_sha256
             FROM chat_backup_media_operations operation
             JOIN chat_backup_media_objects object
               ON object.user_id=operation.user_id AND object.media_id=operation.media_id
             WHERE operation.user_id=$1 AND operation.operation_id=$2",
    )
    .bind(user_id)
    .bind(operation_id)
    .fetch_optional(&state.pool)
    .await?
    {
        if stored_hash != request_hash {
            return Err(AppError::conflict(
                "backup media operation changed across retry",
            ));
        }
        return Ok(Json(kutup_chat_proto::ChatBackupMediaReceiptV1 {
            media_id: request.media_id,
            ciphertext_bytes: u64::try_from(bytes).unwrap_or_default(),
            ciphertext_sha256: ciphertext_hash,
            already_stored: true,
        }));
    }

    let source: Option<(String, i64, Uuid, String)> = sqlx::query_as(
        "SELECT object.storage_path,object.ciphertext_bytes,backup.backup_incarnation_id,
                account.account_incarnation_id
         FROM chat_media_references reference
         JOIN chat_media_objects object ON object.attachment_id=reference.attachment_id
         JOIN chat_backups backup ON backup.user_id=reference.user_id
         JOIN users account ON account.id=reference.user_id
         WHERE reference.user_id=$1 AND reference.attachment_id=$2",
    )
    .bind(user_id)
    .bind(source_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((source_path, source_bytes, stored_backup_id, account_incarnation)) = source else {
        return Err(AppError::not_found(
            "Chat media is no longer available for server copy",
        ));
    };
    if stored_backup_id != backup_id || source_bytes <= 0 {
        return Err(AppError::conflict("backup media account binding changed"));
    }
    let media_context = ChatBackupMediaContextV1 {
        account_incarnation_id: canonical_hex_32("account incarnation", &account_incarnation)?,
        backup_incarnation_id: *backup_id.as_bytes(),
        protection_domain: ChatBackupProtectionDomainV1::StandardChat,
        media_id,
    };
    let typed_header = chat_backup_media::build_media_header(
        media_context,
        u64::try_from(source_bytes).map_err(|_| AppError::internal("stored media length"))?,
    )
    .map_err(|_| AppError::bad_request("backup media length is invalid"))?;
    debug_assert_eq!(typed_header.len(), CHAT_BACKUP_MEDIA_HEADER_BYTES);
    let parsed_header = chat_backup_media::inspect_media_header(&typed_header)
        .map_err(|_| AppError::internal("generated backup media header"))?;
    let expected_outer_bytes =
        chat_backup_media::media_object_ciphertext_bytes(parsed_header.padded_plaintext_bytes)
            .map_err(|_| AppError::bad_request("backup media is too large"))?;
    let (source_body, measured_source_bytes) =
        state.storage.get_object(&source_path).await.map_err(|_| {
            AppError::not_found("Chat media is no longer available for server copy")
        })?;
    if measured_source_bytes != source_bytes {
        return Err(AppError::internal("stored Chat media length mismatch"));
    }

    let mut output =
        NamedTempFile::new().map_err(|_| AppError::internal("create backup media temp file"))?;
    let mut output_digest = Sha256::new();
    output
        .write_all(&typed_header)
        .map_err(|_| AppError::internal("write backup media temp file"))?;
    output_digest.update(typed_header);
    let (mut encryptor, stream_header) =
        StreamEncryptor::new_with_aad(&outer_key, &typed_header)
            .map_err(|_| AppError::internal("initialize backup media encryption"))?;
    output
        .write_all(&stream_header)
        .map_err(|_| AppError::internal("write backup media temp file"))?;
    output_digest.update(stream_header);
    let mut source_reader = source_body.into_async_read();
    let source_bytes = u64::try_from(source_bytes).unwrap_or_default();
    let mut offset = 0u64;
    while offset < parsed_header.padded_plaintext_bytes {
        let chunk_len =
            usize::try_from((parsed_header.padded_plaintext_bytes - offset).min(CHUNK_SIZE as u64))
                .map_err(|_| AppError::internal("backup media chunk length"))?;
        let mut plaintext = vec![0u8; chunk_len];
        if offset < source_bytes {
            let source_in_chunk = usize::try_from((source_bytes - offset).min(chunk_len as u64))
                .map_err(|_| AppError::internal("backup media source chunk length"))?;
            source_reader
                .read_exact(&mut plaintext[..source_in_chunk])
                .await
                .map_err(|_| AppError::internal("read Chat media for backup"))?;
        }
        let final_chunk = offset + chunk_len as u64 == parsed_header.padded_plaintext_bytes;
        let encrypted = encryptor
            .push(
                &plaintext,
                if final_chunk { TAG_FINAL } else { TAG_MESSAGE },
            )
            .map_err(|_| AppError::internal("encrypt backup media"))?;
        output
            .write_all(&encrypted)
            .map_err(|_| AppError::internal("write backup media temp file"))?;
        output_digest.update(&encrypted);
        offset += chunk_len as u64;
    }
    let outer_digest = hex::encode(output_digest.finalize());
    let measured_outer_bytes = output
        .as_file()
        .metadata()
        .map_err(|_| AppError::internal("measure backup media"))?
        .len();
    if measured_outer_bytes != expected_outer_bytes {
        return Err(AppError::internal("backup media framing length mismatch"));
    }
    let path = media_storage_path(user_id, backup_id, &request.media_id, operation_id);
    let body = ByteStream::from_path(output.path())
        .await
        .map_err(|_| AppError::internal("read backup media temp file"))?;
    state
        .storage
        .upload(
            &path,
            body,
            i64::try_from(measured_outer_bytes)
                .map_err(|_| AppError::bad_request("backup media is too large"))?,
        )
        .await
        .map_err(|_| AppError::internal("backup media storage error"))?;

    let store_result: AppResult<bool> = async {
        let mut transaction = state.pool.begin().await?;
        let locked_backup_id: Uuid = sqlx::query_scalar(
            "SELECT backup_incarnation_id FROM chat_backups WHERE user_id=$1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_one(&mut *transaction)
        .await?;
        if locked_backup_id != backup_id {
            return Err(AppError::conflict(
                "backup incarnation changed during media copy",
            ));
        }
        let existing: Option<(i64, String)> = sqlx::query_as(
            "SELECT ciphertext_bytes,ciphertext_sha256 FROM chat_backup_media_objects
             WHERE user_id=$1 AND media_id=$2",
        )
        .bind(user_id)
        .bind(media_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let inserted = if existing.is_some() {
            // Secretstream uses a fresh header, so concurrent valid copies of
            // the same deterministic media ID need not have equal ciphertext.
            false
        } else {
            let (quota, used): (i64, i64) = sqlx::query_as(
                "SELECT chat_storage_quota_bytes,chat_storage_used_bytes
                 FROM users WHERE id=$1 FOR UPDATE",
            )
            .bind(user_id)
            .fetch_one(&mut *transaction)
            .await?;
            let charged = i64::try_from(measured_outer_bytes)
                .map_err(|_| AppError::bad_request("backup media is too large"))?;
            if used.checked_add(charged).is_none_or(|value| value > quota) {
                return Err(AppError::new(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Chat storage full; delete messages or media, or increase storage",
                ));
            }
            sqlx::query(
                "INSERT INTO chat_backup_media_objects
                 (user_id,media_id,ciphertext_bytes,ciphertext_sha256,storage_path)
                 VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(user_id)
            .bind(media_id.as_slice())
            .bind(charged)
            .bind(&outer_digest)
            .bind(&path)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE users SET chat_storage_used_bytes=chat_storage_used_bytes+$1 WHERE id=$2",
            )
            .bind(charged)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
            true
        };
        if let Some(existing_media_id) = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT media_id FROM chat_backup_media_references
             WHERE user_id=$1 AND reference_id=$2",
        )
        .bind(user_id)
        .bind(reference_id)
        .fetch_optional(&mut *transaction)
        .await?
        {
            if existing_media_id != media_id {
                return Err(AppError::conflict(
                    "backup media reference changed across retry",
                ));
            }
        } else {
            sqlx::query(
                "INSERT INTO chat_backup_media_references(user_id,media_id,reference_id)
                 VALUES ($1,$2,$3)",
            )
            .bind(user_id)
            .bind(media_id.as_slice())
            .bind(reference_id)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "INSERT INTO chat_backup_media_operations(user_id,operation_id,request_digest,media_id)
             VALUES ($1,$2,$3,$4)",
        )
        .bind(user_id)
        .bind(operation_id)
        .bind(&request_hash)
        .bind(media_id.as_slice())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(inserted)
    }
    .await;
    let inserted = match store_result {
        Ok(value) => value,
        Err(error) => {
            if let Err(delete_error) = state.storage.delete(&path).await {
                tracing::warn!("failed to remove rejected backup media: {delete_error:#}");
            }
            return Err(error);
        }
    };
    if !inserted {
        if let Err(error) = state.storage.delete(&path).await {
            tracing::warn!("failed to remove duplicate backup media copy: {error:#}");
        }
        let (bytes, stored_digest): (i64, String) = sqlx::query_as(
            "SELECT ciphertext_bytes,ciphertext_sha256 FROM chat_backup_media_objects
             WHERE user_id=$1 AND media_id=$2",
        )
        .bind(user_id)
        .bind(media_id.as_slice())
        .fetch_one(&state.pool)
        .await?;
        return Ok(Json(kutup_chat_proto::ChatBackupMediaReceiptV1 {
            media_id: request.media_id,
            ciphertext_bytes: u64::try_from(bytes).unwrap_or_default(),
            ciphertext_sha256: stored_digest,
            already_stored: true,
        }));
    }
    crate::telemetry::chat_backup_event("media", "copied");
    Ok(Json(kutup_chat_proto::ChatBackupMediaReceiptV1 {
        media_id: request.media_id,
        ciphertext_bytes: measured_outer_bytes,
        ciphertext_sha256: outer_digest,
        already_stored: false,
    }))
}

/// Direct upload fallback for a verified outer-encrypted media copy retained
/// by a client after the administrator-retained delivery object has expired.
#[utoipa::path(post, path = "/api/chat/backup/media", tag = "chat-backup",
    security(("BearerAuth" = [])), request_body(
        content = Vec<u8>, content_type = "multipart/form-data",
        description = "Typed metadata and outer-encrypted media ciphertext"
    ), responses((status = 200, body = kutup_chat_proto::ChatBackupMediaReceiptV1), (status = 507, description = "Chat storage full")))]
pub async fn upload_media(
    State(state): State<AppState>,
    user: AuthUser,
    mut multipart: Multipart,
) -> AppResult<Json<kutup_chat_proto::ChatBackupMediaReceiptV1>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let mut metadata: Option<UploadChatBackupMediaRequestV1> = None;
    let mut object: Option<(NamedTempFile, u64, [u8; 32])> = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::bad_request("invalid backup media multipart form"))?
    {
        match field.name().unwrap_or("") {
            "metadata" => {
                if metadata.is_some() {
                    return Err(AppError::bad_request("duplicate backup media metadata"));
                }
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|_| AppError::bad_request("invalid backup media metadata"))?;
                metadata = Some(
                    serde_json::from_slice(&bytes)
                        .map_err(|_| AppError::bad_request("invalid backup media metadata"))?,
                );
            }
            "ciphertext" => {
                if object.is_some() {
                    return Err(AppError::bad_request("duplicate backup media ciphertext"));
                }
                let mut file = NamedTempFile::new()
                    .map_err(|_| AppError::internal("create backup media temp file"))?;
                let mut bytes = 0u64;
                let mut digest = Sha256::new();
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|_| AppError::bad_request("invalid backup media ciphertext"))?
                {
                    bytes = bytes
                        .checked_add(chunk.len() as u64)
                        .ok_or_else(|| AppError::bad_request("backup media is too large"))?;
                    file.write_all(&chunk)
                        .map_err(|_| AppError::internal("write backup media temp file"))?;
                    digest.update(&chunk);
                }
                object = Some((file, bytes, digest.finalize().into()));
            }
            _ => {
                return Err(AppError::bad_request(
                    "unknown backup media multipart field",
                ))
            }
        }
    }
    let metadata =
        metadata.ok_or_else(|| AppError::bad_request("missing backup media metadata"))?;
    metadata
        .validate()
        .map_err(|error| AppError::bad_request(format!("invalid backup media: {error}")))?;
    let (mut file, measured_bytes, measured_digest) =
        object.ok_or_else(|| AppError::bad_request("missing backup media ciphertext"))?;
    if measured_bytes != metadata.ciphertext_bytes
        || hex::encode(measured_digest) != metadata.ciphertext_sha256
    {
        return Err(AppError::bad_request(
            "backup media ciphertext binding mismatch",
        ));
    }
    let backup_id = canonical_uuid("backup incarnation id", &metadata.backup_incarnation_id)?;
    let reference_id = canonical_uuid("backup media reference id", &metadata.reference_id)?;
    let media_id = canonical_hex_32("backup media id", &metadata.media_id)?;
    let mut public_header = vec![0u8; CHAT_BACKUP_MEDIA_HEADER_BYTES];
    file.as_file_mut()
        .seek(SeekFrom::Start(0))
        .and_then(|_| file.as_file_mut().read_exact(&mut public_header))
        .map_err(|_| AppError::bad_request("backup media header is truncated"))?;
    let parsed = chat_backup_media::inspect_media_header(&public_header)
        .map_err(|_| AppError::bad_request("invalid backup media header"))?;
    let expected_bytes =
        chat_backup_media::media_object_ciphertext_bytes(parsed.padded_plaintext_bytes)
            .map_err(|_| AppError::bad_request("backup media length is invalid"))?;
    if expected_bytes != measured_bytes
        || parsed.source_ciphertext_bytes != metadata.source_ciphertext_bytes
        || parsed.context.backup_incarnation_id != *backup_id.as_bytes()
        || parsed.context.media_id != media_id
        || parsed.context.protection_domain != ChatBackupProtectionDomainV1::StandardChat
        || parsed.suite != ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1
    {
        return Err(AppError::bad_request(
            "backup media public binding mismatch",
        ));
    }
    let account: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT backup.backup_incarnation_id,account.account_incarnation_id
         FROM chat_backups backup JOIN users account ON account.id=backup.user_id
         WHERE backup.user_id=$1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((stored_backup_id, account_incarnation)) = account else {
        return Err(AppError::conflict("Chat history is not provisioned"));
    };
    if stored_backup_id != backup_id
        || parsed.context.account_incarnation_id
            != canonical_hex_32("account incarnation", &account_incarnation)?
    {
        return Err(AppError::conflict(
            "backup media belongs to another account",
        ));
    }

    if let Some((bytes, digest)) = sqlx::query_as::<_, (i64, String)>(
        "SELECT ciphertext_bytes,ciphertext_sha256 FROM chat_backup_media_objects
         WHERE user_id=$1 AND media_id=$2",
    )
    .bind(user_id)
    .bind(media_id.as_slice())
    .fetch_optional(&state.pool)
    .await?
    {
        if bytes != i64::try_from(measured_bytes).unwrap_or_default()
            || digest != metadata.ciphertext_sha256
        {
            return Err(AppError::conflict(
                "backup media id already has different ciphertext",
            ));
        }
        ensure_media_reference(&state, user_id, media_id, reference_id).await?;
        return Ok(Json(kutup_chat_proto::ChatBackupMediaReceiptV1 {
            media_id: metadata.media_id,
            ciphertext_bytes: measured_bytes,
            ciphertext_sha256: digest,
            already_stored: true,
        }));
    }

    let path = format!(
        "chat-backup/{user_id}/{backup_id}/media/{}/direct-{reference_id}",
        metadata.media_id
    );
    let body = ByteStream::from_path(file.path())
        .await
        .map_err(|_| AppError::internal("read backup media temp file"))?;
    state
        .storage
        .upload(
            &path,
            body,
            i64::try_from(measured_bytes)
                .map_err(|_| AppError::bad_request("backup media is too large"))?,
        )
        .await
        .map_err(|_| AppError::internal("backup media storage error"))?;
    let result: AppResult<bool> = async {
        let mut transaction = state.pool.begin().await?;
        sqlx::query("SELECT user_id FROM chat_backups WHERE user_id=$1 FOR UPDATE")
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        let existing: Option<(i64, String)> = sqlx::query_as(
            "SELECT ciphertext_bytes,ciphertext_sha256 FROM chat_backup_media_objects
             WHERE user_id=$1 AND media_id=$2",
        )
        .bind(user_id)
        .bind(media_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let inserted = if let Some((stored_bytes, stored_digest)) = existing {
            if stored_bytes != i64::try_from(measured_bytes).unwrap_or_default()
                || stored_digest != metadata.ciphertext_sha256
            {
                return Err(AppError::conflict(
                    "backup media ID changed across direct-upload retry",
                ));
            }
            false
        } else {
            let (quota, used): (i64, i64) = sqlx::query_as(
                "SELECT chat_storage_quota_bytes,chat_storage_used_bytes
                 FROM users WHERE id=$1 FOR UPDATE",
            )
            .bind(user_id)
            .fetch_one(&mut *transaction)
            .await?;
            let charged = i64::try_from(measured_bytes)
                .map_err(|_| AppError::bad_request("backup media is too large"))?;
            if used.checked_add(charged).is_none_or(|value| value > quota) {
                return Err(AppError::new(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Chat storage full; delete messages or media, or increase storage",
                ));
            }
            sqlx::query(
                "INSERT INTO chat_backup_media_objects
                 (user_id,media_id,ciphertext_bytes,ciphertext_sha256,storage_path)
                 VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(user_id)
            .bind(media_id.as_slice())
            .bind(charged)
            .bind(&metadata.ciphertext_sha256)
            .bind(&path)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE users SET chat_storage_used_bytes=chat_storage_used_bytes+$1 WHERE id=$2",
            )
            .bind(charged)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
            true
        };
        insert_media_reference(&mut transaction, user_id, media_id, reference_id).await?;
        transaction.commit().await?;
        Ok(inserted)
    }
    .await;
    let inserted = match result {
        Ok(inserted) => inserted,
        Err(error) => {
            let _ = state.storage.delete(&path).await;
            return Err(error);
        }
    };
    if !inserted {
        let _ = state.storage.delete(&path).await;
    }
    let (stored_bytes, stored_digest): (i64, String) = sqlx::query_as(
        "SELECT ciphertext_bytes,ciphertext_sha256 FROM chat_backup_media_objects
         WHERE user_id=$1 AND media_id=$2",
    )
    .bind(user_id)
    .bind(media_id.as_slice())
    .fetch_one(&state.pool)
    .await?;
    crate::telemetry::chat_backup_event("media", if inserted { "uploaded" } else { "retried" });
    Ok(Json(kutup_chat_proto::ChatBackupMediaReceiptV1 {
        media_id: metadata.media_id,
        ciphertext_bytes: u64::try_from(stored_bytes).unwrap_or_default(),
        ciphertext_sha256: stored_digest,
        already_stored: !inserted,
    }))
}

async fn insert_media_reference(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    media_id: [u8; 32],
    reference_id: Uuid,
) -> AppResult<()> {
    if let Some(existing) = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT media_id FROM chat_backup_media_references
         WHERE user_id=$1 AND reference_id=$2",
    )
    .bind(user_id)
    .bind(reference_id)
    .fetch_optional(&mut **transaction)
    .await?
    {
        if existing != media_id {
            return Err(AppError::conflict(
                "backup media reference changed across retry",
            ));
        }
    } else {
        sqlx::query(
            "INSERT INTO chat_backup_media_references(user_id,media_id,reference_id)
             VALUES ($1,$2,$3)",
        )
        .bind(user_id)
        .bind(media_id.as_slice())
        .bind(reference_id)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn ensure_media_reference(
    state: &AppState,
    user_id: Uuid,
    media_id: [u8; 32],
    reference_id: Uuid,
) -> AppResult<()> {
    let mut transaction = state.pool.begin().await?;
    insert_media_reference(&mut transaction, user_id, media_id, reference_id).await?;
    transaction.commit().await?;
    Ok(())
}

#[utoipa::path(get, path = "/api/chat/backup/media/{mediaId}", tag = "chat-backup",
    security(("BearerAuth" = [])), params(("mediaId" = String, Path)),
    responses((status = 200, description = "Outer-encrypted backup media", content_type = "application/octet-stream")))]
pub async fn download_media(
    State(state): State<AppState>,
    user: AuthUser,
    Path(media_id): Path<String>,
) -> AppResult<Response> {
    let user_id = trusted_uuid(&user.user_id)?;
    let media_id_bytes = canonical_hex_32("backup media id", &media_id)?;
    let row: Option<(String, i64, String)> = sqlx::query_as(
        "SELECT storage_path,ciphertext_bytes,ciphertext_sha256
         FROM chat_backup_media_objects WHERE user_id=$1 AND media_id=$2",
    )
    .bind(user_id)
    .bind(media_id_bytes.as_slice())
    .fetch_optional(&state.pool)
    .await?;
    let Some((path, expected_bytes, digest)) = row else {
        return Err(AppError::not_found("backup media not found"));
    };
    let (body, stored_bytes) = state
        .storage
        .get_object(&path)
        .await
        .map_err(|_| AppError::internal("backup media storage error"))?;
    if stored_bytes != expected_bytes {
        return Err(AppError::internal("stored backup media length mismatch"));
    }
    Ok(super::octet_stream_response(
        body,
        stored_bytes,
        &[("x-kutup-ciphertext-sha256".parse().expect("header"), digest)],
    ))
}

#[utoipa::path(post, path = "/api/chat/backup/media/reconciliation", tag = "chat-backup",
    security(("BearerAuth" = [])), request_body = ReconcileChatBackupMediaRequestV1,
    responses((status = 200, body = ChatBackupMediaReconciliationReceiptV1)))]
pub async fn reconcile_media(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<ReconcileChatBackupMediaRequestV1>,
) -> AppResult<Json<ChatBackupMediaReconciliationReceiptV1>> {
    request
        .validate()
        .map_err(|error| AppError::bad_request(format!("invalid media reconciliation: {error}")))?;
    let user_id = trusted_uuid(&user.user_id)?;
    let operation_id = canonical_uuid("media reconciliation operation id", &request.operation_id)?;
    let target_generation = i64::try_from(request.target_generation)
        .map_err(|_| AppError::bad_request("target generation exceeds server range"))?;
    let page_index = i32::try_from(request.page_index)
        .map_err(|_| AppError::bad_request("page index exceeds server range"))?;
    let page_digest = request_digest(&request)?;
    let mut transaction = state.pool.begin().await?;
    let current_generation: i64 = sqlx::query_scalar(
        "SELECT current_generation FROM chat_backups WHERE user_id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| AppError::conflict("Chat history is not provisioned"))?;
    if target_generation != current_generation + 1 {
        return Err(AppError::conflict(
            "media reconciliation generation is stale",
        ));
    }
    let staged: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat_backup_bases
         WHERE user_id=$1 AND generation=$2 AND state='staged')",
    )
    .bind(user_id)
    .bind(target_generation)
    .fetch_one(&mut *transaction)
    .await?;
    if !staged {
        return Err(AppError::conflict(
            "stage the backup base before reconciling media",
        ));
    }
    if let Some(stored_digest) = sqlx::query_scalar::<_, String>(
        "SELECT request_digest FROM chat_backup_media_reconciliation_pages
         WHERE user_id=$1 AND operation_id=$2 AND page_index=$3",
    )
    .bind(user_id)
    .bind(operation_id)
    .bind(page_index)
    .fetch_optional(&mut *transaction)
    .await?
    {
        if stored_digest != page_digest {
            return Err(AppError::conflict(
                "media reconciliation page changed across retry",
            ));
        }
        let (next_page, completed): (i32, bool) = sqlx::query_as(
            "SELECT next_page,completed FROM chat_backup_media_reconciliations
             WHERE user_id=$1 AND operation_id=$2",
        )
        .bind(user_id)
        .bind(operation_id)
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        return Ok(Json(ChatBackupMediaReconciliationReceiptV1 {
            operation_id: request.operation_id,
            next_page: u32::try_from(next_page).unwrap_or_default(),
            completed,
        }));
    }
    let operation: Option<(i64, String, i32, bool)> = sqlx::query_as(
        "SELECT target_generation,reference_set_digest,next_page,completed
         FROM chat_backup_media_reconciliations
         WHERE user_id=$1 AND operation_id=$2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(operation_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let (next_page, completed) = if let Some((stored_generation, stored_digest, next, done)) =
        operation
    {
        if stored_generation != target_generation || stored_digest != request.reference_set_digest {
            return Err(AppError::conflict(
                "media reconciliation operation changed across retry",
            ));
        }
        (next, done)
    } else {
        if page_index != 0 {
            return Err(AppError::conflict(
                "media reconciliation must start at page zero",
            ));
        }
        sqlx::query(
            "INSERT INTO chat_backup_media_reconciliations
             (user_id,operation_id,target_generation,reference_set_digest)
             VALUES ($1,$2,$3,$4)",
        )
        .bind(user_id)
        .bind(operation_id)
        .bind(target_generation)
        .bind(&request.reference_set_digest)
        .execute(&mut *transaction)
        .await?;
        (0, false)
    };
    if completed || page_index != next_page {
        return Err(AppError::conflict(
            "media reconciliation page is out of order",
        ));
    }
    for reference in &request.references {
        let reference_id = canonical_uuid("backup media reference id", &reference.reference_id)?;
        let media_id = canonical_hex_32("backup media id", &reference.media_id)?;
        sqlx::query(
            "INSERT INTO chat_backup_media_reconciliation_entries
             (user_id,operation_id,reference_id,media_id) VALUES ($1,$2,$3,$4)",
        )
        .bind(user_id)
        .bind(operation_id)
        .bind(reference_id)
        .bind(media_id.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .is_some_and(|value| value.is_unique_violation())
            {
                AppError::conflict("duplicate media reconciliation reference")
            } else {
                AppError::from(error)
            }
        })?;
    }
    let new_next_page = page_index + 1;
    let mut now_completed = false;
    if request.final_page {
        let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
            "SELECT reference_id,media_id FROM chat_backup_media_reconciliation_entries
             WHERE user_id=$1 AND operation_id=$2 ORDER BY reference_id",
        )
        .bind(user_id)
        .bind(operation_id)
        .fetch_all(&mut *transaction)
        .await?;
        let references = rows
            .into_iter()
            .map(|(reference_id, media_id)| ChatBackupMediaReferenceV1 {
                reference_id: reference_id.hyphenated().to_string(),
                media_id: hex::encode(media_id),
            })
            .collect::<Vec<_>>();
        let computed =
            chat_backup_media_reference_set_digest(&references).map_err(AppError::bad_request)?;
        if computed != request.reference_set_digest {
            return Err(AppError::bad_request(
                "media reconciliation set digest mismatch",
            ));
        }
        now_completed = true;
    }
    sqlx::query(
        "UPDATE chat_backup_media_reconciliations
         SET next_page=$1,completed=$2,updated_at=NOW()
         WHERE user_id=$3 AND operation_id=$4",
    )
    .bind(new_next_page)
    .bind(now_completed)
    .bind(user_id)
    .bind(operation_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO chat_backup_media_reconciliation_pages
         (user_id,operation_id,page_index,request_digest) VALUES ($1,$2,$3,$4)",
    )
    .bind(user_id)
    .bind(operation_id)
    .bind(page_index)
    .bind(page_digest)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(ChatBackupMediaReconciliationReceiptV1 {
        operation_id: request.operation_id,
        next_page: u32::try_from(new_next_page).unwrap_or_default(),
        completed: now_completed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_and_hash_parsers_are_canonical() {
        assert!(canonical_uuid("id", "11111111-1111-4111-8111-111111111111").is_ok());
        assert!(canonical_uuid("id", "11111111111141118111111111111111").is_err());
        assert_eq!(canonical_hex_32("digest", ZERO_DIGEST).unwrap(), [0u8; 32]);
        assert!(canonical_hex_32("digest", &"AA".repeat(32)).is_err());
    }
}
