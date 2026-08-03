//! API request/response DTOs — mirrors `backend/handlers/models.go` (+ `health.go`).
//!
//! Wire-format parity rules (see `docs/rust-conversion/approach.md`):
//!   * JSON keys are camelCase (`serde(rename_all = "camelCase")`).
//!   * Field declaration order == Go struct field order (serde serializes in order).
//!   * Go `,omitempty` on a pointer/string/bool ⇒ `skip_serializing_if` here.
//!   * Go pointer field *without* `omitempty` ⇒ `Option<T>` that serializes `null`.
//!   * `time.Time` ⇒ RFC3339 (`time::serde::rfc3339`), matching Go's `encoding/json`.
//!
//! These DTOs are the full API surface mirrored up front; request-body structs read
//! as dead code until their handler slice lands, so `dead_code` is allowed here and
//! lifted once every handler is wired (server slice 8).
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

/// `skip_serializing_if` predicate for Go `bool ,omitempty` (omit when false).
fn is_false(b: &bool) -> bool {
    !*b
}

/// Liveness/identity probe body — mirrors `handlers/health.go` `Get`.
/// Anonymous, no DB hit; field order is `name`, `version`, `tusVersions`.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub name: &'static str,
    pub version: String,
    #[serde(rename = "tusVersions")]
    pub tus_versions: Vec<&'static str>,
}

/// Wraps API error messages — mirrors `handlers.ErrorResponse`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

/// Wraps simple success messages — mirrors `handlers.MessageResponse`.
#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse {
    pub message: String,
}

/// Public server settings (`GET /api/auth/settings`) — how a client learns what
/// the server supports before showing UI for it.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SettingsResponse {
    pub registration_enabled: bool,
    /// Chat feature advertisement (docs/chat-protocol.md §10). A client
    /// feature-gates chat on this and must not show chat UI when absent/disabled.
    pub chat: kutup_chat_proto::ChatCapabilities,
}

/// `GET /api/auth/login/preflight` — mirrors `handlers.PreflightLoginResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PreflightLoginResponse {
    pub account_protection_suite: u16,
    pub account_protection_salt: String,
    pub argon_memory_kib: u32,
    pub argon_iterations: u32,
    pub argon_parallelism: u32,
}

/// `GET /api/auth/recover/preflight` — mirrors `handlers.PreflightRecoverResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PreflightRecoverResponse {
    pub recovery_key_envelope: String,
}

/// `POST /api/auth/refresh` — mirrors `handlers.RefreshResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub access_token: String,
}

/// `GET /api/user/me` — mirrors `handlers.MeResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    pub id: String,
    pub email: String,
    pub username: String,
    pub public_key: String,
    pub totp_enabled: bool,
    pub storage_quota_bytes: i64,
    pub storage_used_bytes: i64,
    pub is_admin: bool,
    pub color: String,
}

/// Generic success — mirrors `handlers.OkResponse`.
#[derive(Debug, Serialize, ToSchema)]
pub struct OkResponse {
    pub ok: bool,
}

/// `POST /api/user/2fa/setup` — mirrors `handlers.TOTPSetupResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetupResponse {
    pub secret: String,
    #[serde(rename = "qrUri")]
    pub qr_uri: String,
}

/// Body for TOTP verify/disable — mirrors `handlers.TOTPCodeRequest`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpCodeRequest {
    pub code: String,
}

/// `GET /api/users/by-email/:email` — mirrors `handlers.UserLookupResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserLookupResponse {
    pub user_id: String,
    pub account: String,
    pub drive_hpke_public_key: String,
    pub account_incarnation_id: String,
    pub drive_signing_public_key: String,
}

/// Collection list/get row — mirrors `handlers.CollectionRow`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CollectionRow {
    pub id: String,
    pub owner_user_id: String,
    pub name_envelope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_key_envelope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub named_share_envelope: Option<String>,
    pub key_epoch: i32,
    pub name_revision: i64,
    pub epoch_statement: String,
    pub epoch_statement_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_incarnation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_drive_signing_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_authority_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_collection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_upload: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_delete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_quota_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_used_bytes: Option<i64>,
    #[serde(skip_serializing_if = "is_false")]
    pub is_shared: bool,
}

/// `POST /api/collections` body — mirrors `handlers.CreateCollectionRequest`.
/// `default` so missing JSON fields decode to zero values (Go `c.BodyParser`).
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateCollectionRequest {
    pub id: String,
    pub name_envelope: String,
    pub owner_key_envelope: String,
    pub epoch_statement: String,
    pub parent_collection_id: Option<String>,
}

/// `POST /api/collections` result — mirrors `handlers.CreateCollectionResult`.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateCollectionResult {
    pub id: String,
}

/// `PUT /api/collections/{id}` body — mirrors `handlers.UpdateCollectionRequest`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateCollectionRequest {
    pub name_envelope: String,
    pub name_revision: i64,
}

/// `PATCH /api/collections/{id}/color` body — mirrors `handlers.UpdateColorRequest`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct UpdateColorRequest {
    pub color: Option<String>,
}

/// `POST /api/collections/{id}/share` body — mirrors `handlers.ShareCollectionRequest`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct ShareCollectionRequest {
    pub recipient_user_id: String,
    pub named_share_envelope: String,
    pub can_upload: bool,
    pub can_delete: bool,
    pub upload_quota_bytes: Option<i64>,
}

/// File listing row — mirrors `handlers.FileRow`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileRow {
    pub id: String,
    pub collection_id: String,
    pub uploader_user_id: String,
    pub metadata_envelope: String,
    pub file_key_envelope: String,
    pub key_epoch: i32,
    pub metadata_revision: i64,
    pub encrypted_size_bytes: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// File upload result — mirrors `handlers.UploadResult`.
#[derive(Debug, Serialize, ToSchema)]
pub struct UploadResult {
    pub id: String,
}

/// A trashed folder (a trash root) — `GET /api/trash`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TrashFolderRow {
    pub id: String,
    pub owner_user_id: String,
    pub name_envelope: String,
    pub owner_key_envelope: String,
    pub key_epoch: i32,
    pub name_revision: i64,
    pub epoch_statement: String,
    pub epoch_statement_hash: String,
    pub color: Option<String>,
    /// Files trashed together with this folder (its whole subtree).
    pub items: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub deleted_at: OffsetDateTime,
}

/// A trashed file (a trash root) — `GET /api/trash`. Carries the parent collection's
/// owner-wrapped key so the metadata chain decrypts even when the collection itself
/// is not in the live listing.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TrashFileRow {
    pub id: String,
    pub collection_id: String,
    pub metadata_envelope: String,
    pub file_key_envelope: String,
    pub key_epoch: i32,
    pub metadata_revision: i64,
    pub collection_owner_user_id: String,
    pub collection_owner_key_envelope: String,
    pub collection_key_epoch: i32,
    pub collection_epoch_statement: String,
    pub collection_epoch_statement_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub deleted_at: OffsetDateTime,
}

/// `GET /api/trash` body — the caller's trash roots, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct TrashResponse {
    pub folders: Vec<TrashFolderRow>,
    pub files: Vec<TrashFileRow>,
}

/// `POST /api/share` body — mirrors `handlers.CreateShareRequest`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateShareRequest {
    pub share_type: String,
    pub target_id: String,
    pub collection_key_envelope: String,
    pub expires_in_hours: Option<i32>,
}

/// `POST /api/share` result — mirrors `handlers.CreateShareResult`.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateShareResult {
    pub id: String,
    pub token: String,
}

/// `GET /api/share/{token}` — mirrors `handlers.PublicShareResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublicShareResponse {
    pub id: String,
    pub share_type: String,
    pub target_id: String,
    pub collection_key_envelope: String,
    pub collection_key_epoch: i32,
    pub owner_user_id: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

/// Admin user row — mirrors `handlers.UserRow`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub username: String,
    pub storage_quota_bytes: i64,
    pub storage_used_bytes: i64,
    pub is_admin: bool,
    pub is_active: bool,
    pub totp_enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// `POST /api/admin/users` body — mirrors `handlers.CreateAdminUserRequest`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateAdminUserRequest {
    pub email: String,
    pub username: String,
    pub temp_password: String,
    pub storage_quota_bytes: i64,
}

/// `PUT /api/admin/users/{id}` body — mirrors `handlers.UpdateAdminUserRequest`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAdminUserRequest {
    pub storage_quota_bytes: Option<i64>,
    pub is_active: Option<bool>,
    pub is_admin: Option<bool>,
}

/// `PUT /api/admin/settings` body — mirrors `handlers.UpdateAdminSettingsRequest`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAdminSettingsRequest {
    pub registration_enabled: bool,
}

/// `GET /api/admin/stats` — mirrors `handlers.StatsResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StatsResponse {
    pub total_users: i64,
    pub active_users: i64,
    pub total_files: i64,
    #[serde(rename = "totalStorageUsedBytes")]
    pub total_storage_used: i64,
    pub total_collections: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_json_matches_go() {
        // Mirrors handlers/health.go: keys name, version, tusVersions (in order).
        let body = serde_json::to_string(&HealthResponse {
            name: "kutup",
            version: "dev".to_string(),
            tus_versions: vec!["1.0.0"],
        })
        .unwrap();
        assert_eq!(
            body,
            r#"{"name":"kutup","version":"dev","tusVersions":["1.0.0"]}"#
        );
    }

    #[test]
    fn error_response_shape() {
        let body = serde_json::to_string(&ErrorResponse {
            error: "nope".to_string(),
        })
        .unwrap();
        assert_eq!(body, r#"{"error":"nope"}"#);
    }

    #[test]
    fn collection_row_omits_empty_optionals() {
        // Go `,omitempty` pointers/bool are absent when nil/false.
        let row = CollectionRow {
            id: "c1".into(),
            owner_user_id: "u1".into(),
            name_envelope: "n".into(),
            owner_key_envelope: Some("k".into()),
            named_share_envelope: None,
            key_epoch: 1,
            name_revision: 1,
            epoch_statement: "statement".into(),
            epoch_statement_hash: "11".repeat(32),
            owner_account: None,
            owner_incarnation_id: None,
            owner_drive_signing_public_key: None,
            owner_authority_public_key: None,
            parent_collection_id: None,
            color: None,
            can_upload: None,
            can_delete: None,
            upload_quota_bytes: None,
            upload_used_bytes: None,
            is_shared: false,
        };
        let v: serde_json::Value = serde_json::to_value(&row).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("parentCollectionId"));
        assert!(!obj.contains_key("color"));
        assert!(!obj.contains_key("isShared"));
        assert!(obj.contains_key("ownerKeyEnvelope"));
        assert!(!obj.contains_key("namedShareEnvelope"));
    }

    #[test]
    fn public_share_context_serializes_explicitly() {
        let resp = PublicShareResponse {
            id: "s1".into(),
            share_type: "collection".into(),
            target_id: "c1".into(),
            collection_key_envelope: "envelope".into(),
            collection_key_epoch: 1,
            owner_user_id: "u1".into(),
            expires_at: None,
        };
        let v: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(v.get("collectionKeyEpoch").unwrap(), 1);
        assert_eq!(v.get("ownerUserId").unwrap(), "u1");
        assert!(v.get("expiresAt").unwrap().is_null());
    }
}
