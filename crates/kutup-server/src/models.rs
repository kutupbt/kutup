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

/// Public registration settings — mirrors `handlers.SettingsResponse`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SettingsResponse {
    pub registration_enabled: bool,
}

/// `GET /api/auth/login/preflight` — mirrors `handlers.PreflightLoginResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PreflightLoginResponse {
    #[serde(rename = "kdfSalt")]
    pub kdf_salt: String,
    pub login_key_salt: String,
}

/// `GET /api/auth/recover/preflight` — mirrors `handlers.PreflightRecoverResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PreflightRecoverResponse {
    pub encrypted_recovery_key: String,
    pub recovery_key_nonce: String,
    pub encrypted_private_key: String,
    pub private_key_nonce: String,
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
    pub public_key: String,
}

/// Collection list/get row — mirrors `handlers.CollectionRow`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CollectionRow {
    pub id: String,
    pub owner_user_id: String,
    pub encrypted_name: String,
    pub name_nonce: String,
    pub encrypted_key: String,
    pub encrypted_key_nonce: String,
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
    pub encrypted_name: String,
    pub name_nonce: String,
    pub encrypted_key: String,
    pub encrypted_key_nonce: String,
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
    pub encrypted_name: String,
    pub name_nonce: String,
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
    pub encrypted_collection_key: String,
    pub can_upload: bool,
    pub can_delete: bool,
    pub upload_quota_bytes: Option<i64>,
}

/// `POST /api/collections/{id}/share-federated` body — mirrors `handlers.ShareFederatedRequest`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShareFederatedRequest {
    pub recipient_username: String,
    pub recipient_server: String,
    pub encrypted_collection_key: String,
    pub can_upload: bool,
    pub can_delete: bool,
    pub upload_quota_bytes: Option<i64>,
}

/// `POST /api/collections/{id}/share-federated` result — mirrors `handlers.ShareFederatedResult`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShareFederatedResult {
    pub invite_token: String,
    pub invite_url: String,
}

/// Federation pubkey lookup — mirrors `handlers.PubkeyResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PubkeyResponse {
    pub public_key: String,
}

/// File listing row — mirrors `handlers.FileRow`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileRow {
    pub id: String,
    pub collection_id: String,
    pub uploader_user_id: String,
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

/// File upload result — mirrors `handlers.UploadResult`.
#[derive(Debug, Serialize, ToSchema)]
pub struct UploadResult {
    pub id: String,
}

/// A trashed folder (a trash root) — `GET /api/trash`. The owner decrypts
/// `encrypted_key` with their master key, then the name with the collection key.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TrashFolderRow {
    pub id: String,
    pub encrypted_name: String,
    pub name_nonce: String,
    pub encrypted_key: String,
    pub encrypted_key_nonce: String,
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
    pub encrypted_metadata: String,
    pub metadata_nonce: String,
    pub encrypted_file_key: String,
    pub file_key_nonce: String,
    pub collection_encrypted_key: String,
    pub collection_encrypted_key_nonce: String,
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
    pub encrypted_collection_key: String,
    pub encrypted_collection_key_nonce: String,
    pub expires_in_hours: Option<i32>,
}

/// `POST /api/share` result — mirrors `handlers.CreateShareResult`.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateShareResult {
    pub id: String,
    pub token: String,
}

/// `GET /api/share/{token}` — mirrors `handlers.PublicShareResponse`.
/// The pointer fields have no `omitempty` in Go, so they serialize as `null`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublicShareResponse {
    pub id: String,
    pub share_type: String,
    pub target_id: String,
    pub encrypted_collection_key: Option<String>,
    pub encrypted_collection_key_nonce: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

/// Public-share file download URL — mirrors `handlers.DownloadURLResponse`.
#[derive(Debug, Serialize, ToSchema)]
pub struct DownloadUrlResponse {
    pub url: String,
}

/// `GET /api/fed/invites/{token}` — mirrors `handlers.FedInviteResponse`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FedInviteResponse {
    pub wrapped_key: String,
    pub encrypted_name: String,
    pub name_nonce: String,
    pub can_upload: bool,
    pub can_delete: bool,
    pub upload_quota_bytes: Option<i64>,
}

/// `POST /api/fed-proxy/incoming` body — mirrors `handlers.AddIncomingShareRequest`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddIncomingShareRequest {
    pub invite_url: String,
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
            encrypted_name: "n".into(),
            name_nonce: "nn".into(),
            encrypted_key: "k".into(),
            encrypted_key_nonce: "kn".into(),
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
        assert!(obj.contains_key("encryptedKeyNonce"));
    }

    #[test]
    fn public_share_nulls_serialize() {
        // Go pointer fields WITHOUT omitempty serialize as JSON null.
        let resp = PublicShareResponse {
            id: "s1".into(),
            share_type: "collection".into(),
            target_id: "c1".into(),
            encrypted_collection_key: None,
            encrypted_collection_key_nonce: None,
            expires_at: None,
        };
        let v: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert!(v.get("encryptedCollectionKey").unwrap().is_null());
        assert!(v.get("expiresAt").unwrap().is_null());
    }
}
