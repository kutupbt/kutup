//! Request/response types — mirror `cmd/kutup/internal/api/client.go`.
//! JSON keys are camelCase to match the backend.

use serde::{Deserialize, Serialize};

// --- Auth ---

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightResponse {
    pub kdf_salt: String,
    pub login_key_salt: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub email: String,
    /// base64-encoded login key.
    pub login_key: String,
}

/// Registration bundle — mirrors the backend `RegisterRequest` + the web client's
/// `generateRegistrationKeys` output. All key material is base64; the server only bcrypts
/// `login_key` + `recovery_proof` and stores the rest as-is (it never sees plaintext keys).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub email: String,
    pub username: String,
    pub login_key: String,
    pub encrypted_master_key: String,
    pub master_key_nonce: String,
    pub encrypted_recovery_key: String,
    pub recovery_key_nonce: String,
    pub encrypted_private_key: String,
    pub private_key_nonce: String,
    pub public_key: String,
    pub kdf_salt: String,
    pub login_key_salt: String,
    pub recovery_proof: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub storage_quota_bytes: i64,
    #[serde(default)]
    pub storage_used_bytes: i64,
    #[serde(default)]
    pub encrypted_master_key: String,
    #[serde(default)]
    pub master_key_nonce: String,
    #[serde(default)]
    pub encrypted_private_key: String,
    #[serde(default)]
    pub private_key_nonce: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub requires_totp: bool,
    #[serde(default)]
    pub pre_auth_token: String,
    #[serde(default)]
    pub requires_setup: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpRequest {
    pub pre_auth_token: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    #[serde(default)]
    pub access_token: String,
}

/// `POST /user/2fa/setup` response — `secret` is the base32 form for manual entry, `qr_uri`
/// the `otpauth://` URI for scanning. Mirrors `SetupTOTPResponse`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupTotpResponse {
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub qr_uri: String,
}

// --- User ---

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserMe {
    pub id: String,
    pub email: String,
    pub username: String,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub storage_quota_bytes: i64,
    #[serde(default)]
    pub storage_used_bytes: i64,
}

// --- Collections ---

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Collection {
    pub id: String,
    #[serde(default)]
    pub owner_user_id: String,
    #[serde(default)]
    pub encrypted_name: String,
    #[serde(default)]
    pub name_nonce: String,
    #[serde(default)]
    pub encrypted_key: String,
    #[serde(default)]
    pub encrypted_key_nonce: String,
    #[serde(default)]
    pub parent_collection_id: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub is_shared: bool,
    #[serde(default)]
    pub is_remote: bool,
    #[serde(default)]
    pub can_upload: bool,
    #[serde(default)]
    pub can_delete: bool,
    #[serde(default)]
    pub upload_quota_bytes: Option<i64>,
    /// Decrypted client-side; never serialized.
    #[serde(skip)]
    pub name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCollectionRequest {
    pub encrypted_name: String,
    pub name_nonce: String,
    pub encrypted_key: String,
    pub encrypted_key_nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_collection_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCollectionResponse {
    pub id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameCollectionRequest {
    pub encrypted_name: String,
    pub name_nonce: String,
}

// --- Files ---

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct File {
    pub id: String,
    #[serde(default)]
    pub collection_id: String,
    #[serde(default)]
    pub encrypted_metadata: String,
    #[serde(default)]
    pub metadata_nonce: String,
    #[serde(default)]
    pub encrypted_file_key: String,
    #[serde(default)]
    pub file_key_nonce: String,
    #[serde(default)]
    pub encrypted_size_bytes: i64,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadata {
    pub name: String,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub size: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFileMetadataRequest {
    pub encrypted_metadata: String,
    pub metadata_nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct UploadResponse {
    pub id: String,
}

// --- Sharing ---

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareRequest {
    pub recipient_user_id: String,
    pub encrypted_collection_key: String,
    pub can_upload: bool,
    pub can_delete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_quota_bytes: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedShareRequest {
    pub recipient_username: String,
    pub recipient_server: String,
    pub encrypted_collection_key: String,
    pub can_upload: bool,
    pub can_delete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_quota_bytes: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedShareResponse {
    #[serde(default)]
    pub invite_token: String,
    #[serde(default)]
    pub invite_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicShareRequest {
    pub share_type: String,
    pub target_id: String,
    pub encrypted_collection_key: String,
    pub encrypted_collection_key_nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_hours: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicShareResponse {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserByEmail {
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FedPubKeyResponse {
    #[serde(default)]
    pub public_key: String,
}
