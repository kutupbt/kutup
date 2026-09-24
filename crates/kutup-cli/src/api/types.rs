//! Request/response types — mirror `cmd/kutup/internal/api/client.go`.
//! JSON keys are camelCase to match the backend.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsResponse {
    pub chat: ChatSettings,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatSettings {
    pub server_name: String,
}

// --- Auth ---

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightResponse {
    pub account_protection_suite: u16,
    pub account_protection_salt: String,
    pub argon_memory_kib: u32,
    pub argon_iterations: u32,
    pub argon_parallelism: u32,
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
    pub master_key_envelope: String,
    pub recovery_key_envelope: String,
    pub drive_private_key_envelope: String,
    pub public_key: String,
    pub account_authority_public_key: String,
    pub account_authority_key_id: String,
    pub account_incarnation_id: String,
    pub drive_signing_public_key: String,
    pub account_protection_suite: u16,
    pub account_protection_salt: String,
    pub argon_memory_kib: u32,
    pub argon_iterations: u32,
    pub argon_parallelism: u32,
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
    pub master_key_envelope: String,
    #[serde(default)]
    pub drive_private_key_envelope: String,
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

/// `GET /auth/recover/preflight` — encrypted recovery-key material. The
/// server answers unknown emails with deterministic fake data, so a wrong
/// phrase/email only ever fails client-side at unwrap time.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverPreflightResponse {
    #[serde(default)]
    pub recovery_key_envelope: String,
}

/// `POST /auth/recover` — rotates the one-root account-protection revision.
/// `recovery_proof` is HKDF-derived; raw mnemonic entropy never leaves client.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverRequest {
    pub email: String,
    pub new_login_key: String,
    pub new_master_key_envelope: String,
    pub new_account_protection_suite: u16,
    pub new_account_protection_salt: String,
    pub new_argon_memory_kib: u32,
    pub new_argon_iterations: u32,
    pub new_argon_parallelism: u32,
    pub recovery_proof: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    #[serde(default)]
    pub access_token: String,
    /// The rotated refresh token. Absent when a concurrent refresh already
    /// rotated it (the server's grace window); keep the stored one then.
    #[serde(default)]
    pub refresh_token: String,
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
    pub name_envelope: String,
    #[serde(default)]
    pub owner_key_envelope: Option<String>,
    #[serde(default)]
    pub named_share_envelope: Option<String>,
    #[serde(default)]
    pub key_epoch: u32,
    #[serde(default)]
    pub name_revision: u64,
    #[serde(default)]
    pub epoch_statement: String,
    #[serde(default)]
    pub epoch_statement_hash: String,
    #[serde(default)]
    pub owner_account: Option<String>,
    #[serde(default)]
    pub owner_incarnation_id: Option<String>,
    #[serde(default)]
    pub owner_drive_signing_public_key: Option<String>,
    #[serde(default)]
    pub owner_authority_public_key: Option<String>,
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
    pub id: String,
    pub name_envelope: String,
    pub owner_key_envelope: String,
    pub epoch_statement: String,
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
    pub name_envelope: String,
    pub name_revision: u64,
}

// --- Files ---

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct File {
    pub id: String,
    #[serde(default)]
    pub collection_id: String,
    #[serde(default)]
    pub metadata_envelope: String,
    #[serde(default)]
    pub file_key_envelope: String,
    /// The folder epoch the file key is wrapped at; below the folder's own
    /// epoch, the file is re-keyed before it is written to or moved.
    #[serde(default)]
    pub key_epoch: u32,
    /// The generation of the file's current key (docs/plans/drive-move.md).
    pub key_generation: u32,
    #[serde(default)]
    pub metadata_revision: u64,
    #[serde(default)]
    pub encrypted_size_bytes: i64,
    #[serde(default)]
    pub created_at: String,
    /// The key generation of what `/files/{id}/download` serves (its latest
    /// whole-file version, else the upload).
    pub content_key_generation: u32,
    /// The file's older keys, each sealed under the next (generations 2 to
    /// `key_generation`, in order); absent for most files.
    #[serde(default)]
    pub key_history: Vec<FileKeyHistoryEntry>,
}

/// `POST /files/{id}/rekey`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RekeyRequest {
    /// The generation the file is leaving (compare-and-swap).
    pub from_generation: u32,
    /// The new key, sealed under the folder's current key.
    pub file_key_envelope: String,
    /// The metadata, re-sealed under the new key.
    pub metadata_envelope: String,
    /// The key being left, sealed under the new one (`PreviousFileKey`).
    pub previous_key_envelope: String,
}

/// `POST /files/{id}/move`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveFileRequest {
    /// The folder the file is in now (compare-and-swap).
    pub from_collection_id: String,
    pub to_collection_id: String,
    /// The destination's current epoch, which the envelope is sealed at.
    pub to_key_epoch: u32,
    /// The file's current key sealed under the destination's key.
    pub file_key_envelope: String,
}

/// `POST /collections/{id}/move`; `None` moves the folder to the top level.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveCollectionRequest {
    pub parent_collection_id: Option<String>,
}

/// One generation of a file's key history: the key of `generation − 1`
/// sealed under the key of `generation`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileKeyHistoryEntry {
    pub generation: u32,
    pub previous_key_envelope: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    pub metadata_envelope: String,
    pub metadata_revision: u64,
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
    pub named_share_envelope: String,
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
    pub named_share_envelope: String,
    pub can_upload: bool,
    pub can_delete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_quota_bytes: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedShareResponse {
    #[serde(default)]
    pub invite_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicShareRequest {
    /// The link's id, chosen here (bound into the owner's copy of its key).
    pub id: String,
    pub share_type: String,
    pub target_id: String,
    pub collection_key_envelope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_hours: Option<i64>,
    /// The link key sealed for the owner under their master key (purpose 9),
    /// so the owner can list, copy and keep the link across a folder-key
    /// rotation (docs/plans/drive-share-revocation.md).
    pub owner_link_key_envelope: String,
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
    pub account: String,
    #[serde(default)]
    pub drive_hpke_public_key: String,
    #[serde(default)]
    pub account_incarnation_id: String,
    #[serde(default)]
    pub drive_signing_public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FedPubKeyResponse {
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub drive_hpke_public_key: String,
    #[serde(default)]
    pub account_incarnation_id: String,
    #[serde(default)]
    pub drive_signing_public_key: String,
    #[serde(default)]
    pub account_authority_public_key: String,
}

#[cfg(test)]
mod tests {
    use super::RecoverRequest;

    // Exact wire keys the server's RecoverRequest deserializes — the guard
    // for the camelCase mapping of the complete replacement revision.
    #[test]
    fn recover_request_keys() {
        let req = RecoverRequest {
            email: "a@b.c".into(),
            new_login_key: "lk".into(),
            new_master_key_envelope: "envelope".into(),
            new_account_protection_suite: 1,
            new_account_protection_salt: "salt".into(),
            new_argon_memory_kib: 65_536,
            new_argon_iterations: 3,
            new_argon_parallelism: 1,
            recovery_proof: "rp".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        for key in [
            "email",
            "newLoginKey",
            "newMasterKeyEnvelope",
            "newAccountProtectionSuite",
            "newAccountProtectionSalt",
            "newArgonMemoryKib",
            "newArgonIterations",
            "newArgonParallelism",
            "recoveryProof",
        ] {
            assert!(v.get(key).is_some(), "missing key {key}");
        }
    }
}
