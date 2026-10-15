//! Request/response types — mirror `cmd/kutup/internal/api/client.go`.
//! JSON keys are camelCase to match the backend.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsResponse {
    pub chat: ChatSettings,
    /// `on`, `code` or `off`.
    pub registration_mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatSettings {
    pub server_name: String,
}

// --- Auth ---

/// Registration bundle — mirrors the backend `RegisterRequest` + the web client's
/// `generateRegistrationKeys` output. All key material is base64; the password is
/// an OPAQUE record (docs/plans/opaque.md), and the server never sees a key.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub username: String,
    /// The account id the server minted at register/start, and its proof.
    pub account_id: String,
    pub account_id_proof: String,
    /// A referral code, when the server's registration mode asks for one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_code: Option<String>,
    /// The account's key binding, drawn here (a UUID v4).
    pub key_binding: String,
    /// The password's OPAQUE record (`RegistrationUpload`), base64, and the
    /// setup register/start answered under.
    pub opaque_record: String,
    pub opaque_server_key_id: u16,
    pub master_key_envelope: String,
    pub recovery_key_envelope: String,
    pub drive_private_key_envelope: String,
    pub public_key: String,
    pub account_authority_public_key: String,
    pub account_authority_key_id: String,
    pub account_incarnation_id: String,
    pub drive_signing_public_key: String,
    pub recovery_proof: String,
    /// The account authority's signature over its Drive keys
    /// (docs/plans/drive-identity-pins.md).
    pub drive_key_binding: String,
}

// No Debug: it carries tokens, envelopes and grants.
#[derive(Default, Deserialize)]
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
    /// What the account's sealed keys are bound to; only with a session.
    #[serde(default, rename = "keyBinding")]
    pub envelope_binding: String,
    /// The account's record is under a retired setup: re-register the
    /// password just used, with `grant` (purpose `rotate`).
    #[serde(default)]
    pub rotate: bool,
    #[serde(default)]
    pub grant: Option<String>,
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
/// server answers unknown names with deterministic fake data, so a wrong
/// phrase/name only ever fails client-side at unwrap time.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverPreflightResponse {
    #[serde(default)]
    pub envelope_binding: String,
    #[serde(default)]
    pub recovery_key_envelope: String,
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
    /// The account's permanent id and its server.
    pub account_id: String,
    pub server: String,
    /// The account's Kutup address.
    #[serde(default)]
    pub address: String,
    pub username: String,
    /// What the account's envelopes are bound to now.
    #[serde(default)]
    pub envelope_binding: String,
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
    /// A shared folder's owner's server; with `owner_user_id`, the owner.
    #[serde(default)]
    pub owner_server: Option<String>,
    /// Shown only: the owner's address now.
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
    /// Its name's hash in its place, once known.
    #[serde(default)]
    pub name_hash: Option<String>,
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
    /// The name's hash in its place (docs/plans/drive-unique-names.md).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_hash: Option<String>,
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
    /// The new name's hash in the folder's place; none clears it.
    pub name_hash: Option<String>,
}

// --- Files ---

fn first_generation() -> u32 {
    1
}

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
    /// The key generation the original upload was sealed at.
    #[serde(default = "first_generation")]
    pub original_key_generation: u32,
    /// The file's older keys, each sealed under the next (generations 2 to
    /// `key_generation`, in order); absent for most files.
    #[serde(default)]
    pub key_history: Vec<FileKeyHistoryEntry>,
    /// Its name's and content's hashes in its folder, once known
    /// (docs/plans/drive-unique-names.md).
    #[serde(default)]
    pub name_hash: Option<String>,
    #[serde(default)]
    pub content_hash: Option<String>,
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
    /// Its name's hash in the destination (docs/plans/drive-unique-names.md).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_hash: Option<String>,
    /// Its content's hash in the destination, from the content SHA-256 its
    /// metadata holds; none leaves it unknown there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

/// `POST /collections/{id}/move`; `None` moves the folder to the top level.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveCollectionRequest {
    pub parent_collection_id: Option<String>,
    /// Its name's hash in the new place (docs/plans/drive-unique-names.md).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_hash: Option<String>,
}

/// One generation of a file's key history: the key of `generation − 1`
/// sealed under the key of `generation`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileKeyHistoryEntry {
    pub generation: u32,
    pub previous_key_envelope: String,
}

/// A file's metadata: the canonical format in `kutup-crypto` (name, type,
/// size and a photo's details), so a rename keeps what it does not change.
pub use kutup_crypto::file_metadata::FileMetadataV1 as FileMetadata;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFileMetadataRequest {
    pub metadata_envelope: String,
    pub metadata_revision: u64,
    /// The new name's hash in the file's folder; absent keeps the stored one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_hash: Option<String>,
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
    pub recipient_server: String,
    pub recipient_account_id: String,
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
pub struct UserByAddress {
    #[serde(default)]
    pub user_id: String,
    /// The account the address leads to now (server-asserted): its server
    /// and permanent id.
    pub server: String,
    pub account_id: String,
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub drive_hpke_public_key: String,
    #[serde(default)]
    pub account_incarnation_id: String,
    #[serde(default)]
    pub drive_signing_public_key: String,
    /// The account authority and its signature over the Drive keys
    /// (docs/plans/drive-identity-pins.md); the binding is absent for an
    /// account that has not signed one yet.
    #[serde(default)]
    pub account_authority_public_key: String,
    #[serde(default)]
    pub drive_key_binding: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FedPubKeyResponse {
    #[serde(default)]
    pub account: String,
    /// The account's permanent id on its server (docs/plans/account-ids.md).
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub drive_hpke_public_key: String,
    #[serde(default)]
    pub account_incarnation_id: String,
    #[serde(default)]
    pub drive_signing_public_key: String,
    #[serde(default)]
    pub account_authority_public_key: String,
    #[serde(default)]
    pub drive_key_binding: Option<String>,
    /// The account's server (with `account_id`, who it is).
    #[serde(default)]
    pub server: String,
}

/// The account's sealed identity pin list (`GET/PUT /api/user/identity-pins`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPinsRecord {
    /// The revision in the sealed list's header, as the server read it.
    pub revision: u64,
    pub envelope: String,
}

/// A new sealed list, stored only if the server still holds `base_revision`
/// (0: none yet); its own revision is in the envelope's header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPinsWrite {
    pub base_revision: u64,
    pub envelope: String,
    /// The next sealed account head (docs/plans/rollback-protection.md).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
}
