//! Opaque encrypted-profile DTOs.
//!
//! The delivery service validates sizes, revisions, and fetch capabilities but
//! never receives a profile key or plaintext name/avatar.

use serde::{Deserialize, Serialize};

/// Replace the authenticated caller's current encrypted profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PutChatProfileRequest {
    /// Lowercase hex profile version derived from the 32-byte profile key.
    pub version: String,
    /// Monotonic client revision. Equal concurrent revisions are ordered by
    /// `sourceDeviceId` so linked devices converge deterministically.
    pub revision: u64,
    pub source_device_id: u32,
    /// Standard-base64 `nonce || AES-256-GCM(ciphertext || tag)`.
    pub name: String,
    /// Separately encrypted avatar bytes. Absence removes the avatar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// The random profile key encrypted for the account's linked devices with
    /// a key derived from the Kutup account master key.
    pub wrapped_key: String,
    /// Lowercase SHA-256 hex of the derived 16-byte fetch access key.
    pub access_key_verifier: String,
}

/// The owner-only response, including the wrapped random profile key.
pub type OwnChatProfileResponse = PutChatProfileRequest;

/// The capability-gated peer response. Owner recovery material and the access
/// verifier are deliberately omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ChatProfileResponse {
    pub version: String,
    pub revision: u64,
    pub source_device_id: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
}

impl From<&PutChatProfileRequest> for ChatProfileResponse {
    fn from(profile: &PutChatProfileRequest) -> Self {
        Self {
            version: profile.version.clone(),
            revision: profile.revision,
            source_device_id: profile.source_device_id,
            name: profile.name.clone(),
            avatar: profile.avatar.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_response_omits_owner_recovery_and_verifier() {
        let owner = PutChatProfileRequest {
            version: "01".repeat(32),
            revision: 4,
            source_device_id: 2,
            name: "bmFtZQ==".into(),
            avatar: None,
            wrapped_key: "d3JhcHBlZA==".into(),
            access_key_verifier: "02".repeat(32),
        };
        let value = serde_json::to_value(ChatProfileResponse::from(&owner)).unwrap();
        assert!(value.get("wrappedKey").is_none());
        assert!(value.get("accessKeyVerifier").is_none());
    }
}
