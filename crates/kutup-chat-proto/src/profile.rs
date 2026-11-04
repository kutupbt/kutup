//! Opaque encrypted-profile DTOs. The envelope framing and the profile's
//! crypto are kutup-crypto's (`kutup_crypto::chat_profile`,
//! docs/plans/chat-crypto-move.md), re-exported here for the protocol.
//!
//! The delivery service validates suites, framing, exact account/revision
//! bindings, sizes and fetch capabilities. It never receives a profile key or
//! plaintext name/avatar.

use serde::{Deserialize, Serialize};

use crate::AccountRef;
pub use kutup_crypto::chat_profile::{
    decode_profile_envelope, encode_profile_envelope_header, DecodedProfileEnvelopeV1,
    ProfileEnvelopeContextV1, ProfileEnvelopePurpose, ProfileSuiteId, SealedProfile,
    ACCOUNT_PROFILE_SOURCE, MAX_PROFILE_ABOUT_CHARS, MAX_PROFILE_AVATAR_BYTES,
    PROFILE_ABOUT_PADDED_LENGTHS, PROFILE_NAME_PADDED_LENGTHS,
};

/// Replace the authenticated caller's current encrypted profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PutChatProfileRequest {
    #[cfg_attr(feature = "openapi", schema(value_type = u16))]
    pub suite: ProfileSuiteId,
    /// The profile's owner (server and account id). Also authenticated
    /// inside every envelope.
    #[cfg_attr(feature = "openapi", schema(value_type = crate::AccountRefSchema))]
    pub account: AccountRef,
    /// Lowercase hex profile version derived from the 32-byte profile key.
    pub version: String,
    pub revision: u64,
    pub source_device_id: u32,
    /// Standard-base64 canonical `ProfileEnvelopeV1`, display-name purpose.
    pub name: String,
    /// Separately encrypted avatar envelope. Absence removes the avatar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// Separately encrypted "about" envelope. Absence removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    /// Profile-key envelope under an account-master-key-derived wrapping key.
    pub wrapped_key: String,
    pub access_key_verifier: String,
    pub delivery_capability_verifier: String,
}

pub type OwnChatProfileResponse = PutChatProfileRequest;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ChatProfileResponse {
    #[cfg_attr(feature = "openapi", schema(value_type = u16))]
    pub suite: ProfileSuiteId,
    #[cfg_attr(feature = "openapi", schema(value_type = crate::AccountRefSchema))]
    pub account: AccountRef,
    pub version: String,
    pub revision: u64,
    pub source_device_id: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
}

impl From<&PutChatProfileRequest> for ChatProfileResponse {
    fn from(profile: &PutChatProfileRequest) -> Self {
        Self {
            suite: profile.suite,
            account: profile.account.clone(),
            version: profile.version.clone(),
            revision: profile.revision,
            source_device_id: profile.source_device_id,
            name: profile.name.clone(),
            avatar: profile.avatar.clone(),
            about: profile.about.clone(),
        }
    }
}

impl From<PutChatProfileRequest> for SealedProfile {
    fn from(profile: PutChatProfileRequest) -> Self {
        Self {
            suite: profile.suite,
            account: profile.account,
            version: profile.version,
            revision: profile.revision,
            source_device_id: profile.source_device_id,
            name: profile.name,
            avatar: profile.avatar,
            about: profile.about,
            wrapped_key: profile.wrapped_key,
            access_key_verifier: profile.access_key_verifier,
            delivery_capability_verifier: profile.delivery_capability_verifier,
        }
    }
}

impl From<SealedProfile> for PutChatProfileRequest {
    fn from(profile: SealedProfile) -> Self {
        Self {
            suite: profile.suite,
            account: profile.account,
            version: profile.version,
            revision: profile.revision,
            source_device_id: profile.source_device_id,
            name: profile.name,
            avatar: profile.avatar,
            about: profile.about,
            wrapped_key: profile.wrapped_key,
            access_key_verifier: profile.access_key_verifier,
            delivery_capability_verifier: profile.delivery_capability_verifier,
        }
    }
}

/// A fetched profile as sealed: without the owner's fields.
impl From<ChatProfileResponse> for SealedProfile {
    fn from(profile: ChatProfileResponse) -> Self {
        Self {
            suite: profile.suite,
            account: profile.account,
            version: profile.version,
            revision: profile.revision,
            source_device_id: profile.source_device_id,
            name: profile.name,
            avatar: profile.avatar,
            about: profile.about,
            wrapped_key: String::new(),
            access_key_verifier: String::new(),
            delivery_capability_verifier: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> AccountRef {
        "aci:0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b@example.test"
            .parse()
            .unwrap()
    }

    #[test]
    fn peer_response_omits_owner_recovery_and_verifier() {
        let owner = PutChatProfileRequest {
            suite: ProfileSuiteId::XChaCha20Poly1305V1,
            account: alice(),
            version: "01".repeat(32),
            revision: 4,
            source_device_id: 2,
            name: "bmFtZQ==".into(),
            avatar: None,
            about: None,
            wrapped_key: "d3JhcHBlZA==".into(),
            access_key_verifier: "02".repeat(32),
            delivery_capability_verifier: "03".repeat(32),
        };
        let value = serde_json::to_value(ChatProfileResponse::from(&owner)).unwrap();
        assert!(value.get("wrappedKey").is_none());
        assert!(value.get("accessKeyVerifier").is_none());
        // The wire shape is kutup-crypto's sealed profile's.
        let sealed = SealedProfile::from(owner.clone());
        assert_eq!(
            serde_json::to_value(&sealed).unwrap(),
            serde_json::to_value(&owner).unwrap()
        );
        assert_eq!(PutChatProfileRequest::from(sealed), owner);
    }
}
