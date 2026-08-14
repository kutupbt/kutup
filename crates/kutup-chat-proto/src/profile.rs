//! Opaque encrypted-profile DTOs and canonical public envelope framing.
//!
//! The delivery service validates suites, framing, exact account/revision
//! bindings, sizes and fetch capabilities. It never receives a profile key or
//! plaintext name/avatar.

use std::str::FromStr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::AccountAddress;

const MAGIC: &[u8; 8] = b"KUTPPE1\0";
const FIXED_PREFIX_BYTES: usize = 8 + 2 + 1 + 1 + 8 + 4 + 32 + 2;
const NONCE_BYTES: usize = 24;
const LENGTH_BYTES: usize = 4;
const TAG_BYTES: usize = 16;
const MAX_ACCOUNT_BYTES: usize = 286;
pub const PROFILE_NAME_PADDED_LENGTHS: [usize; 2] = [53, 257];
pub const MAX_PROFILE_AVATAR_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum ProfileSuiteId {
    XChaCha20Poly1305V1 = 1,
}

impl ProfileSuiteId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl From<ProfileSuiteId> for u16 {
    fn from(value: ProfileSuiteId) -> Self {
        value.as_u16()
    }
}

impl TryFrom<u16> for ProfileSuiteId {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::XChaCha20Poly1305V1),
            _ => Err(format!("unknown encrypted profile suite {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProfileEnvelopePurpose {
    DisplayName = 1,
    Avatar = 2,
    WrappedProfileKey = 3,
}

impl ProfileEnvelopePurpose {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    fn validate_ciphertext_len(self, len: usize) -> Result<(), String> {
        let valid = match self {
            Self::DisplayName => PROFILE_NAME_PADDED_LENGTHS
                .iter()
                .any(|plain| len == plain + TAG_BYTES),
            Self::Avatar => {
                (2 + TAG_BYTES..=MAX_PROFILE_AVATAR_BYTES + 1 + TAG_BYTES).contains(&len)
            }
            Self::WrappedProfileKey => len == 32 + TAG_BYTES,
        };
        if valid {
            Ok(())
        } else {
            Err(format!(
                "invalid ciphertext length for encrypted profile purpose {}",
                self.as_u8()
            ))
        }
    }
}

impl TryFrom<u8> for ProfileEnvelopePurpose {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DisplayName),
            2 => Ok(Self::Avatar),
            3 => Ok(Self::WrappedProfileKey),
            _ => Err(format!("unknown encrypted profile purpose {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileEnvelopeContextV1 {
    pub suite: ProfileSuiteId,
    pub purpose: ProfileEnvelopePurpose,
    pub account: String,
    pub profile_version: [u8; 32],
    pub revision: u64,
    pub source_device_id: u32,
}

impl ProfileEnvelopeContextV1 {
    pub fn new(
        purpose: ProfileEnvelopePurpose,
        account: &str,
        profile_version: &str,
        revision: u64,
        source_device_id: u32,
    ) -> Result<Self, String> {
        let address = AccountAddress::from_str(account).map_err(|error| error.to_string())?;
        if address.server.is_none()
            || address.canonical() != account
            || account.len() > MAX_ACCOUNT_BYTES
        {
            return Err("encrypted profile account must be a canonical federated address".into());
        }
        let version = hex::decode(profile_version)
            .map_err(|_| "profile version must be lowercase SHA-256 hex".to_string())?;
        if version.len() != 32 || hex::encode(&version) != profile_version {
            return Err("profile version must be lowercase SHA-256 hex".into());
        }
        if revision == 0 || source_device_id == 0 {
            return Err("encrypted profile revision and source device must be non-zero".into());
        }
        Ok(Self {
            suite: ProfileSuiteId::XChaCha20Poly1305V1,
            purpose,
            account: account.to_string(),
            profile_version: version.try_into().expect("32-byte profile version"),
            revision,
            source_device_id,
        })
    }

    pub fn profile_version_hex(&self) -> String {
        hex::encode(self.profile_version)
    }

    /// Stable context used by the profile module's purpose-specific HKDF.
    pub fn key_derivation_info(&self) -> Vec<u8> {
        let account = self.account.as_bytes();
        let mut info = Vec::with_capacity(2 + 1 + 8 + 4 + 32 + 2 + account.len());
        info.extend_from_slice(&self.suite.as_u16().to_be_bytes());
        info.push(self.purpose.as_u8());
        info.extend_from_slice(&self.revision.to_be_bytes());
        info.extend_from_slice(&self.source_device_id.to_be_bytes());
        info.extend_from_slice(&self.profile_version);
        info.extend_from_slice(&(account.len() as u16).to_be_bytes());
        info.extend_from_slice(account);
        info
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedProfileEnvelopeV1 {
    pub context: ProfileEnvelopeContextV1,
    pub aad: Vec<u8>,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

pub fn encode_profile_envelope_header(
    context: &ProfileEnvelopeContextV1,
    nonce: &[u8; NONCE_BYTES],
    ciphertext_len: u32,
) -> Result<Vec<u8>, String> {
    context
        .purpose
        .validate_ciphertext_len(ciphertext_len as usize)?;
    let account = context.account.as_bytes();
    let mut header =
        Vec::with_capacity(FIXED_PREFIX_BYTES + account.len() + NONCE_BYTES + LENGTH_BYTES);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&context.suite.as_u16().to_be_bytes());
    header.push(context.purpose.as_u8());
    header.push(0);
    header.extend_from_slice(&context.revision.to_be_bytes());
    header.extend_from_slice(&context.source_device_id.to_be_bytes());
    header.extend_from_slice(&context.profile_version);
    header.extend_from_slice(&(account.len() as u16).to_be_bytes());
    header.extend_from_slice(account);
    header.extend_from_slice(nonce);
    header.extend_from_slice(&ciphertext_len.to_be_bytes());
    Ok(header)
}

pub fn decode_profile_envelope(encoded: &str) -> Result<DecodedProfileEnvelopeV1, String> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "encrypted profile envelope must be standard base64".to_string())?;
    if STANDARD.encode(&bytes) != encoded {
        return Err("encrypted profile envelope base64 is not canonical".into());
    }
    if bytes.len() < FIXED_PREFIX_BYTES + 1 + NONCE_BYTES + LENGTH_BYTES + TAG_BYTES
        || bytes.get(..MAGIC.len()) != Some(MAGIC)
    {
        return Err("encrypted profile envelope is too short".into());
    }
    let suite = ProfileSuiteId::try_from(u16::from_be_bytes([bytes[8], bytes[9]]))?;
    let purpose = ProfileEnvelopePurpose::try_from(bytes[10])?;
    if bytes[11] != 0 {
        return Err("encrypted profile reserved byte is non-zero".into());
    }
    let revision = u64::from_be_bytes(bytes[12..20].try_into().expect("eight-byte slice"));
    let source_device_id = u32::from_be_bytes(bytes[20..24].try_into().expect("four-byte slice"));
    let version: [u8; 32] = bytes[24..56].try_into().expect("32-byte slice");
    let account_len = u16::from_be_bytes([bytes[56], bytes[57]]) as usize;
    if account_len == 0 || account_len > MAX_ACCOUNT_BYTES {
        return Err("encrypted profile account length is invalid".into());
    }
    let account_end = FIXED_PREFIX_BYTES
        .checked_add(account_len)
        .ok_or_else(|| "encrypted profile account length overflow".to_string())?;
    let header_len = account_end
        .checked_add(NONCE_BYTES + LENGTH_BYTES)
        .ok_or_else(|| "encrypted profile header length overflow".to_string())?;
    if bytes.len() < header_len + TAG_BYTES {
        return Err("encrypted profile envelope is truncated".into());
    }
    let account = std::str::from_utf8(&bytes[FIXED_PREFIX_BYTES..account_end])
        .map_err(|_| "encrypted profile account is not UTF-8".to_string())?;
    let context = ProfileEnvelopeContextV1::new(
        purpose,
        account,
        &hex::encode(version),
        revision,
        source_device_id,
    )?;
    if context.suite != suite {
        return Err("encrypted profile suite mismatch".into());
    }
    let ciphertext_len = u32::from_be_bytes(
        bytes[header_len - LENGTH_BYTES..header_len]
            .try_into()
            .expect("four-byte slice"),
    ) as usize;
    purpose.validate_ciphertext_len(ciphertext_len)?;
    if header_len.checked_add(ciphertext_len) != Some(bytes.len()) {
        return Err("encrypted profile ciphertext length is invalid".into());
    }
    let nonce = bytes[account_end..account_end + NONCE_BYTES]
        .try_into()
        .expect("24-byte nonce");
    Ok(DecodedProfileEnvelopeV1 {
        context,
        aad: bytes[..header_len].to_vec(),
        nonce,
        ciphertext: bytes[header_len..].to_vec(),
    })
}

/// Replace the authenticated caller's current encrypted profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PutChatProfileRequest {
    pub suite: ProfileSuiteId,
    /// Canonical profile owner. Also authenticated inside every envelope.
    pub account: String,
    /// Lowercase hex profile version derived from the 32-byte profile key.
    pub version: String,
    pub revision: u64,
    pub source_device_id: u32,
    /// Standard-base64 canonical `ProfileEnvelopeV1`, display-name purpose.
    pub name: String,
    /// Separately encrypted avatar envelope. Absence removes the avatar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
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
    pub suite: ProfileSuiteId,
    pub account: String,
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
            suite: profile.suite,
            account: profile.account.clone(),
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
            suite: ProfileSuiteId::XChaCha20Poly1305V1,
            account: "alice@example.test".into(),
            version: "01".repeat(32),
            revision: 4,
            source_device_id: 2,
            name: "bmFtZQ==".into(),
            avatar: None,
            wrapped_key: "d3JhcHBlZA==".into(),
            access_key_verifier: "02".repeat(32),
            delivery_capability_verifier: "03".repeat(32),
        };
        let value = serde_json::to_value(ChatProfileResponse::from(&owner)).unwrap();
        assert!(value.get("wrappedKey").is_none());
        assert!(value.get("accessKeyVerifier").is_none());
    }

    #[test]
    fn profile_envelope_parser_rejects_unknown_suite_and_trailing_data() {
        let context = ProfileEnvelopeContextV1::new(
            ProfileEnvelopePurpose::WrappedProfileKey,
            "alice@example.test",
            &"01".repeat(32),
            1,
            1,
        )
        .unwrap();
        let header = encode_profile_envelope_header(&context, &[3; 24], 48).unwrap();
        let mut encoded = header;
        encoded.extend_from_slice(&[4; 48]);
        let valid = STANDARD.encode(&encoded);
        assert_eq!(decode_profile_envelope(&valid).unwrap().context, context);

        encoded[8] = 0x7f;
        assert!(decode_profile_envelope(&STANDARD.encode(&encoded)).is_err());
        encoded[8] = 0;
        encoded.push(0);
        assert!(decode_profile_envelope(&STANDARD.encode(&encoded)).is_err());
    }
}
