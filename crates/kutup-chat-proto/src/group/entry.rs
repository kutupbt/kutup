//! What the sealed parts of a group's state hold, and the invitation an
//! invitee gets pairwise (docs/plans/pairwise-groups.md §3–§4). Members read
//! these; the group's server sees them only as ciphertext.

use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::chat_group::{MASTER_KEY_LEN, SLOT_ID_LEN};
use serde::{Deserialize, Serialize};

use super::{decode_exact, decode_group_id, GroupHomePinV1, GROUP_FORMAT_VERSION};

/// A profile key's length (docs/chat-protocol.md §7).
pub const PROFILE_KEY_LEN: usize = 32;
/// A libsignal identity signature (XEdDSA).
pub const BINDING_SIGNATURE_LEN: usize = 64;

/// A member's sealed entry (subject: their pseudonym): who they are, their
/// profile key, and the binding one of their devices signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupMemberEntryV1 {
    pub version: u16,
    pub account: AccountRef,
    /// The device whose identity key signed the binding.
    pub device_id: u32,
    pub profile_key: String,
    /// The device's signature over `chat_group::binding_signed_bytes`.
    pub binding_signature: String,
}

/// A pending slot's sealed entry (subject: the slot id): who was invited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupSlotEntryV1 {
    pub version: u16,
    pub account: AccountRef,
}

/// What an invitee gets in their own copy of the adder's group update, never
/// in the copy the other members get: the group, and the slot's one-time
/// claim key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupInviteV1 {
    pub version: u16,
    pub group_id: String,
    pub master_key: String,
    pub home: GroupHomePinV1,
    pub slot_id: String,
    pub slot_revision: u64,
    pub claim_key_seed: String,
}

/// Never prints the master key or the claim key.
impl std::fmt::Debug for GroupInviteV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupInviteV1")
            .field("version", &self.version)
            .field("group_id", &self.group_id)
            .field("home", &self.home)
            .field("slot_id", &self.slot_id)
            .field("slot_revision", &self.slot_revision)
            .finish_non_exhaustive()
    }
}

macro_rules! canonical_json {
    ($type:ty, $name:literal) => {
        impl $type {
            pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
                self.validate()?;
                serde_json::to_vec(self).map_err(|error| error.to_string())
            }

            pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
                let value: Self = serde_json::from_slice(bytes)
                    .map_err(|error| format!(concat!("invalid ", $name, ": {}"), error))?;
                if value.canonical_bytes()? != bytes {
                    return Err(concat!($name, " is not canonical JSON").into());
                }
                Ok(value)
            }
        }
    };
}

canonical_json!(GroupMemberEntryV1, "group member entry");
canonical_json!(GroupSlotEntryV1, "group slot entry");
canonical_json!(GroupInviteV1, "group invite");

fn require_version(version: u16) -> Result<(), String> {
    if version != GROUP_FORMAT_VERSION {
        return Err("unsupported group entry version".into());
    }
    Ok(())
}

impl GroupMemberEntryV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_version(self.version)?;
        if self.device_id == 0 {
            return Err("deviceId must be positive".into());
        }
        decode_exact::<PROFILE_KEY_LEN>("profileKey", &self.profile_key)?;
        decode_exact::<BINDING_SIGNATURE_LEN>("bindingSignature", &self.binding_signature)?;
        Ok(())
    }
}

impl GroupSlotEntryV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_version(self.version)
    }
}

impl GroupInviteV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_version(self.version)?;
        decode_group_id(&self.group_id)?;
        decode_exact::<MASTER_KEY_LEN>("masterKey", &self.master_key)?;
        decode_exact::<SLOT_ID_LEN>("slotId", &self.slot_id)?;
        decode_exact::<32>("claimKeySeed", &self.claim_key_seed)?;
        Ok(())
    }
}
