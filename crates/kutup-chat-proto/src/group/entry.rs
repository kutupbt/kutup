//! What the sealed parts of a group's state hold, and the invitation an
//! invitee gets pairwise (docs/plans/pairwise-groups.md §3–§4). Members read
//! these; the group's server sees them only as ciphertext.

use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::chat_group::{MASTER_KEY_LEN, SLOT_ID_LEN};
use serde::{Deserialize, Serialize};

use super::{decode_exact, decode_group_id, validate_home, GroupHomePinV1, GROUP_FORMAT_VERSION};

/// A profile key's length (docs/chat-protocol.md §7).
pub const PROFILE_KEY_LEN: usize = 32;
/// A libsignal identity signature (XEdDSA).
pub const BINDING_SIGNATURE_LEN: usize = 64;

/// A member's sealed entry (subject: their pseudonym): who they are, their
/// profile key, and the binding their account's self-authority signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupMemberEntryV1 {
    pub version: u16,
    pub account: AccountRef,
    pub profile_key: String,
    /// The account self-authority's signature over
    /// `chat_group::binding_signed_bytes`.
    pub binding_signature: String,
}

/// A pending slot's sealed entry (subject: the slot id): who was invited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupSlotEntryV1 {
    pub version: u16,
    pub account: AccountRef,
}

/// The group a group message belongs to, inside its encrypted content
/// (Signal's `GroupContextV2`, plus the home and the chain head): a member
/// that lost the group learns it again from any message, and every receiver
/// compares the revision and head with its own (fork detection).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupContextV1 {
    pub version: u16,
    pub group_id: String,
    pub master_key: String,
    pub home: GroupHomePinV1,
    pub revision: u64,
    pub chain_hash: String,
    /// On content sent pairwise to one account: that account's pseudonym in
    /// the group, as the sender's verified state names it. A device of theirs
    /// that lost the group matches it against the pseudonyms its account key
    /// gives, and asks the home once (docs/plans/pairwise-groups.md §2, "A
    /// device that lost its group list").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_pseudonym: Option<String>,
}

impl GroupContextV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_version(self.version)?;
        decode_group_id(&self.group_id)?;
        decode_exact::<MASTER_KEY_LEN>("masterKey", &self.master_key)?;
        validate_home(&self.home)?;
        decode_exact::<32>("chainHash", &self.chain_hash)?;
        if let Some(pseudonym) = &self.recipient_pseudonym {
            decode_exact::<32>("recipientPseudonym", pseudonym)?;
        }
        Ok(())
    }

    /// This context naming `recipient`'s pseudonym (none: naming nobody).
    pub fn naming(&self, recipient: Option<&str>) -> Self {
        let mut context = self.clone();
        context.recipient_pseudonym = recipient.map(str::to_string);
        context
    }
}

/// Never prints the master key.
impl std::fmt::Debug for GroupContextV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupContextV1")
            .field("group_id", &self.group_id)
            .field("revision", &self.revision)
            .field("chain_hash", &self.chain_hash)
            .finish_non_exhaustive()
    }
}

impl Drop for GroupContextV1 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.master_key);
    }
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
    /// The group's name when the invitation was made, so the invitation can
    /// name the group before the invitee joins (and reads the state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
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

/// The keys are wiped when the invitation is dropped (once claimed, they
/// live only in the record's `Invited` status).
impl Drop for GroupInviteV1 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.master_key);
        zeroize::Zeroize::zeroize(&mut self.claim_key_seed);
    }
}

/// One group in the account's group list (docs/plans/pairwise-groups.md
/// §5), sealed under the account's list key: what another of this account's
/// devices needs to take the group up (its key, its home, the join epoch its
/// pseudonym is derived at) and the newest state it may take.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupListEntryV1 {
    pub version: u16,
    pub group_id: String,
    pub master_key: String,
    pub home: GroupHomePinV1,
    /// Which of this account's joins of the group this is (0 for the first):
    /// its pseudonym is derived from the account key at this epoch
    /// (`kutup_crypto::chat_group::GroupPseudonymKey`).
    pub join_epoch: u32,
    /// `member`, or `gone` (left or removed: its history stays).
    pub status: GroupListStatus,
    /// The last revision this account verified, and its chain head: no
    /// device of the account takes an older state.
    pub verified_revision: u64,
    pub chain_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GroupListStatus {
    Member,
    Gone,
}

impl GroupListEntryV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_version(self.version)?;
        decode_group_id(&self.group_id)?;
        decode_exact::<MASTER_KEY_LEN>("masterKey", &self.master_key)?;
        validate_home(&self.home)?;
        decode_exact::<32>("chainHash", &self.chain_hash)?;
        Ok(())
    }
}

/// Never prints the master key.
impl std::fmt::Debug for GroupListEntryV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupListEntryV1")
            .field("group_id", &self.group_id)
            .field("status", &self.status)
            .field("verified_revision", &self.verified_revision)
            .finish_non_exhaustive()
    }
}

impl Drop for GroupListEntryV1 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.master_key);
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
canonical_json!(GroupListEntryV1, "group list entry");

fn require_version(version: u16) -> Result<(), String> {
    if version != GROUP_FORMAT_VERSION {
        return Err("unsupported group entry version".into());
    }
    Ok(())
}

impl GroupMemberEntryV1 {
    pub fn validate(&self) -> Result<(), String> {
        require_version(self.version)?;
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
        validate_home(&self.home)?;
        decode_exact::<SLOT_ID_LEN>("slotId", &self.slot_id)?;
        decode_exact::<32>("claimKeySeed", &self.claim_key_seed)?;
        if self
            .title
            .as_ref()
            .is_some_and(|title| title.chars().count() > MAX_INVITE_TITLE_CHARS)
        {
            return Err("an invitation's title is too long".into());
        }
        Ok(())
    }
}

/// The longest group name an invitation carries.
pub const MAX_INVITE_TITLE_CHARS: usize = 64;
