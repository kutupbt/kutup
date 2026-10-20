//! Chat groups on one-to-one sessions (docs/plans/pairwise-groups.md §3–§4):
//! the group's state as its server keeps it, and the changes that move it on.
//!
//! - The **plain part** is what the group's server reads: members as
//!   per-group pseudonyms with their roles, pending slots, requests, bans,
//!   the access rules and the link password. No account appears in it.
//! - Every other field (title, description, timer, avatar reference, a
//!   member's entry with its AccountRef, profile key and binding, a slot's
//!   invited account, the ban list) is sealed with the state key
//!   (`kutup_crypto::chat_group`) and carried here as ciphertext.
//! - A change is signed by its actor's pseudonym and names the previous
//!   change's hash and the resulting state's hash. [`check::check_change`]
//!   is the one acceptance check: the server runs it before storing a change,
//!   and every client runs it again, so a stored change is never refused.
//!
//! Encoding: canonical JSON, as the rest of this crate. Binary values are
//! standard padded base64, except the group id, which is unpadded base64url
//! because it also names the group in paths (one definition, in
//! `group_route`).

pub mod check;
pub mod entry;
#[cfg(test)]
mod tests;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::chat_group::{
    change_hash, state_hash, HASH_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN, SLOT_ID_LEN,
};
use serde::{Deserialize, Serialize};

pub use check::{
    check_change, check_genesis, resulting_genesis_state, resulting_state, GroupChangeError,
    GroupLimits,
};
pub use entry::{
    GroupContextV1, GroupInviteV1, GroupListEntryV1, GroupListStatus, GroupMemberEntryV1,
    GroupSlotEntryV1,
};

pub const GROUP_FORMAT_VERSION: u16 = 1;

/// Signal's limits for the sealed title and description
/// (`groups.preload.ts:255-256`), as sealed bytes.
pub const MAX_SEALED_TITLE_BYTES: usize = 1024;
pub const MAX_SEALED_DESCRIPTION_BYTES: usize = 8192;
pub const MAX_SEALED_TIMER_BYTES: usize = 128;
pub const MAX_SEALED_AVATAR_BYTES: usize = 512;
/// A member's or slot's sealed entry: an AccountRef, a profile key and a
/// binding signature, with room to spare.
pub const MAX_SEALED_ENTRY_BYTES: usize = 512;
pub const MAX_SEALED_BAN_LIST_BYTES: usize = 24 * 1024;
/// Actions one change may carry.
pub const MAX_ACTIONS_PER_CHANGE: usize = 64;
/// The largest canonical change: what one request to the home carries
/// (`group_route::MAX_REQUEST_BODY`).
pub const MAX_CHANGE_BYTES: usize = crate::group_route::MAX_REQUEST_BODY;
/// The hard ceiling for `GroupLimits::max_members` (§7).
pub const MAX_GROUP_MEMBERS: usize = 256;
pub const INVITE_LINK_PASSWORD_LEN: usize = 16;

/// A member's role: Signal's two (`Groups.proto` `Member.Role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GroupRole {
    Administrator,
    Member,
}

/// Who may do something (`Groups.proto` `AccessControl.AccessRequired`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccessRequired {
    Any,
    Member,
    Administrator,
    Unsatisfiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupAccessV1 {
    /// Who may change the title, description, avatar and timer.
    pub attributes: AccessRequired,
    /// Who may add members.
    pub members: AccessRequired,
    /// What the invite link does: `any` joins, `administrator` asks for
    /// approval, `unsatisfiable` is off.
    pub add_from_invite_link: AccessRequired,
}

impl GroupAccessV1 {
    /// Signal's values for a new group: members may edit and add, the link is off.
    pub const DEFAULT: Self = Self {
        attributes: AccessRequired::Member,
        members: AccessRequired::Member,
        add_from_invite_link: AccessRequired::Unsatisfiable,
    };

    fn validate(&self) -> Result<(), String> {
        let member_or_admin = |value| {
            matches!(
                value,
                AccessRequired::Member | AccessRequired::Administrator
            )
        };
        if !member_or_admin(self.attributes) || !member_or_admin(self.members) {
            return Err("attributes and members access must be member or administrator".into());
        }
        if self.add_from_invite_link == AccessRequired::Member {
            return Err("invite link access must be any, administrator or unsatisfiable".into());
        }
        Ok(())
    }
}

/// The server that holds the group, fixed at creation, pinned by its
/// federation identity document; that identity signs what the server
/// accepts and its gateway key (`crate::group_route`).
pub use crate::group_route::{decode_group_id, encode_group_id, GroupHomePinV1};

/// The sealed group-wide attributes; `None` when unset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupAttributesV1 {
    pub title: Option<String>,
    pub description: Option<String>,
    pub timer: Option<String>,
    pub avatar: Option<String>,
    /// The SHA-256 (base64) of the avatar blob **as the home stores it**:
    /// sealed and padded, never the plaintext image, which would let the
    /// home recognise a known picture across groups. In the clear beside the
    /// sealed avatar (its key and type), so the home serves the blob and
    /// drops the ones no state names (docs/plans/pairwise-groups.md §11).
    /// Present exactly when `avatar` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GroupAttribute {
    Title,
    Description,
    Timer,
    Avatar,
}

impl GroupAttribute {
    pub fn max_sealed_bytes(self) -> usize {
        match self {
            Self::Title => MAX_SEALED_TITLE_BYTES,
            Self::Description => MAX_SEALED_DESCRIPTION_BYTES,
            Self::Timer => MAX_SEALED_TIMER_BYTES,
            Self::Avatar => MAX_SEALED_AVATAR_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupMemberV1 {
    pub pseudonym: String,
    pub role: GroupRole,
    pub joined_at_revision: u64,
    /// The sealed entry: AccountRef, profile key, binding.
    pub entry: String,
}

/// A place reserved for an invited account until it claims it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupSlotV1 {
    pub slot_id: String,
    pub role: GroupRole,
    /// The pseudonym that added it, who may revoke it with administrators.
    pub adder: String,
    /// The revision that added it; a claim signs it, so a claim can't be
    /// replayed into a later slot with the same id.
    pub created_at_revision: u64,
    /// The one-time key a claim is signed with.
    pub claim_key: String,
    /// The sealed invited account.
    pub entry: String,
}

/// Someone who asked to join through the link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupRequestV1 {
    pub pseudonym: String,
    pub requested_at_revision: u64,
    pub entry: String,
}

/// The group's state as its server keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupStateV1 {
    pub version: u16,
    pub group_id: String,
    pub revision: u64,
    pub home: GroupHomePinV1,
    pub access: GroupAccessV1,
    pub announcements_only: bool,
    pub terminated: bool,
    pub invite_link_password: Option<String>,
    pub attributes: GroupAttributesV1,
    /// The sealed ban list, by account.
    pub ban_list: Option<String>,
    /// Sorted by pseudonym.
    pub members: Vec<GroupMemberV1>,
    /// Sorted by slot id.
    pub slots: Vec<GroupSlotV1>,
    /// Sorted by pseudonym.
    pub requesting: Vec<GroupRequestV1>,
    /// Banned pseudonyms, sorted.
    pub banned: Vec<String>,
}

impl GroupStateV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != GROUP_FORMAT_VERSION {
            return Err("unsupported group state version".into());
        }
        decode_group_id(&self.group_id)?;
        validate_home(&self.home)?;
        self.access.validate()?;
        if let Some(password) = &self.invite_link_password {
            decode_exact::<INVITE_LINK_PASSWORD_LEN>("inviteLinkPassword", password)?;
        }
        validate_attributes(&self.attributes)?;
        if let Some(list) = &self.ban_list {
            decode_sealed("banList", list, MAX_SEALED_BAN_LIST_BYTES)?;
        }
        let mut previous: Option<[u8; PUBLIC_KEY_LEN]> = None;
        for member in &self.members {
            let key = decode_pseudonym(&member.pseudonym)?;
            if previous.is_some_and(|p| p >= key) {
                return Err("members must be sorted and unique".into());
            }
            previous = Some(key);
            if member.joined_at_revision > self.revision {
                return Err("a member joined after the state's revision".into());
            }
            decode_sealed("member entry", &member.entry, MAX_SEALED_ENTRY_BYTES)?;
        }
        let mut previous_slot: Option<[u8; SLOT_ID_LEN]> = None;
        for slot in &self.slots {
            let id = decode_exact::<SLOT_ID_LEN>("slotId", &slot.slot_id)?;
            if previous_slot.is_some_and(|p| p >= id) {
                return Err("slots must be sorted and unique".into());
            }
            previous_slot = Some(id);
            decode_pseudonym(&slot.adder)?;
            if slot.created_at_revision > self.revision {
                return Err("a slot was added after the state's revision".into());
            }
            decode_pseudonym(&slot.claim_key)?;
            decode_sealed("slot entry", &slot.entry, MAX_SEALED_ENTRY_BYTES)?;
        }
        let mut previous_request: Option<[u8; PUBLIC_KEY_LEN]> = None;
        for request in &self.requesting {
            let key = decode_pseudonym(&request.pseudonym)?;
            if previous_request.is_some_and(|p| p >= key) {
                return Err("requests must be sorted and unique".into());
            }
            previous_request = Some(key);
            decode_sealed("request entry", &request.entry, MAX_SEALED_ENTRY_BYTES)?;
        }
        let mut previous_ban: Option<[u8; PUBLIC_KEY_LEN]> = None;
        for banned in &self.banned {
            let key = decode_pseudonym(banned)?;
            if previous_ban.is_some_and(|p| p >= key) {
                return Err("banned pseudonyms must be sorted and unique".into());
            }
            previous_ban = Some(key);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid group state: {error}"))?;
        if value.canonical_bytes()? != bytes {
            return Err("group state is not canonical JSON".into());
        }
        Ok(value)
    }

    /// The hash a change names as its result; computable by a server, since
    /// the sealed fields are in it as ciphertext.
    pub fn hash(&self) -> Result<[u8; HASH_LEN], String> {
        Ok(state_hash(&self.canonical_bytes()?))
    }

    pub fn member(&self, pseudonym: &str) -> Option<&GroupMemberV1> {
        self.members
            .iter()
            .find(|member| member.pseudonym == pseudonym)
    }

    pub fn is_administrator(&self, pseudonym: &str) -> bool {
        self.member(pseudonym)
            .is_some_and(|member| member.role == GroupRole::Administrator)
    }
}

/// One action of a change (`Groups.proto` `GroupChange.Actions`, with
/// members as pseudonyms).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum GroupActionV1 {
    /// Revision 0: the group, with its creator as the first administrator.
    #[serde(rename_all = "camelCase")]
    Genesis {
        home: GroupHomePinV1,
        access: GroupAccessV1,
        entry: String,
    },
    /// Reserves a place for an invited account.
    #[serde(rename_all = "camelCase")]
    AddSlot {
        slot_id: String,
        role: GroupRole,
        claim_key: String,
        entry: String,
    },
    #[serde(rename_all = "camelCase")]
    RevokeSlot {
        slot_id: String,
    },
    /// The actor, a new pseudonym, takes a slot: signed by the slot's claim
    /// key over the actor's pseudonym.
    #[serde(rename_all = "camelCase")]
    Claim {
        slot_id: String,
        claim_signature: String,
        entry: String,
    },
    /// The actor, a new pseudonym, joins through the link (`any`).
    #[serde(rename_all = "camelCase")]
    JoinFromLink {
        password: String,
        entry: String,
    },
    /// The actor, a new pseudonym, asks to join through the link
    /// (`administrator`).
    #[serde(rename_all = "camelCase")]
    RequestToJoin {
        password: String,
        entry: String,
    },
    CancelRequest,
    #[serde(rename_all = "camelCase")]
    ApproveRequest {
        pseudonym: String,
    },
    #[serde(rename_all = "camelCase")]
    DenyRequest {
        pseudonym: String,
    },
    #[serde(rename_all = "camelCase")]
    RemoveMember {
        pseudonym: String,
    },
    Leave,
    #[serde(rename_all = "camelCase")]
    ModifyRole {
        pseudonym: String,
        role: GroupRole,
    },
    /// The actor's own entry: a new profile key, or a binding signed again.
    #[serde(rename_all = "camelCase")]
    ModifyOwnEntry {
        entry: String,
    },
    #[serde(rename_all = "camelCase")]
    ModifyAttribute {
        attribute: GroupAttribute,
        value: Option<String>,
        /// The SHA-256 (base64) of the avatar blob as the home stores it
        /// (sealed and padded, never the plaintext image): only with
        /// `Avatar`, and exactly when `value` is set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        avatar_hash: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    ModifyAccess {
        access: GroupAccessV1,
    },
    #[serde(rename_all = "camelCase")]
    ModifyAnnouncementsOnly {
        on: bool,
    },
    #[serde(rename_all = "camelCase")]
    ModifyInviteLink {
        password: Option<String>,
    },
    /// Bans a pseudonym; a member is removed with it.
    #[serde(rename_all = "camelCase")]
    Ban {
        pseudonym: String,
    },
    #[serde(rename_all = "camelCase")]
    Unban {
        pseudonym: String,
    },
    #[serde(rename_all = "camelCase")]
    ModifyBanList {
        value: Option<String>,
    },
    Terminate,
}

impl GroupActionV1 {
    /// Actions by a pseudonym that isn't yet a member; such a change carries
    /// exactly one action.
    pub fn is_by_newcomer(&self) -> bool {
        matches!(
            self,
            Self::Genesis { .. }
                | Self::Claim { .. }
                | Self::JoinFromLink { .. }
                | Self::RequestToJoin { .. }
                | Self::CancelRequest
        )
    }
}

/// A change: revision `n + 1` of the group, signed by its actor's pseudonym.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupChangeV1 {
    pub version: u16,
    pub group_id: String,
    pub revision: u64,
    /// The previous change's hash; all zeros for the genesis.
    pub previous_hash: String,
    /// The actor's pseudonym.
    pub actor: String,
    pub actions: Vec<GroupActionV1>,
    /// The hash of the state this change results in. Absent, and only
    /// absent, on a newcomer's change (a claim, a link join, a request or its
    /// cancellation): a newcomer never sees the state, whose sealed entries a
    /// link's master key would open, so the home computes the result and its
    /// notary signature names it; every client recomputes it with
    /// [`check::check_change`] and compares.
    pub resulting_state_hash: Option<String>,
    /// The actor's signature over the change with this field empty.
    pub signature: String,
}

impl GroupChangeV1 {
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.version != GROUP_FORMAT_VERSION {
            return Err("unsupported group change version".into());
        }
        decode_group_id(&self.group_id)?;
        decode_exact::<HASH_LEN>("previousHash", &self.previous_hash)?;
        decode_pseudonym(&self.actor)?;
        match (&self.resulting_state_hash, self.is_newcomers_change()) {
            (Some(hash), false) => {
                decode_exact::<HASH_LEN>("resultingStateHash", hash)?;
            }
            (None, true) => {}
            (Some(_), true) => return Err("a newcomer's change names no resulting state".into()),
            (None, false) => return Err("a change names its resulting state".into()),
        }
        if self.actions.is_empty() || self.actions.len() > MAX_ACTIONS_PER_CHANGE {
            return Err("a change carries 1 to 64 actions".into());
        }
        if self.actions.iter().any(GroupActionV1::is_by_newcomer) && self.actions.len() != 1 {
            return Err("a genesis, claim, join or request change carries one action".into());
        }
        Ok(())
    }

    /// A change by someone who isn't a member yet and never saw the state:
    /// its one action is a claim, a link join, a request or its cancellation.
    pub fn is_newcomers_change(&self) -> bool {
        matches!(
            self.actions.as_slice(),
            [GroupActionV1::Claim { .. }
                | GroupActionV1::JoinFromLink { .. }
                | GroupActionV1::RequestToJoin { .. }
                | GroupActionV1::CancelRequest]
        )
    }

    /// The bytes the actor signs: the canonical change with an empty signature.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_shape()?;
        let unsigned = Self {
            signature: String::new(),
            ..self.clone()
        };
        serde_json::to_vec(&unsigned).map_err(|error| error.to_string())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_shape()?;
        decode_exact::<SIGNATURE_LEN>("signature", &self.signature)?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_CHANGE_BYTES {
            return Err("group change is too large".into());
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CHANGE_BYTES {
            return Err("group change is too large".into());
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid group change: {error}"))?;
        if value.canonical_bytes()? != bytes {
            return Err("group change is not canonical JSON".into());
        }
        Ok(value)
    }

    /// The hash the next change names as its previous, and the home
    /// notarises.
    pub fn hash(&self) -> Result<[u8; HASH_LEN], String> {
        Ok(change_hash(&self.canonical_bytes()?))
    }
}

pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn decode_exact<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| format!("{field} must be canonical padded base64"))?;
    if STANDARD.encode(&bytes) != value {
        return Err(format!("{field} is not canonical base64"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("{field} must be {N} bytes"))
}

pub fn decode_pseudonym(value: &str) -> Result<[u8; PUBLIC_KEY_LEN], String> {
    decode_exact::<PUBLIC_KEY_LEN>("pseudonym", value)
}

/// A sealed field: canonical base64, at least an empty plaintext's seal, at
/// most `max` bytes.
pub fn decode_sealed(field: &str, value: &str, max: usize) -> Result<Vec<u8>, String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| format!("{field} must be canonical padded base64"))?;
    if STANDARD.encode(&bytes) != value {
        return Err(format!("{field} is not canonical base64"));
    }
    if bytes.len() < kutup_crypto::chat_group::sealed_len(0) || bytes.len() > max {
        return Err(format!("{field} has an invalid sealed length"));
    }
    Ok(bytes)
}

/// A home pin in its one canonical spelling (the group id binds it:
/// `kutup_crypto::chat_group::GroupHome`), checked wherever one arrives.
pub(crate) fn validate_home(home: &GroupHomePinV1) -> Result<(), String> {
    if !kutup_crypto::account_ref::valid_server(&home.server) {
        return Err("home server is not a valid server name".into());
    }
    // The federation identity document's hash: lowercase hex SHA-256.
    let hash = &home.identity_document_hash;
    if hash.len() != 2 * HASH_LEN
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("home identityDocumentHash must be 64 lowercase hex digits".into());
    }
    Ok(())
}

fn validate_attributes(attributes: &GroupAttributesV1) -> Result<(), String> {
    for (attribute, value) in [
        (GroupAttribute::Title, &attributes.title),
        (GroupAttribute::Description, &attributes.description),
        (GroupAttribute::Timer, &attributes.timer),
        (GroupAttribute::Avatar, &attributes.avatar),
    ] {
        if let Some(value) = value {
            decode_sealed("attribute", value, attribute.max_sealed_bytes())?;
        }
    }
    check_avatar_hash(
        GroupAttribute::Avatar,
        &attributes.avatar,
        &attributes.avatar_hash,
    )?;
    Ok(())
}

/// The avatar's clear hash: 32 bytes, present exactly when the avatar is;
/// never on another attribute.
pub(crate) fn check_avatar_hash(
    attribute: GroupAttribute,
    value: &Option<String>,
    hash: &Option<String>,
) -> Result<(), String> {
    match (attribute, value, hash) {
        (GroupAttribute::Avatar, Some(_), Some(hash)) => {
            decode_exact::<32>("avatarHash", hash)?;
            Ok(())
        }
        (GroupAttribute::Avatar, None, None) => Ok(()),
        (GroupAttribute::Avatar, _, _) => Err("an avatar and its hash come together".into()),
        (_, _, None) => Ok(()),
        (_, _, Some(_)) => Err("only the avatar has a hash".into()),
    }
}
