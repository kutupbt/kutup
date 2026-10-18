//! Chat groups on one-to-one sessions: this device's view of a group's state
//! (docs/plans/pairwise-groups.md §3–§5).
//!
//! A [`GroupRecordV1`] is what a device keeps per group: the master key, its
//! own pseudonym, the home's pin and the last state it verified. Everything
//! here is pure: the network (the anonymous route) and the stores are the
//! engine's; signing a binding and checking one are passed in, because only
//! the session holds the device's identity key and the verified manifests.
//!
//! - A change this device makes is built with `resulting_state` and signed
//!   by its pseudonym ([`author_change`]).
//! - A change it receives is applied only with the home's notary signature,
//!   after the same `check_change` the home ran ([`accept_change`]); a
//!   newcomer's change, which names no state, is compared with the state the
//!   notary names.
//! - Members are read by opening their sealed entries and checking each
//!   binding against its account's verified manifest ([`members`]); an entry
//!   that doesn't open or verify makes that member unverified, never refuses
//!   the change.

use kutup_chat_proto::group::{
    check_change, check_genesis, decode_exact, decode_group_id, encode, encode_group_id,
    resulting_genesis_state, resulting_state, GroupActionV1, GroupAttribute, GroupChangeError,
    GroupChangeV1, GroupHomePinV1, GroupInviteV1, GroupLimits, GroupMemberEntryV1, GroupRole,
    GroupSlotEntryV1, GroupStateV1, GROUP_FORMAT_VERSION,
};
use kutup_chat_proto::group_route::GroupNotaryV1;
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::chat_group::{
    binding_signed_bytes, GroupKeyPair, GroupMasterKey, GroupStateKey, SealedField, HASH_LEN,
    SLOT_ID_LEN,
};
use kutup_federation_proto::FederationIdentityDocumentV1;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Signs a binding's bytes with this device's identity key (the session's).
pub type SignBinding<'a> = dyn Fn(&[u8]) -> Result<Vec<u8>, String> + 'a;

/// Checks a binding: `(account, device_id, signed_bytes, signature)`, against
/// the account's verified manifest (the session's).
pub type VerifyBinding<'a> = dyn Fn(&AccountRef, u32, &[u8], &[u8]) -> bool + 'a;

/// What this device keeps per group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupRecordV1 {
    pub version: u16,
    pub group_id: String,
    pub master_key: String,
    pub home: GroupHomePinV1,
    /// This account's pseudonym in the group (its seed).
    pub pseudonym_seed: String,
    pub status: GroupStatus,
    /// The last verified state's canonical bytes, and the hash of the change
    /// that produced it; absent until the first verified state.
    pub state: Option<String>,
    pub head: Option<String>,
    /// The identity sequence of the last notary taken: a later notary by an
    /// older identity is refused (sequences only move forward).
    pub notary_sequence: Option<u64>,
    /// The home's newest gateway key config and its identity history.
    pub gateway: crate::group_client::GatewayCache,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum GroupStatus {
    /// Invited: the claim waits to be accepted by the home.
    #[serde(rename_all = "camelCase")]
    Invited {
        slot_id: String,
        slot_revision: u64,
    },
    /// Asked to join through the link; waits for an administrator.
    Requesting,
    Member,
    /// Left or removed: the record stays for the history; nothing is sent.
    Gone,
}

/// Who a member is, as this device read and checked their entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMemberView {
    pub pseudonym: String,
    pub role: GroupRole,
    pub joined_at_revision: u64,
    /// The account and profile key, when the entry opened and its binding
    /// verified against the account's manifest; `None` for an unverified
    /// member, who gets no keys.
    pub verified: Option<VerifiedMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMember {
    pub account: AccountRef,
    pub profile_key: [u8; 32],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GroupError {
    #[error("{0}")]
    Change(#[from] GroupChangeError),
    #[error("the home's notary signature is missing or invalid")]
    Notary,
    #[error("the group record is invalid: {0}")]
    Record(String),
    #[error("the group's state can't be opened: {0}")]
    Sealed(String),
}

fn record_error(error: impl ToString) -> GroupError {
    GroupError::Record(error.to_string())
}

impl GroupRecordV1 {
    pub fn master(&self) -> Result<GroupMasterKey, GroupError> {
        let bytes = decode_exact::<32>("masterKey", &self.master_key).map_err(record_error)?;
        GroupMasterKey::from_bytes(&bytes).map_err(record_error)
    }

    pub fn pseudonym(&self) -> Result<GroupKeyPair, GroupError> {
        let seed = Zeroizing::new(
            decode_exact::<32>("pseudonymSeed", &self.pseudonym_seed).map_err(record_error)?,
        );
        Ok(GroupKeyPair::from_seed(&seed))
    }

    pub fn pseudonym_text(&self) -> Result<String, GroupError> {
        Ok(encode(&self.pseudonym()?.public_key()))
    }

    /// The last verified state and its head.
    pub fn verified(&self) -> Result<Option<(GroupStateV1, [u8; HASH_LEN])>, GroupError> {
        let (Some(state), Some(head)) = (&self.state, &self.head) else {
            return Ok(None);
        };
        let bytes = base64_decode(state)?;
        let state = GroupStateV1::from_canonical_bytes(&bytes).map_err(record_error)?;
        let head = decode_exact::<HASH_LEN>("head", head).map_err(record_error)?;
        Ok(Some((state, head)))
    }

    fn set_verified(
        &mut self,
        state: &GroupStateV1,
        head: [u8; HASH_LEN],
    ) -> Result<(), GroupError> {
        self.state = Some(encode(&state.canonical_bytes().map_err(record_error)?));
        self.head = Some(encode(&head));
        let me = self.pseudonym_text()?;
        self.status = if state.member(&me).is_some() {
            GroupStatus::Member
        } else if state.requesting.iter().any(|r| r.pseudonym == me) {
            GroupStatus::Requesting
        } else if matches!(self.status, GroupStatus::Invited { .. })
            && state
                .slots
                .iter()
                .any(|slot| self.is_my_slot(&slot.slot_id))
        {
            self.status.clone()
        } else {
            GroupStatus::Gone
        };
        Ok(())
    }

    fn is_my_slot(&self, slot_id: &str) -> bool {
        matches!(&self.status, GroupStatus::Invited { slot_id: mine, .. } if mine == slot_id)
    }
}

fn base64_decode(value: &str) -> Result<Vec<u8>, GroupError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(record_error)
}

/// Seals this account's entry for `pseudonym`: who it is, its profile key,
/// and the binding `sign_binding` makes with the device's identity key.
pub fn seal_member_entry(
    key: &GroupStateKey,
    group_id: &[u8; 32],
    pseudonym: &[u8; 32],
    me: &AccountRef,
    device_id: u32,
    profile_key: &[u8; 32],
    sign_binding: &SignBinding<'_>,
) -> Result<String, GroupError> {
    let signature =
        sign_binding(&binding_signed_bytes(group_id, pseudonym, me)).map_err(record_error)?;
    let entry = GroupMemberEntryV1 {
        version: GROUP_FORMAT_VERSION,
        account: me.clone(),
        device_id,
        profile_key: encode(profile_key),
        binding_signature: encode(&signature),
    };
    let plain = entry.canonical_bytes().map_err(record_error)?;
    Ok(encode(
        &key.seal(SealedField::MemberEntry, pseudonym, &plain)
            .map_err(record_error)?,
    ))
}

/// What a new group needs from its creator.
pub struct NewGroup<'a> {
    pub home: GroupHomePinV1,
    pub me: &'a AccountRef,
    pub device_id: u32,
    pub profile_key: &'a [u8; 32],
    pub sign_binding: &'a SignBinding<'a>,
}

/// A new group: its record (not yet verified by the home) and its genesis,
/// to send with `Create`.
pub fn create_group(new: NewGroup<'_>) -> Result<(GroupRecordV1, GroupChangeV1), GroupError> {
    let master = GroupMasterKey::generate();
    let pseudonym = GroupKeyPair::generate();
    let group_id = master.group_id();
    let entry = seal_member_entry(
        &master.state_key(),
        &group_id,
        &pseudonym.public_key(),
        new.me,
        new.device_id,
        new.profile_key,
        new.sign_binding,
    )?;
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: encode_group_id(&group_id),
        revision: 0,
        previous_hash: encode(&[0u8; HASH_LEN]),
        actor: encode(&pseudonym.public_key()),
        actions: vec![GroupActionV1::Genesis {
            home: new.home.clone(),
            access: kutup_chat_proto::group::GroupAccessV1::DEFAULT,
            entry,
        }],
        resulting_state_hash: Some(encode(&[0u8; HASH_LEN])),
        signature: String::new(),
    };
    let first = resulting_genesis_state(&change, &new.home, &GroupLimits::MAX)?;
    sign(&mut change, &pseudonym, &first)?;
    let record = GroupRecordV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: change.group_id.clone(),
        master_key: encode(master.as_bytes()),
        home: new.home,
        pseudonym_seed: encode(pseudonym.seed()),
        status: GroupStatus::Member,
        state: None,
        head: None,
        notary_sequence: None,
        gateway: Default::default(),
    };
    Ok((record, change))
}

fn sign(
    change: &mut GroupChangeV1,
    actor: &GroupKeyPair,
    next: &GroupStateV1,
) -> Result<(), GroupError> {
    if !change.is_newcomers_change() {
        change.resulting_state_hash = Some(encode(&next.hash().map_err(record_error)?));
    }
    let bytes = change.signed_bytes().map_err(record_error)?;
    change.signature = encode(&actor.sign_change(&bytes));
    Ok(())
}

/// A change this member makes on its last verified state, signed by its
/// pseudonym: what the home is sent with `SubmitChange`.
pub fn author_change(
    record: &GroupRecordV1,
    actions: Vec<GroupActionV1>,
) -> Result<GroupChangeV1, GroupError> {
    let (state, head) = record
        .verified()?
        .ok_or_else(|| record_error("no verified state yet"))?;
    let pseudonym = record.pseudonym()?;
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: record.group_id.clone(),
        revision: state.revision + 1,
        previous_hash: encode(&head),
        actor: encode(&pseudonym.public_key()),
        actions,
        resulting_state_hash: Some(encode(&[0u8; HASH_LEN])),
        signature: String::new(),
    };
    let next = resulting_state(&state, &head, &change, &GroupLimits::MAX)?;
    sign(&mut change, &pseudonym, &next)?;
    Ok(change)
}

/// Invites `account` with `role`: the `AddSlot` action for a change, and the
/// invitation to send in the invitee's own copy of the update.
pub fn invite(
    record: &GroupRecordV1,
    account: &AccountRef,
    role: GroupRole,
) -> Result<(GroupActionV1, GroupInviteV1, [u8; 32]), GroupError> {
    let (state, _) = record
        .verified()?
        .ok_or_else(|| record_error("no verified state yet"))?;
    let mut slot_id = [0u8; SLOT_ID_LEN];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut slot_id);
    let claim_key = GroupKeyPair::generate();
    let key = record.master()?.state_key();
    let entry = GroupSlotEntryV1 {
        version: GROUP_FORMAT_VERSION,
        account: account.clone(),
    }
    .canonical_bytes()
    .map_err(record_error)?;
    let action = GroupActionV1::AddSlot {
        slot_id: encode(&slot_id),
        role,
        claim_key: encode(&claim_key.public_key()),
        entry: encode(
            &key.seal(SealedField::SlotEntry, &slot_id, &entry)
                .map_err(record_error)?,
        ),
    };
    let invite = GroupInviteV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: record.group_id.clone(),
        master_key: record.master_key.clone(),
        home: record.home.clone(),
        slot_id: encode(&slot_id),
        // The slot is added by the next revision.
        slot_revision: state.revision + 1,
        claim_key_seed: encode(claim_key.seed()),
    };
    invite.validate().map_err(record_error)?;
    Ok((action, invite, claim_key.public_key()))
}

/// What a claimant needs to build its change: the join info's revision and
/// head (never the state, whose entries it mustn't see before joining).
pub struct ClaimBasis {
    pub revision: u64,
    pub head: [u8; HASH_LEN],
}

/// Claims an invitation: this device's new record (not yet a member) and the
/// claim to send with `SubmitChange`, signed by a new pseudonym and by the
/// slot's claim key.
pub fn claim(
    invite: &GroupInviteV1,
    basis: &ClaimBasis,
    me: &AccountRef,
    device_id: u32,
    profile_key: &[u8; 32],
    sign_binding: &SignBinding<'_>,
) -> Result<(GroupRecordV1, GroupChangeV1), GroupError> {
    invite.validate().map_err(record_error)?;
    let master = GroupMasterKey::from_bytes(
        &decode_exact::<32>("masterKey", &invite.master_key).map_err(record_error)?,
    )
    .map_err(record_error)?;
    let group_id = decode_group_id(&invite.group_id).map_err(record_error)?;
    if master.group_id() != group_id {
        return Err(record_error("the invitation's key is not its group's"));
    }
    let slot_id = decode_exact::<SLOT_ID_LEN>("slotId", &invite.slot_id).map_err(record_error)?;
    let claim_key = GroupKeyPair::from_seed(&Zeroizing::new(
        decode_exact::<32>("claimKeySeed", &invite.claim_key_seed).map_err(record_error)?,
    ));
    let pseudonym = GroupKeyPair::generate();
    let entry = seal_member_entry(
        &master.state_key(),
        &group_id,
        &pseudonym.public_key(),
        me,
        device_id,
        profile_key,
        sign_binding,
    )?;
    let claim_signature = claim_key.sign_claim(
        &group_id,
        &slot_id,
        invite.slot_revision,
        &pseudonym.public_key(),
    );
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: invite.group_id.clone(),
        revision: basis.revision + 1,
        previous_hash: encode(&basis.head),
        actor: encode(&pseudonym.public_key()),
        actions: vec![GroupActionV1::Claim {
            slot_id: invite.slot_id.clone(),
            claim_signature: encode(&claim_signature),
            entry,
        }],
        resulting_state_hash: None,
        signature: String::new(),
    };
    change.signature =
        encode(&pseudonym.sign_change(&change.signed_bytes().map_err(record_error)?));
    let record = GroupRecordV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: invite.group_id.clone(),
        master_key: invite.master_key.clone(),
        home: invite.home.clone(),
        pseudonym_seed: encode(pseudonym.seed()),
        status: GroupStatus::Invited {
            slot_id: invite.slot_id.clone(),
            slot_revision: invite.slot_revision,
        },
        state: None,
        head: None,
        notary_sequence: None,
        gateway: Default::default(),
    };
    Ok((record, change))
}

/// Applies a change the home notarised: the same check it ran, then its
/// signature over the change and the resulting state. `history` is the
/// home's identity history followed from the record's pin
/// (`GroupHomePinV1::follow`); a notary by a document it lacks means the
/// history must be fetched again.
pub fn accept_change(
    record: &mut GroupRecordV1,
    change: &GroupChangeV1,
    notary: &GroupNotaryV1,
    history: &[FederationIdentityDocumentV1],
) -> Result<GroupStateV1, GroupError> {
    if change.group_id != record.group_id {
        return Err(GroupError::Change(GroupChangeError::WrongGroup));
    }
    let next = match record.verified()? {
        None if change.revision == 0 => check_genesis(change, &record.home, &GroupLimits::MAX)?,
        Some((state, head)) => check_change(&state, &head, change, &GroupLimits::MAX)?,
        None => return Err(record_error("a change before any verified state")),
    };
    let change_hash = change.hash().map_err(record_error)?;
    let group_id = decode_group_id(&record.group_id).map_err(record_error)?;
    // For a newcomer's change, this is where the notary's state hash is
    // compared with the state this device computed.
    notary
        .verify(
            history,
            record.notary_sequence,
            &group_id,
            change.revision,
            &change_hash,
            &next.hash().map_err(record_error)?,
        )
        .map_err(|_| GroupError::Notary)?;
    record.set_verified(&next, change_hash)?;
    record.notary_sequence = Some(notary.identity_sequence);
    Ok(next)
}

/// Takes a whole state the home served to a device that has none yet (a
/// newcomer just accepted, or a new device of a member), with the change that
/// produced it and its notary: the state must hash to what the notary names,
/// and that change must be the head.
pub fn accept_state(
    record: &mut GroupRecordV1,
    state: &GroupStateV1,
    latest_change: &GroupChangeV1,
    notary: &GroupNotaryV1,
    history: &[FederationIdentityDocumentV1],
) -> Result<(), GroupError> {
    state.validate().map_err(record_error)?;
    if state.group_id != record.group_id
        || latest_change.group_id != record.group_id
        || latest_change.revision != state.revision
        || state.home != record.home
    {
        return Err(GroupError::Change(GroupChangeError::WrongGroup));
    }
    // Only a device with no verified state takes a whole state (it just
    // joined, or is new): a member catches up through the log, so every change
    // is checked, signatures and roles included.
    if record.verified()?.is_some() {
        return Err(record_error("a member catches up through the log"));
    }
    let change_hash = latest_change.hash().map_err(record_error)?;
    let group_id = decode_group_id(&record.group_id).map_err(record_error)?;
    notary
        .verify(
            history,
            None,
            &group_id,
            state.revision,
            &change_hash,
            &state.hash().map_err(record_error)?,
        )
        .map_err(|_| GroupError::Notary)?;
    record.set_verified(state, change_hash)?;
    record.notary_sequence = Some(notary.identity_sequence);
    Ok(())
}

/// The members of the last verified state, each entry opened and its binding
/// checked by `verify_binding(account, device_id, signed_bytes, signature)`
/// against the account's verified manifest.
pub fn members(
    record: &GroupRecordV1,
    verify_binding: &VerifyBinding<'_>,
) -> Result<Vec<GroupMemberView>, GroupError> {
    let Some((state, _)) = record.verified()? else {
        return Ok(Vec::new());
    };
    let key = record.master()?.state_key();
    let group_id = decode_group_id(&record.group_id).map_err(record_error)?;
    let mut seen = std::collections::HashSet::new();
    Ok(state
        .members
        .iter()
        .map(|member| {
            let verified = open_member(
                &key,
                &group_id,
                &member.pseudonym,
                &member.entry,
                verify_binding,
            )
            // The same account twice (added twice): only the first counts.
            .filter(|verified| seen.insert(verified.account.clone()));
            GroupMemberView {
                pseudonym: member.pseudonym.clone(),
                role: member.role,
                joined_at_revision: member.joined_at_revision,
                verified,
            }
        })
        .collect())
}

fn open_member(
    key: &GroupStateKey,
    group_id: &[u8; 32],
    pseudonym_text: &str,
    sealed: &str,
    verify_binding: &VerifyBinding<'_>,
) -> Option<VerifiedMember> {
    let pseudonym = decode_exact::<32>("pseudonym", pseudonym_text).ok()?;
    let sealed = base64_decode(sealed).ok()?;
    let plain = key
        .open(SealedField::MemberEntry, &pseudonym, &sealed)
        .ok()?;
    let entry = GroupMemberEntryV1::from_canonical_bytes(&plain).ok()?;
    let signature = decode_exact::<64>("bindingSignature", &entry.binding_signature).ok()?;
    let signed = binding_signed_bytes(group_id, &pseudonym, &entry.account);
    if !verify_binding(&entry.account, entry.device_id, &signed, &signature) {
        return None;
    }
    Some(VerifiedMember {
        profile_key: decode_exact::<32>("profileKey", &entry.profile_key).ok()?,
        account: entry.account,
    })
}

/// A group-wide sealed attribute of the last verified state, opened.
pub fn attribute(
    record: &GroupRecordV1,
    attribute: GroupAttribute,
) -> Result<Option<Vec<u8>>, GroupError> {
    let Some((state, _)) = record.verified()? else {
        return Ok(None);
    };
    let (value, field) = match attribute {
        GroupAttribute::Title => (&state.attributes.title, SealedField::Title),
        GroupAttribute::Description => (&state.attributes.description, SealedField::Description),
        GroupAttribute::Timer => (&state.attributes.timer, SealedField::Timer),
        GroupAttribute::Avatar => (&state.attributes.avatar, SealedField::Avatar),
    };
    let Some(value) = value else {
        return Ok(None);
    };
    let key = record.master()?.state_key();
    let plain = key
        .open(field, b"", &base64_decode(value)?)
        .map_err(|error| GroupError::Sealed(error.to_string()))?;
    Ok(Some(plain.to_vec()))
}

/// Seals a group-wide attribute for a `ModifyAttribute` action.
pub fn seal_attribute(
    record: &GroupRecordV1,
    attribute: GroupAttribute,
    plain: &[u8],
) -> Result<String, GroupError> {
    let field = match attribute {
        GroupAttribute::Title => SealedField::Title,
        GroupAttribute::Description => SealedField::Description,
        GroupAttribute::Timer => SealedField::Timer,
        GroupAttribute::Avatar => SealedField::Avatar,
    };
    let key = record.master()?.state_key();
    Ok(encode(&key.seal(field, b"", plain).map_err(record_error)?))
}

#[cfg(test)]
mod tests;
