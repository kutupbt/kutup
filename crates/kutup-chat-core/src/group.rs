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

/// A secret kept as text (base64): stored as it is, never printed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretText(pub String);

impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<secret>")
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// What this device keeps per group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupRecordV1 {
    pub version: u16,
    pub group_id: String,
    pub master_key: SecretText,
    pub home: GroupHomePinV1,
    /// This account's pseudonym in the group (its seed).
    pub pseudonym_seed: SecretText,
    pub status: GroupStatus,
    /// The lowest revision a whole state served to this device may have: the
    /// revision of its own claim, or the last one this account verified (from
    /// its group list), so an older snapshot can't be passed off as current.
    pub min_revision: u64,
    /// The last verified state's canonical bytes, and the hash of the change
    /// that produced it; absent until the first verified state.
    pub state: Option<String>,
    pub head: Option<String>,
    /// The identity sequence of the last notary taken: a later notary by an
    /// older identity is refused (sequences only move forward).
    pub notary_sequence: Option<u64>,
    /// The home's newest gateway key config and its identity history.
    pub gateway: crate::group_client::GatewayCache,
    /// Since when the home has answered as if this account weren't in the
    /// group (milliseconds), reset by any answer that isn't that.
    pub not_found_since_ms: Option<i64>,
    /// This device's sender key for the group and the devices that hold it.
    pub sender_book: Option<SenderBook>,
    /// When this device last caught up with the home (milliseconds): a send
    /// catches up first when it is older than a few minutes, and a stranger's
    /// message makes it catch up at most this often.
    #[serde(default)]
    pub synced_at_ms: Option<i64>,
    /// A revision at which a member's message named another chain head than
    /// the one this device verified, still so after catching up: the home
    /// may be showing members different histories. Cleared when a member's
    /// context matches again.
    #[serde(default)]
    pub fork_at_revision: Option<u64>,
}

/// Which member devices hold this device's current sender key for a group
/// (Signal-Desktop's `senderKeyInfo`, `model-types.d.ts:60-70`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SenderBook {
    /// The distribution id (a UUID); a new one starts a new key.
    pub distribution_id: String,
    pub created_at_ms: i64,
    pub devices: Vec<BookDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BookDevice {
    pub account: String,
    pub device_id: u32,
    pub registration_id: u32,
}

/// A sender key older than this is replaced (Signal's
/// `desktop.senderKeyMaxAge`, at most 90 days).
pub const SENDER_KEY_MAX_AGE_MS: i64 = 90 * 24 * 60 * 60 * 1000;

impl SenderBook {
    pub fn new(now_ms: i64) -> Self {
        Self {
            distribution_id: uuid::Uuid::new_v4().to_string(),
            created_at_ms: now_ms,
            devices: Vec::new(),
        }
    }

    /// Whether this key must be replaced before the next send: too old, or a
    /// device that holds it is no longer a current member device (a removed
    /// member, a device that left its account's manifest, or one whose
    /// registration changed). The last is ours: Signal only drops the device
    /// (docs/plans/pairwise-groups.md §1).
    pub fn must_rotate(&self, now_ms: i64, current: &[BookDevice]) -> bool {
        now_ms.saturating_sub(self.created_at_ms) >= SENDER_KEY_MAX_AGE_MS
            || self.devices.iter().any(|held| !current.contains(held))
    }

    /// The current devices that don't hold the key yet.
    pub fn missing(&self, current: &[BookDevice]) -> Vec<BookDevice> {
        current
            .iter()
            .filter(|device| !self.devices.contains(device))
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum GroupStatus {
    /// Invited: the claim waits to be accepted by the home. The claim key
    /// lives only here, and goes when the status changes, in the same write.
    #[serde(rename_all = "camelCase")]
    Invited {
        slot_id: String,
        slot_revision: u64,
        claim_key_seed: SecretText,
        /// Who sent the invitation (their account): a stranger's is a
        /// message request.
        inviter: String,
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
        let bytes = decode_exact::<32>("masterKey", &self.master_key.0).map_err(record_error)?;
        GroupMasterKey::from_bytes(&bytes).map_err(record_error)
    }

    pub fn pseudonym(&self) -> Result<GroupKeyPair, GroupError> {
        let seed = Zeroizing::new(
            decode_exact::<32>("pseudonymSeed", &self.pseudonym_seed.0).map_err(record_error)?,
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

    /// The home's identity history this device holds, followed from the pin:
    /// the only history a notary is checked against.
    fn followed_history(&self) -> Result<&[FederationIdentityDocumentV1], GroupError> {
        let history = &self.gateway.identity_history;
        let current = self.home.follow(history).map_err(|_| GroupError::Notary)?;
        if current.server != self.home.server {
            return Err(GroupError::Notary);
        }
        Ok(history)
    }

    /// Whether `self` may replace `stored` in the store: never an older
    /// verified state, and never another state at the same revision (a fork).
    pub fn may_replace(&self, stored: &GroupRecordV1) -> Result<(), GroupError> {
        if self.group_id != stored.group_id {
            return Err(record_error("another group's record"));
        }
        let mine = self.verified()?.map(|(state, head)| (state.revision, head));
        let theirs = stored
            .verified()?
            .map(|(state, head)| (state.revision, head));
        match (mine, theirs) {
            (_, None) => Ok(()),
            (None, Some(_)) => Err(record_error("a verified group state can't be dropped")),
            (Some((new, new_head)), Some((old, old_head))) => {
                // The same state can't take the status back to an invitation
                // (which would bring back its claim key).
                // A new invitation, made after the state held, may follow a
                // declined or ended membership.
                let regressed = match &self.status {
                    GroupStatus::Invited { slot_revision, .. } => {
                        !matches!(stored.status, GroupStatus::Invited { .. })
                            && *slot_revision <= old
                    }
                    _ => false,
                };
                if new == old && new_head == old_head && regressed {
                    Err(record_error("a stale write can't bring back an invitation"))
                } else if new > old || (new == old && new_head == old_head) {
                    Ok(())
                } else if new == old {
                    Err(record_error("another state at the same revision (a fork)"))
                } else {
                    Err(record_error("an older group state than the one stored"))
                }
            }
        }
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
        master_key: SecretText(encode(master.as_bytes())),
        home: new.home,
        pseudonym_seed: SecretText(encode(pseudonym.seed())),
        status: GroupStatus::Member,
        min_revision: 0,
        state: None,
        head: None,
        notary_sequence: None,
        gateway: Default::default(),
        not_found_since_ms: None,
        sender_book: None,
        synced_at_ms: None,
        fork_at_revision: None,
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
        master_key: record.master_key.0.clone(),
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

/// The record an invitation from `inviter` starts: the group's key and home,
/// a fresh pseudonym, and the slot's claim key, kept in the `Invited` status
/// until the claim is accepted. The invitation is consumed.
///
/// `previous` is the record of a membership that ended (declined, left or
/// removed): its verified state is kept, so no older one is taken later, and
/// only an invitation made after it starts the new one.
pub fn record_from_invite(
    invite: GroupInviteV1,
    inviter: &str,
    previous: Option<&GroupRecordV1>,
) -> Result<GroupRecordV1, GroupError> {
    invite.validate().map_err(record_error)?;
    let master = GroupMasterKey::from_bytes(
        &decode_exact::<32>("masterKey", &invite.master_key).map_err(record_error)?,
    )
    .map_err(record_error)?;
    let group_id = decode_group_id(&invite.group_id).map_err(record_error)?;
    if master.group_id() != group_id {
        return Err(record_error("the invitation's key is not its group's"));
    }
    let pseudonym = GroupKeyPair::generate();
    let mut record = GroupRecordV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: invite.group_id.clone(),
        master_key: SecretText(invite.master_key.clone()),
        home: invite.home.clone(),
        pseudonym_seed: SecretText(encode(pseudonym.seed())),
        status: GroupStatus::Invited {
            slot_id: invite.slot_id.clone(),
            slot_revision: invite.slot_revision,
            claim_key_seed: SecretText(invite.claim_key_seed.clone()),
            inviter: inviter.to_string(),
        },
        // Raised to the claim's revision when the claim is made.
        min_revision: invite.slot_revision,
        state: None,
        head: None,
        notary_sequence: None,
        gateway: Default::default(),
        not_found_since_ms: None,
        sender_book: None,
        synced_at_ms: None,
        fork_at_revision: None,
    };
    if let Some(previous) = previous {
        if previous.group_id != record.group_id || previous.status != GroupStatus::Gone {
            return Err(record_error(
                "only an ended membership takes a new invitation",
            ));
        }
        if previous.home != record.home {
            return Err(record_error("the invitation names another home"));
        }
        if let Some((state, _)) = previous.verified()? {
            if invite.slot_revision <= state.revision {
                return Err(record_error("an invitation older than the state held"));
            }
        }
        record.state = previous.state.clone();
        record.head = previous.head.clone();
        record.notary_sequence = previous.notary_sequence;
        record.gateway = previous.gateway.clone();
        record.min_revision = record.min_revision.max(previous.min_revision);
    }
    Ok(record)
}

/// The claim key of an invited record: what signs the join-info request a
/// claimant needs before its claim.
pub fn claim_key_seed(record: &GroupRecordV1) -> Result<[u8; 32], GroupError> {
    match &record.status {
        GroupStatus::Invited { claim_key_seed, .. } => {
            decode_exact::<32>("claimKeySeed", &claim_key_seed.0).map_err(record_error)
        }
        _ => Err(record_error("no invitation to claim")),
    }
}

/// The claim of an invited record, signed by its pseudonym and by the slot's
/// claim key, built from the join info's revision and head: what is sent
/// with `SubmitChange`. A whole state taken later must be at least this
/// revision.
pub fn claim(
    record: &mut GroupRecordV1,
    basis: &ClaimBasis,
    me: &AccountRef,
    device_id: u32,
    profile_key: &[u8; 32],
    sign_binding: &SignBinding<'_>,
) -> Result<GroupChangeV1, GroupError> {
    let GroupStatus::Invited {
        slot_id: slot_text,
        slot_revision,
        ..
    } = &record.status
    else {
        return Err(record_error("no invitation to claim"));
    };
    let (slot_text, slot_revision) = (slot_text.clone(), *slot_revision);
    let claim_key = GroupKeyPair::from_seed(&Zeroizing::new(claim_key_seed(record)?));
    let master = record.master()?;
    let group_id = decode_group_id(&record.group_id).map_err(record_error)?;
    let slot_id = decode_exact::<SLOT_ID_LEN>("slotId", &slot_text).map_err(record_error)?;
    let pseudonym = record.pseudonym()?;
    let entry = seal_member_entry(
        &master.state_key(),
        &group_id,
        &pseudonym.public_key(),
        me,
        device_id,
        profile_key,
        sign_binding,
    )?;
    let claim_signature =
        claim_key.sign_claim(&group_id, &slot_id, slot_revision, &pseudonym.public_key());
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: record.group_id.clone(),
        revision: basis.revision + 1,
        previous_hash: encode(&basis.head),
        actor: encode(&pseudonym.public_key()),
        actions: vec![GroupActionV1::Claim {
            slot_id: slot_text,
            claim_signature: encode(&claim_signature),
            entry,
        }],
        resulting_state_hash: None,
        signature: String::new(),
    };
    change.signature =
        encode(&pseudonym.sign_change(&change.signed_bytes().map_err(record_error)?));
    record.min_revision = record.min_revision.max(change.revision);
    Ok(change)
}

/// Applies a change the home notarised: the same check it ran, then its
/// signature over the change and the resulting state, by an identity in the
/// history this record followed from its pin. A notary by a document that
/// history lacks means it must be fetched again.
pub fn accept_change(
    record: &mut GroupRecordV1,
    change: &GroupChangeV1,
    notary: &GroupNotaryV1,
) -> Result<GroupStateV1, GroupError> {
    if change.group_id != record.group_id {
        return Err(GroupError::Change(GroupChangeError::WrongGroup));
    }
    let next = match record.verified()? {
        None if change.revision == 0 => {
            let first = check_genesis(change, &record.home, &GroupLimits::MAX)?;
            // The creator's entry must open under this group's key: a genesis
            // of another group can't stand in for it.
            let creator = first
                .members
                .first()
                .ok_or_else(|| record_error("a genesis without its creator"))?;
            let key = record.master()?.state_key();
            let subject =
                decode_exact::<32>("pseudonym", &creator.pseudonym).map_err(record_error)?;
            let plain = key
                .open(
                    SealedField::MemberEntry,
                    &subject,
                    &base64_decode(&creator.entry)?,
                )
                .map_err(|_| record_error("the creator's entry doesn't open"))?;
            GroupMemberEntryV1::from_canonical_bytes(&plain).map_err(record_error)?;
            first
        }
        Some((state, head)) => check_change(&state, &head, change, &GroupLimits::MAX)?,
        None => return Err(record_error("a change before any verified state")),
    };
    let change_hash = change.hash().map_err(record_error)?;
    let group_id = decode_group_id(&record.group_id).map_err(record_error)?;
    let history = record.followed_history()?;
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
/// produced it and its notary. The state must hash to what the notary names,
/// that change must be its head, it must be at least the record's
/// `min_revision` (the claim, or the last revision this account verified),
/// and this account must be a member of it.
pub fn accept_state(
    record: &mut GroupRecordV1,
    state: &GroupStateV1,
    latest_change: &GroupChangeV1,
    notary: &GroupNotaryV1,
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
    if state.revision < record.min_revision {
        return Err(GroupError::Change(GroupChangeError::WrongRevision));
    }
    if state.member(&record.pseudonym_text()?).is_none() {
        return Err(GroupError::Change(GroupChangeError::NotMember));
    }
    let change_hash = latest_change.hash().map_err(record_error)?;
    let group_id = decode_group_id(&record.group_id).map_err(record_error)?;
    let history = record.followed_history()?;
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

/// How a group context in a message compares with this device's state
/// (docs/plans/pairwise-groups.md §3, "Forks and withholding").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextCheck {
    /// The same revision and chain head.
    Current,
    /// The sender is further on: catch up from the home.
    Behind,
    /// The sender hasn't caught up yet: nothing to do.
    SenderBehind,
    /// The same revision with another head: the home shows members different
    /// histories. Fetch again; if it persists, warn.
    Fork,
}

/// Compares a message's group context `{revision, chainHash}` with the last
/// verified state.
pub fn compare_context(
    record: &GroupRecordV1,
    revision: u64,
    chain_hash: &[u8; HASH_LEN],
) -> Result<ContextCheck, GroupError> {
    let Some((state, head)) = record.verified()? else {
        return Ok(ContextCheck::Behind);
    };
    Ok(match revision.cmp(&state.revision) {
        std::cmp::Ordering::Greater => ContextCheck::Behind,
        std::cmp::Ordering::Less => ContextCheck::SenderBehind,
        std::cmp::Ordering::Equal if &head == chain_hash => ContextCheck::Current,
        std::cmp::Ordering::Equal => ContextCheck::Fork,
    })
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

/// The accounts the last verified state's entries name, unverified: whose
/// manifests to fetch before [`members`] checks the bindings.
pub fn member_accounts(record: &GroupRecordV1) -> Result<Vec<AccountRef>, GroupError> {
    let Some((state, _)) = record.verified()? else {
        return Ok(Vec::new());
    };
    let key = record.master()?.state_key();
    let mut accounts = std::collections::BTreeSet::new();
    for member in &state.members {
        let Ok(pseudonym) = decode_exact::<32>("pseudonym", &member.pseudonym) else {
            continue;
        };
        let Ok(sealed) = base64_decode(&member.entry) else {
            continue;
        };
        let Ok(plain) = key.open(SealedField::MemberEntry, &pseudonym, &sealed) else {
            continue;
        };
        if let Ok(entry) = GroupMemberEntryV1::from_canonical_bytes(&plain) {
            accounts.insert(entry.account);
        }
    }
    Ok(accounts.into_iter().collect())
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
