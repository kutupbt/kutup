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
    resulting_genesis_state, resulting_state, GroupActionV1, GroupAttribute, GroupBanListV1,
    GroupChangeError, GroupChangeV1, GroupHomePinV1, GroupInviteV1, GroupLimits, GroupListStatus,
    GroupMemberEntryV1, GroupRole, GroupSlotEntryV1, GroupStateV1, GROUP_FORMAT_VERSION,
};
use kutup_chat_proto::group_route::GroupNotaryV1;
use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::chat_group::{
    GroupKeyPair, GroupMasterKey, GroupStateKey, SealedField, HASH_LEN, SLOT_ID_LEN,
};
use kutup_federation_proto::FederationIdentityDocumentV1;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The self-authority public key of an account's verified manifest, which
/// its members' bindings are checked against (the session's); `None` for an
/// account whose manifest isn't verified now.
pub type AuthorityOf<'a> = dyn Fn(&AccountRef) -> Option<[u8; 32]> + 'a;

/// What this account brings to its groups, from its master key: the
/// self-authority that signs its bindings, and where its pseudonyms come
/// from (`kutup_crypto::chat_group::GroupPseudonymKey`), so any of its
/// devices finds its place in a group again.
pub struct GroupAccountKeys {
    pub authority: crate::manifest::AccountAuthority,
    pub pseudonyms: kutup_crypto::chat_group::GroupPseudonymKey,
    /// The dummies its published delivery capabilities are padded with.
    pub delivery_padding: kutup_crypto::chat_group::DeliveryPaddingKey,
}

impl GroupAccountKeys {
    pub fn derive(master_key: &[u8; 32]) -> crate::error::Result<Self> {
        Ok(Self {
            authority: crate::manifest::AccountAuthority::derive(master_key)?,
            pseudonyms: kutup_crypto::chat_group::GroupPseudonymKey::derive(master_key),
            delivery_padding: kutup_crypto::chat_group::DeliveryPaddingKey::derive(master_key),
        })
    }
}

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
    /// The member whose context showed it: only they clear it.
    #[serde(default)]
    pub fork_sender: Option<String>,
    /// When this device first learned of the group (made it or got its
    /// invitation), milliseconds: where it sorts before its first message.
    #[serde(default)]
    pub known_since_ms: Option<i64>,
    /// What the account's group list says of the group, as this device last
    /// wrote or read it: a write is due when the group's status differs.
    #[serde(default)]
    pub listed_status: Option<kutup_chat_proto::group::GroupListStatus>,
    /// When this device writes the group's list entry (milliseconds): a
    /// random moment after the change that made it due (§5's write pattern).
    #[serde(default)]
    pub list_due_at_ms: Option<i64>,
    /// Which of this account's joins of the group this is (0 for the first):
    /// its pseudonym is derived at this epoch.
    #[serde(default)]
    pub join_epoch: u32,
    /// This account's delivery capability for the group, and which member
    /// accounts this device knows hold it (slice 2's multi-recipient route).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<DeliveryBook>,
    /// The other members' delivery capabilities, by account: what this
    /// device sends group messages to them with on the multi-recipient
    /// route. A member not here gets pairwise copies.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub member_capabilities: BTreeMap<String, HeldCapability>,
    /// When the delivery capability the group list last said was drawn (0
    /// for none): the entry is due again when this device's differs.
    #[serde(default)]
    pub listed_delivery_ms: Option<i64>,
}

/// This account's capability for receiving a group's messages on the
/// multi-recipient route: published (its hash) to the account's server,
/// handed to the members pairwise. Retired as soon as an account that may
/// hold it is no longer a member (`settle_delivery`), so a removed member's
/// copy stops working; the next send draws another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryBook {
    pub capability: SecretText,
    /// When it was drawn (milliseconds): the newest wins, on every device of
    /// the account and at every member.
    pub drawn_at_ms: i64,
    /// The member accounts this device handed it to (their servers took it).
    #[serde(default)]
    pub holders: Vec<String>,
    /// Every account that may hold it: the members when it was drawn, or,
    /// for one taken from the group list, when this device first saw the
    /// group's state with it (`None` until then), and everyone it was
    /// handed to since.
    #[serde(default)]
    pub exposed: Option<Vec<String>>,
    /// This device drew it, so this device publishes it (one taken from the
    /// list was published by the device that drew it, and is never added
    /// again from here: a stale list can't bring back a retired one).
    #[serde(default)]
    pub drawn_here: bool,
}

impl DeliveryBook {
    /// A new capability, drawn here for `members`, dated after `after_ms`
    /// (the one it replaces) even on a clock that went back.
    pub fn draw<R: rand::Rng + rand::CryptoRng>(
        now_ms: i64,
        after_ms: i64,
        members: Vec<String>,
        rng: &mut R,
    ) -> Self {
        let mut capability = [0u8; 16];
        rng.fill_bytes(&mut capability);
        Self {
            capability: SecretText(encode(&capability)),
            drawn_at_ms: now_ms.max(after_ms.saturating_add(1)),
            holders: Vec::new(),
            exposed: Some(members),
            drawn_here: true,
        }
    }

    /// The capability's 16 bytes.
    pub fn bytes(&self) -> Option<[u8; 16]> {
        decode_exact::<16>("a delivery capability", &self.capability.0).ok()
    }

    /// The members that don't hold it yet.
    pub fn missing<'a>(&self, members: &'a [String]) -> Vec<&'a String> {
        members
            .iter()
            .filter(|member| !self.holders.contains(member))
            .collect()
    }

    /// `account` holds it now (its server took it).
    pub fn handed_to(&mut self, account: &str) {
        if !self.holders.iter().any(|holder| holder == account) {
            self.holders.push(account.to_string());
            self.holders.sort();
        }
        let exposed = self.exposed.get_or_insert_with(Vec::new);
        if !exposed.iter().any(|known| known == account) {
            exposed.push(account.to_string());
            exposed.sort();
        }
    }
}

/// After the record's verified state moved (`before`: the member accounts
/// until then, `None` for a first state): the delivery capability is
/// retired when an account that may hold it isn't a member now. One taken
/// from the group list counts as held by every member of the first state
/// this device sees with it.
fn settle_delivery(
    record: &mut GroupRecordV1,
    before: Option<Vec<String>>,
) -> Result<(), GroupError> {
    if record.delivery.is_none() {
        return Ok(());
    }
    let after: Vec<String> = member_accounts(record)?
        .iter()
        .map(ToString::to_string)
        .collect();
    let book = record.delivery.as_mut().expect("checked above");
    let exposed = book
        .exposed
        .get_or_insert_with(|| before.unwrap_or_else(|| after.clone()));
    if exposed.iter().any(|account| !after.contains(account)) {
        record.delivery = None;
    }
    Ok(())
}

/// A member's capability as this device holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeldCapability {
    pub capability: SecretText,
    pub drawn_at_ms: i64,
}

impl HeldCapability {
    pub fn bytes(&self) -> Option<[u8; 16]> {
        decode_exact::<16>("a delivery capability", &self.capability.0).ok()
    }
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
    /// Devices whose key this account's server queued for theirs (not yet
    /// stored there): not handed out again with each message to a server
    /// that is down, until [`QUEUED_KEY_WAIT_MS`] has passed.
    #[serde(default)]
    pub queued: Vec<QueuedKey>,
}

/// A key handed to a device's server only as far as this account's server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueuedKey {
    pub device: BookDevice,
    pub at_ms: i64,
}

/// How long a queued key is left to arrive before it is handed out again.
pub const QUEUED_KEY_WAIT_MS: i64 = 60 * 60 * 1000;

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
            queued: Vec::new(),
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

    /// The current devices that don't hold the key yet, and whose server
    /// wasn't handed it within the last [`QUEUED_KEY_WAIT_MS`].
    pub fn missing(&self, current: &[BookDevice], now_ms: i64) -> Vec<BookDevice> {
        current
            .iter()
            .filter(|device| !self.devices.contains(device))
            .filter(|device| {
                !self.queued.iter().any(|queued| {
                    &queued.device == *device
                        && now_ms.saturating_sub(queued.at_ms) < QUEUED_KEY_WAIT_MS
                })
            })
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
        /// The group's name as the invitation gave it, shown until the state
        /// is read.
        #[serde(default)]
        title: Option<String>,
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

/// A home pin as the group id binds it (`kutup_crypto::chat_group::GroupHome`).
pub fn home_of(pin: &GroupHomePinV1) -> kutup_crypto::chat_group::GroupHome<'_> {
    kutup_crypto::chat_group::GroupHome {
        server: &pin.server,
        identity_sequence: pin.identity_sequence,
        identity_document_hash: &pin.identity_document_hash,
    }
}

/// The master key `master_key` (base64) of the group `group_id` at `home`:
/// refused unless the key at that home is that group's. A member who keeps
/// the key can't move the group to a home of theirs.
pub fn master_at(
    master_key: &str,
    group_id: &str,
    home: &GroupHomePinV1,
) -> Result<GroupMasterKey, GroupError> {
    let bytes = Zeroizing::new(decode_exact::<32>("masterKey", master_key).map_err(record_error)?);
    let master = GroupMasterKey::from_bytes(bytes.as_ref(), home_of(home)).map_err(record_error)?;
    let id = decode_group_id(group_id).map_err(record_error)?;
    if master.group_id() != id {
        return Err(record_error("the key is not this group's at this home"));
    }
    Ok(master)
}

impl GroupRecordV1 {
    /// The group's master key, at the record's home: refused unless that is
    /// the group's id there.
    pub fn master(&self) -> Result<GroupMasterKey, GroupError> {
        master_at(&self.master_key.0, &self.group_id, &self.home)
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
/// and the binding its self-authority signs.
pub fn seal_member_entry(
    key: &GroupStateKey,
    group_id: &[u8; 32],
    pseudonym: &[u8; 32],
    me: &AccountRef,
    profile_key: &[u8; 32],
    authority: &crate::manifest::AccountAuthority,
) -> Result<String, GroupError> {
    let signature = authority.sign_group_binding(group_id, pseudonym, me);
    let entry = GroupMemberEntryV1 {
        version: GROUP_FORMAT_VERSION,
        account: me.clone(),
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
    pub profile_key: &'a [u8; 32],
    pub keys: &'a GroupAccountKeys,
}

/// A new group: its record (not yet verified by the home) and its genesis,
/// to send with `Create`.
pub fn create_group(new: NewGroup<'_>) -> Result<(GroupRecordV1, GroupChangeV1), GroupError> {
    let master = GroupMasterKey::generate(home_of(&new.home)).map_err(record_error)?;
    let group_id = master.group_id();
    // The creator's first join.
    let join_epoch = 0;
    let pseudonym = new.keys.pseudonyms.pseudonym(&group_id, join_epoch);
    let entry = seal_member_entry(
        &master.state_key(),
        &group_id,
        &pseudonym.public_key(),
        new.me,
        new.profile_key,
        &new.keys.authority,
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
        fork_sender: None,
        known_since_ms: None,
        listed_status: None,
        list_due_at_ms: None,
        join_epoch,
        delivery: None,
        member_capabilities: Default::default(),
        listed_delivery_ms: None,
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
        title: attribute(record, GroupAttribute::Title)
            .ok()
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|title| {
                title.chars().count() <= kutup_chat_proto::group::entry::MAX_INVITE_TITLE_CHARS
            }),
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
/// this account's pseudonym for the join, and the slot's claim key, kept in
/// the `Invited` status until the claim is accepted. The invitation is
/// consumed.
///
/// `previous` is the record of a membership that ended (declined, left or
/// removed), or of an older invitation (its slot perhaps revoked): its
/// verified state is kept, so no older one is taken later, and only an
/// invitation made after it starts the new one.
///
/// The pseudonym is derived at the join epoch after the last one this
/// account used: one more than an ended membership's (here, or `listed` in
/// the account's group list), the same as an older invitation's (never
/// claimed) or as a current membership the list names (another device's,
/// where the account is in already), 0 for a group the account never was in.
/// So a rejoin is a new pseudonym. Never past [`MAX_JOIN_EPOCHS`] − 1: an
/// invitation that would need a later epoch is refused.
pub fn record_from_invite(
    invite: GroupInviteV1,
    inviter: &str,
    previous: Option<&GroupRecordV1>,
    listed: Option<(GroupListStatus, u32)>,
    keys: &GroupAccountKeys,
) -> Result<GroupRecordV1, GroupError> {
    invite.validate().map_err(record_error)?;
    // The key must be the group's at the home the invitation names.
    master_at(&invite.master_key, &invite.group_id, &invite.home)
        .map_err(|_| record_error("the invitation's key is not its group's"))?;
    let group_id = decode_group_id(&invite.group_id).map_err(record_error)?;
    let after = |status: &GroupStatus, epoch: u32| match status {
        GroupStatus::Invited { .. } | GroupStatus::Requesting => epoch,
        GroupStatus::Member | GroupStatus::Gone => epoch.saturating_add(1),
    };
    let join_epoch = within_join_epochs(
        previous
            .map(|previous| after(&previous.status, previous.join_epoch))
            .into_iter()
            .chain(listed_join_epoch(listed))
            .max()
            .unwrap_or(0),
    )?;
    let pseudonym = keys.pseudonyms.pseudonym(&group_id, join_epoch);
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
            title: invite.title.clone(),
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
        fork_sender: None,
        known_since_ms: None,
        listed_status: None,
        list_due_at_ms: None,
        join_epoch,
        delivery: None,
        member_capabilities: Default::default(),
        listed_delivery_ms: None,
    };
    if let Some(previous) = previous {
        let replaceable = match &previous.status {
            GroupStatus::Gone => true,
            GroupStatus::Invited { slot_revision, .. } => invite.slot_revision > *slot_revision,
            GroupStatus::Member | GroupStatus::Requesting => false,
        };
        if previous.group_id != record.group_id || !replaceable {
            return Err(record_error(
                "only an ended membership or an older invitation takes a new one",
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

/// How many join epochs an account has in a group: 0 to this − 1, and no
/// path takes a higher one (an invitation, the list, a claim the home refuses
/// as a used pseudonym), so a device without the group list, which matches a
/// pseudonym named to it against exactly these epochs, always finds its
/// place. Matching is local (one derivation per epoch).
pub const MAX_JOIN_EPOCHS: u32 = 64;

/// `epoch`, when it is one an account may join at ([`MAX_JOIN_EPOCHS`]).
pub fn within_join_epochs(epoch: u32) -> Result<u32, GroupError> {
    if epoch >= MAX_JOIN_EPOCHS {
        return Err(record_error(
            "this account has joined this group as often as it can",
        ));
    }
    Ok(epoch)
}

/// The lowest join epoch an invitation may take by the account's group
/// list: past an ended membership there, but a current one's own epoch,
/// since another device of the account is in the group under it (a claim
/// made there finds the account in; one past it would find it out and take
/// the group as gone). A current entry whose leave was never written is
/// caught by the home instead: it refuses the claim as `pseudonymUsed`, and
/// the claim moves on.
pub fn listed_join_epoch(listed: Option<(GroupListStatus, u32)>) -> Option<u32> {
    listed.map(|(status, epoch)| match status {
        GroupListStatus::Member => epoch,
        GroupListStatus::Gone => epoch.saturating_add(1),
    })
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
    profile_key: &[u8; 32],
    authority: &crate::manifest::AccountAuthority,
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
        profile_key,
        authority,
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

/// A record to join `link`'s group with (docs/plans/pairwise-groups.md §11):
/// at the join epoch a claim would take (past an ended membership here or
/// in the list, never past `MAX_JOIN_EPOCHS` − 1), `Requesting` until the
/// home has the join. Only an ended membership's record (or none) is
/// replaced; its verified state is kept, so no older one is taken later.
pub fn record_from_link(
    link: &kutup_chat_proto::group::link::GroupInviteLinkV1,
    previous: Option<&GroupRecordV1>,
    listed: Option<(GroupListStatus, u32)>,
    keys: &GroupAccountKeys,
) -> Result<GroupRecordV1, GroupError> {
    let master = GroupMasterKey::from_bytes(&link.master_key, home_of(&link.home))
        .map_err(|_| record_error("the link's group key and home don't make a group"))?;
    let group_id = master.group_id();
    let group_text = encode_group_id(&group_id);
    let join_epoch = within_join_epochs(
        previous
            .map(|previous| match previous.status {
                GroupStatus::Member | GroupStatus::Gone => previous.join_epoch.saturating_add(1),
                GroupStatus::Invited { .. } | GroupStatus::Requesting => previous.join_epoch,
            })
            .into_iter()
            .chain(listed_join_epoch(listed))
            .max()
            .unwrap_or(0),
    )?;
    if let Some(previous) = previous {
        if previous.group_id != group_text || previous.home != link.home {
            return Err(record_error("the link names another group"));
        }
        if previous.status == GroupStatus::Member {
            return Err(record_error("this account is in the group already"));
        }
    }
    let pseudonym = keys.pseudonyms.pseudonym(&group_id, join_epoch);
    let mut record = GroupRecordV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: group_text,
        master_key: SecretText(encode(master.as_bytes())),
        home: link.home.clone(),
        pseudonym_seed: SecretText(encode(pseudonym.seed())),
        status: GroupStatus::Requesting,
        min_revision: 0,
        state: None,
        head: None,
        notary_sequence: None,
        gateway: Default::default(),
        not_found_since_ms: None,
        sender_book: None,
        synced_at_ms: None,
        fork_at_revision: None,
        fork_sender: None,
        known_since_ms: None,
        listed_status: None,
        list_due_at_ms: None,
        join_epoch,
        delivery: None,
        member_capabilities: Default::default(),
        listed_delivery_ms: None,
    };
    if let Some(previous) = previous {
        record.state = previous.state.clone();
        record.head = previous.head.clone();
        record.notary_sequence = previous.notary_sequence;
        record.gateway = previous.gateway.clone();
        record.min_revision = previous.min_revision;
    }
    Ok(record)
}

/// The change joining (`approval` false) or asking to join (`approval`
/// true) through the link with `password`, signed by the record's
/// pseudonym, built from the join info's revision and head; its member
/// entry is sealed as `MemberEntry` (an approval moves it as it is).
pub fn link_change(
    record: &mut GroupRecordV1,
    basis: &ClaimBasis,
    password: &[u8; kutup_chat_proto::group::INVITE_LINK_PASSWORD_LEN],
    approval: bool,
    me: &AccountRef,
    profile_key: &[u8; 32],
    authority: &crate::manifest::AccountAuthority,
) -> Result<GroupChangeV1, GroupError> {
    let master = record.master()?;
    let group_id = decode_group_id(&record.group_id).map_err(record_error)?;
    let pseudonym = record.pseudonym()?;
    let entry = seal_member_entry(
        &master.state_key(),
        &group_id,
        &pseudonym.public_key(),
        me,
        profile_key,
        authority,
    )?;
    let password = encode(password);
    let action = if approval {
        GroupActionV1::RequestToJoin { password, entry }
    } else {
        GroupActionV1::JoinFromLink { password, entry }
    };
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: record.group_id.clone(),
        revision: basis.revision + 1,
        previous_hash: encode(&basis.head),
        actor: encode(&pseudonym.public_key()),
        actions: vec![action],
        resulting_state_hash: None,
        signature: String::new(),
    };
    change.signature =
        encode(&pseudonym.sign_change(&change.signed_bytes().map_err(record_error)?));
    record.min_revision = record.min_revision.max(change.revision);
    Ok(change)
}

/// Withdrawing this record's request to join, signed by its pseudonym, at
/// the revision and head the home's request status names.
pub fn cancel_change(
    record: &GroupRecordV1,
    basis: &ClaimBasis,
) -> Result<GroupChangeV1, GroupError> {
    let pseudonym = record.pseudonym()?;
    let mut change = GroupChangeV1 {
        version: GROUP_FORMAT_VERSION,
        group_id: record.group_id.clone(),
        revision: basis.revision + 1,
        previous_hash: encode(&basis.head),
        actor: encode(&pseudonym.public_key()),
        actions: vec![GroupActionV1::CancelRequest],
        resulting_state_hash: None,
        signature: String::new(),
    };
    change.signature =
        encode(&pseudonym.sign_change(&change.signed_bytes().map_err(record_error)?));
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
    let before = match record.verified()? {
        Some(_) => Some(
            member_accounts(record)?
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        None => None,
    };
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
    settle_delivery(record, before)?;
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
    // joined, or is new), or one joining again (invited, or through the
    // link: asking or approved): a member catches up through the log, so
    // every change is checked, signatures and roles included. A rejoiner's
    // kept state only sets the lowest revision it takes (its new pseudonym
    // reads the log only from its join on).
    let kept = record.verified()?;
    if kept.is_some()
        && !matches!(
            record.status,
            GroupStatus::Invited { .. } | GroupStatus::Requesting
        )
    {
        return Err(record_error("a member catches up through the log"));
    }
    // A rejoiner takes only a state newer than the one it kept, from a notary
    // no older than the one it took last: never a rollback.
    if let Some((kept, _)) = &kept {
        if state.revision <= kept.revision {
            return Err(GroupError::Change(GroupChangeError::WrongRevision));
        }
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
            kept.as_ref().and(record.notary_sequence),
            &group_id,
            state.revision,
            &change_hash,
            &state.hash().map_err(record_error)?,
        )
        .map_err(|_| GroupError::Notary)?;
    record.set_verified(state, change_hash)?;
    record.notary_sequence = Some(notary.identity_sequence);
    if kept.is_some() {
        // Joining again: the capability of the earlier membership was
        // retired when it ended; a new one is drawn.
        record.delivery = None;
    }
    settle_delivery(record, None)?;
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
/// checked against the self-authority of the account's verified manifest
/// (`authority_of`): devices coming and going never touch it.
pub fn members(
    record: &GroupRecordV1,
    authority_of: &AuthorityOf<'_>,
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
                authority_of,
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

pub(crate) fn open_member(
    key: &GroupStateKey,
    group_id: &[u8; 32],
    pseudonym_text: &str,
    sealed: &str,
    authority_of: &AuthorityOf<'_>,
) -> Option<VerifiedMember> {
    let pseudonym = decode_exact::<32>("pseudonym", pseudonym_text).ok()?;
    let sealed = base64_decode(sealed).ok()?;
    let plain = key
        .open(SealedField::MemberEntry, &pseudonym, &sealed)
        .ok()?;
    let entry = GroupMemberEntryV1::from_canonical_bytes(&plain).ok()?;
    let signature = decode_exact::<64>("bindingSignature", &entry.binding_signature).ok()?;
    let authority = authority_of(&entry.account)?;
    kutup_crypto::chat_group::verify_binding(
        &authority,
        group_id,
        &pseudonym,
        &entry.account,
        &signature,
    )
    .ok()?;
    Some(VerifiedMember {
        profile_key: decode_exact::<32>("profileKey", &entry.profile_key).ok()?,
        account: entry.account,
    })
}

/// This account's own entry in the last verified state, opened: who it
/// names, its binding and the profile key it gives the group. `None` when
/// this account isn't a member of that state.
pub fn own_entry(record: &GroupRecordV1) -> Result<Option<GroupMemberEntryV1>, GroupError> {
    let Some((state, _)) = record.verified()? else {
        return Ok(None);
    };
    let me = record.pseudonym_text()?;
    let Some(member) = state.member(&me) else {
        return Ok(None);
    };
    let pseudonym = decode_exact::<32>("pseudonym", &member.pseudonym).map_err(record_error)?;
    let sealed = base64_decode(&member.entry)?;
    let plain = record
        .master()?
        .state_key()
        .open(SealedField::MemberEntry, &pseudonym, &sealed)
        .map_err(record_error)?;
    GroupMemberEntryV1::from_canonical_bytes(&plain)
        .map(Some)
        .map_err(record_error)
}

/// A new own entry for `record`, bound by this account's self-authority and
/// carrying `profile_key`: what `ModifyOwnEntry` sends when the binding
/// doesn't verify under the account's current authority, or the profile key
/// changed.
pub fn renewed_own_entry(
    record: &GroupRecordV1,
    me: &AccountRef,
    profile_key: &[u8; 32],
    authority: &crate::manifest::AccountAuthority,
) -> Result<GroupActionV1, GroupError> {
    let pseudonym = record.pseudonym()?;
    let group_id = decode_group_id(&record.group_id).map_err(record_error)?;
    let entry = seal_member_entry(
        &record.master()?.state_key(),
        &group_id,
        &pseudonym.public_key(),
        me,
        profile_key,
        authority,
    )?;
    Ok(GroupActionV1::ModifyOwnEntry { entry })
}

/// The accounts the last verified state's entries name, unverified: whose
/// manifests to fetch before [`members`] checks the bindings.
pub fn member_accounts(record: &GroupRecordV1) -> Result<Vec<AccountRef>, GroupError> {
    entry_accounts(record, |state| {
        state
            .members
            .iter()
            .map(|member| (member.pseudonym.clone(), member.entry.clone()))
            .collect()
    })
}

/// The accounts the requests to join name, unverified: whose manifests to
/// fetch before [`requesters`] checks the bindings.
pub fn request_accounts(record: &GroupRecordV1) -> Result<Vec<AccountRef>, GroupError> {
    entry_accounts(record, |state| {
        state
            .requesting
            .iter()
            .map(|request| (request.pseudonym.clone(), request.entry.clone()))
            .collect()
    })
}

fn entry_accounts(
    record: &GroupRecordV1,
    entries: impl Fn(&GroupStateV1) -> Vec<(String, String)>,
) -> Result<Vec<AccountRef>, GroupError> {
    let Some((state, _)) = record.verified()? else {
        return Ok(Vec::new());
    };
    let key = record.master()?.state_key();
    let mut accounts = std::collections::BTreeSet::new();
    for (pseudonym, entry) in entries(&state) {
        let Ok(pseudonym) = decode_exact::<32>("pseudonym", &pseudonym) else {
            continue;
        };
        let Ok(sealed) = base64_decode(&entry) else {
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

/// A request to join through the link, as an administrator sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRequesterView {
    pub pseudonym: String,
    pub requested_at_revision: u64,
    /// Who asks, when the entry opened and its binding verified; `None` for
    /// one that didn't (approving it gives an unverified member).
    pub verified: Option<VerifiedMember>,
    /// The account the entry names, verified or not: what a ban is checked
    /// against, since anyone can make their own binding fail.
    pub claimed: Option<AccountRef>,
    /// The claimed account's manifest couldn't be fetched now: whether its
    /// binding holds isn't known yet.
    pub unconfirmed: bool,
}

/// The account each member's and requester's entry names, by pseudonym,
/// without checking bindings: what bans are checked against.
pub fn claimed_accounts(
    record: &GroupRecordV1,
) -> Result<std::collections::BTreeMap<String, AccountRef>, GroupError> {
    let Some((state, _)) = record.verified()? else {
        return Ok(Default::default());
    };
    let key = record.master()?.state_key();
    Ok(state
        .members
        .iter()
        .map(|member| (&member.pseudonym, &member.entry))
        .chain(state.requesting.iter().map(|r| (&r.pseudonym, &r.entry)))
        .filter_map(|(pseudonym, entry)| {
            claimed_account(&key, pseudonym, entry).map(|account| (pseudonym.clone(), account))
        })
        .collect())
}

/// The account a sealed entry names, without checking its binding.
pub(crate) fn claimed_account(
    key: &GroupStateKey,
    pseudonym: &str,
    entry: &str,
) -> Option<AccountRef> {
    let pseudonym = decode_exact::<32>("pseudonym", pseudonym).ok()?;
    let sealed = base64_decode(entry).ok()?;
    let plain = key
        .open(SealedField::MemberEntry, &pseudonym, &sealed)
        .ok()?;
    GroupMemberEntryV1::from_canonical_bytes(&plain)
        .ok()
        .map(|entry| entry.account)
}

/// The requests to join, each binding checked as a member's is.
pub fn requesters(
    record: &GroupRecordV1,
    authority_of: &AuthorityOf<'_>,
    unconfirmed: &[AccountRef],
) -> Result<Vec<GroupRequesterView>, GroupError> {
    let Some((state, _)) = record.verified()? else {
        return Ok(Vec::new());
    };
    let key = record.master()?.state_key();
    let group_id = decode_group_id(&record.group_id).map_err(record_error)?;
    Ok(state
        .requesting
        .iter()
        .map(|request| {
            let claimed = claimed_account(&key, &request.pseudonym, &request.entry);
            GroupRequesterView {
                pseudonym: request.pseudonym.clone(),
                requested_at_revision: request.requested_at_revision,
                verified: open_member(
                    &key,
                    &group_id,
                    &request.pseudonym,
                    &request.entry,
                    authority_of,
                ),
                unconfirmed: claimed
                    .as_ref()
                    .is_some_and(|account| unconfirmed.contains(account)),
                claimed,
            }
        })
        .collect())
}

/// The ban list's plaintext is padded before sealing (a 0x80 marker, then
/// zeros) to one of these sizes, the last filling the sealed cap: what the
/// home sees says roughly how long the list is, not how many are on it.
fn ban_list_buckets() -> [usize; 4] {
    let cap = kutup_chat_proto::group::MAX_SEALED_BAN_LIST_BYTES
        - kutup_crypto::chat_group::sealed_len(0);
    [1024, 4096, 12 * 1024, cap]
}

/// `plain` padded to its bucket; `None` when it doesn't fit the largest.
fn pad_ban_list(plain: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let bucket = ban_list_buckets()
        .into_iter()
        .find(|bucket| plain.len() < *bucket)?;
    let mut padded = Zeroizing::new(Vec::with_capacity(bucket));
    padded.extend_from_slice(plain);
    padded.push(0x80);
    padded.resize(bucket, 0);
    Some(padded)
}

/// A ban list's opened plaintext, unpadded and read.
pub(crate) fn read_ban_list(padded: &[u8]) -> Result<GroupBanListV1, GroupError> {
    if !ban_list_buckets().contains(&padded.len()) {
        return Err(GroupError::Sealed(
            "a ban list is padded to a bucket".into(),
        ));
    }
    let end = padded
        .iter()
        .rposition(|byte| *byte != 0)
        .filter(|at| padded[*at] == 0x80)
        .ok_or_else(|| GroupError::Sealed("a ban list's padding is malformed".into()))?;
    GroupBanListV1::from_canonical_bytes(&padded[..end]).map_err(GroupError::Sealed)
}

/// The sealed ban list of the last verified state, opened; empty when there
/// is none. One that doesn't open is an error, never read as empty: an
/// administrator writing over it would lift every ban.
pub fn ban_list(record: &GroupRecordV1) -> Result<GroupBanListV1, GroupError> {
    let empty = GroupBanListV1 {
        version: GROUP_FORMAT_VERSION,
        banned: Vec::new(),
    };
    let Some((state, _)) = record.verified()? else {
        return Ok(empty);
    };
    let Some(sealed) = &state.ban_list else {
        return Ok(empty);
    };
    let key = record.master()?.state_key();
    let plain = key
        .open(SealedField::BanList, b"", &base64_decode(sealed)?)
        .map_err(|error| GroupError::Sealed(error.to_string()))?;
    read_ban_list(&plain)
}

/// Whether `list` has no room for one more account (the longest an account
/// reference can be, with one pseudonym) under the sealed cap.
pub fn ban_list_full(list: &GroupBanListV1) -> bool {
    let mut next = list.clone();
    let longest = AccountRef::new(
        &format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        ),
        "ffffffff-ffff-4fff-bfff-ffffffffffff",
    );
    let Ok(account) = longest else {
        return false;
    };
    if next.get(&account).is_some() {
        return false;
    }
    next.ban(&account, Some(&encode(&[0xff; 32])));
    next.canonical_bytes()
        .map_or(true, |bytes| pad_ban_list(&bytes).is_none())
}

/// Seals a ban list for a `ModifyBanList` action: `None` when it is empty.
pub fn seal_ban_list(
    record: &GroupRecordV1,
    list: &GroupBanListV1,
) -> Result<Option<String>, GroupError> {
    if list.banned.is_empty() {
        return Ok(None);
    }
    let plain = Zeroizing::new(list.canonical_bytes().map_err(record_error)?);
    let plain = pad_ban_list(&plain).ok_or(GroupError::Change(GroupChangeError::LimitReached))?;
    let key = record.master()?.state_key();
    Ok(Some(encode(
        &key.seal(SealedField::BanList, b"", &plain)
            .map_err(record_error)?,
    )))
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

/// A valid context of a test group (`seed` makes its id): what a pairwise
/// group's content carries.
#[cfg(test)]
pub(crate) fn test_context(seed: u8) -> kutup_chat_proto::group::GroupContextV1 {
    kutup_chat_proto::group::GroupContextV1 {
        version: 1,
        group_id: kutup_chat_proto::group_route::encode_group_id(&[seed; 32]),
        master_key: kutup_chat_proto::group::encode(&[6u8; 32]),
        home: kutup_chat_proto::group_route::GroupHomePinV1 {
            server: "a.test".into(),
            identity_sequence: 0,
            identity_document_hash: "9".repeat(64),
        },
        revision: 1,
        chain_hash: kutup_chat_proto::group::encode(&[7u8; 32]),
        recipient_pseudonym: None,
    }
}

#[cfg(test)]
mod tests;
