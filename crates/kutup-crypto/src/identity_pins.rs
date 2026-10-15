//! Identity pins (docs/plans/drive-identity-pins.md, docs/plans/account-id.md):
//! the accounts this account has met, by their permanent account id, and the
//! authority each one was trusted at, synced through the server.
//!
//! A pin is keyed by the account ([`AccountRef`]: server and account id),
//! never by an address, as Signal keeps identity keys per ACI. Addresses are
//! labels the pin remembers (newest last): a rename only adds one; a name the
//! account left and someone else took later belongs to another account id,
//! so it can never find this pin. The first authority met for an account is
//! trusted (`seen`), one compared in person is `verified`, and another
//! authority for the same account later (an administrator's reset, a
//! recovery, or a server handing out keys of its own) is a change the user is
//! warned about until they accept it: Signal's "safety number changed".
//!
//! One list serves every app of the account and survives a new browser: it is
//! sealed with XChaCha20-Poly1305 under a key derived from the master key and
//! stored by the server, which can neither read nor rewrite it. The revision
//! (a time in unix milliseconds, above every revision seen) is in the header
//! and authenticated, so the server cannot relabel an old list as a new one;
//! clients also remember the highest revision they have seen. Suite 3
//! (`KUTIP3`) binds the owner's key binding. Earlier suites are not read:
//! nothing from before carries over.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::account_ref::AccountRef;
use crate::account_rename::{self, AccountRenameV1};
use crate::error::{CryptoError, Result};
use crate::identity::incarnation_id_from_authority_public;
use crate::key_binding;
use crate::named_share::canonical_account;
use crate::padding::Length;

const PINS_KEY_SALT: &[u8] = b"kutup/identity-pins/v1\0";
const PINS_KEY_INFO: &[u8] = b"kutup/identity-pins/list-key/v1\0";
const MAGIC: &[u8; 8] = b"KUTIP3\0\0";
const AAD_DOMAIN: &[u8] = b"kutup/identity-pins/v3\0";
const SUITE: u16 = 3;
const NONCE_LEN: usize = 24;
const REVISION_LEN: usize = 8;
const HEADER_LEN: usize = 8 + 2 + REVISION_LEN + NONCE_LEN;
const TAG_LEN: usize = 16;
/// How a list is padded before it is sealed: its length then tells only
/// roughly how many accounts it pins.
const PADDING: Length = Length::Bucket(256);

/// The most accounts one list keeps.
pub const MAX_PINS: usize = 10_000;
/// Earlier authorities remembered for one account (changes the user accepted).
pub const MAX_REPLACED: usize = 10;
/// The most addresses a pin remembers: the newest are kept. Renames are at
/// least days apart, so 32 covers any real account; an address dropped from
/// the list only loses its "someone else has it now" warning.
pub const MAX_ADDRESSES: usize = 32;
/// The largest list, encoded.
pub const MAX_LIST_BYTES: usize = 4 * 1024 * 1024;
/// The version of this format a reader understands. A writer that adds
/// something older readers would misread sets [`IdentityPinsV2::min_reader`]
/// above it, and those readers refuse the list ("needs a newer app") instead
/// of misreading it.
pub const READER_VERSION: u32 = 1;

/// How far an account's authority is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PinState {
    /// The first authority seen for the account (trust on first use), or one
    /// the user accepted after a change.
    Seen,
    /// Compared in person (a safety number or QR code).
    Verified,
}

/// Fields a later version added, kept as they are: read past, written back
/// after the known fields in name order (the canonical rule for every field
/// added later), so an older app never strips a newer app's data.
pub type UnknownFields = std::collections::BTreeMap<String, serde_json::Value>;

/// One account's pinned authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPinV2 {
    /// Who: the key of the pin, permanent.
    pub account: AccountRef,
    /// Canonical padded base64 of the 32-byte Ed25519 authority public key.
    pub authority_public_key: String,
    pub state: PinState,
    /// When it was first pinned or last accepted: RFC 3339, UTC.
    pub since: String,
    /// Incarnation ids this account had before, oldest first: changes the
    /// user accepted. One of them handed out again is an old key coming back.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaced: Vec<String>,
    /// Canonical addresses the account was met at, oldest first, one per
    /// folded name: labels, never keys. The last is the newest known.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    /// The newest rename statement verified for the pinned authority: a later
    /// chain is accepted only if it holds this one at `sequence`, so no server
    /// can roll the account's name history back, on any device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renames: Option<RenameAnchorV1>,
    #[serde(flatten)]
    pub unknown: UnknownFields,
}

/// Where an authority's verified rename chain ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameAnchorV1 {
    /// The last statement's sequence (1 for the first rename).
    pub sequence: u64,
    /// That statement's digest, lowercase hex.
    pub digest: String,
    #[serde(flatten)]
    pub unknown: UnknownFields,
}

impl IdentityPinV2 {
    /// The authority's raw bytes.
    pub fn authority(&self) -> Result<[u8; 32]> {
        authority_bytes(&self.authority_public_key)
    }

    /// The account incarnation the pin stands for.
    pub fn incarnation_id(&self) -> Result<String> {
        Ok(incarnation_id_from_authority_public(&self.authority()?))
    }

    /// The newest address the account was met at.
    pub fn address(&self) -> Option<&str> {
        self.addresses.last().map(String::as_str)
    }

    /// Whether the account was met at `address` (folded).
    pub fn had(&self, address: &str) -> bool {
        self.addresses.iter().any(|known| same(known, address))
    }

    fn validate(&self) -> Result<()> {
        self.authority()?;
        if !rfc3339_utc(&self.since) {
            return Err(invalid("since is not an RFC 3339 UTC time"));
        }
        let incarnation = self.incarnation_id()?;
        let mut ids = std::collections::BTreeSet::new();
        if self.replaced.len() > MAX_REPLACED
            || !self
                .replaced
                .iter()
                .all(|id| is_lower_hex_32(id) && *id != incarnation && ids.insert(id.as_str()))
        {
            return Err(invalid("replaced identities are invalid"));
        }
        let mut folded = std::collections::BTreeSet::new();
        if self.addresses.len() > MAX_ADDRESSES
            || !self.addresses.iter().all(|address| {
                canonical_account(address).ok().as_deref() == Some(address.as_str())
                    && crate::names::fold_address(address).is_some_and(|f| folded.insert(f))
            })
        {
            return Err(invalid("addresses are invalid"));
        }
        if let Some(anchor) = &self.renames {
            if !(1..=account_rename::MAX_CHAIN as u64).contains(&anchor.sequence)
                || !is_lower_hex_32(&anchor.digest)
            {
                return Err(invalid("the rename anchor is invalid"));
            }
        }
        Ok(())
    }

    /// A pin for `account` at `authority` (canonical base64), with no history.
    fn fresh(account: &AccountRef, authority: &str, state: PinState, since: &str) -> Self {
        Self {
            account: account.clone(),
            authority_public_key: authority.to_owned(),
            state,
            since: since.to_owned(),
            replaced: Vec::new(),
            addresses: Vec::new(),
            renames: None,
            unknown: UnknownFields::new(),
        }
    }

    /// Notes `address` as the newest one the account was met at: moved to the
    /// end (in this spelling) if known, the oldest dropped past the cap.
    /// Whether anything changed.
    fn label(&mut self, address: &str) -> bool {
        if self.address() == Some(address) {
            return false;
        }
        self.addresses.retain(|known| !same(known, address));
        self.addresses.push(address.to_owned());
        let excess = self.addresses.len().saturating_sub(MAX_ADDRESSES);
        self.addresses.drain(..excess);
        true
    }
}

fn authority_bytes(value: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD.decode(value)?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|b: Vec<u8>| CryptoError::InvalidLength {
            expected: 32,
            got: b.len(),
        })?;
    if STANDARD.encode(key) != value {
        return Err(invalid("authority key is not canonical base64"));
    }
    Ok(key)
}

/// Whether two addresses are one name: equal once folded (a Kutup server
/// keeps one account per folded name), so `ada-l` typed today finds the
/// label saved as `ada_l`.
fn same(a: &str, b: &str) -> bool {
    a == b
        || matches!(
            (crate::names::fold_address(a), crate::names::fold_address(b)),
            (Some(a), Some(b)) if a == b
        )
}

/// The whole list: one pin per account, sorted by account.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPinsV2 {
    /// Sorted by account (server, then account id), one each.
    pub pins: Vec<IdentityPinV2>,
    /// The lowest [`READER_VERSION`] that may read this list; absent: 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_reader: Option<u32>,
    #[serde(flatten)]
    pub unknown: UnknownFields,
}

impl IdentityPinsV2 {
    pub fn validate(&self) -> Result<()> {
        if self.pins.len() > MAX_PINS {
            return Err(invalid("too many pins"));
        }
        match self.min_reader {
            None => {}
            Some(version) if version > READER_VERSION => {
                return Err(invalid(&format!(
                    "this identity list needs a newer app (reader version {version})"
                )))
            }
            // Present only to ask for more than version 1.
            Some(_) => return Err(invalid("minReader is not above 1")),
        }
        for pin in &self.pins {
            pin.validate()?;
        }
        if !self
            .pins
            .windows(2)
            .all(|pair| pair[0].account < pair[1].account)
        {
            return Err(invalid("pins must be sorted by account, one each"));
        }
        // An authority speaks for one account: the key binding and the
        // manifest sign the account id.
        let mut authorities = std::collections::BTreeSet::new();
        if !self
            .pins
            .iter()
            .all(|pin| authorities.insert(pin.authority_public_key.as_str()))
        {
            return Err(invalid("an authority is pinned for two accounts"));
        }
        Ok(())
    }

    /// The pin of `account`.
    pub fn get(&self, account: &AccountRef) -> Option<&IdentityPinV2> {
        self.position(account).ok().map(|i| &self.pins[i])
    }

    fn position(&self, account: &AccountRef) -> std::result::Result<usize, usize> {
        self.pins.binary_search_by(|pin| pin.account.cmp(account))
    }

    /// Every pin met at `address`, newest holder first (the one with the
    /// address as its newest label, then by `since`, newest first).
    pub fn at(&self, address: &str) -> Vec<&IdentityPinV2> {
        let mut found: Vec<&IdentityPinV2> =
            self.pins.iter().filter(|pin| pin.had(address)).collect();
        found.sort_by(|a, b| {
            let current = |pin: &IdentityPinV2| pin.address().is_some_and(|a| same(a, address));
            current(b)
                .cmp(&current(a))
                .then_with(|| b.since.cmp(&a.since))
        });
        found
    }
}

fn invalid(message: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("identity pins: {message}"))
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `YYYY-MM-DDTHH:MM:SSZ`, optionally with fractional seconds.
fn rfc3339_utc(value: &str) -> bool {
    let b = value.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        range
            .into_iter()
            .all(|i| b.get(i).is_some_and(u8::is_ascii_digit))
    };
    b.len() >= 20
        && b.len() <= 30
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && b[b.len() - 1] == b'Z'
        && (b.len() == 20 || (b[19] == b'.' && digits(20..b.len() - 1)))
}

/// A pin's `since` for a moment given in Unix seconds (UTC, whole seconds).
pub fn since_from_unix(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

// --- what apps do with the list ----------------------------------------------
// The same rules for every app (web through WASM, the CLI, Chat core), so a pin
// one app writes is never undone or misread by another.

/// What a client learned about an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PinUpdate {
    /// Met with a valid binding: pinned only if the account is not pinned
    /// yet and nobody else the list knows was met at the address (trust on
    /// first use). Never replaces an authority; notes the address.
    FirstSeen,
    /// The user accepted the authority now published: it replaces another
    /// one (`seen`), or pins an account met at an address someone else had.
    Accepted,
    /// Compared in person: `verified`, replacing another authority if need be.
    Verified,
}

/// What [`record`] did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Recorded {
    /// The list changed.
    Updated,
    /// Nothing to change (for `FirstSeen`, also: another authority than the
    /// pinned one, which [`lookup`] reports as a change).
    Unchanged,
    /// Not pinned: accounts the user knew were met at this address before,
    /// and this is another one ("not the person you verified"). The user may
    /// accept it explicitly ([`PinUpdate::Accepted`]).
    AddressHadOthers { pins: Vec<IdentityPinV2> },
    /// Refused: this authority is pinned for another account. An authority
    /// signs one account id, so this is a server handing out someone else's
    /// keys under this account; nothing is changed.
    AuthorityElsewhere { pin: Box<IdentityPinV2> },
}

/// Records `update` about `account`, met at `address` (when known) with
/// `authority` (canonical base64), at time `since`; see [`Recorded`]. A pin
/// that is replaced keeps its earlier incarnation in `replaced`.
pub fn record(
    list: &mut IdentityPinsV2,
    account: &AccountRef,
    address: Option<&str>,
    authority: &str,
    update: PinUpdate,
    since: &str,
) -> Result<Recorded> {
    let mut candidate = IdentityPinV2::fresh(account, authority, PinState::Seen, since);
    if let Some(address) = address {
        candidate.label(address);
    }
    candidate.validate()?;
    if let Some(other) = list
        .pins
        .iter()
        .find(|pin| pin.authority_public_key == authority && pin.account != *account)
    {
        return Ok(Recorded::AuthorityElsewhere {
            pin: Box::new(other.clone()),
        });
    }
    let before = list.clone();
    let result = record_checked(list, candidate, account, address, authority, update, since);
    if result.is_err() || list.validate().is_err() {
        let error = result
            .err()
            .unwrap_or_else(|| invalid("the list would be invalid"));
        *list = before;
        return Err(error);
    }
    result
}

fn record_checked(
    list: &mut IdentityPinsV2,
    mut candidate: IdentityPinV2,
    account: &AccountRef,
    address: Option<&str>,
    authority: &str,
    update: PinUpdate,
    since: &str,
) -> Result<Recorded> {
    let state = match update {
        PinUpdate::Verified => PinState::Verified,
        PinUpdate::FirstSeen | PinUpdate::Accepted => PinState::Seen,
    };
    match list.position(account) {
        Ok(i) => {
            let pin = &mut list.pins[i];
            let mut changed = address.is_some_and(|address| pin.label(address));
            if pin.authority_public_key == authority {
                if update == PinUpdate::Verified && pin.state != PinState::Verified {
                    pin.state = PinState::Verified;
                    pin.since = since.to_owned();
                    changed = true;
                }
            } else if update != PinUpdate::FirstSeen {
                // A new authority for the same person, accepted or verified:
                // the old one goes into the history. Its rename anchor was
                // signed by the old authority and goes with it.
                let previous = pin.incarnation_id()?;
                pin.replaced
                    .retain(|id| *id != candidate.incarnation_id().unwrap_or_default());
                pin.replaced.push(previous);
                let excess = pin.replaced.len().saturating_sub(MAX_REPLACED);
                pin.replaced.drain(..excess);
                pin.authority_public_key = authority.to_owned();
                pin.state = state;
                pin.since = since.to_owned();
                pin.renames = None;
                changed = true;
            }
            Ok(if changed {
                Recorded::Updated
            } else {
                Recorded::Unchanged
            })
        }
        Err(at) => {
            if update == PinUpdate::FirstSeen {
                if let Some(address) = address {
                    let others: Vec<IdentityPinV2> =
                        list.at(address).into_iter().cloned().collect();
                    if !others.is_empty() {
                        return Ok(Recorded::AddressHadOthers { pins: others });
                    }
                }
            }
            candidate.state = state;
            list.pins.insert(at, candidate);
            Ok(Recorded::Updated)
        }
    }
}

/// What the list says about an account met at an address, given the
/// authority published for it now (`None`: it could not be looked up).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum PinMatch {
    /// The account is pinned.
    Pinned {
        pin: Box<IdentityPinV2>,
        /// Whether it is the authority published now. If not, the safety
        /// number changed.
        same_authority: bool,
        /// The published authority is one this account had before, which the
        /// user replaced: an old key handed out again.
        earlier_authority: bool,
    },
    /// The account is not pinned, but accounts the list knows were met at
    /// the address (newest holder first): whoever has it now is someone else.
    SomeoneElse { pins: Vec<IdentityPinV2> },
    /// Nothing known.
    New,
}

/// What the list says about `account`, met at `address` (when the caller
/// came by an address) with `published` authority; see [`PinMatch`].
pub fn lookup(
    list: &IdentityPinsV2,
    account: &AccountRef,
    address: Option<&str>,
    published: Option<&str>,
) -> PinMatch {
    if let Some(pin) = list.get(account) {
        let earlier = published
            .and_then(|key| authority_bytes(key).ok())
            .map(|key| incarnation_id_from_authority_public(&key))
            .is_some_and(|id| pin.replaced.contains(&id));
        return PinMatch::Pinned {
            pin: Box::new(pin.clone()),
            same_authority: published == Some(pin.authority_public_key.as_str()),
            earlier_authority: earlier,
        };
    }
    let others: Vec<IdentityPinV2> = address
        .map(|address| list.at(address).into_iter().cloned().collect())
        .unwrap_or_default();
    if others.is_empty() {
        PinMatch::New
    } else {
        PinMatch::SomeoneElse { pins: others }
    }
}

/// What [`apply_rename`] did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameApplied {
    /// The pin's newest address before.
    pub from: Option<String>,
    /// The chain's current address, now the pin's newest.
    pub to: String,
    /// Whether the list changed (false: this chain was already applied).
    pub changed: bool,
}

/// Follows a verified rename chain of `account`, signed by its pinned
/// authority: every address in it becomes a label (the current one newest),
/// and the chain's head becomes the anchor. Refuses a chain by another
/// authority than the pinned one, or one that does not extend the anchor the
/// pin holds (a rollback or a fork). Idempotent. Trust is untouched: a rename
/// changes nothing about who the account is.
pub fn apply_rename(
    list: &mut IdentityPinsV2,
    account: &AccountRef,
    chain: &[AccountRenameV1],
) -> Result<RenameApplied> {
    let i = list
        .position(account)
        .map_err(|_| invalid("no pin for this account"))?;
    let authority = list.pins[i].authority()?;
    let view = account_rename::verify_chain(&authority, chain)?;
    if let Some(anchor) = &list.pins[i].renames {
        let held = anchor
            .sequence
            .checked_sub(1)
            .and_then(|at| view.digests.get(at as usize))
            .map(hex::encode);
        if held.as_deref() != Some(anchor.digest.as_str()) {
            return Err(invalid("the rename chain does not extend the one pinned"));
        }
    }
    let before = list.clone();
    let pin = &mut list.pins[i];
    let from = pin.address().map(str::to_owned);
    // Oldest first, so the newest address ends last; addresses the pin knew
    // from elsewhere and the chain does not name stay, older.
    let mut addresses: Vec<String> = pin
        .addresses
        .iter()
        .filter(|known| !view.addresses.iter().any(|a| same(a, known)))
        .cloned()
        .collect();
    for address in &view.addresses {
        addresses.retain(|known| !same(known, address));
        addresses.push(address.clone());
    }
    let excess = addresses.len().saturating_sub(MAX_ADDRESSES);
    addresses.drain(..excess);
    pin.addresses = addresses;
    pin.renames = Some(RenameAnchorV1 {
        sequence: view.sequence,
        digest: hex::encode(view.digests.last().expect("a verified chain is not empty")),
        unknown: pin
            .renames
            .as_ref()
            .filter(|anchor| anchor.sequence == view.sequence)
            .map(|anchor| anchor.unknown.clone())
            .unwrap_or_default(),
    });
    if let Err(error) = list.validate() {
        *list = before;
        return Err(error);
    }
    Ok(RenameApplied {
        from,
        to: view.current,
        changed: *list != before,
    })
}

/// The list's canonical bytes.
pub fn encode(list: &IdentityPinsV2) -> Result<Vec<u8>> {
    list.validate()?;
    let bytes = serde_json::to_vec(list).map_err(|_| invalid("encode"))?;
    if bytes.len() > MAX_LIST_BYTES {
        return Err(invalid("the list is too large"));
    }
    Ok(bytes)
}

/// A list from its canonical bytes only.
pub fn decode(bytes: &[u8]) -> Result<IdentityPinsV2> {
    if bytes.len() > MAX_LIST_BYTES {
        return Err(invalid("the list is too large"));
    }
    let list: IdentityPinsV2 = serde_json::from_slice(bytes).map_err(|_| invalid("decode"))?;
    if encode(&list)? != bytes {
        return Err(invalid("the list is not canonical"));
    }
    Ok(list)
}

/// The account's pins key, derived from the master key.
pub fn derive_key(master_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(PINS_KEY_SALT), master_key)
        .expand(PINS_KEY_INFO, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("identity pins key HKDF expand".into()))?;
    Ok(key)
}

fn aad(binding: &str, revision: u64) -> Result<Vec<u8>> {
    let binding = key_binding::check(binding).map_err(|_| invalid("owner binding is invalid"))?;
    let mut aad = Vec::with_capacity(MAGIC.len() + 2 + AAD_DOMAIN.len() + 2 + binding.len() + 8);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&SUITE.to_be_bytes());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&(binding.len() as u16).to_be_bytes());
    aad.extend_from_slice(binding.as_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    Ok(aad)
}

/// Seals the list of the account whose key binding is `owner` at
/// `revision`: `magic ‖ suite ‖ revision ‖ nonce ‖ ciphertext`.
pub fn seal(key: &[u8; 32], owner: &str, revision: u64, list: &IdentityPinsV2) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_with_nonce(key, owner, revision, list, &nonce)
}

/// [`seal`] with a fixed nonce, for checked-in vectors only.
pub fn seal_with_nonce(
    key: &[u8; 32],
    owner: &str,
    revision: u64,
    list: &IdentityPinsV2,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    if revision == 0 {
        return Err(invalid("revisions start at 1"));
    }
    let plain = Zeroizing::new(PADDING.pad(&encode(list)?)?);
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &plain,
                aad: &aad(owner, revision)?,
            },
        )
        .map_err(|_| CryptoError::Backend("identity pins seal".into()))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&SUITE.to_be_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens the list of the account whose key binding is `owner`: the list and
/// the revision it was sealed at (refuse one older than seen).
pub fn open(key: &[u8; 32], owner: &str, sealed: &[u8]) -> Result<(IdentityPinsV2, u64)> {
    let revision = inspect(sealed)?;
    let plain = XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(&sealed[10 + REVISION_LEN..HEADER_LEN]),
            Payload {
                msg: &sealed[HEADER_LEN..],
                aad: &aad(owner, revision)?,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::AuthFailed)?;
    let plain = Zeroizing::new(PADDING.unpad(plain.to_vec())?);
    Ok((decode(&plain)?, revision))
}

/// Checks a sealed list's framing, size and revision without opening it (the
/// server's view), and returns the revision.
pub fn inspect(sealed: &[u8]) -> Result<u64> {
    if sealed.len() <= HEADER_LEN + TAG_LEN
        || sealed.len() > MAX_SEALED_BYTES
        || !PADDING.allows_padded_len(sealed.len() - HEADER_LEN - TAG_LEN)
    {
        return Err(invalid("size is invalid"));
    }
    if &sealed[..MAGIC.len()] != MAGIC || sealed[8..10] != SUITE.to_be_bytes() {
        return Err(invalid("not an identity pin list"));
    }
    let revision = u64::from_be_bytes(sealed[10..10 + REVISION_LEN].try_into().expect("8"));
    if revision == 0 {
        return Err(invalid("revisions start at 1"));
    }
    Ok(revision)
}

/// The largest sealed list.
pub const MAX_SEALED_BYTES: usize = HEADER_LEN + MAX_LIST_BYTES + 256 + TAG_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AccountIdentityKeysV1;

    const OWNER: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
    const OTHER: &str = "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d";
    const T: i64 = 1_790_000_000_000;
    const NOW: &str = "2026-10-13T12:00:00Z";
    const LATER: &str = "2026-10-14T12:00:00Z";

    /// Account `n` on kutup.dev.
    fn acct(n: u8) -> AccountRef {
        AccountRef::new(
            "kutup.dev",
            &format!("00000000-0000-4000-8000-0000000000{n:02x}"),
        )
        .unwrap()
    }

    fn identity(seed: u8) -> AccountIdentityKeysV1 {
        AccountIdentityKeysV1::derive(&[seed; 32]).unwrap()
    }

    fn authority(seed: u8) -> String {
        STANDARD.encode(identity(seed).authority_public_key())
    }

    fn pin(n: u8, seed: u8, address: &str) -> IdentityPinV2 {
        let mut pin = IdentityPinV2::fresh(&acct(n), &authority(seed), PinState::Seen, NOW);
        pin.label(address);
        pin
    }

    fn list() -> IdentityPinsV2 {
        let mut bob = pin(2, 2, "bob@kutup.dev");
        bob.state = PinState::Verified;
        bob.replaced = vec![identity(9).incarnation_id()];
        IdentityPinsV2 {
            pins: vec![pin(1, 1, "alice@kutup.dev"), bob],
            ..Default::default()
        }
    }

    fn renames(seed: u8, addresses: &[&str]) -> Vec<AccountRenameV1> {
        let id = identity(seed);
        addresses
            .windows(2)
            .enumerate()
            .map(|(i, pair)| {
                account_rename::sign(&id, i as u64 + 1, pair[0], pair[1], T + i as i64).unwrap()
            })
            .collect()
    }

    fn rec(
        list: &mut IdentityPinsV2,
        n: u8,
        address: &str,
        seed: u8,
        update: PinUpdate,
    ) -> Recorded {
        record(list, &acct(n), Some(address), &authority(seed), update, NOW).unwrap()
    }

    #[test]
    fn a_list_round_trips_under_its_owner_and_revision() {
        let key = derive_key(&[7u8; 32]).unwrap();
        let sealed = seal(&key, OWNER, 3, &list()).unwrap();
        assert_eq!(open(&key, OWNER, &sealed).unwrap(), (list(), 3));
        assert_eq!(inspect(&sealed).unwrap(), 3);
        // Relabelled as another revision, or another account's: refused.
        let mut relabelled = sealed.clone();
        relabelled[10..18].copy_from_slice(&4u64.to_be_bytes());
        assert!(matches!(
            open(&key, OWNER, &relabelled),
            Err(CryptoError::AuthFailed)
        ));
        assert!(matches!(
            open(&key, OTHER, &sealed),
            Err(CryptoError::AuthFailed)
        ));
        // A name is not a key binding: refused before anything is opened.
        assert!(open(&key, "owner@kutup.dev", &sealed).is_err());
        assert!(seal(&key, "owner@kutup.dev", 3, &list()).is_err());
        // Earlier suites are not read.
        for (magic, suite) in [(b"KUTIP1\0\0", 1u16), (b"KUTIP2\0\0", 2)] {
            let mut old = sealed.clone();
            old[..8].copy_from_slice(magic);
            old[8..10].copy_from_slice(&suite.to_be_bytes());
            assert!(inspect(&old).is_err());
        }
        assert!(open(&derive_key(&[8u8; 32]).unwrap(), OWNER, &sealed).is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&key, OWNER, &tampered).is_err());
        let mut zero = sealed.clone();
        zero[10..18].copy_from_slice(&0u64.to_be_bytes());
        assert!(inspect(&zero).is_err());
        assert!(seal(&key, OWNER, 0, &list()).is_err());
    }

    #[test]
    fn since_is_rfc3339_utc() {
        assert_eq!(since_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(since_from_unix(1_791_633_600), "2026-10-10T12:00:00Z");
        assert_eq!(since_from_unix(951_782_400), "2000-02-29T00:00:00Z");
        assert!(rfc3339_utc(&since_from_unix(4_102_444_799)));
    }

    #[test]
    fn only_canonical_lists_are_accepted() {
        let mut unsorted = list();
        unsorted.pins.reverse();
        assert!(encode(&unsorted).is_err());
        let mut twice = list();
        twice.pins.push(pin(2, 3, "bob@kutup.dev"));
        assert!(encode(&twice).is_err());
        let mut shared_authority = list();
        shared_authority.pins[1].authority_public_key = authority(1);
        shared_authority.pins[1].replaced.clear();
        assert!(encode(&shared_authority).is_err());
        let mut bad_time = list();
        bad_time.pins[0].since = "yesterday".into();
        assert!(encode(&bad_time).is_err());
        let mut bad_key = list();
        bad_key.pins[0].authority_public_key = "AAAA".into();
        assert!(encode(&bad_key).is_err());
        let bytes = encode(&list()).unwrap();
        assert_eq!(decode(&bytes).unwrap(), list());
        let spaced = String::from_utf8(bytes).unwrap().replace("\":", "\": ");
        assert!(decode(spaced.as_bytes()).is_err());
    }

    #[test]
    fn addresses_are_labels_checked_and_capped() {
        let mut p = pin(1, 1, "alice@kutup.dev");
        for (bad, why) in [
            (vec!["alice@kutup.dev", "alice@kutup.dev"], "twice"),
            (vec!["alice@kutup.dev", "a.lice@kutup.dev"], "twice folded"),
            (vec!["Alice@kutup.dev"], "not canonical"),
            (vec!["alice"], "no server"),
        ] {
            p.addresses = bad.into_iter().map(String::from).collect();
            assert!(p.validate().is_err(), "{why}");
        }
        // Newest last; met again under a known name moves it to the end in
        // the new spelling; the oldest go past the cap.
        let mut p = pin(1, 1, "alice@kutup.dev");
        assert!(p.label("alicia@kutup.dev"));
        assert!(!p.label("alicia@kutup.dev"));
        assert!(p.label("a_lice@kutup.dev"));
        assert_eq!(p.addresses, ["alicia@kutup.dev", "a_lice@kutup.dev"]);
        for i in 0..MAX_ADDRESSES + 3 {
            p.label(&format!("n{i}@kutup.dev"));
        }
        assert_eq!(p.addresses.len(), MAX_ADDRESSES);
        assert_eq!(
            p.address(),
            Some(format!("n{}@kutup.dev", MAX_ADDRESSES + 2).as_str())
        );
        assert!(p.validate().is_ok());
    }

    #[test]
    fn record_follows_one_rule_for_every_app() {
        let mut list = IdentityPinsV2::default();
        // First met: pinned with the address; met again under another
        // authority: not replaced (the caller's lookup says it changed).
        assert_eq!(
            rec(&mut list, 2, "bob@kutup.dev", 2, PinUpdate::FirstSeen),
            Recorded::Updated
        );
        assert_eq!(
            rec(&mut list, 2, "bob@kutup.dev", 3, PinUpdate::FirstSeen),
            Recorded::Unchanged
        );
        assert_eq!(list.pins[0].authority_public_key, authority(2));
        assert_eq!(list.pins[0].addresses, ["bob@kutup.dev"]);
        // Verified in person.
        assert_eq!(
            rec(&mut list, 2, "bob@kutup.dev", 2, PinUpdate::Verified),
            Recorded::Updated
        );
        assert_eq!(list.pins[0].state, PinState::Verified);
        assert_eq!(
            rec(&mut list, 2, "bob@kutup.dev", 2, PinUpdate::Verified),
            Recorded::Unchanged
        );
        assert_eq!(
            rec(&mut list, 2, "bob@kutup.dev", 2, PinUpdate::Accepted),
            Recorded::Unchanged
        );
        // Met under a new name (renamed): the same pin, a new label, trust kept.
        assert_eq!(
            rec(&mut list, 2, "robert@kutup.dev", 2, PinUpdate::FirstSeen),
            Recorded::Updated
        );
        assert_eq!(list.pins.len(), 1);
        assert_eq!(list.pins[0].state, PinState::Verified);
        assert_eq!(
            list.pins[0].addresses,
            ["bob@kutup.dev", "robert@kutup.dev"]
        );
        // Another authority accepted (an administrator's reset): `seen`, the
        // old incarnation in the history, the labels kept.
        list.pins[0].renames = Some(RenameAnchorV1 {
            sequence: 1,
            digest: "ab".repeat(32),
            unknown: UnknownFields::new(),
        });
        assert_eq!(
            record(
                &mut list,
                &acct(2),
                None,
                &authority(3),
                PinUpdate::Accepted,
                LATER
            )
            .unwrap(),
            Recorded::Updated
        );
        let p = &list.pins[0];
        assert_eq!(
            (p.state, p.authority_public_key.as_str(), p.since.as_str()),
            (PinState::Seen, authority(3).as_str(), LATER)
        );
        assert_eq!(p.replaced, [identity(2).incarnation_id()]);
        assert_eq!(p.addresses, ["bob@kutup.dev", "robert@kutup.dev"]);
        assert!(
            p.renames.is_none(),
            "the old authority's anchor goes with it"
        );
        // Back to the first authority, verified: it leaves the history.
        rec(&mut list, 2, "robert@kutup.dev", 2, PinUpdate::Verified);
        assert_eq!(list.pins[0].replaced, [identity(3).incarnation_id()]);
        // Sorted by account; a bad authority or time is refused, the list kept.
        rec(&mut list, 1, "alice@kutup.dev", 1, PinUpdate::FirstSeen);
        assert_eq!(list.pins[0].account, acct(1));
        let before = list.clone();
        assert!(record(&mut list, &acct(4), None, "AAAA", PinUpdate::FirstSeen, NOW).is_err());
        assert!(record(
            &mut list,
            &acct(4),
            None,
            &authority(4),
            PinUpdate::FirstSeen,
            "now"
        )
        .is_err());
        assert!(record(
            &mut list,
            &acct(4),
            Some("Carol@kutup.dev"),
            &authority(4),
            PinUpdate::FirstSeen,
            NOW
        )
        .is_err());
        assert_eq!(list, before);
    }

    #[test]
    fn replaced_history_is_capped_oldest_first() {
        let mut list = IdentityPinsV2::default();
        rec(&mut list, 1, "a@kutup.dev", 100, PinUpdate::FirstSeen);
        for seed in 101..101 + MAX_REPLACED as u8 + 2 {
            rec(&mut list, 1, "a@kutup.dev", seed, PinUpdate::Accepted);
        }
        let p = &list.pins[0];
        assert_eq!(p.replaced.len(), MAX_REPLACED);
        assert_eq!(
            p.replaced.last().unwrap(),
            &identity(100 + MAX_REPLACED as u8 + 1).incarnation_id()
        );
        assert!(encode(&list).is_ok());
    }

    #[test]
    fn a_freed_name_taken_by_someone_else_is_someone_else() {
        // Alice, verified at alice@, renamed to alicia@; Mallory later takes
        // alice@ and is another account id.
        let mut list = IdentityPinsV2::default();
        rec(&mut list, 1, "alice@kutup.dev", 1, PinUpdate::Verified);
        rec(&mut list, 1, "alicia@kutup.dev", 1, PinUpdate::FirstSeen);
        let mallory = acct(6);
        match lookup(
            &list,
            &mallory,
            Some("alice@kutup.dev"),
            Some(&authority(6)),
        ) {
            PinMatch::SomeoneElse { pins } => {
                assert_eq!(pins.len(), 1);
                assert_eq!(pins[0].account, acct(1));
                assert_eq!(pins[0].address(), Some("alicia@kutup.dev"));
            }
            other => panic!("{other:?}"),
        }
        // First sight does not pin her; the user's explicit accept does.
        match rec(&mut list, 6, "alice@kutup.dev", 6, PinUpdate::FirstSeen) {
            Recorded::AddressHadOthers { pins } => assert_eq!(pins[0].account, acct(1)),
            other => panic!("{other:?}"),
        }
        assert_eq!(list.pins.len(), 1);
        assert_eq!(
            rec(&mut list, 6, "alice@kutup.dev", 6, PinUpdate::Accepted),
            Recorded::Updated
        );
        assert!(matches!(
            lookup(
                &list,
                &mallory,
                Some("alice@kutup.dev"),
                Some(&authority(6))
            ),
            PinMatch::Pinned {
                same_authority: true,
                ..
            }
        ));
        // Alice is untouched, still verified, and found by her account.
        let alice = list.get(&acct(1)).unwrap();
        assert_eq!(alice.state, PinState::Verified);
        // Both had alice@: Mallory, who has it as her newest name, first.
        let at: Vec<_> = list
            .at("alice@kutup.dev")
            .into_iter()
            .map(|p| p.account.clone())
            .collect();
        assert_eq!(at, [acct(6), acct(1)]);
        // Without an address (inbound, by the sender's account): no warning.
        assert_eq!(
            lookup(&list, &acct(7), None, Some(&authority(7))),
            PinMatch::New
        );
    }

    #[test]
    fn a_reset_is_a_change_of_the_same_account() {
        let mut list = IdentityPinsV2::default();
        rec(&mut list, 1, "alice@kutup.dev", 1, PinUpdate::Verified);
        assert_eq!(
            lookup(
                &list,
                &acct(1),
                Some("alice@kutup.dev"),
                Some(&authority(2))
            ),
            PinMatch::Pinned {
                pin: Box::new(list.pins[0].clone()),
                same_authority: false,
                earlier_authority: false
            }
        );
        rec(&mut list, 1, "alice@kutup.dev", 2, PinUpdate::Accepted);
        // The replaced key handed out again: a change, and an old one.
        match lookup(&list, &acct(1), None, Some(&authority(1))) {
            PinMatch::Pinned {
                same_authority: false,
                earlier_authority: true,
                ..
            } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_authority_speaks_for_one_account() {
        let mut list = IdentityPinsV2::default();
        rec(&mut list, 1, "alice@kutup.dev", 1, PinUpdate::FirstSeen);
        let before = list.clone();
        for update in [
            PinUpdate::FirstSeen,
            PinUpdate::Accepted,
            PinUpdate::Verified,
        ] {
            match rec(&mut list, 2, "eve@kutup.dev", 1, update) {
                Recorded::AuthorityElsewhere { pin } => assert_eq!(pin.account, acct(1)),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(list, before);
    }

    #[test]
    fn a_rename_chain_labels_the_pin_and_never_rolls_back() {
        let mut list = IdentityPinsV2::default();
        rec(&mut list, 1, "alice@kutup.dev", 1, PinUpdate::Verified);
        let chain = renames(1, &["alice@kutup.dev", "alicia@kutup.dev", "ali@kutup.dev"]);
        let applied = apply_rename(&mut list, &acct(1), &chain).unwrap();
        assert_eq!(
            applied,
            RenameApplied {
                from: Some("alice@kutup.dev".into()),
                to: "ali@kutup.dev".into(),
                changed: true
            }
        );
        let p = &list.pins[0];
        assert_eq!(
            p.addresses,
            ["alice@kutup.dev", "alicia@kutup.dev", "ali@kutup.dev"]
        );
        assert_eq!(p.state, PinState::Verified);
        assert_eq!(p.renames.as_ref().unwrap().sequence, 2);
        // Again: nothing changes. The first statement alone rolls one back.
        assert!(!apply_rename(&mut list, &acct(1), &chain).unwrap().changed);
        let before = list.clone();
        assert!(apply_rename(&mut list, &acct(1), &chain[..1]).is_err());
        // Another authority's chain, or one for an account not pinned: refused.
        let forged = renames(5, &["alice@kutup.dev", "ali@kutup.dev"]);
        assert!(apply_rename(&mut list, &acct(1), &forged).is_err());
        assert!(apply_rename(&mut list, &acct(3), &chain).is_err());
        assert_eq!(list, before);
        // A label met outside the chain stays, older than the chain's.
        let mut list = IdentityPinsV2::default();
        rec(&mut list, 1, "ali_ce@kutup.dev", 1, PinUpdate::FirstSeen);
        rec(&mut list, 1, "nick@kutup.dev", 1, PinUpdate::FirstSeen);
        apply_rename(&mut list, &acct(1), &chain).unwrap();
        assert_eq!(
            list.pins[0].addresses,
            [
                "nick@kutup.dev",
                "alice@kutup.dev",
                "alicia@kutup.dev",
                "ali@kutup.dev"
            ]
        );
    }

    #[test]
    fn later_fields_are_kept_and_newer_lists_refused() {
        let text = r#"{"pins":[{"account":{"server":"kutup.dev","accountId":"00000000-0000-4000-8000-000000000002"},"authorityPublicKey":"AUTH","state":"seen","since":"2026-10-10T12:00:00Z","nickname":"B","zone":1}],"later":true}"#
            .replace("AUTH", &authority(2));
        let mut list = decode(text.as_bytes()).unwrap();
        assert_eq!(list.pins[0].unknown["nickname"], "B");
        assert_eq!(String::from_utf8(encode(&list).unwrap()).unwrap(), text);
        // An app that updates the pin keeps what it does not know.
        rec(&mut list, 2, "bob@kutup.dev", 2, PinUpdate::Verified);
        assert_eq!(list.pins[0].unknown["zone"], 1);
        assert_eq!(list.unknown["later"], true);
        // Not in name order after the known fields: not canonical.
        let unordered = text.replace(r#""nickname":"B","zone":1"#, r#""zone":1,"nickname":"B""#);
        assert!(decode(unordered.as_bytes()).is_err());
        // The account is exactly two fields.
        let extra = text.replace(r#""accountId":"#, r#""x":1,"accountId":"#);
        assert!(decode(extra.as_bytes()).is_err());
        // A list for newer readers is refused, not misread.
        let error = decode(br#"{"pins":[],"minReader":2}"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("newer app"), "{error}");
        assert!(decode(br#"{"pins":[],"minReader":1}"#).is_err());
    }
}
