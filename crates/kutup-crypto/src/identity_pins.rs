//! Identity pins (docs/plans/drive-identity-pins.md): the accounts this
//! account has seen, by their authority, synced through the server.
//!
//! A client pins the authority of every account whose Drive keys it uses
//! (`drive_key_binding`): the first one seen is trusted (`seen`), one compared
//! in person is `verified`, and a different authority for the same address
//! later is a change the user is warned about until they accept it. One list
//! serves every app of the account and survives a new browser: it is sealed
//! with XChaCha20-Poly1305 under a key derived from the master key and stored
//! by the server, which can neither read nor rewrite it. The revision (a time
//! in unix milliseconds, above every revision seen) is in the header and
//! authenticated, so the server cannot relabel an old list as a new one;
//! clients also remember the highest revision they have seen.
//!
//! Suite 2 (`KUTIP2`) binds the owner's key binding (docs/plans/account-identity.md),
//! never its address, which may change; the pinned accounts inside the list
//! stay addresses, because those are what the pins are about. Suite 1 (bound
//! to the owner's address) is not read: nothing from before carries over.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::account_rename::{self, AccountRenameV1};
use crate::error::{CryptoError, Result};
use crate::identity::incarnation_id_from_authority_public;
use crate::key_binding;
use crate::named_share::canonical_account;
use crate::padding::Length;

const PINS_KEY_SALT: &[u8] = b"kutup/identity-pins/v1\0";
const PINS_KEY_INFO: &[u8] = b"kutup/identity-pins/list-key/v1\0";
const MAGIC: &[u8; 8] = b"KUTIP2\0\0";
const AAD_DOMAIN: &[u8] = b"kutup/identity-pins/v2\0";
const SUITE: u16 = 2;
const NONCE_LEN: usize = 24;
const REVISION_LEN: usize = 8;
const HEADER_LEN: usize = 8 + 2 + REVISION_LEN + NONCE_LEN;
const TAG_LEN: usize = 16;
/// How a list is padded before it is sealed: its length then tells only
/// roughly how many accounts it pins.
const PADDING: Length = Length::Bucket(256);

/// The most accounts one list keeps.
pub const MAX_PINS: usize = 10_000;
/// Earlier identities kept for one address (after accepted changes).
pub const MAX_REPLACED: usize = 10;
/// The most former addresses a pin remembers: the newest are kept. An address
/// dropped from the list loses its "moved" warning (a lookup of it is
/// [`PinMatch::New`] again); renames are at least days apart and holds expire,
/// so 32 covers any real account.
pub const MAX_FORMERLY: usize = 32;
/// The largest list, encoded.
pub const MAX_LIST_BYTES: usize = 4 * 1024 * 1024;

/// How far an account's authority is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PinState {
    /// The first authority seen for the address (trust on first use), or one
    /// the user accepted after a change.
    Seen,
    /// Compared in person (a safety number or QR code).
    Verified,
}

/// Fields a later version added, kept as they are: read past, written back
/// after the known fields in name order (the canonical rule for every field
/// added after V1), so an older app never strips a newer app's data.
pub type UnknownFields = std::collections::BTreeMap<String, serde_json::Value>;

/// One account's pinned authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPinV1 {
    /// Canonical `username@server`. For a pin in [`IdentityPinsV1::detached`],
    /// the last address it was known at.
    pub account: String,
    /// Canonical padded base64 of the 32-byte Ed25519 authority public key.
    pub authority_public_key: String,
    pub state: PinState,
    /// When it was first pinned or last accepted: RFC 3339, UTC.
    pub since: String,
    /// Incarnation ids this address had before, oldest first: changes the
    /// user accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaced: Vec<String>,
    /// Addresses this same incarnation had before `account`, oldest first: its
    /// renames (docs/plans/username-renames.md). A lookup of one of them that
    /// finds another authority there is "not the person you verified".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub formerly: Vec<String>,
    /// The newest rename statement verified for this incarnation: a later
    /// chain is accepted only if it holds this one at `sequence`, so no server
    /// can roll a rename back, on any device of the account. Present whenever
    /// `formerly` is not empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renames: Option<RenameAnchorV1>,
    /// Why a pin in [`IdentityPinsV1::detached`] left its address; absent on a
    /// live pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detached_by: Option<DetachReason>,
    #[serde(flatten)]
    pub unknown: UnknownFields,
}

/// Why a pin was pushed off its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DetachReason {
    /// A verified rename landed on its address: it left on its own, and comes
    /// back with its trust when met there again.
    Rename,
    /// The user accepted (or verified) another authority at its address. Its
    /// trust is revoked for good: wherever it turns up (any address, a rename
    /// chain of its own), it is warned about, and only the user's explicit
    /// accept (`seen`) or in-person verification brings it back.
    Replaced,
}

/// Where an incarnation's verified rename chain ended.
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

impl IdentityPinV1 {
    /// The authority's raw bytes.
    pub fn authority(&self) -> Result<[u8; 32]> {
        let bytes = STANDARD.decode(&self.authority_public_key)?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|b: Vec<u8>| CryptoError::InvalidLength {
                expected: 32,
                got: b.len(),
            })?;
        if STANDARD.encode(key) != self.authority_public_key {
            return Err(invalid("authority key is not canonical base64"));
        }
        Ok(key)
    }

    /// The account incarnation the pin stands for.
    pub fn incarnation_id(&self) -> Result<String> {
        Ok(incarnation_id_from_authority_public(&self.authority()?))
    }

    fn validate(&self) -> Result<()> {
        if canonical_account(&self.account).ok().as_deref() != Some(self.account.as_str()) {
            return Err(invalid("account is not canonical"));
        }
        self.authority()?;
        if !rfc3339_utc(&self.since) {
            return Err(invalid("since is not an RFC 3339 UTC time"));
        }
        if self.replaced.len() > MAX_REPLACED || !self.replaced.iter().all(|id| is_lower_hex_32(id))
        {
            return Err(invalid("replaced identities are invalid"));
        }
        let server = server_of(&self.account);
        let mut seen = std::collections::BTreeSet::new();
        if self.formerly.len() > MAX_FORMERLY
            || !self.formerly.iter().all(|address| {
                canonical_account(address).ok().as_deref() == Some(address.as_str())
                    && *address != self.account
                    && server_of(address) == server
                    && seen.insert(address.as_str())
            })
        {
            return Err(invalid("former addresses are invalid"));
        }
        // Former addresses come from a verified chain, so they need its anchor;
        // an anchor may stand alone (back at a name it had, accepted there).
        match &self.renames {
            None if self.formerly.is_empty() => {}
            Some(anchor)
                if (1..=account_rename::MAX_CHAIN as u64).contains(&anchor.sequence)
                    && is_lower_hex_32(&anchor.digest) => {}
            _ => return Err(invalid("the rename anchor is invalid")),
        }
        Ok(())
    }

    /// A pin for `account` at `authority` (canonical base64), with no history.
    fn fresh(account: &str, authority: &str, state: PinState, since: &str) -> Self {
        Self {
            account: account.to_owned(),
            authority_public_key: authority.to_owned(),
            state,
            since: since.to_owned(),
            replaced: Vec::new(),
            formerly: Vec::new(),
            renames: None,
            detached_by: None,
            unknown: UnknownFields::new(),
        }
    }

    /// Whether this incarnation is known to have had `address` before (its
    /// renames, or the address a detached pin was pushed off).
    fn had(&self, address: &str) -> bool {
        self.formerly.iter().any(|former| same(former, address))
    }
}

/// Whether two addresses are one account: equal once folded (a Kutup server
/// keeps one account per folded name), so `ada-l` typed today finds the pin
/// saved as `ada_l`. A pin keeps the spelling it was saved with.
fn same(a: &str, b: &str) -> bool {
    a == b
        || matches!(
            (crate::names::fold_address(a), crate::names::fold_address(b)),
            (Some(a), Some(b)) if a == b
        )
}

fn server_of(account: &str) -> &str {
    account.split_once('@').map_or("", |(_, server)| server)
}

/// The version of this format a reader understands. A writer that adds
/// something older readers would misread sets [`IdentityPinsV1::min_reader`]
/// above it, and those readers refuse the list ("needs a newer app") instead
/// of misreading it.
pub const READER_VERSION: u32 = 1;
/// The most detached pins a list keeps: past it, the oldest unverified go
/// first, then the oldest.
pub const MAX_DETACHED: usize = 256;
/// The most replaced identities remembered after their detached pin was
/// dropped past [`MAX_DETACHED`] (their incarnation ids only); the oldest go
/// first.
pub const MAX_REPLACED_IDS: usize = 4096;

/// The whole list: one pin per account at its current address, and the pins
/// pushed off their address (`detached`). An incarnation (an authority key)
/// appears at most once in the whole list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPinsV1 {
    /// Sorted by account, one each.
    pub pins: Vec<IdentityPinV1>,
    /// Pins of incarnations pushed off the address they were pinned at (a
    /// rename landed there, or the user accepted another authority there),
    /// where they are now unknown. They keep their trust and history, so a
    /// later rename chain or their return re-attaches them. Sorted by
    /// (account, authority).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detached: Vec<IdentityPinV1>,
    /// Incarnation ids of identities the user replaced whose detached pin was
    /// dropped (past [`MAX_DETACHED`]), oldest first: still warned about
    /// wherever they turn up, never pinned again on first sight.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaced_ids: Vec<String>,
    /// The lowest [`READER_VERSION`] that may read this list; absent: 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_reader: Option<u32>,
    #[serde(flatten)]
    pub unknown: UnknownFields,
}

impl IdentityPinsV1 {
    pub fn validate(&self) -> Result<()> {
        if self.pins.len() + self.detached.len() > MAX_PINS || self.detached.len() > MAX_DETACHED {
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
        for pin in self.pins.iter().chain(&self.detached) {
            pin.validate()?;
        }
        if self.pins.iter().any(|pin| pin.detached_by.is_some())
            || self.detached.iter().any(|pin| pin.detached_by.is_none())
        {
            return Err(invalid("detachedBy is set exactly on detached pins"));
        }
        if !self
            .pins
            .windows(2)
            .all(|pair| pair[0].account < pair[1].account)
        {
            return Err(invalid("pins must be sorted by account, one each"));
        }
        if !self.detached.windows(2).all(|pair| {
            (&pair[0].account, &pair[0].authority_public_key)
                < (&pair[1].account, &pair[1].authority_public_key)
        }) {
            return Err(invalid(
                "detached pins must be sorted by account and authority",
            ));
        }
        let mut authorities = std::collections::BTreeSet::new();
        if !self
            .pins
            .iter()
            .chain(&self.detached)
            .all(|pin| authorities.insert(pin.authority_public_key.as_str()))
        {
            return Err(invalid("an account is pinned more than once"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for pin in self.pins.iter().chain(&self.detached) {
            ids.insert(pin.incarnation_id()?);
        }
        if self.replaced_ids.len() > MAX_REPLACED_IDS
            || !self
                .replaced_ids
                .iter()
                .all(|id| is_lower_hex_32(id) && ids.insert(id.clone()))
        {
            return Err(invalid("replaced identities are invalid or pinned too"));
        }
        Ok(())
    }

    /// The entry for `authority`, live or detached: `(detached, index)`.
    fn find_authority(&self, authority: &str) -> Option<(bool, usize)> {
        if let Some(i) = self
            .pins
            .iter()
            .position(|pin| pin.authority_public_key == authority)
        {
            return Some((false, i));
        }
        self.detached
            .iter()
            .position(|pin| pin.authority_public_key == authority)
            .map(|i| (true, i))
    }

    fn take(&mut self, (detached, index): (bool, usize)) -> IdentityPinV1 {
        if detached {
            let mut pin = self.detached.remove(index);
            pin.detached_by = None;
            pin
        } else {
            self.pins.remove(index)
        }
    }

    fn insert(&mut self, pin: IdentityPinV1) {
        let at = self
            .pins
            .binary_search_by(|p| p.account.as_str().cmp(&pin.account))
            .unwrap_or_else(|at| at);
        self.pins.insert(at, pin);
    }

    /// Moves a pin off its address into `detached`, keeping it whole; drops
    /// the oldest unverified detached pins (then the oldest) past the cap.
    fn detach(&mut self, mut pin: IdentityPinV1, reason: DetachReason) {
        pin.detached_by = Some(reason);
        // Replacing an identity revokes its trust for good: the usual reason
        // is a reset or a lost key, which is the key an attacker may hold.
        if reason == DetachReason::Replaced {
            pin.state = PinState::Seen;
        }
        let key = |p: &IdentityPinV1| (p.account.clone(), p.authority_public_key.clone());
        let at = self
            .detached
            .binary_search_by(|p| key(p).cmp(&key(&pin)))
            .unwrap_or_else(|at| at);
        self.detached.insert(at, pin);
        while self.detached.len() > MAX_DETACHED {
            let oldest = (0..self.detached.len())
                .min_by(|&a, &b| {
                    let rank = |p: &IdentityPinV1| (p.state == PinState::Verified, p.since.clone());
                    rank(&self.detached[a]).cmp(&rank(&self.detached[b]))
                })
                .expect("not empty");
            let dropped = self.detached.remove(oldest);
            // A replaced identity stays revoked: its incarnation is kept.
            if dropped.detached_by == Some(DetachReason::Replaced) {
                if let Ok(id) = dropped.incarnation_id() {
                    self.replaced_ids.retain(|known| *known != id);
                    self.replaced_ids.push(id);
                    let excess = self.replaced_ids.len().saturating_sub(MAX_REPLACED_IDS);
                    self.replaced_ids.drain(..excess);
                }
            }
        }
    }

    /// Whether `authority` is a replaced identity remembered only by its id.
    fn replaced_id(&self, authority: &str) -> Option<String> {
        let key: [u8; 32] = STANDARD.decode(authority).ok()?.try_into().ok()?;
        let id = incarnation_id_from_authority_public(&key);
        self.replaced_ids.contains(&id).then_some(id)
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
    /// Met with a valid binding: pinned only if nothing is known of the
    /// address or the account yet (trust on first use). Never replaces a pin.
    FirstSeen,
    /// The user accepted the authority now published (after a change): it
    /// replaces another one, `seen`.
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
    Pinned,
    /// Nothing to change.
    Unchanged,
    /// Not pinned: an account the user knew had this address before, and
    /// this is another one ("not the person you verified"). The user may
    /// accept it explicitly ([`PinUpdate::Accepted`]).
    FormerAddressTaken { pins: Vec<MovedPin> },
    /// Not pinned again: this account is already pinned under another
    /// address (`pin.account`, or detached). Follow its rename chain
    /// ([`apply_rename`]) to move it; an account is never pinned twice. A
    /// `verified` update still marks that pin verified (the list changes).
    KnownElsewhere { pin: IdentityPinV1 },
    /// Not pinned: an identity the user replaced (its trust revoked), turning
    /// up again, at this address or another. Warned about like a change; the
    /// user may accept it (`seen`) or verify it in person.
    ReplacedIdentity {
        /// Its detached pin (absent once only its id is remembered).
        pin: Option<IdentityPinV1>,
        incarnation_id: String,
    },
}

/// Records `update` about `account` at `authority` (canonical base64) at time
/// `since`; see [`Recorded`]. Whether the list changed is whether it differs
/// from before. A pin of the same authority keeps its history; a
/// pin of another authority that is replaced is detached, not lost, so its
/// trust follows it if it turns up elsewhere.
pub fn record(
    list: &mut IdentityPinsV1,
    account: &str,
    authority: &str,
    update: PinUpdate,
    since: &str,
) -> Result<Recorded> {
    let candidate = IdentityPinV1::fresh(account, authority, PinState::Seen, since);
    candidate.validate()?;
    let state = match update {
        PinUpdate::Verified => PinState::Verified,
        PinUpdate::FirstSeen | PinUpdate::Accepted => PinState::Seen,
    };
    let live = list.pins.iter().position(|pin| same(&pin.account, account));
    if let Some(i) = live {
        let pin = &mut list.pins[i];
        if pin.authority_public_key == authority {
            if update == PinUpdate::Verified && pin.state != PinState::Verified {
                pin.state = PinState::Verified;
                pin.since = since.to_owned();
                return Ok(Recorded::Pinned);
            }
            return Ok(Recorded::Unchanged);
        }
        if update == PinUpdate::FirstSeen {
            // Another authority than the pinned one: the caller warns.
            return Ok(Recorded::Unchanged);
        }
    }
    let known = list.find_authority(authority);
    let mut trusted_back = true;
    match known {
        // An identity the user replaced, wherever it turns up: warned about;
        // only the user's explicit accept or verification pins it again, and
        // then only as that act says.
        Some((true, j)) if list.detached[j].detached_by == Some(DetachReason::Replaced) => {
            if update == PinUpdate::FirstSeen {
                return Ok(Recorded::ReplacedIdentity {
                    incarnation_id: list.detached[j].incarnation_id()?,
                    pin: Some(list.detached[j].clone()),
                });
            }
            trusted_back = false;
        }
        // The same account, pushed off this very address by a rename, is met
        // there again: back as it was.
        Some((true, j)) if same(&list.detached[j].account, account) => {}
        Some((detached, j)) => {
            let pin = if detached {
                &mut list.detached[j]
            } else {
                &mut list.pins[j]
            };
            // Compared in person: the account is verified wherever it is pinned.
            if update == PinUpdate::Verified && pin.state != PinState::Verified {
                pin.state = PinState::Verified;
                pin.since = since.to_owned();
            }
            return Ok(Recorded::KnownElsewhere { pin: pin.clone() });
        }
        // Replaced long ago, remembered by its id only.
        None if list.replaced_id(authority).is_some() => {
            let id = list.replaced_id(authority).expect("checked");
            if update == PinUpdate::FirstSeen {
                return Ok(Recorded::ReplacedIdentity {
                    pin: None,
                    incarnation_id: id,
                });
            }
            list.replaced_ids.retain(|known| *known != id);
            trusted_back = false;
        }
        None if live.is_none() && update == PinUpdate::FirstSeen => {
            let pins = moved_from(list, account);
            if !pins.is_empty() {
                return Ok(Recorded::FormerAddressTaken { pins });
            }
        }
        None => {}
    }
    // Pin it: the returning detached pin with its history, or a fresh one.
    let before = list.clone();
    let result = pin_now(list, known, candidate, account, state, since, trusted_back);
    if result.is_err() {
        *list = before;
    }
    result
}

fn pin_now(
    list: &mut IdentityPinsV1,
    known: Option<(bool, usize)>,
    candidate: IdentityPinV1,
    account: &str,
    state: PinState,
    since: &str,
    trusted_back: bool,
) -> Result<Recorded> {
    let mut pin = match known {
        Some(entry) => list.take(entry),
        None => candidate,
    };
    pin.account = account.to_owned();
    // A replaced identity accepted again starts afresh: its old addresses and
    // rename anchor belonged to the trust that was revoked.
    if !trusted_back {
        pin.formerly.clear();
        pin.renames = None;
    }
    pin.formerly.retain(|former| !same(former, account));
    if state == PinState::Verified || !trusted_back {
        pin.state = state;
        pin.since = since.to_owned();
    }
    if let Some(i) = list.pins.iter().position(|p| same(&p.account, account)) {
        let previous = list.pins.remove(i);
        let mut replaced = previous.replaced.clone();
        replaced.push(previous.incarnation_id()?);
        let excess = replaced.len().saturating_sub(MAX_REPLACED);
        replaced.drain(..excess);
        pin.replaced = replaced;
        list.detach(previous, DetachReason::Replaced);
    }
    list.insert(pin);
    list.validate()?;
    Ok(Recorded::Pinned)
}

/// A pin that had an address before, and where it is now (`None`: detached,
/// not known).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MovedPin {
    pub pin: IdentityPinV1,
    pub now: Option<String>,
}

/// Every pin that had `address` before: live ones (renamed away) first, then
/// detached ones (last known there).
fn moved_from(list: &IdentityPinsV1, address: &str) -> Vec<MovedPin> {
    let live = list
        .pins
        .iter()
        .filter(|pin| pin.had(address))
        .map(|pin| MovedPin {
            pin: pin.clone(),
            now: Some(pin.account.clone()),
        });
    let detached = list
        .detached
        .iter()
        .filter(|pin| same(&pin.account, address) || pin.had(address))
        .map(|pin| MovedPin {
            pin: pin.clone(),
            now: None,
        });
    live.chain(detached).collect()
}

/// What the list says about an address, given the authority its server
/// publishes for it now (`None`: nobody, or it could not be looked up).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum PinMatch {
    /// A pin for the address itself.
    Pinned {
        pin: IdentityPinV1,
        /// Whether it is the authority published there now.
        same_authority: bool,
    },
    /// No pin for the address, but the authority published there is pinned
    /// under another address (or detached from another): this account was
    /// renamed. Fetch its rename chain and [`apply_rename`].
    Renamed { pin: IdentityPinV1 },
    /// The authority published there is a pin a rename pushed off this very
    /// address: it is back; [`record`] re-attaches it with its trust. (One the
    /// user replaced there is [`PinMatch::Moved`] instead.)
    Returned { pin: IdentityPinV1 },
    /// No pin for the address, but pinned accounts had it before; whoever is
    /// there now is someone else: "this is not the person you verified".
    Moved { pins: Vec<MovedPin> },
    /// The authority published there is one the user replaced (its trust
    /// revoked), at this address or another: warned about like a change.
    Replaced {
        /// Its detached pin (absent once only its id is remembered).
        pin: Option<IdentityPinV1>,
        incarnation_id: String,
    },
    /// Nothing known.
    New,
}

/// What the list says about `address`; see [`PinMatch`].
pub fn lookup(list: &IdentityPinsV1, address: &str, published: Option<&str>) -> PinMatch {
    if let Some(pin) = list.pins.iter().find(|pin| same(&pin.account, address)) {
        return PinMatch::Pinned {
            pin: pin.clone(),
            same_authority: published == Some(pin.authority_public_key.as_str()),
        };
    }
    if let Some(entry) = published.and_then(|published| list.find_authority(published)) {
        return match entry {
            (true, j) if list.detached[j].detached_by == Some(DetachReason::Replaced) => {
                PinMatch::Replaced {
                    incarnation_id: list.detached[j].incarnation_id().unwrap_or_default(),
                    pin: Some(list.detached[j].clone()),
                }
            }
            (true, j)
                if same(&list.detached[j].account, address)
                    && list.detached[j].detached_by == Some(DetachReason::Rename) =>
            {
                PinMatch::Returned {
                    pin: list.detached[j].clone(),
                }
            }
            // A former holder the user replaced, met at that address again.
            (true, j) if same(&list.detached[j].account, address) => PinMatch::Moved {
                pins: moved_from(list, address),
            },
            (true, j) => PinMatch::Renamed {
                pin: list.detached[j].clone(),
            },
            (false, j) => PinMatch::Renamed {
                pin: list.pins[j].clone(),
            },
        };
    }
    if let Some(id) = published.and_then(|published| list.replaced_id(published)) {
        return PinMatch::Replaced {
            pin: None,
            incarnation_id: id,
        };
    }
    let pins = moved_from(list, address);
    if pins.is_empty() {
        PinMatch::New
    } else {
        PinMatch::Moved { pins }
    }
}

/// What [`apply_rename`] did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameApplied {
    /// Where the pin was (an address in the chain; for a detached pin, the
    /// last one known).
    pub from: String,
    /// Where it is now: the chain's current address.
    pub to: String,
    /// Whether the list changed (false: this chain was already applied).
    pub changed: bool,
    /// Another incarnation pinned at `to` before: the address's previous
    /// holder, now detached (its trust kept, for when it turns up) and in the
    /// moved pin's `replaced` (which follows the address). The user is told
    /// that `to` is now the person they knew as `from`.
    pub displaced: Option<String>,
}

/// Follows a verified rename of the account whose authority is `authority`:
/// its pin (live or detached) moves to the chain's current address, keeping
/// its trust (the safety number did not change), with every earlier address
/// in `formerly` and the chain's head as its anchor. Refuses a chain that does
/// not verify against `authority`, does not hold the address the pin is at,
/// or does not extend the anchor the pin holds (a rollback or a fork).
/// Idempotent.
pub fn apply_rename(
    list: &mut IdentityPinsV1,
    authority: &[u8; 32],
    chain: &[AccountRenameV1],
) -> Result<RenameApplied> {
    let view = account_rename::verify_chain(authority, chain)?;
    let authority_b64 = STANDARD.encode(authority);
    let entry = list
        .find_authority(&authority_b64)
        .ok_or_else(|| invalid("no pin for this account"))?;
    let pin = if entry.0 {
        &list.detached[entry.1]
    } else {
        &list.pins[entry.1]
    };
    if !view.had(&pin.account) {
        return Err(invalid("the rename chain does not hold the pinned address"));
    }
    if let Some(anchor) = &pin.renames {
        let held = anchor
            .sequence
            .checked_sub(1)
            .and_then(|at| view.digests.get(at as usize))
            .map(hex::encode);
        if held.as_deref() != Some(anchor.digest.as_str()) {
            return Err(invalid("the rename chain does not extend the one pinned"));
        }
    }
    let from = pin.account.clone();
    let mut formerly: Vec<String> = Vec::new();
    for address in &view.addresses[..view.addresses.len() - 1] {
        if *address != view.current {
            formerly.retain(|known| !same(known, address));
            formerly.push(address.clone());
        }
    }
    let excess = formerly.len().saturating_sub(MAX_FORMERLY);
    formerly.drain(..excess);
    let head = RenameAnchorV1 {
        sequence: view.sequence,
        digest: hex::encode(view.digests.last().expect("a verified chain is not empty")),
        unknown: pin
            .renames
            .as_ref()
            .filter(|anchor| anchor.sequence == view.sequence)
            .map(|anchor| anchor.unknown.clone())
            .unwrap_or_default(),
    };

    let before = list.clone();
    let replaced_identity =
        entry.0 && list.detached[entry.1].detached_by == Some(DetachReason::Replaced);
    let mut moved = list.take(entry);
    let restore = |list: &mut IdentityPinsV1, error| {
        *list = before.clone();
        error
    };
    let changed_address = !same(&moved.account, &view.current) || entry.0;
    moved.account = view.current.clone();
    moved.formerly = formerly;
    moved.renames = Some(head);
    // `replaced` is the history of an address: the pin now stands at the new
    // one, whose history is its previous holder's, if it had one.
    if changed_address && from != view.current {
        moved.replaced = Vec::new();
    }
    if replaced_identity {
        // A chain moves its address, never its revoked trust: it stays
        // detached as replaced, and takes no address from a live pin.
        list.detach(moved, DetachReason::Replaced);
        if let Err(error) = list.validate() {
            *list = before;
            return Err(error);
        }
        return Ok(RenameApplied {
            from,
            to: view.current,
            changed: *list != before,
            displaced: None,
        });
    }
    let mut displaced = None;
    if let Some(i) = list
        .pins
        .iter()
        .position(|p| same(&p.account, &view.current))
    {
        let holder = list.pins.remove(i);
        let mut replaced = holder.replaced.clone();
        let incarnation = holder.incarnation_id().map_err(|e| restore(list, e))?;
        replaced.push(incarnation.clone());
        let excess = replaced.len().saturating_sub(MAX_REPLACED);
        replaced.drain(..excess);
        moved.replaced = replaced;
        displaced = Some(incarnation);
        list.detach(holder, DetachReason::Rename);
    }
    list.insert(moved);
    if let Err(error) = list.validate() {
        *list = before;
        return Err(error);
    }
    Ok(RenameApplied {
        from,
        to: view.current,
        changed: *list != before,
        displaced,
    })
}

/// The list's canonical bytes.
pub fn encode(list: &IdentityPinsV1) -> Result<Vec<u8>> {
    list.validate()?;
    let bytes = serde_json::to_vec(list).map_err(|_| invalid("encode"))?;
    if bytes.len() > MAX_LIST_BYTES {
        return Err(invalid("the list is too large"));
    }
    Ok(bytes)
}

/// A list from its canonical bytes only.
pub fn decode(bytes: &[u8]) -> Result<IdentityPinsV1> {
    if bytes.len() > MAX_LIST_BYTES {
        return Err(invalid("the list is too large"));
    }
    let list: IdentityPinsV1 = serde_json::from_slice(bytes).map_err(|_| invalid("decode"))?;
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
pub fn seal(key: &[u8; 32], owner: &str, revision: u64, list: &IdentityPinsV1) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_with_nonce(key, owner, revision, list, &nonce)
}

/// [`seal`] with a fixed nonce, for checked-in vectors only.
pub fn seal_with_nonce(
    key: &[u8; 32],
    owner: &str,
    revision: u64,
    list: &IdentityPinsV1,
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
pub fn open(key: &[u8; 32], owner: &str, sealed: &[u8]) -> Result<(IdentityPinsV1, u64)> {
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

    fn pin(account: &str, seed: u8) -> IdentityPinV1 {
        let identity = AccountIdentityKeysV1::derive(&[seed; 32]).unwrap();
        IdentityPinV1 {
            account: account.into(),
            authority_public_key: STANDARD.encode(identity.authority_public_key()),
            state: PinState::Seen,
            since: "2026-10-10T12:00:00Z".into(),
            replaced: vec![],
            formerly: vec![],
            renames: None,
            detached_by: None,
            unknown: UnknownFields::new(),
        }
    }

    fn list() -> IdentityPinsV1 {
        let mut bob = pin("bob@kutup.dev", 2);
        bob.state = PinState::Verified;
        bob.replaced = vec![pin("bob@kutup.dev", 9).incarnation_id().unwrap()];
        IdentityPinsV1 {
            pins: vec![pin("alice@kutup.dev", 1), bob],
            ..Default::default()
        }
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
        let mut old_suite = sealed.clone();
        old_suite[..8].copy_from_slice(b"KUTIP1\0\0");
        old_suite[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert!(inspect(&old_suite).is_err());
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
        twice.pins.push(pin("bob@kutup.dev", 3));
        assert!(encode(&twice).is_err());
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

    const T: i64 = 1_790_000_000_000;
    const NOW: &str = "2026-10-13T12:00:00Z";

    fn identity(seed: u8) -> AccountIdentityKeysV1 {
        AccountIdentityKeysV1::derive(&[seed; 32]).unwrap()
    }

    fn authority(seed: u8) -> String {
        STANDARD.encode(identity(seed).authority_public_key())
    }

    fn key(seed: u8) -> [u8; 32] {
        identity(seed).authority_public_key()
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

    fn rec(list: &mut IdentityPinsV1, account: &str, seed: u8, update: PinUpdate) -> Recorded {
        record(list, account, &authority(seed), update, NOW).unwrap()
    }

    #[test]
    fn record_follows_one_rule_for_every_app() {
        let mut list = IdentityPinsV1::default();
        // First met: pinned; met again under another authority: not replaced.
        assert_eq!(
            rec(&mut list, "bob@kutup.dev", 2, PinUpdate::FirstSeen),
            Recorded::Pinned
        );
        assert_eq!(
            rec(&mut list, "bob@kutup.dev", 3, PinUpdate::FirstSeen),
            Recorded::Unchanged
        );
        assert_eq!(list.pins[0].authority_public_key, authority(2));
        // Verified in person: the same authority keeps its history.
        list.pins[0].formerly = vec!["robert@kutup.dev".into()];
        list.pins[0].renames = Some(RenameAnchorV1 {
            sequence: 1,
            digest: "ab".repeat(32),
            unknown: UnknownFields::new(),
        });
        assert_eq!(
            rec(&mut list, "bob@kutup.dev", 2, PinUpdate::Verified),
            Recorded::Pinned
        );
        assert_eq!(list.pins[0].state, PinState::Verified);
        assert_eq!(list.pins[0].formerly, ["robert@kutup.dev"]);
        assert_eq!(
            rec(&mut list, "bob@kutup.dev", 2, PinUpdate::Verified),
            Recorded::Unchanged
        );
        assert_eq!(
            rec(&mut list, "bob@kutup.dev", 2, PinUpdate::Accepted),
            Recorded::Unchanged
        );
        // Another authority accepted: pinned fresh; the old one detached, whole.
        assert_eq!(
            rec(&mut list, "bob@kutup.dev", 3, PinUpdate::Accepted),
            Recorded::Pinned
        );
        let pin = &list.pins[0];
        assert_eq!(
            (pin.state, pin.authority_public_key.as_str()),
            (PinState::Seen, authority(3).as_str())
        );
        assert_eq!(pin.replaced, [identity(2).incarnation_id()]);
        assert!(pin.formerly.is_empty() && pin.renames.is_none());
        assert_eq!(list.detached.len(), 1);
        assert_eq!(
            list.detached[0].state,
            PinState::Seen,
            "replacing revokes its trust"
        );
        assert_eq!(list.detached[0].formerly, ["robert@kutup.dev"]);
        // Inserted in order; a bad authority or time is refused, the list kept.
        rec(&mut list, "alice@kutup.dev", 1, PinUpdate::FirstSeen);
        assert_eq!(list.pins[0].account, "alice@kutup.dev");
        assert!(encode(&list).is_ok());
        let before = list.clone();
        assert!(record(
            &mut list,
            "carol@kutup.dev",
            "AAAA",
            PinUpdate::FirstSeen,
            NOW
        )
        .is_err());
        assert!(record(
            &mut list,
            "carol@kutup.dev",
            &authority(4),
            PinUpdate::FirstSeen,
            "now"
        )
        .is_err());
        assert_eq!(list, before);
    }

    #[test]
    fn a_released_name_is_not_pinned_for_its_next_holder() {
        // Verified alice@; she becomes alicia@; Mallory later takes alice@.
        let mut list = IdentityPinsV1::default();
        rec(&mut list, "alice@kutup.dev", 1, PinUpdate::Verified);
        apply_rename(
            &mut list,
            &key(1),
            &renames(1, &["alice@kutup.dev", "alicia@kutup.dev"]),
        )
        .unwrap();
        match rec(&mut list, "alice@kutup.dev", 6, PinUpdate::FirstSeen) {
            Recorded::FormerAddressTaken { pins } => {
                assert_eq!(pins.len(), 1);
                assert_eq!(pins[0].now.as_deref(), Some("alicia@kutup.dev"));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(list.pins.len(), 1, "nothing pinned for the newcomer");
        // Alice met at a name this device has not followed yet: never a
        // second, unverified pin; the caller follows her chain first.
        let mut stale = IdentityPinsV1::default();
        rec(&mut stale, "alice@kutup.dev", 1, PinUpdate::Verified);
        for update in [
            PinUpdate::FirstSeen,
            PinUpdate::Accepted,
            PinUpdate::Verified,
        ] {
            match rec(&mut stale, "alicia@kutup.dev", 1, update) {
                Recorded::KnownElsewhere { pin } => assert_eq!(pin.account, "alice@kutup.dev"),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(stale.pins.len(), 1);
        // Accepting the newcomer is the user's explicit choice.
        assert_eq!(
            rec(&mut list, "alice@kutup.dev", 6, PinUpdate::Accepted),
            Recorded::Pinned
        );
        assert_eq!(list.pins.len(), 2);
        // Two pins for one authority are not a valid list.
        let mut twice = list.clone();
        twice.pins[0].authority_public_key = authority(1);
        assert!(encode(&twice).is_err());
    }

    #[test]
    fn a_rename_moves_the_pin_with_its_trust() {
        let mut list = IdentityPinsV1::default();
        rec(&mut list, "alice@kutup.dev", 1, PinUpdate::Verified);
        rec(&mut list, "zed@kutup.dev", 9, PinUpdate::FirstSeen);
        let chain = renames(1, &["alice@kutup.dev", "alicia@kutup.dev"]);
        let applied = apply_rename(&mut list, &key(1), &chain).unwrap();
        assert_eq!(
            applied,
            RenameApplied {
                from: "alice@kutup.dev".into(),
                to: "alicia@kutup.dev".into(),
                changed: true,
                displaced: None
            }
        );
        let pin = &list.pins[0];
        assert_eq!(pin.account, "alicia@kutup.dev");
        assert_eq!(pin.state, PinState::Verified);
        assert_eq!(pin.formerly, ["alice@kutup.dev"]);
        assert_eq!(pin.renames.as_ref().unwrap().sequence, 1);
        assert!(encode(&list).is_ok());
        // Again: nothing changes.
        let before = list.clone();
        assert!(!apply_rename(&mut list, &key(1), &chain).unwrap().changed);
        assert_eq!(list, before);

        assert!(matches!(
            lookup(&list, "alicia@kutup.dev", Some(&authority(1))),
            PinMatch::Pinned {
                same_authority: true,
                ..
            }
        ));
        match lookup(&list, "alice@kutup.dev", Some(&authority(5))) {
            PinMatch::Moved { pins } => {
                assert_eq!(pins[0].now.as_deref(), Some("alicia@kutup.dev"))
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            lookup(&list, "alice@kutup.dev", None),
            PinMatch::Moved { .. }
        ));
        assert!(matches!(
            lookup(&list, "ali@kutup.dev", Some(&authority(1))),
            PinMatch::Renamed { .. }
        ));
        assert_eq!(
            lookup(&list, "nobody@kutup.dev", Some(&authority(6))),
            PinMatch::New
        );

        // The next rename extends the anchor; the old chain alone is a rollback.
        let longer = renames(1, &["alice@kutup.dev", "alicia@kutup.dev", "ali@kutup.dev"]);
        apply_rename(&mut list, &key(1), &longer).unwrap();
        assert_eq!(list.pins[0].account, "ali@kutup.dev");
        assert_eq!(
            list.pins[0].formerly,
            ["alice@kutup.dev", "alicia@kutup.dev"]
        );
        let before = list.clone();
        assert!(
            apply_rename(&mut list, &key(1), &chain).is_err(),
            "rolled back"
        );
        // A fork: the same sequence with another statement.
        let id = identity(1);
        let fork = vec![
            account_rename::sign(&id, 1, "alice@kutup.dev", "alicia@kutup.dev", T + 7).unwrap(),
            account_rename::sign(&id, 2, "alicia@kutup.dev", "ali@kutup.dev", T + 8).unwrap(),
        ];
        assert!(apply_rename(&mut list, &key(1), &fork).is_err());
        // A forked chain that never had the pinned address.
        let elsewhere =
            vec![account_rename::sign(&id, 1, "al@kutup.dev", "alix@kutup.dev", T).unwrap()];
        assert!(apply_rename(&mut list, &key(1), &elsewhere).is_err());
        assert_eq!(list, before, "refusals change nothing");
        // Back to a former name: it leaves `formerly`.
        let back = renames(
            1,
            &[
                "alice@kutup.dev",
                "alicia@kutup.dev",
                "ali@kutup.dev",
                "alice@kutup.dev",
            ],
        );
        apply_rename(&mut list, &key(1), &back).unwrap();
        assert_eq!(list.pins[0].account, "alice@kutup.dev");
        assert_eq!(list.pins[0].formerly, ["alicia@kutup.dev", "ali@kutup.dev"]);
    }

    #[test]
    fn formerly_keeps_the_newest_addresses() {
        let names: Vec<String> = (0..=MAX_FORMERLY + 2)
            .map(|i| format!("n{i}@kutup.dev"))
            .collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut list = IdentityPinsV1::default();
        rec(&mut list, refs[0], 1, PinUpdate::FirstSeen);
        apply_rename(&mut list, &key(1), &renames(1, &refs)).unwrap();
        let pin = &list.pins[0];
        assert_eq!(pin.formerly.len(), MAX_FORMERLY);
        assert_eq!(
            pin.formerly.last().map(String::as_str),
            Some(refs[refs.len() - 2])
        );
        assert!(!pin.had(refs[0]), "the oldest went");
        assert_eq!(lookup(&list, refs[0], Some(&authority(5))), PinMatch::New);
    }

    #[test]
    fn a_rename_is_only_followed_for_its_own_authority() {
        let mut list = IdentityPinsV1::default();
        rec(&mut list, "alice@kutup.dev", 1, PinUpdate::FirstSeen);
        let other = renames(2, &["alice@kutup.dev", "mallory@kutup.dev"]);
        assert!(apply_rename(&mut list, &key(2), &other).is_err());
        assert!(apply_rename(&mut list, &key(1), &other).is_err());
        let unrelated = renames(1, &["bob@kutup.dev", "rob@kutup.dev"]);
        assert!(apply_rename(&mut list, &key(1), &unrelated).is_err());
    }

    #[test]
    fn a_displaced_holder_keeps_its_trust_whatever_the_order() {
        // Erin (verified) held alicia@ and moves to erin@; Alice takes alicia@.
        let alice = renames(1, &["alice@kutup.dev", "alicia@kutup.dev"]);
        let erin = renames(7, &["alicia@kutup.dev", "erin@kutup.dev"]);
        for alice_first in [true, false] {
            let mut list = IdentityPinsV1::default();
            rec(&mut list, "alice@kutup.dev", 1, PinUpdate::FirstSeen);
            rec(&mut list, "alicia@kutup.dev", 7, PinUpdate::Verified);
            if alice_first {
                let applied = apply_rename(&mut list, &key(1), &alice).unwrap();
                assert_eq!(applied.displaced, Some(identity(7).incarnation_id()));
                assert_eq!(list.detached[0].authority_public_key, authority(7));
                assert!(matches!(
                    lookup(&list, "erin@kutup.dev", Some(&authority(7))),
                    PinMatch::Renamed { .. }
                ));
                apply_rename(&mut list, &key(7), &erin).unwrap();
            } else {
                apply_rename(&mut list, &key(7), &erin).unwrap();
                assert!(apply_rename(&mut list, &key(1), &alice)
                    .unwrap()
                    .displaced
                    .is_none());
            }
            assert!(list.detached.is_empty(), "alice_first: {alice_first}");
            let erin_pin = list
                .pins
                .iter()
                .find(|p| p.account == "erin@kutup.dev")
                .unwrap();
            assert_eq!(
                erin_pin.state,
                PinState::Verified,
                "alice_first: {alice_first}"
            );
            let alice_pin = list
                .pins
                .iter()
                .find(|p| p.account == "alicia@kutup.dev")
                .unwrap();
            assert_eq!(alice_pin.authority_public_key, authority(1));
            assert!(encode(&list).is_ok());
        }
    }

    #[test]
    fn a_replaced_identity_is_never_trusted_back_silently() {
        // Verified A at bob@; the user accepted B there (A's account reset).
        let mut list = IdentityPinsV1::default();
        rec(&mut list, "bob@kutup.dev", 2, PinUpdate::Verified);
        rec(&mut list, "bob@kutup.dev", 3, PinUpdate::Accepted);
        let detached = &list.detached[0];
        assert_eq!(detached.detached_by, Some(DetachReason::Replaced));
        assert_eq!(
            detached.state,
            PinState::Seen,
            "its trust is revoked at once"
        );
        // A's old identity turns up again: at bob@ (B gone) or anywhere else.
        let mut gone = list.clone();
        gone.pins.clear();
        for (list, address) in [(&gone, "bob@kutup.dev"), (&list, "carol@kutup.dev")] {
            assert!(
                matches!(
                    lookup(list, address, Some(&authority(2))),
                    PinMatch::Replaced { .. }
                ),
                "{address}"
            );
            let mut next = list.clone();
            assert!(
                matches!(
                    rec(&mut next, address, 2, PinUpdate::FirstSeen),
                    Recorded::ReplacedIdentity { .. }
                ),
                "{address}"
            );
            assert_eq!(&next, list, "not pinned at {address}");
            // Accepted explicitly: only seen. Verified in person: verified.
            assert_eq!(
                rec(&mut next, address, 2, PinUpdate::Accepted),
                Recorded::Pinned
            );
            let pin = next.pins.iter().find(|p| p.account == address).unwrap();
            assert_eq!((pin.state, pin.detached_by), (PinState::Seen, None));
            let mut verified = list.clone();
            rec(&mut verified, address, 2, PinUpdate::Verified);
            let pin = verified.pins.iter().find(|p| p.account == address).unwrap();
            assert_eq!(pin.state, PinState::Verified);
            assert!(encode(&next).is_ok() && encode(&verified).is_ok());
        }
    }

    #[test]
    fn a_chain_never_brings_back_a_replaced_identity() {
        let mut list = IdentityPinsV1::default();
        rec(&mut list, "bob@kutup.dev", 2, PinUpdate::Verified);
        rec(&mut list, "bob@kutup.dev", 3, PinUpdate::Accepted);
        // A's key signs a chain bob@ -> carol@: the pin's address follows it,
        // its revoked trust does not.
        let away = renames(2, &["bob@kutup.dev", "carol@kutup.dev"]);
        apply_rename(&mut list, &key(2), &away).unwrap();
        assert!(list
            .pins
            .iter()
            .all(|p| p.authority_public_key != authority(2)));
        let detached = &list.detached[0];
        assert_eq!(
            (
                detached.account.as_str(),
                detached.detached_by,
                detached.state
            ),
            (
                "carol@kutup.dev",
                Some(DetachReason::Replaced),
                PinState::Seen
            )
        );
        assert!(matches!(
            lookup(&list, "carol@kutup.dev", Some(&authority(2))),
            PinMatch::Replaced { .. }
        ));
        // A chain back to bob@ (renames may return to a name) takes nothing
        // from B, who is pinned there.
        let back = renames(2, &["bob@kutup.dev", "carol@kutup.dev", "bob@kutup.dev"]);
        assert!(
            account_rename::verify_chain(&key(2), &back).is_ok(),
            "a chain may return to a name"
        );
        apply_rename(&mut list, &key(2), &back).unwrap();
        let b = list
            .pins
            .iter()
            .find(|p| p.account == "bob@kutup.dev")
            .unwrap();
        assert_eq!(b.authority_public_key, authority(3));
        assert_eq!(list.detached[0].detached_by, Some(DetachReason::Replaced));
        assert!(encode(&list).is_ok());
    }

    #[test]
    fn a_pin_a_rename_pushed_off_comes_back_with_its_trust() {
        // Erin (verified) at alicia@; Alice's rename lands there.
        let mut list = IdentityPinsV1::default();
        rec(&mut list, "alice@kutup.dev", 1, PinUpdate::FirstSeen);
        rec(&mut list, "alicia@kutup.dev", 7, PinUpdate::Verified);
        apply_rename(
            &mut list,
            &key(1),
            &renames(1, &["alice@kutup.dev", "alicia@kutup.dev"]),
        )
        .unwrap();
        assert_eq!(list.detached[0].detached_by, Some(DetachReason::Rename));
        // Alice moves on; Erin is met at alicia@ again.
        apply_rename(
            &mut list,
            &key(1),
            &renames(1, &["alice@kutup.dev", "alicia@kutup.dev", "ali@kutup.dev"]),
        )
        .unwrap();
        assert!(matches!(
            lookup(&list, "alicia@kutup.dev", Some(&authority(7))),
            PinMatch::Returned { .. }
        ));
        assert_eq!(
            rec(&mut list, "alicia@kutup.dev", 7, PinUpdate::FirstSeen),
            Recorded::Pinned
        );
        let erin = list
            .pins
            .iter()
            .find(|p| p.account == "alicia@kutup.dev")
            .unwrap();
        assert_eq!(erin.state, PinState::Verified);
        assert!(list.detached.is_empty());
        assert!(encode(&list).is_ok());
    }

    #[test]
    fn detached_by_is_set_exactly_on_detached_pins() {
        let mut list = IdentityPinsV1::default();
        rec(&mut list, "bob@kutup.dev", 2, PinUpdate::FirstSeen);
        let mut marked = list.clone();
        marked.pins[0].detached_by = Some(DetachReason::Rename);
        assert!(encode(&marked).is_err());
        let mut unmarked = list.clone();
        let pin = unmarked.pins.remove(0);
        unmarked.detached.push(pin);
        assert!(encode(&unmarked).is_err());
    }

    #[test]
    fn two_accounts_that_had_one_address_are_both_named() {
        let mut list = IdentityPinsV1::default();
        rec(&mut list, "x@kutup.dev", 1, PinUpdate::FirstSeen);
        apply_rename(
            &mut list,
            &key(1),
            &renames(1, &["x@kutup.dev", "y@kutup.dev"]),
        )
        .unwrap();
        rec(&mut list, "x@kutup.dev", 2, PinUpdate::Accepted);
        apply_rename(
            &mut list,
            &key(2),
            &renames(2, &["x@kutup.dev", "z@kutup.dev"]),
        )
        .unwrap();
        match lookup(&list, "x@kutup.dev", Some(&authority(3))) {
            PinMatch::Moved { pins } => {
                let now: Vec<_> = pins.iter().map(|p| p.now.clone().unwrap()).collect();
                assert_eq!(now, ["y@kutup.dev", "z@kutup.dev"]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn detached_pins_are_capped_unverified_first() {
        let mut list = IdentityPinsV1::default();
        for i in 0..=MAX_DETACHED {
            let mut pin = pin(&format!("p{i}@kutup.dev"), 0);
            let id = AccountIdentityKeysV1::derive(&{
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
                seed
            })
            .unwrap();
            pin.authority_public_key = STANDARD.encode(id.authority_public_key());
            pin.state = if i == 0 {
                PinState::Verified
            } else {
                PinState::Seen
            };
            pin.since = since_from_unix(1_790_000_000 + i as u64);
            list.detach(pin, DetachReason::Rename);
        }
        assert_eq!(list.detached.len(), MAX_DETACHED);
        assert!(
            list.detached.iter().any(|p| p.account == "p0@kutup.dev"),
            "the verified one stays"
        );
        assert!(
            !list.detached.iter().any(|p| p.account == "p1@kutup.dev"),
            "the oldest unverified went"
        );
    }

    #[test]
    fn later_fields_are_kept_and_newer_lists_refused() {
        let text = r#"{"pins":[{"account":"bob@kutup.dev","authorityPublicKey":"AUTH","state":"seen","since":"2026-10-10T12:00:00Z","nickname":"B","zone":1}],"later":true}"#
            .replace("AUTH", &authority(2));
        let mut list = decode(text.as_bytes()).unwrap();
        assert_eq!(list.pins[0].unknown["nickname"], "B");
        assert_eq!(String::from_utf8(encode(&list).unwrap()).unwrap(), text);
        // An app that updates the pin keeps what it does not know.
        rec(&mut list, "bob@kutup.dev", 2, PinUpdate::Verified);
        assert_eq!(list.pins[0].unknown["zone"], 1);
        assert_eq!(list.unknown["later"], true);
        // Not in name order after the known fields: not canonical.
        let unordered = text.replace(r#""nickname":"B","zone":1"#, r#""zone":1,"nickname":"B""#);
        assert!(decode(unordered.as_bytes()).is_err());
        // A list for newer readers is refused, not misread.
        let newer = r#"{"pins":[],"minReader":2}"#;
        let error = decode(newer.as_bytes()).unwrap_err().to_string();
        assert!(error.contains("newer app"), "{error}");
        assert!(decode(br#"{"pins":[],"minReader":1}"#).is_err());
    }

    #[test]
    fn former_addresses_and_anchors_are_checked() {
        let anchored = |formerly: Vec<&str>, sequence: u64| {
            let mut p = pin("alicia@kutup.dev", 1);
            p.formerly = formerly.into_iter().map(String::from).collect();
            p.renames = Some(RenameAnchorV1 {
                sequence,
                digest: "0f".repeat(32),
                unknown: UnknownFields::new(),
            });
            IdentityPinsV1 {
                pins: vec![p],
                ..Default::default()
            }
        };
        assert!(encode(&anchored(vec!["alice@kutup.dev"], 1)).is_ok());
        // An anchor alone: back at a name it had, accepted there.
        assert!(encode(&anchored(vec![], 1)).is_ok());
        for (case, list) in [
            ("its own address", anchored(vec!["alicia@kutup.dev"], 1)),
            (
                "twice",
                anchored(vec!["alice@kutup.dev", "alice@kutup.dev"], 2),
            ),
            ("another server", anchored(vec!["alice@other.dev"], 1)),
            ("not canonical", anchored(vec!["Alice@kutup.dev"], 1)),
            ("sequence 0", anchored(vec!["alice@kutup.dev"], 0)),
        ] {
            assert!(encode(&list).is_err(), "{case}");
        }
        let mut no_anchor = anchored(vec!["alice@kutup.dev"], 1);
        no_anchor.pins[0].renames = None;
        assert!(encode(&no_anchor).is_err());
        let mut bad_digest = anchored(vec!["alice@kutup.dev"], 1);
        bad_digest.pins[0].renames.as_mut().unwrap().digest = "0F".repeat(32);
        assert!(encode(&bad_digest).is_err());
        let too_many: Vec<String> = (0..=MAX_FORMERLY)
            .map(|i| format!("a{i}@kutup.dev"))
            .collect();
        let mut long = anchored(vec![], 1);
        long.pins[0].formerly = too_many;
        assert!(encode(&long).is_err());
        // Without renames, the list encodes exactly as before the fields.
        assert!(!String::from_utf8(encode(&list()).unwrap())
            .unwrap()
            .contains("formerly"));
    }

    fn numbered(i: usize) -> AccountIdentityKeysV1 {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(i as u64 + 1000).to_be_bytes());
        AccountIdentityKeysV1::derive(&seed).unwrap()
    }

    #[test]
    fn a_replaced_identity_stays_revoked_after_its_pin_is_dropped() {
        let mut list = IdentityPinsV1::default();
        // More identities replaced than detached pins are kept.
        for i in 0..=MAX_DETACHED {
            let address = format!("p{i}@kutup.dev");
            let old = STANDARD.encode(numbered(2 * i).authority_public_key());
            let new = STANDARD.encode(numbered(2 * i + 1).authority_public_key());
            let since = since_from_unix(1_790_000_000 + i as u64);
            record(&mut list, &address, &old, PinUpdate::Verified, &since).unwrap();
            record(&mut list, &address, &new, PinUpdate::Accepted, &since).unwrap();
        }
        assert_eq!(list.detached.len(), MAX_DETACHED);
        let first = numbered(0);
        assert_eq!(list.replaced_ids, [first.incarnation_id()]);
        assert!(encode(&list).is_ok());
        // The dropped one turns up somewhere: still warned about.
        let authority = STANDARD.encode(first.authority_public_key());
        assert!(matches!(
            lookup(&list, "elsewhere@kutup.dev", Some(&authority)),
            PinMatch::Replaced { pin: None, .. }
        ));
        let before = list.clone();
        assert!(matches!(
            record(
                &mut list,
                "elsewhere@kutup.dev",
                &authority,
                PinUpdate::FirstSeen,
                NOW
            )
            .unwrap(),
            Recorded::ReplacedIdentity { pin: None, .. }
        ));
        assert_eq!(list, before);
        // Accepted explicitly: pinned seen, and no longer remembered as replaced.
        record(
            &mut list,
            "elsewhere@kutup.dev",
            &authority,
            PinUpdate::Accepted,
            NOW,
        )
        .unwrap();
        assert!(list.replaced_ids.is_empty());
        let pin = list
            .pins
            .iter()
            .find(|p| p.account == "elsewhere@kutup.dev")
            .unwrap();
        assert_eq!(pin.state, PinState::Seen);
        assert!(encode(&list).is_ok());
        // An id both remembered and pinned is not a valid list.
        let mut both = list.clone();
        both.replaced_ids.push(first.incarnation_id());
        assert!(encode(&both).is_err());
    }

    #[test]
    fn a_replaced_identity_accepted_again_starts_afresh() {
        // A (renamed once, then replaced by the user at alicia@).
        let mut list = IdentityPinsV1::default();
        rec(&mut list, "alice@kutup.dev", 1, PinUpdate::Verified);
        apply_rename(
            &mut list,
            &key(1),
            &renames(1, &["alice@kutup.dev", "alicia@kutup.dev"]),
        )
        .unwrap();
        rec(&mut list, "alicia@kutup.dev", 4, PinUpdate::Accepted);
        assert!(!list.detached[0].formerly.is_empty());
        // Accepted again on another server: a fresh pin, a valid list.
        let mut other = list.clone();
        rec(&mut other, "alice@other.dev", 1, PinUpdate::Accepted);
        let pin = other
            .pins
            .iter()
            .find(|p| p.account == "alice@other.dev")
            .unwrap();
        assert!(pin.formerly.is_empty() && pin.renames.is_none());
        assert!(encode(&other).is_ok());
        // Accepted at an address its old chain never had: its own next chain
        // from there is followed.
        rec(&mut list, "ali@kutup.dev", 1, PinUpdate::Verified);
        let fresh =
            vec![
                account_rename::sign(&identity(1), 1, "ali@kutup.dev", "alix@kutup.dev", T)
                    .unwrap(),
            ];
        apply_rename(&mut list, &key(1), &fresh).unwrap();
        let pin = list
            .pins
            .iter()
            .find(|p| p.authority_public_key == authority(1))
            .unwrap();
        assert_eq!(pin.account, "alix@kutup.dev");
        assert_eq!(pin.state, PinState::Verified);
        assert!(encode(&list).is_ok());
    }
}
