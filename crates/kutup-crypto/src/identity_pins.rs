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

/// One account's pinned authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityPinV1 {
    /// Canonical `username@server`.
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
    /// can roll a rename back, on any device of the account. Present exactly
    /// when `formerly` is not empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renames: Option<RenameAnchorV1>,
}

/// Where an incarnation's verified rename chain ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenameAnchorV1 {
    /// The last statement's sequence (1 for the first rename).
    pub sequence: u64,
    /// That statement's digest, lowercase hex.
    pub digest: String,
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
        match &self.renames {
            None if self.formerly.is_empty() => {}
            Some(anchor)
                if !self.formerly.is_empty()
                    && (1..=account_rename::MAX_CHAIN as u64).contains(&anchor.sequence)
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
        }
    }
}

fn server_of(account: &str) -> &str {
    account.split_once('@').map_or("", |(_, server)| server)
}

/// The whole list: pins sorted by account, one per account.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityPinsV1 {
    pub pins: Vec<IdentityPinV1>,
}

impl IdentityPinsV1 {
    pub fn validate(&self) -> Result<()> {
        if self.pins.len() > MAX_PINS {
            return Err(invalid("too many pins"));
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
        Ok(())
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
    /// Met with a valid binding: pinned only if nothing is pinned for the
    /// address yet (trust on first use). Never replaces a pin.
    FirstSeen,
    /// The user accepted the authority now published (after a change): it
    /// replaces another one, `seen`; the replaced incarnation is remembered.
    Accepted,
    /// Compared in person: `verified`, replacing another authority if need be.
    Verified,
}

/// Records `update` about `account` at `authority` (canonical base64) at time
/// `since`. A pin of the same authority keeps its history (`replaced`,
/// `formerly`, `renames`); one of another authority is replaced, its
/// incarnation kept in `replaced`. Returns whether the list changed.
pub fn record(
    list: &mut IdentityPinsV1,
    account: &str,
    authority: &str,
    update: PinUpdate,
    since: &str,
) -> Result<bool> {
    let candidate = IdentityPinV1::fresh(account, authority, PinState::Seen, since);
    candidate.validate()?;
    let index = list.pins.iter().position(|pin| pin.account == account);
    let Some(index) = index else {
        let state = match update {
            PinUpdate::Verified => PinState::Verified,
            PinUpdate::FirstSeen | PinUpdate::Accepted => PinState::Seen,
        };
        insert(list, IdentityPinV1 { state, ..candidate });
        return Ok(true);
    };
    let pin = &mut list.pins[index];
    if pin.authority_public_key == authority {
        if update == PinUpdate::Verified && pin.state != PinState::Verified {
            pin.state = PinState::Verified;
            pin.since = since.to_owned();
            return Ok(true);
        }
        return Ok(false);
    }
    let state = match update {
        PinUpdate::FirstSeen => return Ok(false),
        PinUpdate::Accepted => PinState::Seen,
        PinUpdate::Verified => PinState::Verified,
    };
    let mut replaced = std::mem::take(&mut pin.replaced);
    replaced.push(pin.incarnation_id()?);
    let excess = replaced.len().saturating_sub(MAX_REPLACED);
    replaced.drain(..excess);
    *pin = IdentityPinV1 {
        state,
        replaced,
        ..candidate
    };
    Ok(true)
}

fn insert(list: &mut IdentityPinsV1, pin: IdentityPinV1) {
    let at = list
        .pins
        .binary_search_by(|p| p.account.as_str().cmp(&pin.account))
        .unwrap_or_else(|at| at);
    list.pins.insert(at, pin);
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
    /// under another one: this account was renamed (to the address, or back to
    /// it). Fetch its rename chain and [`apply_rename`].
    Renamed { pin: IdentityPinV1 },
    /// No pin for the address, but a pinned account had it before and is now
    /// `pin.account`; whoever is there now is someone else: "this is not the
    /// person you verified, they are now …".
    Moved { pin: IdentityPinV1 },
    /// Nothing known.
    New,
}

/// What the list says about `address`; see [`PinMatch`].
pub fn lookup(list: &IdentityPinsV1, address: &str, published: Option<&str>) -> PinMatch {
    if let Some(pin) = list.pins.iter().find(|pin| pin.account == address) {
        return PinMatch::Pinned {
            pin: pin.clone(),
            same_authority: published == Some(pin.authority_public_key.as_str()),
        };
    }
    if let Some(published) = published {
        if let Some(pin) = list
            .pins
            .iter()
            .find(|pin| pin.authority_public_key == published)
        {
            return PinMatch::Renamed { pin: pin.clone() };
        }
    }
    // The newest move wins when several incarnations once held the address.
    list.pins
        .iter()
        .filter(|pin| pin.formerly.iter().any(|former| former == address))
        .max_by(|a, b| a.since.cmp(&b.since))
        .map_or(PinMatch::New, |pin| PinMatch::Moved { pin: pin.clone() })
}

/// What [`apply_rename`] did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameApplied {
    /// Where the pin was (an address in the chain).
    pub from: String,
    /// Where it is now: the chain's current address.
    pub to: String,
    /// Whether the list changed (false: this chain was already applied).
    pub changed: bool,
    /// Another incarnation pinned at `to` before: the address's previous
    /// holder, now in the moved pin's `replaced` (which follows the address:
    /// the history of `from` stays behind with it). The user is told that `to`
    /// is now the person they knew as `from`.
    pub displaced: Option<String>,
}

/// Follows a verified rename of the account whose authority is `authority`:
/// its pin moves to the chain's current address, keeping its trust (the
/// safety number did not change), with every earlier address in `formerly`
/// and the chain's head as its anchor. Refuses a chain that does not verify
/// against `authority`, or that does not extend the anchor the pin holds (a
/// rollback). Idempotent.
pub fn apply_rename(
    list: &mut IdentityPinsV1,
    authority: &[u8; 32],
    chain: &[AccountRenameV1],
) -> Result<RenameApplied> {
    let view = account_rename::verify_chain(authority, chain)?;
    let authority_b64 = STANDARD.encode(authority);
    let mine: Vec<usize> = (0..list.pins.len())
        .filter(|&i| {
            list.pins[i].authority_public_key == authority_b64 && view.had(&list.pins[i].account)
        })
        .collect();
    // The pin to move: the one at the newest address of the chain (several
    // only when apps pinned the account under two of its names meanwhile).
    let &primary = mine
        .iter()
        .max_by_key(|&&i| {
            view.addresses
                .iter()
                .rposition(|address| *address == list.pins[i].account)
        })
        .ok_or_else(|| invalid("no pin for this account"))?;
    for &i in &mine {
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
    }
    let head = RenameAnchorV1 {
        sequence: view.sequence,
        digest: hex::encode(view.digests.last().expect("a verified chain is not empty")),
    };
    let mut formerly: Vec<String> = Vec::new();
    for address in &view.addresses[..view.addresses.len() - 1] {
        if *address != view.current {
            formerly.retain(|known| known != address);
            formerly.push(address.clone());
        }
    }
    let excess = formerly.len().saturating_sub(MAX_FORMERLY);
    formerly.drain(..excess);

    let from = list.pins[primary].account.clone();
    let mut moved = list.pins[primary].clone();
    let verified = mine
        .iter()
        .any(|&i| list.pins[i].state == PinState::Verified);
    moved.account = view.current.clone();
    moved.state = if verified {
        PinState::Verified
    } else {
        PinState::Seen
    };
    moved.formerly = formerly;
    moved.renames = Some(head);
    // `replaced` is the history of an address: the pin now stands at the new
    // one, whose history is its previous holder's, if it had one.
    if moved.account != from {
        moved.replaced = Vec::new();
    }

    let mut displaced = None;
    let mut next: Vec<IdentityPinV1> = Vec::with_capacity(list.pins.len());
    for (i, pin) in list.pins.iter().enumerate() {
        if mine.contains(&i) {
            continue;
        }
        if pin.account == view.current {
            // Whoever held the new address before: another incarnation.
            let mut replaced = pin.replaced.clone();
            replaced.push(pin.incarnation_id()?);
            moved.replaced = replaced;
            displaced = Some(pin.incarnation_id()?);
            continue;
        }
        next.push(pin.clone());
    }
    let excess = moved.replaced.len().saturating_sub(MAX_REPLACED);
    moved.replaced.drain(..excess);
    let changed = !(mine.len() == 1 && list.pins[primary] == moved && displaced.is_none());
    if !changed {
        return Ok(RenameApplied {
            from,
            to: view.current,
            changed,
            displaced,
        });
    }
    moved.validate()?;
    let mut updated = IdentityPinsV1 { pins: next };
    insert(&mut updated, moved);
    updated.validate()?;
    *list = updated;
    Ok(RenameApplied {
        from,
        to: view.current,
        changed,
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
        }
    }

    fn list() -> IdentityPinsV1 {
        let mut bob = pin("bob@kutup.dev", 2);
        bob.state = PinState::Verified;
        bob.replaced = vec![pin("bob@kutup.dev", 9).incarnation_id().unwrap()];
        IdentityPinsV1 {
            pins: vec![pin("alice@kutup.dev", 1), bob],
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

    #[test]
    fn record_follows_one_rule_for_every_app() {
        let mut list = IdentityPinsV1::default();
        // First met: pinned; met again under another authority: not replaced.
        assert!(record(
            &mut list,
            "bob@kutup.dev",
            &authority(2),
            PinUpdate::FirstSeen,
            NOW
        )
        .unwrap());
        assert!(!record(
            &mut list,
            "bob@kutup.dev",
            &authority(3),
            PinUpdate::FirstSeen,
            NOW
        )
        .unwrap());
        assert_eq!(list.pins[0].authority_public_key, authority(2));
        // Verified in person: the same authority keeps its history.
        list.pins[0].formerly = vec!["robert@kutup.dev".into()];
        list.pins[0].renames = Some(RenameAnchorV1 {
            sequence: 1,
            digest: "ab".repeat(32),
        });
        assert!(record(
            &mut list,
            "bob@kutup.dev",
            &authority(2),
            PinUpdate::Verified,
            NOW
        )
        .unwrap());
        assert_eq!(list.pins[0].state, PinState::Verified);
        assert_eq!(list.pins[0].formerly, ["robert@kutup.dev"]);
        assert!(!record(
            &mut list,
            "bob@kutup.dev",
            &authority(2),
            PinUpdate::Verified,
            NOW
        )
        .unwrap());
        assert!(!record(
            &mut list,
            "bob@kutup.dev",
            &authority(2),
            PinUpdate::Accepted,
            NOW
        )
        .unwrap());
        // Another authority accepted: a fresh pin, the old incarnation replaced.
        assert!(record(
            &mut list,
            "bob@kutup.dev",
            &authority(3),
            PinUpdate::Accepted,
            NOW
        )
        .unwrap());
        let pin = &list.pins[0];
        assert_eq!(
            (pin.state, pin.authority_public_key.as_str()),
            (PinState::Seen, authority(3).as_str())
        );
        assert_eq!(pin.replaced, [identity(2).incarnation_id()]);
        assert!(pin.formerly.is_empty() && pin.renames.is_none());
        // Inserted in order; a bad authority or time is refused.
        record(
            &mut list,
            "alice@kutup.dev",
            &authority(1),
            PinUpdate::FirstSeen,
            NOW,
        )
        .unwrap();
        assert_eq!(list.pins[0].account, "alice@kutup.dev");
        assert!(encode(&list).is_ok());
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
    }

    #[test]
    fn a_rename_moves_the_pin_with_its_trust() {
        let mut list = IdentityPinsV1::default();
        record(
            &mut list,
            "alice@kutup.dev",
            &authority(1),
            PinUpdate::Verified,
            NOW,
        )
        .unwrap();
        record(
            &mut list,
            "zed@kutup.dev",
            &authority(9),
            PinUpdate::FirstSeen,
            NOW,
        )
        .unwrap();
        let chain = renames(1, &["alice@kutup.dev", "alicia@kutup.dev"]);
        let key = identity(1).authority_public_key();
        let applied = apply_rename(&mut list, &key, &chain).unwrap();
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
        assert_eq!(list.pins[1].account, "zed@kutup.dev");
        assert!(encode(&list).is_ok());
        // Again: nothing changes.
        let before = list.clone();
        assert!(!apply_rename(&mut list, &key, &chain).unwrap().changed);
        assert_eq!(list, before);

        // Lookups: the new address is pinned; the old one, now someone else's,
        // is "moved"; the account seen at a name it went back to is "renamed".
        assert!(matches!(
            lookup(&list, "alicia@kutup.dev", Some(&authority(1))),
            PinMatch::Pinned {
                same_authority: true,
                ..
            }
        ));
        match lookup(&list, "alice@kutup.dev", Some(&authority(5))) {
            PinMatch::Moved { pin } => assert_eq!(pin.account, "alicia@kutup.dev"),
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
        apply_rename(&mut list, &key, &longer).unwrap();
        assert_eq!(list.pins[0].account, "ali@kutup.dev");
        assert_eq!(
            list.pins[0].formerly,
            ["alice@kutup.dev", "alicia@kutup.dev"]
        );
        assert!(
            apply_rename(&mut list, &key, &chain).is_err(),
            "rolled back"
        );
        // A rewritten history under the same authority is refused too.
        let id = identity(1);
        let rewritten = vec![
            account_rename::sign(&id, 1, "alice@kutup.dev", "alicia@kutup.dev", T + 7).unwrap(),
            account_rename::sign(&id, 2, "alicia@kutup.dev", "ali@kutup.dev", T + 8).unwrap(),
        ];
        assert!(apply_rename(&mut list, &key, &rewritten).is_err());
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
        apply_rename(&mut list, &key, &back).unwrap();
        assert_eq!(list.pins[0].account, "alice@kutup.dev");
        assert_eq!(list.pins[0].formerly, ["alicia@kutup.dev", "ali@kutup.dev"]);
    }

    #[test]
    fn a_rename_is_only_followed_for_its_own_authority() {
        let mut list = IdentityPinsV1::default();
        record(
            &mut list,
            "alice@kutup.dev",
            &authority(1),
            PinUpdate::FirstSeen,
            NOW,
        )
        .unwrap();
        // The next holder of a name cannot move the old owner's pin, nor can
        // a chain signed by another authority than the pinned one.
        let other = renames(2, &["alice@kutup.dev", "mallory@kutup.dev"]);
        assert!(apply_rename(&mut list, &identity(2).authority_public_key(), &other).is_err());
        assert!(apply_rename(&mut list, &identity(1).authority_public_key(), &other).is_err());
        // A chain about addresses the pin never had moves nothing.
        let unrelated = renames(1, &["bob@kutup.dev", "rob@kutup.dev"]);
        assert!(apply_rename(&mut list, &identity(1).authority_public_key(), &unrelated).is_err());
    }

    #[test]
    fn a_rename_onto_a_pinned_address_replaces_its_previous_holder() {
        let mut list = IdentityPinsV1::default();
        record(
            &mut list,
            "alice@kutup.dev",
            &authority(1),
            PinUpdate::FirstSeen,
            NOW,
        )
        .unwrap();
        record(
            &mut list,
            "alicia@kutup.dev",
            &authority(7),
            PinUpdate::Verified,
            NOW,
        )
        .unwrap();
        // The same account also pinned under its new name by another app.
        let key = identity(1).authority_public_key();
        let applied = apply_rename(
            &mut list,
            &key,
            &renames(1, &["alice@kutup.dev", "alicia@kutup.dev"]),
        )
        .unwrap();
        assert_eq!(applied.displaced, Some(identity(7).incarnation_id()));
        assert_eq!(list.pins.len(), 1);
        let pin = &list.pins[0];
        assert_eq!(pin.authority_public_key, authority(1));
        assert_eq!(pin.replaced, [identity(7).incarnation_id()]);
        assert_eq!(
            pin.state,
            PinState::Seen,
            "the displaced pin's trust is not inherited"
        );

        // Pinned under both names (two apps raced): merged, keeping the trust.
        let mut twice = IdentityPinsV1::default();
        record(
            &mut twice,
            "alice@kutup.dev",
            &authority(1),
            PinUpdate::Verified,
            NOW,
        )
        .unwrap();
        record(
            &mut twice,
            "alicia@kutup.dev",
            &authority(1),
            PinUpdate::FirstSeen,
            NOW,
        )
        .unwrap();
        let applied = apply_rename(
            &mut twice,
            &key,
            &renames(1, &["alice@kutup.dev", "alicia@kutup.dev"]),
        )
        .unwrap();
        assert!(applied.changed && applied.displaced.is_none());
        assert_eq!(twice.pins.len(), 1);
        assert_eq!(twice.pins[0].state, PinState::Verified);
    }

    #[test]
    fn former_addresses_and_anchors_are_checked() {
        let anchored = |formerly: Vec<&str>, sequence: u64| {
            let mut p = pin("alicia@kutup.dev", 1);
            p.formerly = formerly.into_iter().map(String::from).collect();
            p.renames = Some(RenameAnchorV1 {
                sequence,
                digest: "0f".repeat(32),
            });
            IdentityPinsV1 { pins: vec![p] }
        };
        assert!(encode(&anchored(vec!["alice@kutup.dev"], 1)).is_ok());
        for (case, list) in [
            ("its own address", anchored(vec!["alicia@kutup.dev"], 1)),
            (
                "twice",
                anchored(vec!["alice@kutup.dev", "alice@kutup.dev"], 2),
            ),
            ("another server", anchored(vec!["alice@other.dev"], 1)),
            ("not canonical", anchored(vec!["Alice@kutup.dev"], 1)),
            ("sequence 0", anchored(vec!["alice@kutup.dev"], 0)),
            ("no former address", anchored(vec![], 1)),
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
}
