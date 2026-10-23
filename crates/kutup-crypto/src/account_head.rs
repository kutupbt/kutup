//! The account head (docs/plans/rollback-protection.md): one small sealed value
//! that says, for every kind of mutable sealed value the account keeps
//! (contact cards, mail names, identity pins, Pass vault secrets, settings),
//! how many there are and a digest of their (id, revision) pairs. It is
//! numbered and hash-chained, and every listed write writes the next one.
//!
//! What it gives:
//! - a device refuses a value rolled back, dropped or brought back, even one it
//!   never read (the value's revision must be the one the verified index says);
//! - one highest-seen head protects every value at once;
//! - a device that wrote head n and is later shown a chain not descending from
//!   it has been forked, and says so.
//!
//! A device with no history trusts the first head it reads: nothing can do
//! better for a device whose only link to the account is the server.
//!
//! The head is sealed (XChaCha20-Poly1305) under a key derived from the master
//! key, bound to the account's key binding and its sequence; value ids and the
//! writing device are HMAC'd, so the head tells the server nothing it does not
//! already know.

use crate::primitives::{Aead, Kdf, Suite};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::key_binding;

const SALT: &[u8] = b"kutup/account-head/v1\0";
const SEAL_KEY_INFO: &[u8] = b"kutup/account-head/seal-key/v1\0";
const ID_KEY_INFO: &[u8] = b"kutup/account-head/id-key/v1\0";
const VALUE_ID_DOMAIN: &[u8] = b"kutup/account-head/value/v1\0";
const WRITER_DOMAIN: &[u8] = b"kutup/account-head/writer/v1\0";
const SCOPE_DOMAIN: &[u8] = b"kutup/account-head/scope/v1\0";
const AAD_DOMAIN: &[u8] = b"kutup/account-head/sealed/v1\0";
const LOCAL_NAME_DOMAIN: &[u8] = b"kutup/account-head/local-name/v1\0";
const LOCAL_AAD_DOMAIN: &[u8] = b"kutup/account-head/local/v1\0";
const MAGIC: &[u8; 8] = b"KUTAH1\0\0";
const LOCAL_MAGIC: &[u8; 8] = b"KUTAL1\0\0";
const SUITE: u16 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 2 + 8 + NONCE_LEN;
/// The most scopes a head lists.
pub const MAX_SCOPES: usize = 64;
/// The largest sealed head.
pub const MAX_SEALED_BYTES: usize = 16 * 1024;
/// The most values one scope may hold (an index larger than this is refused).
pub const MAX_SCOPE_VALUES: usize = 1_000_000;

fn invalid(what: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("account head: {what}"))
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The account's head keys, derived from the master key.
pub struct HeadKeys {
    seal: Zeroizing<[u8; 32]>,
    id: Zeroizing<[u8; 32]>,
}

impl HeadKeys {
    pub fn derive(master_key: &[u8; 32]) -> Result<Self> {
        let hkdf = Kdf::new(Suite::V1, SALT, master_key);
        let mut seal = Zeroizing::new([0u8; 32]);
        let mut id = Zeroizing::new([0u8; 32]);
        hkdf.expand(SEAL_KEY_INFO, seal.as_mut_slice())
            .and_then(|_| hkdf.expand(ID_KEY_INFO, id.as_mut_slice()))
            .map_err(|_| CryptoError::Backend("account head key".into()))?;
        Ok(Self { seal, id })
    }

    fn mac(&self, domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.id.as_slice())
            .expect("HMAC takes any key length");
        mac.update(domain);
        for part in parts {
            mac.update(&(part.len() as u32).to_be_bytes());
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    }

    /// What the head knows a value by: an HMAC of its scope and id.
    pub fn value_id(&self, scope: &str, id: &str) -> Result<[u8; 32]> {
        check_scope(scope)?;
        if id.is_empty() || id.len() > 1024 {
            return Err(invalid("value id is invalid"));
        }
        Ok(self.mac(VALUE_ID_DOMAIN, &[scope.as_bytes(), id.as_bytes()]))
    }

    /// The name a device stores its [`LocalHeadStateV1`] under (hex): one per
    /// account and incarnation, so two accounts in one store, or an account
    /// before and after a reset, never share or compare anchors.
    pub fn local_state_name(&self, incarnation_id: &str) -> Result<String> {
        if !is_lower_hex_32(incarnation_id) {
            return Err(invalid("incarnation id is invalid"));
        }
        Ok(hex::encode(
            self.mac(LOCAL_NAME_DOMAIN, &[incarnation_id.as_bytes()]),
        ))
    }

    /// Which device wrote a head, as the head says it (hex): stable for the
    /// device, unlinkable to it by the server.
    pub fn writer(&self, device_id: &str) -> Result<String> {
        if device_id.is_empty() || device_id.len() > 256 {
            return Err(invalid("device id is invalid"));
        }
        Ok(hex::encode(
            self.mac(WRITER_DOMAIN, &[device_id.as_bytes()]),
        ))
    }

    /// A scope's entry in the head, for its whole index of `(id, revision)`
    /// pairs (as the server lists them; any order).
    pub fn scope_digest(&self, scope: &str, index: &[(String, u64)]) -> Result<ScopeV1> {
        check_scope(scope)?;
        if index.len() > MAX_SCOPE_VALUES {
            return Err(invalid("the scope holds too many values"));
        }
        let mut pairs = index
            .iter()
            .map(|(id, revision)| {
                if *revision == 0 {
                    return Err(invalid("revisions start at 1"));
                }
                Ok((self.value_id(scope, id)?, *revision))
            })
            .collect::<Result<Vec<_>>>()?;
        pairs.sort();
        if pairs.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(invalid("a value is listed twice"));
        }
        let mut hasher = Sha256::new();
        hasher.update(SCOPE_DOMAIN);
        hasher.update((scope.len() as u32).to_be_bytes());
        hasher.update(scope.as_bytes());
        hasher.update((pairs.len() as u64).to_be_bytes());
        for (id, revision) in &pairs {
            hasher.update(id);
            hasher.update(revision.to_be_bytes());
        }
        Ok(ScopeV1 {
            scope: scope.to_owned(),
            count: pairs.len() as u64,
            digest: hex::encode(hasher.finalize()),
        })
    }
}

fn check_scope(scope: &str) -> Result<()> {
    if scope.is_empty() || scope.len() > 32 || !scope.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(invalid("scope name is invalid"));
    }
    Ok(())
}

/// One scope's entry: how many values, and the digest of their pairs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeV1 {
    pub scope: String,
    pub count: u64,
    /// Lowercase hex SHA-256.
    pub digest: String,
}

/// The account head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountHeadV1 {
    /// The account's incarnation (lowercase hex).
    pub incarnation_id: String,
    /// 1, 2, 3, …: one per change of any listed value.
    pub sequence: u64,
    /// The digest of the head before (lowercase hex); absent at 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    /// [`HeadKeys::writer`] of the device that wrote it.
    pub writer: String,
    /// Sorted by scope, one each.
    pub scopes: Vec<ScopeV1>,
}

impl AccountHeadV1 {
    fn validate(&self) -> Result<()> {
        if !is_lower_hex_32(&self.incarnation_id) || !is_lower_hex_32(&self.writer) {
            return Err(invalid("incarnation or writer is invalid"));
        }
        if self.sequence == 0 || self.sequence > 1 << 53 {
            return Err(invalid("sequence is invalid"));
        }
        match &self.previous {
            None if self.sequence == 1 => {}
            Some(previous) if self.sequence > 1 && is_lower_hex_32(previous) => {}
            _ => return Err(invalid("previous does not match the sequence")),
        }
        if self.scopes.len() > MAX_SCOPES
            || !self
                .scopes
                .windows(2)
                .all(|pair| pair[0].scope < pair[1].scope)
        {
            return Err(invalid("scopes must be sorted, one each"));
        }
        for scope in &self.scopes {
            check_scope(&scope.scope)?;
            if !is_lower_hex_32(&scope.digest) || scope.count > MAX_SCOPE_VALUES as u64 {
                return Err(invalid("a scope entry is invalid"));
            }
        }
        Ok(())
    }

    /// The entry for `scope`, if the head covers it yet.
    pub fn scope(&self, scope: &str) -> Option<&ScopeV1> {
        self.scopes.iter().find(|entry| entry.scope == scope)
    }

    /// The head after this one (sealed as `sealed`), written by `writer`,
    /// with `scope` set to `entry` (the others kept).
    pub fn next(&self, sealed: &[u8], writer: &str, entries: Vec<ScopeV1>) -> Result<Self> {
        let mut scopes = self.scopes.clone();
        for entry in entries {
            scopes.retain(|known| known.scope != entry.scope);
            scopes.push(entry);
        }
        scopes.sort_by(|a, b| a.scope.cmp(&b.scope));
        let next = Self {
            incarnation_id: self.incarnation_id.clone(),
            sequence: self.sequence + 1,
            previous: Some(hex::encode(digest(sealed))),
            writer: writer.to_owned(),
            scopes,
        };
        next.validate()?;
        Ok(next)
    }

    /// The first head of an account: trust on first use of what is there now.
    pub fn first(incarnation_id: &str, writer: &str, mut scopes: Vec<ScopeV1>) -> Result<Self> {
        scopes.sort_by(|a, b| a.scope.cmp(&b.scope));
        let head = Self {
            incarnation_id: incarnation_id.to_owned(),
            sequence: 1,
            previous: None,
            writer: writer.to_owned(),
            scopes,
        };
        head.validate()?;
        Ok(head)
    }
}

/// What a head is known by: the SHA-256 of its sealed bytes.
pub fn digest(sealed: &[u8]) -> [u8; 32] {
    Sha256::digest(sealed).into()
}

fn aad(binding: &str, sequence: u64) -> Result<Vec<u8>> {
    let binding = key_binding::check(binding).map_err(|_| invalid("key binding is invalid"))?;
    Ok([
        MAGIC.as_slice(),
        &SUITE.to_be_bytes(),
        AAD_DOMAIN,
        &(binding.len() as u16).to_be_bytes(),
        binding.as_bytes(),
        &sequence.to_be_bytes(),
    ]
    .concat())
}

/// Seals `head` for the account whose key binding is `binding`:
/// `magic ‖ suite ‖ sequence ‖ nonce ‖ ciphertext`. The sequence is in clear
/// (the server's compare-and-swap reads it) and authenticated.
pub fn seal(keys: &HeadKeys, binding: &str, head: &AccountHeadV1) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::primitives::random(&mut nonce);
    seal_with_nonce(keys, binding, head, &nonce)
}

/// [`seal`] with a fixed nonce, for checked-in vectors only.
#[cfg(any(test, feature = "test-vectors"))]
pub fn seal_for_vectors(
    keys: &HeadKeys,
    binding: &str,
    head: &AccountHeadV1,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    seal_with_nonce(keys, binding, head, nonce)
}

fn seal_with_nonce(
    keys: &HeadKeys,
    binding: &str,
    head: &AccountHeadV1,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    head.validate()?;
    let plain = serde_json::to_vec(head).map_err(|_| invalid("encode"))?;
    let ciphertext = Aead::new(Suite::V1, keys.seal.as_ref())?
        .seal_with_nonce(nonce, &aad(binding, head.sequence)?, &plain)
        .map_err(|_| CryptoError::Backend("account head seal".into()))?;
    let sealed = [
        MAGIC.as_slice(),
        &SUITE.to_be_bytes(),
        &head.sequence.to_be_bytes(),
        nonce,
        &ciphertext,
    ]
    .concat();
    if sealed.len() > MAX_SEALED_BYTES {
        return Err(invalid("the head is too large"));
    }
    Ok(sealed)
}

/// The sequence a sealed head carries, without opening it (the server's view).
pub fn inspect(sealed: &[u8]) -> Result<u64> {
    if sealed.len() <= HEADER_LEN + TAG_LEN || sealed.len() > MAX_SEALED_BYTES {
        return Err(invalid("size is invalid"));
    }
    if &sealed[..8] != MAGIC || sealed[8..10] != SUITE.to_be_bytes() {
        return Err(invalid("not an account head"));
    }
    let sequence = u64::from_be_bytes(sealed[10..18].try_into().expect("8 bytes"));
    if sequence == 0 {
        return Err(invalid("sequence is invalid"));
    }
    Ok(sequence)
}

/// Opens a sealed head of the account whose key binding is `binding`.
pub fn open(keys: &HeadKeys, binding: &str, sealed: &[u8]) -> Result<AccountHeadV1> {
    let sequence = inspect(sealed)?;
    let plain = Aead::new(Suite::V1, keys.seal.as_ref())?
        .open_with_nonce(
            &sealed[18..HEADER_LEN],
            &aad(binding, sequence)?,
            &sealed[HEADER_LEN..],
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    let head: AccountHeadV1 = serde_json::from_slice(&plain).map_err(|_| invalid("decode"))?;
    head.validate()?;
    if head.sequence != sequence || serde_json::to_vec(&head).ok().as_deref() != Some(&plain[..]) {
        return Err(invalid("the head is not canonical"));
    }
    Ok(head)
}

/// How many heads the server keeps (the chain a device's anchor can be shown
/// to descend from). The server prunes below this window; a device whose anchor
/// is further back than this cannot verify its descent ([`HeadStatus::TooOld`]).
pub const RETENTION: u64 = 1000;

/// What a device remembers of a head: its sequence and digest. Only a check
/// or a re-anchoring gives one ([`VerifiedHead::anchor`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Anchor {
    pub sequence: u64,
    /// Lowercase hex.
    pub digest: String,
}

impl Anchor {
    fn of(sealed: &[u8]) -> Result<Self> {
        Ok(Self {
            sequence: inspect(sealed)?,
            digest: hex::encode(digest(sealed)),
        })
    }
}

/// A head this device has verified (by [`check`] or [`reanchor`]): the only
/// kind an index is checked against, and the only kind a next head is
/// written on top of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHead {
    head: AccountHeadV1,
    sealed: Vec<u8>,
    anchor: Anchor,
}

impl VerifiedHead {
    pub fn head(&self) -> &AccountHeadV1 {
        &self.head
    }

    /// What to remember now.
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }

    /// The next head, written by `writer`, with `entries` replaced.
    pub fn next(&self, writer: &str, entries: Vec<ScopeV1>) -> Result<AccountHeadV1> {
        self.head.next(&self.sealed, writer, entries)
    }

    /// After the server stored `sealed` (this device's next head): the newly
    /// verified head, which must directly follow this one.
    pub fn committed(&self, keys: &HeadKeys, binding: &str, sealed: &[u8]) -> Result<Self> {
        let head = open(keys, binding, sealed)?;
        if head.sequence != self.head.sequence + 1
            || head.previous.as_deref() != Some(self.anchor.digest.as_str())
            || head.incarnation_id != self.head.incarnation_id
        {
            return Err(invalid("the head does not follow the verified one"));
        }
        verified(head, sealed)
    }
}

fn verified(head: AccountHeadV1, sealed: &[u8]) -> Result<VerifiedHead> {
    Ok(VerifiedHead {
        anchor: Anchor::of(sealed)?,
        sealed: sealed.to_vec(),
        head,
    })
}

/// How the current head relates to what a device remembers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum HeadStatus {
    /// The device remembers nothing: the head is trusted from now on.
    Fresh,
    /// The same head the device remembers.
    Current,
    /// A later head, descending from the one remembered.
    Extends,
    /// A head older than the one remembered: the server rolled the account
    /// back (or was restored from a backup). Blocking.
    Rollback,
    /// A head that does not descend from the remembered one, or a chain the
    /// server will not or cannot show within its window: another history (or a
    /// restore from a backup). Blocking.
    Fork,
    /// The remembered head is further back than the server keeps
    /// ([`RETENTION`]): descent can be neither shown nor refuted. Re-anchor,
    /// with a notice; not blocking.
    TooOld,
}

/// The outcome of a check: the status, and the verified head when it is
/// trusted (`fresh`, `current`, `extends`); the others need [`reanchor`].
#[derive(Clone, Debug)]
pub struct Checked {
    pub status: HeadStatus,
    pub verified: Option<VerifiedHead>,
}

/// Checks the current head (`current`, sealed) against `anchor`, what this
/// device remembers (its highest seen, or its own last write). `segment` is
/// the chain from the anchor's sequence to the current one inclusive, as the
/// server returns it, or `None` when it does not. The current head must open
/// and name `incarnation_id`; anything else the server shows that does not
/// hold together is a fork, never an error to retry.
pub fn check(
    keys: &HeadKeys,
    binding: &str,
    incarnation_id: &str,
    anchor: Option<&Anchor>,
    current: &[u8],
    segment: Option<&[Vec<u8>]>,
) -> Result<Checked> {
    let head = open(keys, binding, current)?;
    if head.incarnation_id != incarnation_id {
        return Err(invalid("the head is another incarnation's"));
    }
    let status = status_of(
        keys,
        binding,
        incarnation_id,
        &head,
        anchor,
        current,
        segment,
    );
    let verified = match status {
        HeadStatus::Fresh | HeadStatus::Current | HeadStatus::Extends => {
            Some(verified(head, current)?)
        }
        _ => None,
    };
    Ok(Checked { status, verified })
}

fn status_of(
    keys: &HeadKeys,
    binding: &str,
    incarnation_id: &str,
    head: &AccountHeadV1,
    anchor: Option<&Anchor>,
    current: &[u8],
    segment: Option<&[Vec<u8>]>,
) -> HeadStatus {
    let Some(anchor) = anchor else {
        return HeadStatus::Fresh;
    };
    if head.sequence < anchor.sequence {
        return HeadStatus::Rollback;
    }
    if head.sequence == anchor.sequence {
        return if hex::encode(digest(current)) == anchor.digest {
            HeadStatus::Current
        } else {
            HeadStatus::Fork
        };
    }
    let Some(segment) = segment else {
        // Only a gap past what the server keeps may go unshown.
        return if head.sequence - anchor.sequence > RETENTION {
            HeadStatus::TooOld
        } else {
            HeadStatus::Fork
        };
    };
    if descends(keys, binding, incarnation_id, anchor, current, segment) {
        HeadStatus::Extends
    } else {
        HeadStatus::Fork
    }
}

/// Whether `segment` runs from the anchored head to `current`, each head
/// naming the one before it.
fn descends(
    keys: &HeadKeys,
    binding: &str,
    incarnation_id: &str,
    anchor: &Anchor,
    current: &[u8],
    segment: &[Vec<u8>],
) -> bool {
    let Ok(current_sequence) = inspect(current) else {
        return false;
    };
    let expected = (current_sequence - anchor.sequence + 1) as usize;
    if segment.len() != expected
        || segment.last().map(Vec::as_slice) != Some(current)
        || hex::encode(digest(&segment[0])) != anchor.digest
    {
        return false;
    }
    segment.windows(2).all(|pair| {
        let (Ok(earlier), Ok(later)) = (inspect(&pair[0]), open(keys, binding, &pair[1])) else {
            return false;
        };
        later.sequence == earlier + 1
            && later.previous.as_deref() == Some(hex::encode(digest(&pair[0]))).as_deref()
            && later.incarnation_id == incarnation_id
    })
}

/// What a device logs when it re-anchors: from what it remembered to the
/// current head, and why. Every client re-anchors through [`reanchor`] and
/// keeps these, so a re-anchoring is never silent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Reanchored {
    pub from: Anchor,
    pub to: Anchor,
    /// The status the check found: `tooOld`, `rollback` or `fork`.
    pub status: HeadStatus,
    /// When, in Unix milliseconds.
    pub at_ms: u64,
}

/// Re-anchors this device on the current head when [`check`] did not trust
/// it. It runs the check again itself:
/// - `tooOld` re-anchors (the client shows a notice);
/// - `rollback` and `fork` re-anchor only when the person `confirmed` it (a
///   restore from a backup looks the same; the person decides);
/// - a trusted head needs no re-anchoring (an error).
///
/// Returns the record to log and the newly verified head.
#[allow(clippy::too_many_arguments)]
pub fn reanchor(
    keys: &HeadKeys,
    binding: &str,
    incarnation_id: &str,
    anchor: &Anchor,
    current: &[u8],
    segment: Option<&[Vec<u8>]>,
    confirmed: bool,
    at_ms: u64,
) -> Result<(Reanchored, VerifiedHead)> {
    let checked = check(
        keys,
        binding,
        incarnation_id,
        Some(anchor),
        current,
        segment,
    )?;
    match checked.status {
        HeadStatus::TooOld => {}
        HeadStatus::Rollback | HeadStatus::Fork if confirmed => {}
        HeadStatus::Rollback | HeadStatus::Fork => {
            return Err(invalid(
                "a rollback or a fork is re-anchored only when the person confirms it",
            ))
        }
        HeadStatus::Fresh | HeadStatus::Current | HeadStatus::Extends => {
            return Err(invalid("nothing to re-anchor: the head is trusted"))
        }
    }
    let head = open(keys, binding, current)?;
    let verified = verified(head, current)?;
    Ok((
        Reanchored {
            from: anchor.clone(),
            to: verified.anchor.clone(),
            status: checked.status,
            at_ms,
        },
        verified,
    ))
}

/// What a scope's index says against the verified head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IndexCheck {
    /// The index is exactly the one the head describes.
    Matches,
    /// The head does not cover the scope yet: trust on first use, until the
    /// scope's first write puts it in the head.
    Uncovered,
}

/// Checks a scope's index (as the server lists it) against a verified head;
/// an error when it differs (a value rolled back, dropped or brought back).
pub fn check_index(
    keys: &HeadKeys,
    verified: &VerifiedHead,
    scope: &str,
    index: &[(String, u64)],
) -> Result<IndexCheck> {
    let Some(entry) = verified.head.scope(scope) else {
        return Ok(IndexCheck::Uncovered);
    };
    if keys.scope_digest(scope, index)? != *entry {
        return Err(invalid("the index does not match the head"));
    }
    Ok(IndexCheck::Matches)
}

/// The account's first head, verified as written (the server has none yet).
pub fn first(
    keys: &HeadKeys,
    binding: &str,
    incarnation_id: &str,
    writer: &str,
    scopes: Vec<ScopeV1>,
) -> Result<(Vec<u8>, VerifiedHead)> {
    let head = AccountHeadV1::first(incarnation_id, writer, scopes)?;
    let sealed = seal(keys, binding, &head)?;
    let verified = verified(head, &sealed)?;
    Ok((sealed, verified))
}

// --- What a device keeps --------------------------------------------------

/// The most entries a device's local log keeps (the newest).
pub const LOCAL_LOG_LEN: usize = 20;
/// The largest sealed local state.
pub const MAX_LOCAL_SEALED_BYTES: usize = 16 * 1024;

/// Something a device notes about its anchor, newest last, so that trusting
/// a head on first use, or moving to another history, is never silent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum LocalHeadEvent {
    /// The device had no anchor (new, cleared, or its state did not open) and
    /// trusted the head it read first. `reason` says why it had none when
    /// that was not a first use: `unreadable` (its stored state did not open).
    #[serde(rename_all = "camelCase")]
    StartedFresh {
        anchor: Anchor,
        at_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// The device moved to another history ([`reanchor`]).
    #[serde(rename_all = "camelCase")]
    Reanchored { record: Reanchored },
    /// The server showed no head at all though the device remembered one (a
    /// restore from before the first head), and the person chose to go on
    /// with the server's data: the anchor was dropped.
    #[serde(rename_all = "camelCase")]
    Forgotten { from: Anchor, at_ms: u64 },
}

/// What one device keeps for one account incarnation: its anchor (the
/// highest verified head it has seen, its own writes included), its writer
/// id, and its log. Every client (web origin, Chat store, CLI profile) keeps
/// one, sealed ([`seal_local_state`]) under the name
/// [`HeadKeys::local_state_name`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalHeadStateV1 {
    pub incarnation_id: String,
    /// Random, this device's: [`HeadKeys::writer`] hashes it into heads.
    pub device_id: String,
    pub anchor: Option<Anchor>,
    /// When the anchor last changed, in Unix milliseconds (0: never).
    pub anchored_at_ms: u64,
    pub log: Vec<LocalHeadEvent>,
    /// Why this state started over before its first anchor (`unreadable`):
    /// kept until the anchor it starts from is logged with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_over: Option<String>,
}

impl LocalHeadStateV1 {
    /// A device's state before it has seen any head, with a new random device id.
    pub fn new(incarnation_id: &str) -> Result<Self> {
        let mut device = [0u8; 16];
        crate::primitives::random(&mut device);
        Self::with_device(incarnation_id, &hex::encode(device))
    }

    /// [`Self::new`] with a given device id (vectors; a device moving its id).
    pub fn with_device(incarnation_id: &str, device_id: &str) -> Result<Self> {
        let state = Self {
            incarnation_id: incarnation_id.to_owned(),
            device_id: device_id.to_owned(),
            anchor: None,
            anchored_at_ms: 0,
            log: Vec::new(),
            started_over: None,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<()> {
        if !is_lower_hex_32(&self.incarnation_id) {
            return Err(invalid("incarnation id is invalid"));
        }
        if self.device_id.is_empty() || self.device_id.len() > 256 {
            return Err(invalid("device id is invalid"));
        }
        if self.log.len() > LOCAL_LOG_LEN {
            return Err(invalid("the local log is too long"));
        }
        Ok(())
    }

    fn note(&mut self, event: LocalHeadEvent) {
        self.log.push(event);
        if self.log.len() > LOCAL_LOG_LEN {
            let extra = self.log.len() - LOCAL_LOG_LEN;
            self.log.drain(..extra);
        }
    }

    /// A head this device verified ([`check`] or [`VerifiedHead::committed`]):
    /// the anchor moves to it, never back (another tab may have stored a later
    /// one meanwhile; that one stays). The first anchor is logged as started
    /// fresh. Returns whether anything changed.
    pub fn advance(&mut self, verified: &VerifiedHead, at_ms: u64) -> bool {
        let anchor = verified.anchor();
        match &self.anchor {
            Some(known) if known.sequence >= anchor.sequence => false,
            Some(_) => {
                self.anchor = Some(anchor.clone());
                self.anchored_at_ms = at_ms;
                true
            }
            None => {
                self.anchor = Some(anchor.clone());
                self.anchored_at_ms = at_ms;
                let reason = self.started_over.take();
                self.note(LocalHeadEvent::StartedFresh {
                    anchor: anchor.clone(),
                    at_ms,
                    reason,
                });
                true
            }
        }
    }

    /// The server has no head at all, this device remembered one, and the
    /// person confirmed going on with the server's data: the anchor is
    /// dropped and logged, and the next head is trusted on first use. Returns
    /// whether there was an anchor to drop.
    pub fn forgotten(&mut self, at_ms: u64) -> bool {
        let Some(from) = self.anchor.take() else {
            return false;
        };
        self.anchored_at_ms = at_ms;
        self.note(LocalHeadEvent::Forgotten { from, at_ms });
        true
    }

    /// A fresh state that replaces one which did not open (`reason`, e.g.
    /// `unreadable`): the anchor it then starts from is logged with why.
    pub fn starting_over(mut self, reason: &str) -> Self {
        self.started_over = Some(reason.to_owned());
        self
    }

    /// After [`reanchor`]: the anchor moves to the new head, back or sideways
    /// as the person (or the window) decided, and the record is logged.
    pub fn reanchored(&mut self, record: &Reanchored) {
        self.anchor = Some(record.to.clone());
        self.anchored_at_ms = record.at_ms;
        self.note(LocalHeadEvent::Reanchored {
            record: record.clone(),
        });
    }
}

fn local_aad(binding: &str, incarnation_id: &str) -> Result<Vec<u8>> {
    let binding = key_binding::check(binding).map_err(|_| invalid("key binding is invalid"))?;
    Ok([
        LOCAL_MAGIC.as_slice(),
        &SUITE.to_be_bytes(),
        LOCAL_AAD_DOMAIN,
        &(binding.len() as u16).to_be_bytes(),
        binding.as_bytes(),
        incarnation_id.as_bytes(),
    ]
    .concat())
}

/// Seals a device's state for the account bound to `binding`:
/// `magic ‖ suite ‖ nonce ‖ ciphertext`, bound to the binding and the
/// incarnation, so it opens for no other account or incarnation.
pub fn seal_local_state(
    keys: &HeadKeys,
    binding: &str,
    state: &LocalHeadStateV1,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::primitives::random(&mut nonce);
    seal_local_with_nonce(keys, binding, state, &nonce)
}

/// [`seal_local_state`] with a fixed nonce, for checked-in vectors only.
#[cfg(any(test, feature = "test-vectors"))]
pub fn seal_local_state_for_vectors(
    keys: &HeadKeys,
    binding: &str,
    state: &LocalHeadStateV1,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    seal_local_with_nonce(keys, binding, state, nonce)
}

fn seal_local_with_nonce(
    keys: &HeadKeys,
    binding: &str,
    state: &LocalHeadStateV1,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    state.validate()?;
    let plain = Zeroizing::new(serde_json::to_vec(state).map_err(|_| invalid("encode"))?);
    let ciphertext = Aead::new(Suite::V1, keys.seal.as_ref())?
        .seal_with_nonce(nonce, &local_aad(binding, &state.incarnation_id)?, &plain)
        .map_err(|_| CryptoError::Backend("account head local seal".into()))?;
    let sealed = [
        LOCAL_MAGIC.as_slice(),
        &SUITE.to_be_bytes(),
        nonce,
        &ciphertext,
    ]
    .concat();
    if sealed.len() > MAX_LOCAL_SEALED_BYTES {
        return Err(invalid("the local state is too large"));
    }
    Ok(sealed)
}

/// Opens a device's state for the account bound to `binding`, incarnation
/// `incarnation_id`. Anything that does not open (altered, moved from another
/// account or incarnation, another format) is an error: the device then
/// starts fresh, which a disk attacker could cause by deleting it anyway.
pub fn open_local_state(
    keys: &HeadKeys,
    binding: &str,
    incarnation_id: &str,
    sealed: &[u8],
) -> Result<LocalHeadStateV1> {
    let header = 8 + 2 + NONCE_LEN;
    if sealed.len() <= header + TAG_LEN || sealed.len() > MAX_LOCAL_SEALED_BYTES {
        return Err(invalid("size is invalid"));
    }
    if &sealed[..8] != LOCAL_MAGIC || sealed[8..10] != SUITE.to_be_bytes() {
        return Err(invalid("not a local head state"));
    }
    let plain = Zeroizing::new(
        Aead::new(Suite::V1, keys.seal.as_ref())?
            .open_with_nonce(
                &sealed[10..header],
                &local_aad(binding, incarnation_id)?,
                &sealed[header..],
            )
            .map_err(|_| CryptoError::AuthFailed)?,
    );
    let state: LocalHeadStateV1 = serde_json::from_slice(&plain).map_err(|_| invalid("decode"))?;
    state.validate()?;
    if state.incarnation_id != incarnation_id {
        return Err(invalid("the local state is another incarnation's"));
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
    const INCARNATION: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn keys() -> HeadKeys {
        HeadKeys::derive(&[7u8; 32]).unwrap()
    }

    fn index(pairs: &[(&str, u64)]) -> Vec<(String, u64)> {
        pairs
            .iter()
            .map(|(id, rev)| (id.to_string(), *rev))
            .collect()
    }

    /// A chain of `n` sealed heads; each adds a contact.
    fn chain(keys: &HeadKeys, n: usize) -> Vec<Vec<u8>> {
        let writer = keys.writer("device-a").unwrap();
        let mut sealed = Vec::new();
        let mut contacts: Vec<(String, u64)> = Vec::new();
        for i in 0..n {
            contacts.push((format!("contact-{i}"), 100 + i as u64));
            let entry = keys.scope_digest("contacts", &contacts).unwrap();
            let head = if i == 0 {
                AccountHeadV1::first(INCARNATION, &writer, vec![entry]).unwrap()
            } else {
                let before: &Vec<u8> = &sealed[i - 1];
                open(keys, BINDING, before)
                    .unwrap()
                    .next(before, &writer, vec![entry])
                    .unwrap()
            };
            sealed.push(seal(keys, BINDING, &head).unwrap());
        }
        sealed
    }

    #[test]
    fn a_head_round_trips_and_binds_its_account_and_sequence() {
        let keys = keys();
        let sealed = chain(&keys, 2);
        let head = open(&keys, BINDING, &sealed[1]).unwrap();
        assert_eq!(head.sequence, 2);
        assert_eq!(inspect(&sealed[1]).unwrap(), 2);
        assert_eq!(head.previous, Some(hex::encode(digest(&sealed[0]))));
        assert!(open(&keys, "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d", &sealed[1]).is_err());
        assert!(open(&HeadKeys::derive(&[8u8; 32]).unwrap(), BINDING, &sealed[1]).is_err());
        let mut relabelled = sealed[1].clone();
        relabelled[10..18].copy_from_slice(&3u64.to_be_bytes());
        assert!(open(&keys, BINDING, &relabelled).is_err());
    }

    fn status(
        keys: &HeadKeys,
        anchor: Option<&Anchor>,
        current: &[u8],
        segment: Option<&[Vec<u8>]>,
    ) -> HeadStatus {
        check(keys, BINDING, INCARNATION, anchor, current, segment)
            .unwrap()
            .status
    }

    fn verified_of(keys: &HeadKeys, sealed: &[u8]) -> VerifiedHead {
        check(keys, BINDING, INCARNATION, None, sealed, None)
            .unwrap()
            .verified
            .unwrap()
    }

    #[test]
    fn an_index_is_checked_only_against_a_verified_head() {
        let keys = keys();
        let entry = keys
            .scope_digest("contacts", &index(&[("a", 1), ("b", 2)]))
            .unwrap();
        let (_, head) = first(
            &keys,
            BINDING,
            INCARNATION,
            &keys.writer("d").unwrap(),
            vec![entry],
        )
        .unwrap();
        assert_eq!(
            check_index(&keys, &head, "contacts", &index(&[("b", 2), ("a", 1)])).unwrap(),
            IndexCheck::Matches
        );
        // A rolled-back value, a dropped one, one brought back: refused.
        assert!(check_index(&keys, &head, "contacts", &index(&[("a", 1), ("b", 1)])).is_err());
        assert!(check_index(&keys, &head, "contacts", &index(&[("a", 1)])).is_err());
        assert!(check_index(
            &keys,
            &head,
            "contacts",
            &index(&[("a", 1), ("b", 2), ("c", 3)])
        )
        .is_err());
        assert_eq!(
            check_index(&keys, &head, "mailNames", &index(&[("x", 1)])).unwrap(),
            IndexCheck::Uncovered
        );
        assert!(keys
            .scope_digest("contacts", &index(&[("a", 1), ("a", 2)]))
            .is_err());
        assert!(keys.scope_digest("contacts", &index(&[("a", 0)])).is_err());
    }

    #[test]
    fn devices_tell_extension_rollback_fork_and_age_apart() {
        let keys = keys();
        let sealed = chain(&keys, 4);
        let anchor = verified_of(&keys, &sealed[1]).anchor().clone();
        assert_eq!(status(&keys, None, &sealed[3], None), HeadStatus::Fresh);
        assert_eq!(
            status(&keys, Some(&anchor), &sealed[1], None),
            HeadStatus::Current
        );
        assert_eq!(
            status(&keys, Some(&anchor), &sealed[3], Some(&sealed[1..])),
            HeadStatus::Extends
        );
        assert_eq!(
            status(&keys, Some(&anchor), &sealed[0], None),
            HeadStatus::Rollback
        );
        // A segment withheld inside the server's window is no excuse: a fork.
        assert_eq!(
            status(&keys, Some(&anchor), &sealed[3], None),
            HeadStatus::Fork
        );
        // Another history from head 2 on, at the same sequence or later.
        let other = {
            let writer = keys.writer("device-b").unwrap();
            let entry = keys
                .scope_digest("contacts", &index(&[("evil", 1)]))
                .unwrap();
            let head = open(&keys, BINDING, &sealed[0])
                .unwrap()
                .next(&sealed[0], &writer, vec![entry])
                .unwrap();
            let second = seal(&keys, BINDING, &head).unwrap();
            let third = open(&keys, BINDING, &second)
                .unwrap()
                .next(&second, &writer, vec![])
                .unwrap();
            vec![second.clone(), seal(&keys, BINDING, &third).unwrap()]
        };
        assert_eq!(
            status(&keys, Some(&anchor), &other[0], None),
            HeadStatus::Fork
        );
        assert_eq!(
            status(&keys, Some(&anchor), &other[1], Some(&other)),
            HeadStatus::Fork
        );
        // A segment that does not reach the current head, or is spliced: a fork.
        assert_eq!(
            status(&keys, Some(&anchor), &sealed[3], Some(&sealed[1..3])),
            HeadStatus::Fork
        );
        let spliced = vec![sealed[1].clone(), other[1].clone(), sealed[3].clone()];
        assert_eq!(
            status(&keys, Some(&anchor), &sealed[3], Some(&spliced)),
            HeadStatus::Fork
        );
        // Only trusted outcomes give a verified head.
        assert!(
            check(&keys, BINDING, INCARNATION, Some(&anchor), &sealed[0], None)
                .unwrap()
                .verified
                .is_none()
        );
        // Another incarnation's head: refused.
        assert!(check(
            &keys,
            BINDING,
            &"2".repeat(64),
            Some(&anchor),
            &sealed[3],
            Some(&sealed[1..])
        )
        .is_err());
    }

    #[test]
    fn too_old_only_past_what_the_server_keeps() {
        let keys = keys();
        let sealed = chain(&keys, 1);
        let old = Anchor {
            sequence: 1,
            digest: hex::encode(digest(&sealed[0])),
        };
        // A head far past the anchor, with no chain shown.
        let writer = keys.writer("d").unwrap();
        let mut far = open(&keys, BINDING, &sealed[0]).unwrap();
        far.sequence = 1 + RETENTION + 1;
        far.previous = Some("ab".repeat(32));
        far.writer = writer;
        let far = seal(&keys, BINDING, &far).unwrap();
        assert_eq!(status(&keys, Some(&old), &far, None), HeadStatus::TooOld);
        let mut near = open(&keys, BINDING, &far).unwrap();
        near.sequence = 1 + RETENTION;
        let near = seal(&keys, BINDING, &near).unwrap();
        assert_eq!(status(&keys, Some(&old), &near, None), HeadStatus::Fork);
    }

    #[test]
    fn a_head_is_written_on_the_verified_one_and_committed() {
        let keys = keys();
        let sealed = chain(&keys, 2);
        let verified = verified_of(&keys, &sealed[1]);
        let writer = keys.writer("device-a").unwrap();
        let next = seal(&keys, BINDING, &verified.next(&writer, vec![]).unwrap()).unwrap();
        let committed = verified.committed(&keys, BINDING, &next).unwrap();
        assert_eq!(committed.anchor().sequence, 3);
        // Something else than its direct successor is not committed.
        assert!(verified.committed(&keys, BINDING, &sealed[0]).is_err());
        assert!(committed.committed(&keys, BINDING, &next).is_err());
    }

    #[test]
    fn heads_are_canonical_and_well_formed() {
        let keys = keys();
        let writer = keys.writer("d").unwrap();
        let a = keys.scope_digest("a", &[]).unwrap();
        let b = keys.scope_digest("b", &[]).unwrap();
        let head = AccountHeadV1::first(INCARNATION, &writer, vec![b.clone(), a.clone()]).unwrap();
        assert_eq!(head.scopes, vec![a.clone(), b.clone()], "sorted");
        let mut twice = head.clone();
        twice.scopes = vec![a.clone(), a];
        assert!(seal(&keys, BINDING, &twice).is_err());
        let mut no_previous = head.clone();
        no_previous.sequence = 2;
        assert!(seal(&keys, BINDING, &no_previous).is_err());
        assert!(keys.scope_digest("bad scope", &[]).is_err());
    }

    #[test]
    fn reanchoring_needs_the_check_and_for_a_fork_the_person() {
        let keys = keys();
        let sealed = chain(&keys, 3);
        let anchor = verified_of(&keys, &sealed[2]).anchor().clone();
        // A rollback: refused unless confirmed; the record carries what the check found.
        assert!(reanchor(
            &keys,
            BINDING,
            INCARNATION,
            &anchor,
            &sealed[0],
            None,
            false,
            5
        )
        .is_err());
        let (record, verified) = reanchor(
            &keys,
            BINDING,
            INCARNATION,
            &anchor,
            &sealed[0],
            None,
            true,
            5,
        )
        .unwrap();
        assert_eq!(record.status, HeadStatus::Rollback);
        assert_eq!(
            (&record.from, &record.to, record.at_ms),
            (&anchor, verified.anchor(), 5)
        );
        // A trusted head needs no re-anchoring.
        assert!(reanchor(
            &keys,
            BINDING,
            INCARNATION,
            &anchor,
            &sealed[2],
            None,
            true,
            5
        )
        .is_err());
    }

    #[test]
    fn a_device_state_opens_only_for_its_account_and_incarnation() {
        let keys = keys();
        let other = "2222222222222222222222222222222222222222222222222222222222222222";
        // One name per account and incarnation.
        assert_ne!(
            keys.local_state_name(INCARNATION).unwrap(),
            keys.local_state_name(other).unwrap()
        );
        assert_ne!(
            keys.local_state_name(INCARNATION).unwrap(),
            HeadKeys::derive(&[8u8; 32])
                .unwrap()
                .local_state_name(INCARNATION)
                .unwrap()
        );
        let state = LocalHeadStateV1::new(INCARNATION).unwrap();
        assert_eq!(state.device_id.len(), 32);
        let sealed = seal_local_state(&keys, BINDING, &state).unwrap();
        assert_eq!(
            open_local_state(&keys, BINDING, INCARNATION, &sealed).unwrap(),
            state
        );
        // Another incarnation, binding or account: it does not open.
        assert!(open_local_state(&keys, BINDING, other, &sealed).is_err());
        assert!(open_local_state(
            &keys,
            "1b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b",
            INCARNATION,
            &sealed
        )
        .is_err());
        assert!(open_local_state(
            &HeadKeys::derive(&[8u8; 32]).unwrap(),
            BINDING,
            INCARNATION,
            &sealed
        )
        .is_err());
        // Altered: it does not open.
        let mut altered = sealed.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(open_local_state(&keys, BINDING, INCARNATION, &altered).is_err());
        // A head is not a local state.
        assert!(open_local_state(&keys, BINDING, INCARNATION, &chain(&keys, 1)[0]).is_err());
    }

    #[test]
    fn a_device_anchor_only_moves_forward_unless_reanchored() {
        let keys = keys();
        let sealed = chain(&keys, 3);
        let verified = |i: usize| {
            check(&keys, BINDING, INCARNATION, None, &sealed[i], None)
                .unwrap()
                .verified
                .unwrap()
        };
        let mut state = LocalHeadStateV1::with_device(INCARNATION, "device-a").unwrap();
        // The first anchor is trusted on first use, and says so.
        assert!(state.advance(&verified(1), 10));
        assert_eq!(state.anchor.as_ref().unwrap().sequence, 2);
        assert!(matches!(
            state.log.as_slice(),
            [LocalHeadEvent::StartedFresh { at_ms: 10, .. }]
        ));
        // Forward only: another tab's later anchor stays.
        assert!(state.advance(&verified(2), 20));
        assert!(!state.advance(&verified(0), 30));
        assert_eq!(state.anchor.as_ref().unwrap().sequence, 3);
        assert_eq!(state.anchored_at_ms, 20);
        assert_eq!(state.log.len(), 1);
        // A confirmed re-anchoring moves it back, and is logged.
        let anchor = state.anchor.clone().unwrap();
        let (record, _) = reanchor(
            &keys,
            BINDING,
            INCARNATION,
            &anchor,
            &sealed[0],
            None,
            true,
            40,
        )
        .unwrap();
        state.reanchored(&record);
        assert_eq!(state.anchor.as_ref().unwrap().sequence, 1);
        assert!(matches!(
            state.log.last(),
            Some(LocalHeadEvent::Reanchored { .. })
        ));
        // The log keeps the newest.
        for at in 0..(LOCAL_LOG_LEN as u64 + 5) {
            state.reanchored(&Reanchored {
                at_ms: 100 + at,
                ..record.clone()
            });
        }
        assert_eq!(state.log.len(), LOCAL_LOG_LEN);
        assert!(
            matches!(state.log.last(), Some(LocalHeadEvent::Reanchored { record }) if record.at_ms == 100 + LOCAL_LOG_LEN as u64 + 4)
        );
        // A server with no head at all: dropped only on the person's word, logged.
        let mut gone = state.clone();
        assert!(gone.forgotten(50));
        assert_eq!(gone.anchor, None);
        assert!(matches!(
            gone.log.last(),
            Some(LocalHeadEvent::Forgotten { at_ms: 50, .. })
        ));
        assert!(!gone.forgotten(60));
        let sealed_state = seal_local_state(&keys, BINDING, &state).unwrap();
        assert_eq!(
            open_local_state(&keys, BINDING, INCARNATION, &sealed_state).unwrap(),
            state
        );
    }

    #[test]
    fn a_state_that_started_over_says_why_with_its_first_anchor() {
        let keys = keys();
        let sealed = chain(&keys, 1);
        let state = LocalHeadStateV1::with_device(INCARNATION, "device-a")
            .unwrap()
            .starting_over("unreadable");
        // Kept through a save until the first anchor.
        let reopened = open_local_state(
            &keys,
            BINDING,
            INCARNATION,
            &seal_local_state(&keys, BINDING, &state).unwrap(),
        )
        .unwrap();
        assert_eq!(reopened.started_over.as_deref(), Some("unreadable"));
        let mut state = reopened;
        let verified = check(&keys, BINDING, INCARNATION, None, &sealed[0], None)
            .unwrap()
            .verified
            .unwrap();
        state.advance(&verified, 7);
        assert!(matches!(
            state.log.as_slice(),
            [LocalHeadEvent::StartedFresh { reason: Some(reason), .. }] if reason == "unreadable"
        ));
        assert_eq!(state.started_over, None);
    }
}
