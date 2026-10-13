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

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
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
const MAGIC: &[u8; 8] = b"KUTAH1\0\0";
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
        let hkdf = Hkdf::<Sha256>::new(Some(SALT), master_key);
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
    copy_randombytes(&mut nonce);
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
    let ciphertext = XChaCha20Poly1305::new(keys.seal.as_slice().into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &plain,
                aad: &aad(binding, head.sequence)?,
            },
        )
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
    let plain = XChaCha20Poly1305::new(keys.seal.as_slice().into())
        .decrypt(
            XNonce::from_slice(&sealed[18..HEADER_LEN]),
            Payload {
                msg: &sealed[HEADER_LEN..],
                aad: &aad(binding, sequence)?,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    let head: AccountHeadV1 = serde_json::from_slice(&plain).map_err(|_| invalid("decode"))?;
    head.validate()?;
    if head.sequence != sequence || serde_json::to_vec(&head).ok().as_deref() != Some(&plain[..]) {
        return Err(invalid("the head is not canonical"));
    }
    Ok(head)
}

/// What a device remembers of a head: its sequence and digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Anchor {
    pub sequence: u64,
    /// Lowercase hex.
    pub digest: String,
}

impl Anchor {
    /// The anchor of a sealed head.
    pub fn of(sealed: &[u8]) -> Result<Self> {
        Ok(Self {
            sequence: inspect(sealed)?,
            digest: hex::encode(digest(sealed)),
        })
    }
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
    /// back (or was restored from a backup).
    Rollback,
    /// A head at or after the remembered sequence that does not descend from
    /// the remembered head: another history (or a restore from a backup).
    Fork,
    /// The remembered head is older than the chain the server keeps: it can be
    /// neither confirmed nor refuted; re-anchor, with a notice.
    TooOld,
}

/// Checks the current head (`current`, sealed) against `anchor`, what this
/// device remembers (its highest seen, or its own last write). `segment` is
/// the chain from the anchor's sequence to the current one inclusive, as the
/// server returns it, or `None` when the server no longer keeps it (`410`).
/// The current head must open, and name `incarnation_id`.
pub fn check(
    keys: &HeadKeys,
    binding: &str,
    incarnation_id: &str,
    anchor: Option<&Anchor>,
    current: &[u8],
    segment: Option<&[Vec<u8>]>,
) -> Result<HeadStatus> {
    let head = open(keys, binding, current)?;
    if head.incarnation_id != incarnation_id {
        return Err(invalid("the head is another incarnation's"));
    }
    let Some(anchor) = anchor else {
        return Ok(HeadStatus::Fresh);
    };
    if head.sequence < anchor.sequence {
        return Ok(HeadStatus::Rollback);
    }
    if head.sequence == anchor.sequence {
        return Ok(if hex::encode(digest(current)) == anchor.digest {
            HeadStatus::Current
        } else {
            HeadStatus::Fork
        });
    }
    let Some(segment) = segment else {
        return Ok(HeadStatus::TooOld);
    };
    // The segment runs from the remembered head to the current one, each head
    // naming the one before it.
    let expected = (head.sequence - anchor.sequence + 1) as usize;
    if segment.len() != expected || segment.last().map(Vec::as_slice) != Some(current) {
        return Err(invalid("the chain segment does not reach the current head"));
    }
    if hex::encode(digest(&segment[0])) != anchor.digest {
        return Ok(HeadStatus::Fork);
    }
    for pair in segment.windows(2) {
        let later = open(keys, binding, &pair[1])?;
        let earlier_sequence = inspect(&pair[0])?;
        if later.sequence != earlier_sequence + 1
            || later.previous.as_deref() != Some(hex::encode(digest(&pair[0]))).as_deref()
            || later.incarnation_id != incarnation_id
        {
            return Err(invalid("the chain segment is broken"));
        }
    }
    Ok(HeadStatus::Extends)
}

/// What a device logs when it re-anchors: from what it remembered to the
/// current head, and why. Every client re-anchors through [`reanchor`] and
/// keeps these, so a re-anchoring is never silent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Reanchored {
    pub from: Option<Anchor>,
    pub to: Anchor,
    /// The status that led to it: `fresh`, `tooOld` (no notice needed beyond
    /// a passing one), or `rollback` / `fork`, which only the person decides.
    pub reason: String,
    /// When, in Unix milliseconds.
    pub at_ms: u64,
}

/// Re-anchors this device on the current head (`current`, sealed), after
/// [`check`] gave `status`: a first use, a remembered head too old to verify,
/// or, only when the person chose it, a rollback or fork (a restore from a
/// backup). The head must open and name `incarnation_id`. Returns the new
/// anchor and the record to log.
pub fn reanchor(
    keys: &HeadKeys,
    binding: &str,
    incarnation_id: &str,
    from: Option<&Anchor>,
    current: &[u8],
    status: &HeadStatus,
    at_ms: u64,
) -> Result<Reanchored> {
    let head = open(keys, binding, current)?;
    if head.incarnation_id != incarnation_id {
        return Err(invalid("the head is another incarnation's"));
    }
    let reason = match status {
        HeadStatus::Fresh => "fresh",
        HeadStatus::TooOld => "tooOld",
        HeadStatus::Rollback => "rollback",
        HeadStatus::Fork => "fork",
        HeadStatus::Current | HeadStatus::Extends => {
            return Err(invalid(
                "nothing to re-anchor: the head descends from the anchor",
            ))
        }
    };
    Ok(Reanchored {
        from: from.cloned(),
        to: Anchor::of(current)?,
        reason: reason.to_owned(),
        at_ms,
    })
}

/// Checks a scope's index (as the server lists it) against the verified head:
/// `Ok(true)` if it matches, `Ok(false)` if the head does not cover the scope
/// yet (trust on first use until its first write), an error if it differs.
pub fn check_index(
    keys: &HeadKeys,
    head: &AccountHeadV1,
    scope: &str,
    index: &[(String, u64)],
) -> Result<bool> {
    let Some(entry) = head.scope(scope) else {
        return Ok(false);
    };
    if keys.scope_digest(scope, index)? != *entry {
        return Err(invalid("the index does not match the head"));
    }
    Ok(true)
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

    #[test]
    fn an_index_is_checked_whatever_its_order() {
        let keys = keys();
        let entry = keys
            .scope_digest("contacts", &index(&[("a", 1), ("b", 2)]))
            .unwrap();
        let head =
            AccountHeadV1::first(INCARNATION, &keys.writer("d").unwrap(), vec![entry]).unwrap();
        assert!(check_index(&keys, &head, "contacts", &index(&[("b", 2), ("a", 1)])).unwrap());
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
        // A scope the head does not cover yet.
        assert!(!check_index(&keys, &head, "mailNames", &index(&[("x", 1)])).unwrap());
        // Twice the same id, or revision 0: not an index.
        assert!(keys
            .scope_digest("contacts", &index(&[("a", 1), ("a", 2)]))
            .is_err());
        assert!(keys.scope_digest("contacts", &index(&[("a", 0)])).is_err());
    }

    #[test]
    fn devices_tell_extension_rollback_fork_and_age_apart() {
        let keys = keys();
        let sealed = chain(&keys, 4);
        let anchor = Anchor::of(&sealed[1]).unwrap();
        let status = |current: &[u8], segment: Option<&[Vec<u8>]>| {
            check(&keys, BINDING, INCARNATION, Some(&anchor), current, segment).unwrap()
        };
        assert_eq!(
            check(&keys, BINDING, INCARNATION, None, &sealed[3], None).unwrap(),
            HeadStatus::Fresh
        );
        assert_eq!(status(&sealed[1], None), HeadStatus::Current);
        assert_eq!(status(&sealed[3], Some(&sealed[1..])), HeadStatus::Extends);
        assert_eq!(status(&sealed[0], None), HeadStatus::Rollback);
        assert_eq!(status(&sealed[3], None), HeadStatus::TooOld);
        // Another history from head 2 on: a fork, at the same sequence or later.
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
        assert_eq!(status(&other[0], None), HeadStatus::Fork);
        assert_eq!(status(&other[1], Some(&other)), HeadStatus::Fork);
        // A segment that does not reach the current head, or is broken: refused.
        assert!(check(
            &keys,
            BINDING,
            INCARNATION,
            Some(&anchor),
            &sealed[3],
            Some(&sealed[1..3])
        )
        .is_err());
        let spliced = vec![sealed[1].clone(), other[1].clone(), sealed[3].clone()];
        assert!(check(
            &keys,
            BINDING,
            INCARNATION,
            Some(&anchor),
            &sealed[3],
            Some(&spliced)
        )
        .is_err());
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
    fn reanchoring_is_explicit_and_recorded() {
        let keys = keys();
        let sealed = chain(&keys, 3);
        let anchor = Anchor::of(&sealed[2]).unwrap();
        let record = reanchor(
            &keys,
            BINDING,
            INCARNATION,
            Some(&anchor),
            &sealed[0],
            &HeadStatus::Rollback,
            5,
        )
        .unwrap();
        assert_eq!(record.to, Anchor::of(&sealed[0]).unwrap());
        assert_eq!(
            (record.from, record.reason.as_str(), record.at_ms),
            (Some(anchor.clone()), "rollback", 5)
        );
        // A head that descends needs no re-anchoring.
        assert!(reanchor(
            &keys,
            BINDING,
            INCARNATION,
            Some(&anchor),
            &sealed[2],
            &HeadStatus::Current,
            5
        )
        .is_err());
        assert!(reanchor(
            &keys,
            BINDING,
            &"2".repeat(64),
            None,
            &sealed[0],
            &HeadStatus::Fresh,
            5
        )
        .is_err());
    }
}
