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

use crate::error::{CryptoError, Result};
use crate::identity::incarnation_id_from_authority_public;
use crate::key_binding;
use crate::named_share::canonical_account;

const PINS_KEY_SALT: &[u8] = b"kutup/identity-pins/v1\0";
const PINS_KEY_INFO: &[u8] = b"kutup/identity-pins/list-key/v1\0";
const MAGIC: &[u8; 8] = b"KUTIP2\0\0";
const AAD_DOMAIN: &[u8] = b"kutup/identity-pins/v2\0";
const SUITE: u16 = 2;
const NONCE_LEN: usize = 24;
const REVISION_LEN: usize = 8;
const HEADER_LEN: usize = 8 + 2 + REVISION_LEN + NONCE_LEN;
const TAG_LEN: usize = 16;

/// The most accounts one list keeps.
pub const MAX_PINS: usize = 10_000;
/// Earlier identities kept for one address (after accepted changes).
pub const MAX_REPLACED: usize = 10;
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
        Ok(())
    }
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
    let plain = Zeroizing::new(encode(list)?);
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
    Ok((decode(&plain)?, revision))
}

/// Checks a sealed list's framing, size and revision without opening it (the
/// server's view), and returns the revision.
pub fn inspect(sealed: &[u8]) -> Result<u64> {
    if sealed.len() <= HEADER_LEN + TAG_LEN || sealed.len() > HEADER_LEN + MAX_LIST_BYTES + TAG_LEN
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
pub const MAX_SEALED_BYTES: usize = HEADER_LEN + MAX_LIST_BYTES + TAG_LEN;

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
}
