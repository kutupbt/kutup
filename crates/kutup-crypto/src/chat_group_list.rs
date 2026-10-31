//! An account's list of its Chat groups (docs/plans/pairwise-groups.md §5):
//! one sealed entry per group, kept by the account's server so that a new
//! device of the account can take its groups up.
//!
//! - Two keys come from the account master key: the id key names each entry
//!   (an HMAC of the group id, so the server never sees a group id and can't
//!   match one account's entries with another's), the seal key seals it.
//! - A sealed entry is `magic ‖ suite u16 ‖ revision u64 ‖ nonce ‖
//!   ciphertext+tag`, always exactly [`SEALED_LEN`] bytes: the plaintext is
//!   padded to one size, so the server learns nothing from it. The server
//!   reads the revision from the header ([`inspect`]) to order writes.
//! - The AAD binds the header, the account's key binding and the entry id, so
//!   an entry opens only under its own id and revision, for this incarnation
//!   of the account.

use crate::primitives::{Aead, Kdf, Mac, Suite};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::chat_group::GROUP_ID_LEN;
use crate::error::{CryptoError, Result};

const SALT: &[u8] = crate::labels::CHAT_GROUP_LIST_V1;
const ID_KEY_INFO: &[u8] = crate::labels::CHAT_GROUP_LIST_ID_KEY_V1;
const SEAL_KEY_INFO: &[u8] = crate::labels::CHAT_GROUP_LIST_SEAL_KEY_V1;
const ID_DOMAIN: &[u8] = crate::labels::CHAT_GROUP_LIST_ID_V1;

const MAGIC: &[u8; 8] = b"KUTPGL1\0";
/// XChaCha20-Poly1305 under the list's seal key.
pub const SUITE_V1: u16 = 1;
pub const ENTRY_ID_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = MAGIC.len() + 2 + 8 + NONCE_LEN;
/// Every sealed entry is exactly this long.
pub const SEALED_LEN: usize = 4096 - 64;
const PADDED_LEN: usize = SEALED_LEN - HEADER_LEN - TAG_LEN;
/// The longest entry plaintext (the padded plaintext starts with its u16 length).
pub const MAX_PLAIN_LEN: usize = PADDED_LEN - 2;

/// The keys of an account's group list, from its master key.
pub struct GroupListKey {
    id_key: Zeroizing<[u8; 32]>,
    seal_key: Zeroizing<[u8; 32]>,
}

/// An opened entry: its revision (from the authenticated header) and plaintext.
pub struct OpenedEntry {
    pub revision: u64,
    pub plain: Zeroizing<Vec<u8>>,
}

impl GroupListKey {
    pub fn derive(account_master_key: &[u8; 32]) -> Self {
        let hkdf = Kdf::new(Suite::V1, SALT, account_master_key);
        let mut id_key = Zeroizing::new([0u8; 32]);
        let mut seal_key = Zeroizing::new([0u8; 32]);
        hkdf.expand(ID_KEY_INFO, id_key.as_mut())
            .expect("HKDF output length is fixed and valid");
        hkdf.expand(SEAL_KEY_INFO, seal_key.as_mut())
            .expect("HKDF output length is fixed and valid");
        Self { id_key, seal_key }
    }

    /// The entry id of `group_id` in this account's list.
    pub fn entry_id(&self, group_id: &[u8; GROUP_ID_LEN]) -> [u8; ENTRY_ID_LEN] {
        let mut mac = Mac::new(Suite::V1, self.id_key.as_ref());
        mac.update(ID_DOMAIN);
        mac.update(group_id);
        mac.finish().to_array()
    }

    /// Seals an entry's plaintext for `entry_id` at `revision`, bound to the
    /// account's key `binding`.
    pub fn seal(
        &self,
        binding: &str,
        entry_id: &[u8; ENTRY_ID_LEN],
        revision: u64,
        plain: &[u8],
    ) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        crate::primitives::random(&mut nonce);
        self.seal_with_nonce(binding, entry_id, revision, plain, &nonce)
    }

    #[cfg(any(test, feature = "test-vectors"))]
    pub fn seal_with_fixed_nonce(
        &self,
        binding: &str,
        entry_id: &[u8; ENTRY_ID_LEN],
        revision: u64,
        plain: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        self.seal_with_nonce(binding, entry_id, revision, plain, nonce)
    }

    /// The id key and the seal key, for the checked-in vector only.
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn vector_keys(&self) -> ([u8; 32], [u8; 32]) {
        (*self.id_key, *self.seal_key)
    }

    fn seal_with_nonce(
        &self,
        binding: &str,
        entry_id: &[u8; ENTRY_ID_LEN],
        revision: u64,
        plain: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        if plain.len() > MAX_PLAIN_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "a group list entry is at most {MAX_PLAIN_LEN} bytes"
            )));
        }
        let mut padded = Zeroizing::new(vec![0u8; PADDED_LEN]);
        padded[..2].copy_from_slice(&(plain.len() as u16).to_be_bytes());
        padded[2..2 + plain.len()].copy_from_slice(plain);
        let mut sealed = Vec::with_capacity(SEALED_LEN);
        sealed.extend_from_slice(MAGIC);
        sealed.extend_from_slice(&SUITE_V1.to_be_bytes());
        sealed.extend_from_slice(&revision.to_be_bytes());
        sealed.extend_from_slice(nonce);
        let ciphertext = Aead::new(Suite::V1, self.seal_key.as_ref())?
            .seal_with_nonce(
                nonce,
                &aad(&sealed[..MAGIC.len() + 10], binding, entry_id)?,
                &padded,
            )
            .map_err(|_| CryptoError::Backend("group list entry seal".into()))?;
        sealed.extend_from_slice(&ciphertext);
        debug_assert_eq!(sealed.len(), SEALED_LEN);
        Ok(sealed)
    }

    /// Opens an entry; fails unless it was sealed for `entry_id` under this
    /// account's `binding` (so the server can't move an entry, or change its
    /// revision).
    pub fn open(
        &self,
        binding: &str,
        entry_id: &[u8; ENTRY_ID_LEN],
        sealed: &[u8],
    ) -> Result<OpenedEntry> {
        let revision = inspect(sealed).map_err(|_| CryptoError::AuthFailed)?;
        let nonce = &sealed[MAGIC.len() + 10..HEADER_LEN];
        let padded = Aead::new(Suite::V1, self.seal_key.as_ref())?
            .open_with_nonce(
                nonce,
                &aad(&sealed[..MAGIC.len() + 10], binding, entry_id)?,
                &sealed[HEADER_LEN..],
            )
            .map_err(|_| CryptoError::AuthFailed)?;
        let padded = Zeroizing::new(padded);
        let len = usize::from(u16::from_be_bytes([padded[0], padded[1]]));
        if len > MAX_PLAIN_LEN || padded[2 + len..].iter().any(|&byte| byte != 0) {
            return Err(CryptoError::AuthFailed);
        }
        Ok(OpenedEntry {
            revision,
            plain: Zeroizing::new(padded[2..2 + len].to_vec()),
        })
    }
}

/// The revision of a sealed entry, read from its header: what the server
/// orders writes by. Refuses anything but a [`SEALED_LEN`]-byte entry of a
/// known suite. Says nothing about authenticity (only the account can open it).
pub fn inspect(sealed: &[u8]) -> Result<u64> {
    if sealed.len() != SEALED_LEN {
        return Err(CryptoError::InvalidInput(format!(
            "a sealed group list entry is exactly {SEALED_LEN} bytes"
        )));
    }
    if &sealed[..MAGIC.len()] != MAGIC {
        return Err(CryptoError::InvalidInput("not a group list entry".into()));
    }
    let suite = u16::from_be_bytes([sealed[8], sealed[9]]);
    if suite != SUITE_V1 {
        return Err(CryptoError::InvalidInput(format!(
            "unknown group list suite {suite}"
        )));
    }
    Ok(u64::from_be_bytes(
        sealed[10..18].try_into().expect("eight bytes"),
    ))
}

/// An entry id as it appears in the API: base64url without padding.
pub fn encode_entry_id(entry_id: &[u8; ENTRY_ID_LEN]) -> String {
    URL_SAFE_NO_PAD.encode(entry_id)
}

/// Parses an entry id from the API (exactly 43 characters, canonical).
pub fn decode_entry_id(id: &str) -> Result<[u8; ENTRY_ID_LEN]> {
    let invalid =
        || CryptoError::InvalidInput("a group list entry id is 32 bytes base64url".into());
    let bytes: [u8; ENTRY_ID_LEN] = URL_SAFE_NO_PAD
        .decode(id)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    if encode_entry_id(&bytes) != id {
        return Err(invalid());
    }
    Ok(bytes)
}

/// An entry's AAD, for the checked-in vector only.
#[cfg(any(test, feature = "test-vectors"))]
pub fn vector_aad(revision: u64, binding: &str, entry_id: &[u8; ENTRY_ID_LEN]) -> Result<Vec<u8>> {
    let header = [&MAGIC[..], &SUITE_V1.to_be_bytes(), &revision.to_be_bytes()].concat();
    aad(&header, binding, entry_id)
}

/// header (magic ‖ suite ‖ revision) ‖ u16 binding length ‖ binding ‖ entry id.
fn aad(header: &[u8], binding: &str, entry_id: &[u8; ENTRY_ID_LEN]) -> Result<Vec<u8>> {
    let binding = crate::key_binding::check(binding)
        .map_err(|_| CryptoError::InvalidInput("the account's key binding is invalid".into()))?;
    let binding_len = u16::try_from(binding.len())
        .map_err(|_| CryptoError::InvalidInput("key binding length".into()))?;
    Ok([
        header,
        &binding_len.to_be_bytes(),
        binding.as_bytes(),
        entry_id,
    ]
    .concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f607";

    #[test]
    fn an_entry_opens_only_for_its_id_and_account() {
        let key = GroupListKey::derive(&[1u8; 32]);
        let other = GroupListKey::derive(&[2u8; 32]);
        let group = [7u8; GROUP_ID_LEN];
        let id = key.entry_id(&group);
        // The id is per account and is never the group id itself.
        assert_ne!(id, other.entry_id(&group));
        assert_ne!(id, group);
        assert_eq!(id, GroupListKey::derive(&[1u8; 32]).entry_id(&group));

        let sealed = key.seal(BINDING, &id, 3, b"entry").unwrap();
        assert_eq!(sealed.len(), SEALED_LEN);
        assert_eq!(inspect(&sealed).unwrap(), 3);
        let opened = key.open(BINDING, &id, &sealed).unwrap();
        assert_eq!((opened.revision, &opened.plain[..]), (3, &b"entry"[..]));

        let elsewhere = key.entry_id(&[9u8; GROUP_ID_LEN]);
        assert!(
            key.open(BINDING, &elsewhere, &sealed).is_err(),
            "another entry"
        );
        assert!(
            other.open(BINDING, &id, &sealed).is_err(),
            "another account"
        );
        assert!(
            key.open("0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d", &id, &sealed)
                .is_err(),
            "another incarnation"
        );
        // The server can't change the revision it orders by.
        let mut moved = sealed.clone();
        moved[17] ^= 1;
        assert_eq!(inspect(&moved).unwrap(), 2);
        assert!(key.open(BINDING, &id, &moved).is_err(), "another revision");
    }

    /// Seals `padded` as it stands, so a test can make what `seal` never
    /// would: an entry that authenticates but whose padding is wrong.
    fn seal_padded(key: &GroupListKey, id: &[u8; ENTRY_ID_LEN], padded: &[u8]) -> Vec<u8> {
        let nonce = [5u8; NONCE_LEN];
        let mut sealed = [
            &MAGIC[..],
            &SUITE_V1.to_be_bytes(),
            &1u64.to_be_bytes(),
            &nonce,
        ]
        .concat();
        let ciphertext = Aead::new(Suite::V1, key.seal_key.as_ref())
            .unwrap()
            .seal_with_nonce(
                &nonce,
                &aad(&sealed[..MAGIC.len() + 10], BINDING, id).unwrap(),
                padded,
            )
            .unwrap();
        sealed.extend_from_slice(&ciphertext);
        assert_eq!(sealed.len(), SEALED_LEN);
        sealed
    }

    #[test]
    fn an_entry_with_a_bad_length_or_padding_does_not_open() {
        let key = GroupListKey::derive(&[1u8; 32]);
        let id = key.entry_id(&[7u8; GROUP_ID_LEN]);
        let mut padded = vec![0u8; PADDED_LEN];
        padded[..2].copy_from_slice(&5u16.to_be_bytes());
        padded[2..7].copy_from_slice(b"entry");
        // Sealed the way `seal` does it: opens.
        let good = seal_padded(&key, &id, &padded);
        assert_eq!(&key.open(BINDING, &id, &good).unwrap().plain[..], b"entry");
        // A length past the longest plaintext.
        let mut long = padded.clone();
        long[..2].copy_from_slice(&((MAX_PLAIN_LEN + 1) as u16).to_be_bytes());
        assert!(key
            .open(BINDING, &id, &seal_padded(&key, &id, &long))
            .is_err());
        let mut longest = padded.clone();
        longest[..2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(key
            .open(BINDING, &id, &seal_padded(&key, &id, &longest))
            .is_err());
        // A non-zero byte in the padding, at its start and at its end.
        for at in [7, PADDED_LEN - 1] {
            let mut dirty = padded.clone();
            dirty[at] = 1;
            assert!(
                key.open(BINDING, &id, &seal_padded(&key, &id, &dirty))
                    .is_err(),
                "padding byte {at}"
            );
        }
    }

    #[test]
    fn every_entry_has_one_size() {
        let key = GroupListKey::derive(&[1u8; 32]);
        let id = key.entry_id(&[7u8; GROUP_ID_LEN]);
        for len in [0, 1, 400, MAX_PLAIN_LEN] {
            let plain = vec![b'x'; len];
            let sealed = key.seal(BINDING, &id, 1, &plain).unwrap();
            assert_eq!(sealed.len(), SEALED_LEN);
            assert_eq!(
                &key.open(BINDING, &id, &sealed).unwrap().plain[..],
                &plain[..]
            );
        }
        assert!(key
            .seal(BINDING, &id, 1, &vec![0u8; MAX_PLAIN_LEN + 1])
            .is_err());
    }

    #[test]
    fn inspect_refuses_what_is_not_an_entry() {
        let key = GroupListKey::derive(&[1u8; 32]);
        let id = key.entry_id(&[7u8; GROUP_ID_LEN]);
        let sealed = key.seal(BINDING, &id, 1, b"e").unwrap();
        assert!(inspect(&sealed[..SEALED_LEN - 1]).is_err(), "short");
        assert!(
            inspect(&[sealed.clone(), vec![0]].concat()).is_err(),
            "long"
        );
        let mut magic = sealed.clone();
        magic[0] ^= 1;
        assert!(inspect(&magic).is_err(), "magic");
        let mut suite = sealed;
        suite[9] = 2;
        assert!(inspect(&suite).is_err(), "suite");
    }

    #[test]
    fn entry_ids_are_canonical_base64url() {
        let id = GroupListKey::derive(&[1u8; 32]).entry_id(&[7u8; GROUP_ID_LEN]);
        let text = encode_entry_id(&id);
        assert_eq!(text.len(), 43);
        assert_eq!(decode_entry_id(&text).unwrap(), id);
        assert!(decode_entry_id(&format!("{text}=")).is_err());
        assert!(decode_entry_id(&text[..42]).is_err());
        assert!(
            decode_entry_id(&format!("{}+", &text[..42])).is_err(),
            "standard alphabet"
        );
        // 43 characters carry two spare bits; a set one is not canonical.
        let mut loose = URL_SAFE_NO_PAD.encode([0u8; ENTRY_ID_LEN]);
        loose.replace_range(42.., "B");
        assert!(decode_entry_id(&loose).is_err(), "non-zero spare bits");
    }
}
