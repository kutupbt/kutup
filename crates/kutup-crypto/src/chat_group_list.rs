//! An account's list of its Chat groups (docs/plans/pairwise-groups.md §5):
//! one sealed entry per group, kept by the account's server so that a new
//! device of the account can take its groups up.
//!
//! Each entry is an account record (`account_record`, purpose
//! `ChatGroupListEntry`) under the master key. Its object, the entry id, is
//! [`account_record::hashed_object`] of the group id, so the server never sees
//! a group id and can't match one account's entries with another's; the
//! plaintext is padded to one size, so the server learns nothing from it; and
//! the server reads the revision from the record's header to order writes.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::chat_group::GROUP_ID_LEN;
use crate::error::{CryptoError, Result};

const PURPOSE: AccountRecordPurpose = AccountRecordPurpose::ChatGroupListEntry;
pub const ENTRY_ID_LEN: usize = 32;
const NONCE_LEN: usize = 24;
/// The longest entry plaintext.
pub const MAX_PLAIN_LEN: usize = 3972;
/// Every sealed entry's length: the plaintext is padded to one size, so the
/// server can't tell entries apart by their length.
pub const SEALED_LEN: usize = match account_record::exact_record_len(PURPOSE) {
    Some(len) => len,
    None => panic!("list entries have one length"),
};

/// An account's group list: its master key and the generation it seals at.
pub struct GroupListKey {
    master_key: Zeroizing<[u8; 32]>,
    generation: MasterKeyGeneration,
}

/// An opened entry: its revision (from the authenticated header) and plaintext.
pub struct OpenedEntry {
    pub revision: u64,
    pub plain: Zeroizing<Vec<u8>>,
}

impl GroupListKey {
    pub fn new(master_key: &[u8; 32], generation: MasterKeyGeneration) -> Self {
        Self {
            master_key: Zeroizing::new(*master_key),
            generation,
        }
    }

    /// The entry id of `group_id` in this account's list.
    pub fn entry_id(&self, group_id: &[u8; GROUP_ID_LEN]) -> [u8; ENTRY_ID_LEN] {
        account_record::hashed_object(&self.master_key, PURPOSE, group_id)
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

    /// [`Self::seal`] with a fixed nonce, for checked-in vectors only.
    pub fn seal_with_nonce(
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
        account_record::seal_suite(
            account_record::AccountRecordSuiteId::V1,
            plain,
            self.master_key.as_slice(),
            PURPOSE,
            self.generation,
            binding,
            entry_id,
            Some(revision),
            nonce,
        )
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
        let (plain, revision) = account_record::open_revision(
            sealed,
            self.master_key.as_slice(),
            PURPOSE,
            binding,
            entry_id,
        )?;
        Ok(OpenedEntry {
            revision,
            plain: Zeroizing::new(plain),
        })
    }
}

/// The revision of a sealed entry, read from its header. Says nothing about
/// authenticity (only the account can open it).
pub fn inspect(sealed: &[u8]) -> Result<u64> {
    let header = account_record::inspect(sealed)?;
    if header.purpose != PURPOSE {
        return Err(CryptoError::InvalidInput("not a group list entry".into()));
    }
    header
        .revision
        .ok_or_else(|| CryptoError::InvalidInput("an entry has a revision".into()))
}

/// What the server checks before storing an entry: a well-formed entry of
/// the account bound by `binding`, filed under `entry_id`; returns its
/// revision.
pub fn validate(sealed: &[u8], binding: &str, entry_id: &[u8; ENTRY_ID_LEN]) -> Result<u64> {
    account_record::validate_for(sealed, PURPOSE, binding, entry_id)?
        .revision
        .ok_or_else(|| CryptoError::InvalidInput("an entry has a revision".into()))
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

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "6f1c2a3b-4d5e-4f60-8a71-b2c3d4e5f607";
    const FIRST: MasterKeyGeneration = MasterKeyGeneration::FIRST;

    #[test]
    fn an_entry_opens_only_for_its_id_and_account() {
        let key = GroupListKey::new(&[1u8; 32], FIRST);
        let other = GroupListKey::new(&[2u8; 32], FIRST);
        let group = [7u8; GROUP_ID_LEN];
        let id = key.entry_id(&group);
        // The id is per account and is never the group id itself.
        assert_ne!(id, other.entry_id(&group));
        assert_ne!(id, group);
        assert_eq!(id, GroupListKey::new(&[1u8; 32], FIRST).entry_id(&group));

        let sealed = key.seal(BINDING, &id, 3, b"entry").unwrap();
        assert_eq!(sealed.len(), SEALED_LEN);
        assert_eq!(inspect(&sealed).unwrap(), 3);
        assert_eq!(validate(&sealed, BINDING, &id).unwrap(), 3);
        assert!(validate(&sealed, BINDING, &key.entry_id(&[9u8; GROUP_ID_LEN])).is_err());
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
    }

    #[test]
    fn every_entry_has_one_size() {
        let key = GroupListKey::new(&[1u8; 32], FIRST);
        let id = key.entry_id(&[7u8; GROUP_ID_LEN]);
        let mut sizes = std::collections::BTreeSet::new();
        for len in [0, 1, 400, MAX_PLAIN_LEN] {
            let plain = vec![b'x'; len];
            let sealed = key.seal(BINDING, &id, 1, &plain).unwrap();
            assert_eq!(sealed.len(), SEALED_LEN);
            sizes.insert(sealed.len());
            assert_eq!(
                &key.open(BINDING, &id, &sealed).unwrap().plain[..],
                &plain[..]
            );
        }
        assert_eq!(sizes.len(), 1);
        assert!(key
            .seal(BINDING, &id, 1, &vec![0u8; MAX_PLAIN_LEN + 1])
            .is_err());
    }

    #[test]
    fn entry_ids_are_canonical_base64url() {
        let id = GroupListKey::new(&[1u8; 32], FIRST).entry_id(&[7u8; GROUP_ID_LEN]);
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
