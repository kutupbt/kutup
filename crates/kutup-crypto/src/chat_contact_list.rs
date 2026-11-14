//! An account's Chat contacts (docs/plans/chat-contacts-sync.md): one sealed
//! entry per person the account accepted, rejected, blocked or asked, kept by
//! the account's server so that a device that lost everything restores them.
//!
//! Each entry is an account record (`account_record`, purpose
//! `ChatContactListEntry`) under the master key. Its object, the entry id, is
//! [`account_record::hashed_object`] of the contact's [`AccountRef`], so the
//! server never sees whom an entry is about and can't match two accounts'
//! entries; the plaintext is padded to one size; and the server reads the
//! revision from the record's header to order writes.
//!
//! What the record can't check, and the client must: that the plaintext's
//! contact re-derives to the entry id ([`ContactListKey::entry_id`]), so a
//! writer's mistake can't file one contact under another's id; and that the
//! revision isn't below the highest this device saw for the id (with the
//! account head's `chatContacts` scope).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::account_ref::AccountRef;
use crate::error::{CryptoError, Result};

const PURPOSE: AccountRecordPurpose = AccountRecordPurpose::ChatContactListEntry;
pub const ENTRY_ID_LEN: usize = 32;
const NONCE_LEN: usize = 24;
/// The longest entry plaintext.
pub const MAX_PLAIN_LEN: usize = 1988;
/// Every sealed entry's length: the plaintext is padded to one size, so the
/// server can't tell entries apart by their length.
pub const SEALED_LEN: usize = match account_record::exact_record_len(PURPOSE) {
    Some(len) => len,
    None => panic!("list entries have one length"),
};

/// An account's contact list: its master key and the generation it seals at.
pub struct ContactListKey {
    master_key: Zeroizing<[u8; 32]>,
    generation: MasterKeyGeneration,
    object_id_key: crate::account_roots::ObjectIdKey,
}

/// An opened entry: its revision (from the authenticated header) and plaintext.
pub struct OpenedEntry {
    pub revision: u64,
    pub plain: Zeroizing<Vec<u8>>,
}

impl ContactListKey {
    /// Entries sealed under `master_key` (of `generation`), their ids
    /// hashed under the account's `object_id_key`.
    pub fn new(
        master_key: &[u8; 32],
        generation: MasterKeyGeneration,
        object_id_key: &crate::account_roots::ObjectIdKey,
    ) -> Self {
        Self {
            master_key: Zeroizing::new(*master_key),
            generation,
            object_id_key: object_id_key.clone(),
        }
    }

    /// The entry id of `contact` in this account's list.
    pub fn entry_id(&self, contact: &AccountRef) -> [u8; ENTRY_ID_LEN] {
        account_record::hashed_object(&self.object_id_key, PURPOSE, &contact.bytes())
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
                "a contact list entry is at most {MAX_PLAIN_LEN} bytes"
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
        return Err(CryptoError::InvalidInput("not a contact list entry".into()));
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
        || CryptoError::InvalidInput("a contact list entry id is 32 bytes base64url".into());
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

    fn account(id: &str) -> AccountRef {
        AccountRef::new("a.test", id).unwrap()
    }

    #[test]
    fn an_entry_opens_only_for_its_id_and_account() {
        let key = ContactListKey::new(
            &[1u8; 32],
            FIRST,
            &crate::account_roots::ObjectIdKey::from_bytes([1u8; 32]),
        );
        let other = ContactListKey::new(
            &[2u8; 32],
            FIRST,
            &crate::account_roots::ObjectIdKey::from_bytes([2u8; 32]),
        );
        let contact = account("00000000-0000-4000-8000-0000000000b2");
        let id = key.entry_id(&contact);
        // The id differs per account, and is the same for one account.
        assert_ne!(id, other.entry_id(&contact));
        assert_eq!(
            id,
            ContactListKey::new(
                &[1u8; 32],
                FIRST,
                &crate::account_roots::ObjectIdKey::from_bytes([1u8; 32])
            )
            .entry_id(&contact)
        );

        let sealed = key.seal(BINDING, &id, 3, b"entry").unwrap();
        assert_eq!(sealed.len(), SEALED_LEN);
        assert_eq!(inspect(&sealed).unwrap(), 3);
        assert_eq!(validate(&sealed, BINDING, &id).unwrap(), 3);
        let opened = key.open(BINDING, &id, &sealed).unwrap();
        assert_eq!((opened.revision, &opened.plain[..]), (3, &b"entry"[..]));

        let elsewhere = key.entry_id(&account("00000000-0000-4000-8000-0000000000c3"));
        assert!(
            key.open(BINDING, &elsewhere, &sealed).is_err(),
            "another entry"
        );
        assert!(validate(&sealed, BINDING, &elsewhere).is_err());
        assert!(
            other.open(BINDING, &id, &sealed).is_err(),
            "another account"
        );
        // A group list entry is not a contact list entry.
        let group = crate::chat_group_list::GroupListKey::new(
            &[1u8; 32],
            FIRST,
            &crate::account_roots::ObjectIdKey::from_bytes([1u8; 32]),
        );
        let group_entry = group.seal(BINDING, &id, 3, b"entry").unwrap();
        assert!(key.open(BINDING, &id, &group_entry).is_err());
        assert!(inspect(&group_entry).is_err());
    }

    #[test]
    fn every_entry_has_one_size() {
        let key = ContactListKey::new(
            &[1u8; 32],
            FIRST,
            &crate::account_roots::ObjectIdKey::from_bytes([1u8; 32]),
        );
        let id = key.entry_id(&account("00000000-0000-4000-8000-0000000000b2"));
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
        let id = ContactListKey::new(
            &[1u8; 32],
            FIRST,
            &crate::account_roots::ObjectIdKey::from_bytes([1u8; 32]),
        )
        .entry_id(&account("00000000-0000-4000-8000-0000000000b2"));
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
