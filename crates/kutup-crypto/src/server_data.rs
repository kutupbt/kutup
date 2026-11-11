//! Server-held personal data (docs/plans/server-personal-data.md, A2): each
//! account's **data key**, and the personal fields the server seals under it.
//!
//! The server keeps a little personal data it has to read itself (a TOTP
//! secret, later the parsed browser family of a session, a recovery email,
//! mail headers). Each account gets a random 32-byte data key; its fields are
//! sealed under it, so destroying the key destroys them everywhere they are
//! copied, backups included, without finding each copy.
//!
//! The data key is kept wrapped under a key-encryption key derived from an
//! entry of the server key list (`OPAQUE_SETUP_KEYS`), which never enters the
//! database or its dumps. A wrapped key names the entry it is wrapped under,
//! so an entry can be retired once no wrapped key uses it.
//!
//! Formats:
//! - wrapped key: `magic (8) ‖ entry id (u16) ‖ generation (u32) ‖ nonce (24)
//!   ‖ XChaCha20-Poly1305(data key)`, the AAD the header and the account id;
//! - sealed field: `suite (u16) ‖ generation (u32) ‖ nonce (24) ‖
//!   XChaCha20-Poly1305(value)`, under a subkey of the data key, the AAD the
//!   header and the field's table, column, row and account, so a value can't
//!   move to another row or account;
//! - destruction subject: 32 bytes, HKDF of the entry expanded with the label
//!   and the account id, so the destruction log names an account only to
//!   whoever holds the entry.

use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::primitives::{Aead, Kdf, Suite};

const SALT: &[u8] = crate::labels::SERVER_DATA_V1;
const KEK_INFO: &[u8] = crate::labels::SERVER_DATA_KEK_V1;
const WRAP_AAD: &[u8] = crate::labels::SERVER_DATA_KEY_WRAP_V1;
const FIELD_KEY_INFO: &[u8] = crate::labels::SERVER_DATA_FIELD_KEY_V1;
const FIELD_AAD: &[u8] = crate::labels::SERVER_DATA_FIELD_V1;
const SUBJECT_INFO: &[u8] = crate::labels::SERVER_DESTRUCTION_SUBJECT_V1;
const WRAP_MAGIC: &[u8; 8] = b"KUTSDK1\0";
const FIELD_SUITE: u16 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const WRAP_HEADER_LEN: usize = 8 + 2 + 4 + NONCE_LEN;
const FIELD_HEADER_LEN: usize = 2 + 4 + NONCE_LEN;
/// A wrapped data key's length.
pub const WRAPPED_KEY_LEN: usize = WRAP_HEADER_LEN + 32 + TAG_LEN;
/// The longest value a field may seal.
pub const MAX_FIELD_LEN: usize = 64 * 1024;

fn invalid(what: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("server data: {what}"))
}

fn expand(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    Kdf::new(Suite::V1, SALT, ikm)
        .expand(info, out.as_mut_slice())
        .map_err(|_| CryptoError::Backend("server data key".into()))?;
    Ok(out)
}

/// An account's data key, opened; one generation of it.
pub struct DataKey {
    key: Zeroizing<[u8; 32]>,
    generation: u32,
}

impl DataKey {
    /// A new random data key at `generation` (1 for an account's first).
    pub fn generate(generation: u32) -> Result<Self> {
        if generation == 0 {
            return Err(invalid("generations start at 1"));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        crate::primitives::random(key.as_mut_slice());
        Ok(Self { key, generation })
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Wraps this key for account `account_id` under entry `entry_id` of the
    /// server key list (`entry` its 32 bytes).
    pub fn wrap(&self, entry: &[u8; 32], entry_id: u16, account_id: &[u8; 16]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        crate::primitives::random(&mut nonce);
        self.wrap_with_nonce(entry, entry_id, account_id, &nonce)
    }

    /// [`DataKey::wrap`] with a fixed nonce, for checked-in vectors only.
    pub fn wrap_with_nonce(
        &self,
        entry: &[u8; 32],
        entry_id: u16,
        account_id: &[u8; 16],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let mut header = Vec::with_capacity(WRAP_HEADER_LEN);
        header.extend_from_slice(WRAP_MAGIC);
        header.extend_from_slice(&entry_id.to_be_bytes());
        header.extend_from_slice(&self.generation.to_be_bytes());
        header.extend_from_slice(nonce);
        let kek = expand(entry, KEK_INFO)?;
        let ciphertext = Aead::new(Suite::V1, kek.as_ref())?
            .seal_with_nonce(nonce, &wrap_aad(&header, account_id), self.key.as_slice())
            .map_err(|_| CryptoError::Backend("server data key wrap".into()))?;
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    /// Opens a wrapped key of account `account_id`, under the server key
    /// list entry it names (`entry_for` gives an entry's 32 bytes by id, or
    /// none when the list no longer holds it).
    pub fn unwrap<'a>(
        wrapped: &[u8],
        account_id: &[u8; 16],
        entry_for: impl FnOnce(u16) -> Option<&'a [u8; 32]>,
    ) -> Result<Self> {
        let (entry_id, generation) = inspect_wrapped(wrapped)?;
        let entry = entry_for(entry_id).ok_or_else(|| {
            invalid("the server key list no longer holds the entry this key is wrapped under")
        })?;
        let kek = expand(entry, KEK_INFO)?;
        let plain = Zeroizing::new(
            Aead::new(Suite::V1, kek.as_ref())?
                .open_with_nonce(
                    &wrapped[8 + 2 + 4..WRAP_HEADER_LEN],
                    &wrap_aad(&wrapped[..WRAP_HEADER_LEN], account_id),
                    &wrapped[WRAP_HEADER_LEN..],
                )
                .map_err(|_| CryptoError::AuthFailed)
                .map(crate::primitives::into_vec)?,
        );
        let key: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::AuthFailed)?;
        Ok(Self {
            key: Zeroizing::new(key),
            generation,
        })
    }

    /// Seals `value` for `field`.
    pub fn seal(&self, field: &Field<'_>, value: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        crate::primitives::random(&mut nonce);
        self.seal_with_nonce(field, value, &nonce)
    }

    /// [`DataKey::seal`] with a fixed nonce, for checked-in vectors only.
    pub fn seal_with_nonce(
        &self,
        field: &Field<'_>,
        value: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        if value.len() > MAX_FIELD_LEN {
            return Err(invalid("the value is too long"));
        }
        let mut header = Vec::with_capacity(FIELD_HEADER_LEN);
        header.extend_from_slice(&FIELD_SUITE.to_be_bytes());
        header.extend_from_slice(&self.generation.to_be_bytes());
        header.extend_from_slice(nonce);
        let key = expand(self.key.as_slice(), FIELD_KEY_INFO)?;
        let ciphertext = Aead::new(Suite::V1, key.as_ref())?
            .seal_with_nonce(nonce, &field.aad(&header)?, value)
            .map_err(|_| CryptoError::Backend("server data field seal".into()))?;
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    /// Opens a value sealed for `field` under this generation of the key.
    pub fn open(&self, field: &Field<'_>, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < FIELD_HEADER_LEN + TAG_LEN || sealed[..2] != FIELD_SUITE.to_be_bytes() {
            return Err(invalid("not a sealed field"));
        }
        if sealed[2..6] != self.generation.to_be_bytes() {
            return Err(invalid("sealed under another generation of the key"));
        }
        let key = expand(self.key.as_slice(), FIELD_KEY_INFO)?;
        Aead::new(Suite::V1, key.as_ref())?
            .open_with_nonce(
                &sealed[6..FIELD_HEADER_LEN],
                &field.aad(&sealed[..FIELD_HEADER_LEN])?,
                &sealed[FIELD_HEADER_LEN..],
            )
            .map_err(|_| CryptoError::AuthFailed)
            .map(|plain| Zeroizing::new(crate::primitives::into_vec(plain)))
    }
}

fn wrap_aad(header: &[u8], account_id: &[u8; 16]) -> Vec<u8> {
    [WRAP_AAD, header, account_id.as_slice()].concat()
}

/// The generation of the key a field was sealed under, without opening it:
/// which of an account's keys opens it.
pub fn sealed_generation(sealed: &[u8]) -> Result<u32> {
    if sealed.len() < FIELD_HEADER_LEN + TAG_LEN || sealed[..2] != FIELD_SUITE.to_be_bytes() {
        return Err(invalid("not a sealed field"));
    }
    let generation = u32::from_be_bytes(sealed[2..6].try_into().expect("4 bytes"));
    if generation == 0 {
        return Err(invalid("generations start at 1"));
    }
    Ok(generation)
}

/// A wrapped key's entry id and generation, without opening it (what the
/// server counts when it checks an entry can be retired).
pub fn inspect_wrapped(wrapped: &[u8]) -> Result<(u16, u32)> {
    if wrapped.len() != WRAPPED_KEY_LEN || &wrapped[..8] != WRAP_MAGIC {
        return Err(invalid("not a wrapped data key"));
    }
    let entry_id = u16::from_be_bytes([wrapped[8], wrapped[9]]);
    let generation = u32::from_be_bytes(wrapped[10..14].try_into().expect("4 bytes"));
    if generation == 0 {
        return Err(invalid("generations start at 1"));
    }
    Ok((entry_id, generation))
}

/// The account as the destruction log names it under one entry of the server
/// key list (docs/plans/server-personal-data.md, A7): a keyed hash of its id,
/// which a restore computes again for the accounts it holds.
pub fn destruction_subject(entry: &[u8; 32], account_id: &[u8; 16]) -> Result<[u8; 32]> {
    let info = [SUBJECT_INFO, account_id.as_slice()].concat();
    Ok(*expand(entry, &info)?)
}

/// Where a sealed value lives: its table, column and row, and the account it
/// belongs to.
pub struct Field<'a> {
    pub table: &'a str,
    pub column: &'a str,
    /// The row's id as text (a UUID, or a composite key joined by `/`).
    pub row: &'a str,
    pub account_id: &'a [u8; 16],
}

impl Field<'_> {
    fn aad(&self, header: &[u8]) -> Result<Vec<u8>> {
        let mut aad = Vec::with_capacity(FIELD_AAD.len() + header.len() + 96);
        aad.extend_from_slice(FIELD_AAD);
        aad.extend_from_slice(header);
        for part in [self.table, self.column, self.row] {
            if part.is_empty() || part.len() > 255 {
                return Err(invalid("a field's table, column or row is invalid"));
            }
            aad.push(part.len() as u8);
            aad.extend_from_slice(part.as_bytes());
        }
        aad.extend_from_slice(self.account_id);
        Ok(aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: [u8; 16] = [0x11; 16];
    const ENTRY: [u8; 32] = [0x22; 32];

    fn field<'a>(row: &'a str) -> Field<'a> {
        Field {
            table: "users",
            column: "totp_secret",
            row,
            account_id: &ACCOUNT,
        }
    }

    #[test]
    fn a_destruction_subject_is_the_accounts_under_its_entry() {
        let subject = destruction_subject(&ENTRY, &ACCOUNT).unwrap();
        assert_eq!(destruction_subject(&ENTRY, &ACCOUNT).unwrap(), subject);
        assert_ne!(destruction_subject(&ENTRY, &[0x12; 16]).unwrap(), subject);
        assert_ne!(destruction_subject(&[0x23; 32], &ACCOUNT).unwrap(), subject);
    }

    #[test]
    fn a_sealed_field_names_its_keys_generation() {
        let key = DataKey::generate(3).unwrap();
        let sealed = key.seal(&field("r"), b"x").unwrap();
        assert_eq!(sealed_generation(&sealed).unwrap(), 3);
        assert!(sealed_generation(&sealed[..10]).is_err());
    }

    #[test]
    fn a_wrapped_key_opens_only_for_its_account_and_entry() {
        let key = DataKey::generate(1).unwrap();
        let wrapped = key.wrap(&ENTRY, 3, &ACCOUNT).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
        assert_eq!(inspect_wrapped(&wrapped).unwrap(), (3, 1));
        let opened = DataKey::unwrap(&wrapped, &ACCOUNT, |id| (id == 3).then_some(&ENTRY)).unwrap();
        assert_eq!(*opened.key, *key.key);
        // Another account, another entry's bytes, an entry the list no longer
        // holds, or altered: refused.
        assert!(DataKey::unwrap(&wrapped, &[0x12; 16], |_| Some(&ENTRY)).is_err());
        assert!(DataKey::unwrap(&wrapped, &ACCOUNT, |_| Some(&[0x23; 32])).is_err());
        assert!(DataKey::unwrap(&wrapped, &ACCOUNT, |_| None).is_err());
        let mut relabelled = wrapped.clone();
        relabelled[9] = 4;
        assert!(DataKey::unwrap(&relabelled, &ACCOUNT, |_| Some(&ENTRY)).is_err());
        let mut altered = wrapped;
        *altered.last_mut().unwrap() ^= 1;
        assert!(DataKey::unwrap(&altered, &ACCOUNT, |_| Some(&ENTRY)).is_err());
        assert!(DataKey::generate(0).is_err());
    }

    #[test]
    fn a_sealed_field_opens_only_where_it_was_sealed() {
        let key = DataKey::generate(1).unwrap();
        let row = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
        let sealed = key.seal(&field(row), b"JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(
            &*key.open(&field(row), &sealed).unwrap(),
            b"JBSWY3DPEHPK3PXP"
        );
        // Another row, column or account; another key or generation;
        // altered: refused.
        assert!(key
            .open(&field("7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d"), &sealed)
            .is_err());
        let other_column = Field {
            column: "recovery_email",
            ..field(row)
        };
        assert!(key.open(&other_column, &sealed).is_err());
        let other_account = Field {
            account_id: &[0x12; 16],
            ..field(row)
        };
        assert!(key.open(&other_account, &sealed).is_err());
        assert!(DataKey::generate(1)
            .unwrap()
            .open(&field(row), &sealed)
            .is_err());
        let next = DataKey::generate(2).unwrap();
        assert!(next.open(&field(row), &sealed).is_err());
        let mut altered = sealed;
        *altered.last_mut().unwrap() ^= 1;
        assert!(key.open(&field(row), &altered).is_err());
        assert!(key.seal(&field(""), b"x").is_err());
    }
}
