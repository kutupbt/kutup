//! Kutup Pass vault secrets (docs/plans/pass.md, "Vault secrets").
//!
//! A vault is a KeePass file in Drive with its own composite key (a password,
//! a key file, or both), so KeePass apps keep opening it. Kutup Pass and
//! `kutup sync` unlock it with the Kutup sign-in, as Proton Pass does: the
//! vault's key is kept in an [`account_envelope`] under the master key
//! (purpose `PassVaultSecret`, the vault's file id as the header's object),
//! one per person and vault, stored by the server and unreadable to it.
//!
//! What is kept opens the vault without holding a password the person chose:
//! of such a password only its SHA-256 is kept, which is how KeePass uses a
//! password in the composite key. Whoever opens the envelope (with the master
//! key) cannot read the password directly; a weak one can still be guessed
//! from its unsalted hash. A password Kutup Pass generated for the vault (one
//! nobody uses elsewhere) is kept as it is, so it can be shown for a KeePass
//! app. Key files are kept as KeePass reads them. Every payload is padded to
//! one length, so an envelope's size does not tell which of these it holds.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::account_envelope::{self, AccountEnvelopePurpose};
use crate::error::{CryptoError, Result};

const DOMAIN: &[u8] = b"kutup/pass-vault-secret/v2\0";
const HAS_PASSWORD_HASH: u8 = 1;
const HAS_KEY_FILE: u8 = 2;
const HAS_GENERATED_PASSWORD: u8 = 4;

/// The longest vault password, in bytes (UTF-8).
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// The largest key file kept, in bytes. KeePass reduces any other file to
/// its SHA-256, which works as the same key (`kutup_pass::key_file_secret`).
pub const MAX_KEY_FILE_BYTES: usize = 2048;
/// Every payload's length: the largest one (a key file and a generated
/// password at their limits), the rest padded with zeros to it.
const PAYLOAD_LEN: usize =
    DOMAIN.len() + 16 + 1 + (2 + MAX_KEY_FILE_BYTES) + (2 + MAX_PASSWORD_BYTES);

/// What opens one vault.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultSecret {
    /// SHA-256 of a password the person chose: KeePass's password part of
    /// the composite key, which opens the vault without telling the password.
    pub password_hash: Option<Zeroizing<[u8; 32]>>,
    /// A password Kutup Pass generated for the vault, kept as it is so it
    /// can be shown (for KeePassXC on another device).
    pub generated_password: Option<Zeroizing<String>>,
    pub key_file: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for VaultSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSecret")
            .field(
                "password_hash",
                &self.password_hash.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "generated_password",
                &self.generated_password.as_ref().map(|_| "[redacted]"),
            )
            .field("key_file", &self.key_file.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// KeePass's password part of the composite key: SHA-256 of its UTF-8.
pub fn password_hash(password: &str) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(password.as_bytes()).into())
}

impl VaultSecret {
    /// The key of a vault whose password (if any) the person chose: only the
    /// password's hash is kept.
    pub fn chosen(password: Option<&str>, key_file: Option<&[u8]>) -> Self {
        Self {
            password_hash: password.map(password_hash),
            generated_password: None,
            key_file: key_file.map(|k| Zeroizing::new(k.to_vec())),
        }
    }

    /// The key of a vault whose password Kutup Pass generated.
    pub fn generated(password: &str, key_file: Option<&[u8]>) -> Self {
        Self {
            password_hash: None,
            generated_password: Some(Zeroizing::new(password.to_owned())),
            key_file: key_file.map(|k| Zeroizing::new(k.to_vec())),
        }
    }

    /// The password part of the composite key, whichever way it is kept.
    pub fn password_element(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.password_hash
            .clone()
            .or_else(|| self.generated_password.as_deref().map(|p| password_hash(p)))
    }
}

fn invalid(message: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("vault secret: {message}"))
}

fn payload(file_id: &[u8; 16], secret: &VaultSecret) -> Result<Zeroizing<Vec<u8>>> {
    if secret.password_hash.is_some() && secret.generated_password.is_some() {
        return Err(invalid("a vault has one password"));
    }
    if secret.password_hash.is_none()
        && secret.generated_password.is_none()
        && secret.key_file.is_none()
    {
        return Err(invalid("a vault needs a password or a key file"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(file_id);
    let mut flags = 0;
    if secret.password_hash.is_some() {
        flags |= HAS_PASSWORD_HASH;
    }
    if secret.key_file.is_some() {
        flags |= HAS_KEY_FILE;
    }
    if secret.generated_password.is_some() {
        flags |= HAS_GENERATED_PASSWORD;
    }
    out.push(flags);
    if let Some(hash) = &secret.password_hash {
        out.extend_from_slice(hash.as_slice());
    }
    if let Some(key_file) = &secret.key_file {
        if key_file.is_empty() || key_file.len() > MAX_KEY_FILE_BYTES {
            return Err(invalid("the key file must be 1 to 2048 bytes"));
        }
        push(&mut out, key_file);
    }
    if let Some(password) = &secret.generated_password {
        if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
            return Err(invalid("the password must be 1 to 1024 bytes"));
        }
        push(&mut out, password.as_bytes());
    }
    debug_assert!(out.len() <= PAYLOAD_LEN);
    out.resize(PAYLOAD_LEN, 0);
    Ok(out)
}

fn push(out: &mut Vec<u8>, value: &[u8]) {
    // Both limits are far below u16::MAX.
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn take<'a>(rest: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    if rest.len() < len {
        return Err(CryptoError::AuthFailed);
    }
    let (head, tail) = rest.split_at(len);
    *rest = tail;
    Ok(head)
}

fn take_value<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = u16::from_be_bytes(take(rest, 2)?.try_into().expect("two bytes")) as usize;
    take(rest, len)
}

/// Seals the secret of vault `file_id` (the Drive file's UUID bytes) under
/// the master key, for the account's key binding.
pub fn seal_vault_secret(
    master_key: &[u8],
    binding: &str,
    file_id: &[u8; 16],
    secret: &VaultSecret,
) -> Result<Vec<u8>> {
    account_envelope::seal_object(
        &payload(file_id, secret)?,
        master_key,
        AccountEnvelopePurpose::PassVaultSecret,
        binding,
        file_id,
    )
}

/// [`seal_vault_secret`] with a fixed nonce, for checked-in vectors only.
pub fn seal_vault_secret_with_nonce(
    master_key: &[u8],
    binding: &str,
    file_id: &[u8; 16],
    secret: &VaultSecret,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    account_envelope::seal_suite(
        account_envelope::AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2,
        &payload(file_id, secret)?,
        master_key,
        AccountEnvelopePurpose::PassVaultSecret,
        binding,
        file_id,
        nonce,
    )
}

/// Opens the secret of vault `file_id`; fails unless it was sealed for that
/// vault.
pub fn open_vault_secret(
    envelope: &[u8],
    master_key: &[u8],
    binding: &str,
    file_id: &[u8; 16],
) -> Result<VaultSecret> {
    let plain = Zeroizing::new(account_envelope::open_object(
        envelope,
        master_key,
        AccountEnvelopePurpose::PassVaultSecret,
        binding,
        file_id,
    )?);
    parse_payload(&plain, file_id)
}

/// Reads a payload, held to the same bounds sealing keeps.
fn parse_payload(plain: &[u8], file_id: &[u8; 16]) -> Result<VaultSecret> {
    if plain.len() != PAYLOAD_LEN {
        return Err(CryptoError::AuthFailed);
    }
    let mut rest = plain.strip_prefix(DOMAIN).ok_or(CryptoError::AuthFailed)?;
    if take(&mut rest, 16)? != file_id {
        return Err(CryptoError::AuthFailed);
    }
    let flags = take(&mut rest, 1)?[0];
    let known = HAS_PASSWORD_HASH | HAS_KEY_FILE | HAS_GENERATED_PASSWORD;
    if flags == 0
        || flags & !known != 0
        || flags & (HAS_PASSWORD_HASH | HAS_GENERATED_PASSWORD)
            == HAS_PASSWORD_HASH | HAS_GENERATED_PASSWORD
    {
        return Err(CryptoError::AuthFailed);
    }
    let password_hash = if flags & HAS_PASSWORD_HASH != 0 {
        let hash: [u8; 32] = take(&mut rest, 32)?.try_into().expect("32 bytes");
        Some(Zeroizing::new(hash))
    } else {
        None
    };
    let key_file = if flags & HAS_KEY_FILE != 0 {
        let bytes = take_value(&mut rest)?;
        if bytes.is_empty() || bytes.len() > MAX_KEY_FILE_BYTES {
            return Err(CryptoError::AuthFailed);
        }
        Some(Zeroizing::new(bytes.to_vec()))
    } else {
        None
    };
    let generated_password = if flags & HAS_GENERATED_PASSWORD != 0 {
        let bytes = take_value(&mut rest)?;
        if bytes.is_empty() || bytes.len() > MAX_PASSWORD_BYTES {
            return Err(CryptoError::AuthFailed);
        }
        Some(Zeroizing::new(
            std::str::from_utf8(bytes)
                .map_err(|_| CryptoError::AuthFailed)?
                .to_owned(),
        ))
    } else {
        None
    };
    // Only the padding may follow.
    if rest.iter().any(|&byte| byte != 0) {
        return Err(CryptoError::AuthFailed);
    }
    Ok(VaultSecret {
        password_hash,
        generated_password,
        key_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; 32] = [7; 32];
    const VAULT: [u8; 16] = [1; 16];
    const BINDING: &str = "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90";

    #[test]
    fn round_trips_every_kind_of_key() {
        for s in [
            VaultSecret::chosen(Some("parola-çğ"), None),
            VaultSecret::chosen(None, Some(b"<KeyFile/>")),
            VaultSecret::chosen(Some(""), Some(&[9; 32])),
            VaultSecret::generated("abcd-efgh-ijkl", None),
            VaultSecret::generated("abcd-efgh-ijkl", Some(b"kf")),
        ] {
            let sealed = seal_vault_secret(&MASTER, BINDING, &VAULT, &s).unwrap();
            assert_eq!(
                open_vault_secret(&sealed, &MASTER, BINDING, &VAULT).unwrap(),
                s
            );
        }
    }

    #[test]
    fn a_chosen_password_is_kept_only_as_keepass_hashes_it() {
        let s = VaultSecret::chosen(Some("parola-çğ"), None);
        let sealed = seal_vault_secret(&MASTER, BINDING, &VAULT, &s).unwrap();
        let plain = account_envelope::open_object(
            &sealed,
            &MASTER,
            AccountEnvelopePurpose::PassVaultSecret,
            BINDING,
            &VAULT,
        )
        .unwrap();
        assert!(!plain
            .windows("parola-çğ".len())
            .any(|w| w == "parola-çğ".as_bytes()));
        let opened = open_vault_secret(&sealed, &MASTER, BINDING, &VAULT).unwrap();
        assert_eq!(
            opened.password_element().unwrap().as_slice(),
            Sha256::digest("parola-çğ".as_bytes()).as_slice()
        );
        assert!(opened.generated_password.is_none());
        let generated = VaultSecret::generated("abcd", None);
        assert_eq!(
            generated.password_element().unwrap().as_slice(),
            Sha256::digest(b"abcd").as_slice()
        );
    }

    #[test]
    fn bound_to_the_vault_the_account_and_the_key() {
        let sealed = seal_vault_secret(
            &MASTER,
            BINDING,
            &VAULT,
            &VaultSecret::chosen(Some("p"), None),
        )
        .unwrap();
        assert!(open_vault_secret(&sealed, &MASTER, BINDING, &[2; 16]).is_err());
        assert!(open_vault_secret(
            &sealed,
            &MASTER,
            "1c2d3e4f-0000-4000-8000-000000000000",
            &VAULT
        )
        .is_err());
        assert!(open_vault_secret(&sealed, &[8; 32], BINDING, &VAULT).is_err());
    }

    /// Seals `payload` as a vault secret's envelope as is, to hand the
    /// parser what sealing never makes.
    fn sealed_raw(payload: &[u8]) -> Vec<u8> {
        account_envelope::seal_object(
            payload,
            &MASTER,
            AccountEnvelopePurpose::PassVaultSecret,
            BINDING,
            &VAULT,
        )
        .unwrap()
    }

    fn padded(mut payload: Vec<u8>) -> Vec<u8> {
        payload.resize(PAYLOAD_LEN, 0);
        payload
    }

    fn head(flags: u8) -> Vec<u8> {
        let mut out = DOMAIN.to_vec();
        out.extend_from_slice(&VAULT);
        out.push(flags);
        out
    }

    #[test]
    fn every_kind_of_key_seals_to_one_length() {
        let sizes: std::collections::BTreeSet<usize> = [
            VaultSecret::chosen(Some("p"), None),
            VaultSecret::chosen(Some("p"), Some(&[1; MAX_KEY_FILE_BYTES])),
            VaultSecret::chosen(None, Some(b"k")),
            VaultSecret::generated(
                &"g".repeat(MAX_PASSWORD_BYTES),
                Some(&[1; MAX_KEY_FILE_BYTES]),
            ),
            VaultSecret::generated("g", None),
        ]
        .iter()
        .map(|s| {
            seal_vault_secret(&MASTER, BINDING, &VAULT, s)
                .unwrap()
                .len()
        })
        .collect();
        assert_eq!(sizes.len(), 1, "{sizes:?}");
    }

    #[test]
    fn the_parser_takes_only_what_sealing_makes() {
        let open =
            |payload: &[u8]| open_vault_secret(&sealed_raw(payload), &MASTER, BINDING, &VAULT);
        // What sealing makes, by hand, opens.
        let mut good = head(HAS_PASSWORD_HASH);
        good.extend_from_slice(&[3; 32]);
        assert!(open(&padded(good.clone())).is_ok());
        // Unpadded, or padded with something other than zeros.
        assert!(open(&good).is_err());
        let mut dirty = padded(good.clone());
        *dirty.last_mut().unwrap() = 1;
        assert!(open(&dirty).is_err());
        // Unknown flags, no flags, a hash and a generated password together.
        for flags in [0, 8, HAS_PASSWORD_HASH | HAS_GENERATED_PASSWORD] {
            let mut p = head(flags);
            p.extend_from_slice(&[3; 32]);
            p.extend_from_slice(&[0, 1, b'g']);
            assert!(open(&padded(p)).is_err(), "flags {flags}");
        }
        // An empty key file or generated password.
        for flags in [HAS_KEY_FILE, HAS_GENERATED_PASSWORD] {
            let mut p = head(flags);
            p.extend_from_slice(&[0, 0]);
            assert!(open(&padded(p)).is_err(), "empty, flags {flags}");
        }
        // Another vault's id, or the v1 domain.
        let mut other = DOMAIN.to_vec();
        other.extend_from_slice(&[2; 16]);
        other.push(HAS_PASSWORD_HASH);
        other.extend_from_slice(&[3; 32]);
        assert!(open(&padded(other)).is_err());
        let mut v1 = b"kutup/pass-vault-secret/v1\0".to_vec();
        v1.extend_from_slice(&VAULT);
        v1.push(1);
        v1.extend_from_slice(&[0, 1, b'p']);
        assert!(open(&padded(v1)).is_err());
    }

    #[test]
    fn refuses_empty_doubled_and_oversized_secrets() {
        let seal = |s: &VaultSecret| seal_vault_secret(&MASTER, BINDING, &VAULT, s);
        assert!(seal(&VaultSecret::chosen(None, None)).is_err());
        let mut both = VaultSecret::chosen(Some("a"), None);
        both.generated_password = Some(Zeroizing::new("b".into()));
        assert!(seal(&both).is_err());
        assert!(seal(&VaultSecret::generated("", None)).is_err());
        assert!(seal(&VaultSecret::generated(
            &"x".repeat(MAX_PASSWORD_BYTES + 1),
            None
        ))
        .is_err());
        assert!(seal(&VaultSecret::chosen(
            None,
            Some(&[0; MAX_KEY_FILE_BYTES + 1])
        ))
        .is_err());
        assert!(seal(&VaultSecret::chosen(None, Some(&[]))).is_err());
    }
}
