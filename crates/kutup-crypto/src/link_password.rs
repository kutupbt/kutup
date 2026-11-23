//! A public link's password (docs/plans/drive-link-password.md), after
//! Proton Drive's "generated password + custom password".
//!
//! A link's URL fragment carries its 32-byte **secret** `S`. Without a
//! password `S` is the link key itself. With one, the key the link's target
//! is sealed under is a separate random **link key** `L`, sealed under a
//! wrap key that needs both `S` and the password:
//!
//! - `stretched = Argon2id(NFC(password), salt, params)`, a 16-byte random
//!   salt and the cost stored with the link;
//! - `HKDF-SHA256(salt = FAMILY, ikm = S ‖ stretched)` expands, with the
//!   link id, to the **wrap key** and to a **proof**;
//! - `L` sealed under the wrap key is Drive envelope purpose 14
//!   (`PublicLinkPasswordKey`), bound to the link, its owner and the link's
//!   key revision;
//! - the server keeps `verifier = SHA-256(VERIFIER_DOMAIN ‖ proof)` and
//!   releases the purpose-14 envelope only to a request carrying the proof.
//!
//! The server never holds `S`, so it cannot test a password against the
//! verifier; a holder of the URL never gets the verifier or the envelope, so
//! each guess is a request the server counts. The owner keeps `S ‖ password`
//! under their Drive root (purpose 15, [`seal_owner_secret`]) to copy the
//! link and see its password, as Proton's owner does.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::account_roots::{DriveRoot, RootGeneration};
use crate::drive_envelope::{self, DriveEnvelopeContextV1};
use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};
use crate::primitives::{ct_eq, pwhash, Hasher, Kdf, PwhashParams, Suite};

/// A link's URL secret, and its link key, in bytes.
pub const SECRET_LEN: usize = 32;
/// A password's salt, in bytes.
pub const SALT_LEN: usize = 16;
/// The proof, the verifier and the wrap key, in bytes.
pub const PROOF_LEN: usize = 32;
/// The longest password, in bytes (after NFC): what purpose 15 holds at
/// most. The site's own limit in characters is below it.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// The cost a new link password is stretched at: the account password's
/// (64 MiB, 3 passes, one lane).
pub const PARAMS_V1: PwhashParams = PwhashParams {
    operations: 3,
    memory: 64 * 1024 * 1024,
};
/// The costs an opener accepts, so a server can neither make a page
/// allocate without bound nor serve a trivial cost it was never given.
pub const MIN_OPERATIONS: u64 = 1;
pub const MAX_OPERATIONS: u64 = 10;
pub const MIN_MEMORY: usize = 8 * 1024 * 1024;
pub const MAX_MEMORY: usize = 256 * 1024 * 1024;

const FAMILY: &[u8] = crate::labels::DRIVE_LINK_PASSWORD_V1;
const WRAP_INFO: &[u8] = crate::labels::DRIVE_LINK_PASSWORD_WRAP_V1;
const PROOF_INFO: &[u8] = crate::labels::DRIVE_LINK_PASSWORD_PROOF_V1;
const VERIFIER_DOMAIN: &[u8] = crate::labels::DRIVE_LINK_PASSWORD_VERIFIER_V1;

/// A stored cost, checked: within the bounds above.
pub fn check_params(operations: u64, memory: u64) -> Result<PwhashParams> {
    let memory = usize::try_from(memory)
        .map_err(|_| CryptoError::InvalidInput("link password memory out of range".into()))?;
    if !(MIN_OPERATIONS..=MAX_OPERATIONS).contains(&operations)
        || !(MIN_MEMORY..=MAX_MEMORY).contains(&memory)
    {
        return Err(CryptoError::InvalidInput(
            "link password cost out of range".into(),
        ));
    }
    Ok(PwhashParams { operations, memory })
}

/// The password as it is stretched: NFC, not empty, at most
/// [`MAX_PASSWORD_BYTES`].
pub fn normalize(password: &str) -> Result<Zeroizing<String>> {
    let composed = Zeroizing::new(password.nfc().collect::<String>());
    if composed.is_empty() || composed.len() > MAX_PASSWORD_BYTES {
        return Err(CryptoError::InvalidInput(
            "a link password is 1 to 1024 bytes".into(),
        ));
    }
    Ok(composed)
}

fn secret_of(secret: &[u8]) -> Result<&[u8]> {
    if secret.len() != SECRET_LEN {
        return Err(CryptoError::InvalidLength {
            expected: SECRET_LEN,
            got: secret.len(),
        });
    }
    Ok(secret)
}

/// What a link's secret and password derive.
pub struct LinkPasswordKeys {
    /// Opens (and seals) the link key, purpose 14.
    pub wrap_key: Zeroizing<[u8; PROOF_LEN]>,
    /// Sent to the server, which checks it against the verifier.
    pub proof: Zeroizing<[u8; PROOF_LEN]>,
}

/// The wrap key and proof from the URL secret, the password, the salt and
/// cost stored with the link, and the link's id.
pub fn derive(
    secret: &[u8],
    password: &str,
    salt: &[u8],
    params: &PwhashParams,
    link_id: &str,
) -> Result<LinkPasswordKeys> {
    let secret = secret_of(secret)?;
    let salt: &[u8; SALT_LEN] = salt.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: SALT_LEN,
        got: salt.len(),
    })?;
    let params = check_params(params.operations, params.memory as u64)?;
    let link = parse_canonical_uuid(link_id, "link")?;
    let password = normalize(password)?;
    let mut ikm = Zeroizing::new([0u8; SECRET_LEN + PROOF_LEN]);
    ikm[..SECRET_LEN].copy_from_slice(secret);
    pwhash(&params, password.as_bytes(), salt, &mut ikm[SECRET_LEN..])?;
    let hkdf = Kdf::new(Suite::V1, FAMILY, ikm.as_slice());
    let mut keys = LinkPasswordKeys {
        wrap_key: Zeroizing::new([0u8; PROOF_LEN]),
        proof: Zeroizing::new([0u8; PROOF_LEN]),
    };
    for (info, out) in [
        (WRAP_INFO, keys.wrap_key.as_mut_slice()),
        (PROOF_INFO, keys.proof.as_mut_slice()),
    ] {
        let mut full = info.to_vec();
        full.extend_from_slice(&link);
        hkdf.expand(&full, out)
            .map_err(|_| CryptoError::Backend("link password HKDF expand".into()))?;
    }
    Ok(keys)
}

/// What the server stores to check a proof.
pub fn verifier(proof: &[u8]) -> Result<[u8; PROOF_LEN]> {
    if proof.len() != PROOF_LEN {
        return Err(CryptoError::InvalidLength {
            expected: PROOF_LEN,
            got: proof.len(),
        });
    }
    Ok(Hasher::new(Suite::V1)
        .chain(VERIFIER_DOMAIN)
        .chain(proof)
        .finish()
        .to_array())
}

/// Whether `proof` is the one `stored` was made from (constant time).
pub fn verify(proof: &[u8], stored: &[u8]) -> bool {
    match verifier(proof) {
        Ok(expected) => stored.len() == PROOF_LEN && ct_eq(&expected, stored),
        Err(_) => false,
    }
}

/// A password set on a link: what the server stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protection {
    pub salt: [u8; SALT_LEN],
    pub params: PwhashParams,
    pub verifier: [u8; PROOF_LEN],
    /// The link key under the wrap key (purpose 14), canonical base64.
    pub link_key_envelope: String,
}

/// Protects `link_key` with the URL `secret` and `password`, at
/// [`PARAMS_V1`] with a fresh salt.
pub fn protect(
    secret: &[u8],
    password: &str,
    link_key: &[u8],
    link_id: &str,
    owner_id: &str,
    key_revision: u32,
) -> Result<Protection> {
    let salt: [u8; SALT_LEN] = crate::primitives::random_array();
    let nonce: [u8; 24] = crate::primitives::random_array();
    protect_with(
        secret,
        password,
        link_key,
        link_id,
        owner_id,
        key_revision,
        &PARAMS_V1,
        &salt,
        &nonce,
    )
}

/// [`protect`] with a given cost, salt and nonce (the vectors).
#[allow(clippy::too_many_arguments)]
pub fn protect_with(
    secret: &[u8],
    password: &str,
    link_key: &[u8],
    link_id: &str,
    owner_id: &str,
    key_revision: u32,
    params: &PwhashParams,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; 24],
) -> Result<Protection> {
    if link_key.len() != SECRET_LEN {
        return Err(CryptoError::InvalidLength {
            expected: SECRET_LEN,
            got: link_key.len(),
        });
    }
    if link_key == secret_of(secret)? {
        return Err(CryptoError::InvalidInput(
            "a protected link's key is not its URL secret".into(),
        ));
    }
    let keys = derive(secret, password, salt, params, link_id)?;
    let context = DriveEnvelopeContextV1::link_password_key(link_id, owner_id, key_revision)?;
    let envelope =
        drive_envelope::seal_with_nonce(link_key, keys.wrap_key.as_slice(), context, nonce)?;
    Ok(Protection {
        salt: *salt,
        params: *params,
        verifier: verifier(keys.proof.as_slice())?,
        link_key_envelope: STANDARD.encode(envelope),
    })
}

/// Opens a protected link's key with the wrap key [`derive`] gave.
pub fn open_link_key(
    envelope_b64: &str,
    wrap_key: &[u8],
    link_id: &str,
    owner_id: &str,
    key_revision: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    let context = DriveEnvelopeContextV1::link_password_key(link_id, owner_id, key_revision)?;
    drive_envelope::open_b64(envelope_b64, wrap_key, context).map(Zeroizing::new)
}

/// A link's URL secret and password, as its owner keeps them.
pub struct LinkSecret {
    pub secret: Zeroizing<[u8; SECRET_LEN]>,
    pub password: Zeroizing<String>,
}

/// Seals the URL secret and password for the link's owner under their Drive
/// root of `generation` (purpose 15).
pub fn seal_owner_secret(
    secret: &[u8],
    password: &str,
    drive_root: &DriveRoot,
    link_id: &str,
    owner_id: &str,
    generation: RootGeneration,
) -> Result<String> {
    let password = normalize(password)?;
    let mut plain = Zeroizing::new(secret_of(secret)?.to_vec());
    plain.extend_from_slice(password.as_bytes());
    let context = DriveEnvelopeContextV1::owner_link_secret(link_id, owner_id, generation)?;
    drive_envelope::seal_under_drive_root(&plain, drive_root, context)
}

/// Opens a link's owner secret (purpose 15).
pub fn open_owner_secret(
    envelope_b64: &str,
    drive_root: &DriveRoot,
    link_id: &str,
    owner_id: &str,
    generation: RootGeneration,
) -> Result<LinkSecret> {
    let context = DriveEnvelopeContextV1::owner_link_secret(link_id, owner_id, generation)?;
    let plain = drive_envelope::open_under_drive_root(envelope_b64, drive_root, context)?;
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    secret.copy_from_slice(&plain[..SECRET_LEN]);
    let password = std::str::from_utf8(&plain[SECRET_LEN..])
        .map_err(|_| CryptoError::InvalidInput("a link password is UTF-8".into()))?;
    Ok(LinkSecret {
        secret,
        password: normalize(password)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "33333333-3333-4333-8333-333333333333";
    const OWNER: &str = "22222222-2222-4222-8222-222222222222";
    const FAST: PwhashParams = PwhashParams {
        operations: 1,
        memory: MIN_MEMORY,
    };

    fn protected(password: &str) -> Protection {
        protect_with(
            &[1; 32], password, &[2; 32], LINK, OWNER, 2, &FAST, &[3; 16], &[4; 24],
        )
        .unwrap()
    }

    #[test]
    fn the_secret_and_the_password_open_the_link_key() {
        let protection = protected("correct horse");
        let keys = derive(&[1; 32], "correct horse", &[3; 16], &FAST, LINK).unwrap();
        assert!(verify(keys.proof.as_slice(), &protection.verifier));
        let key = open_link_key(
            &protection.link_key_envelope,
            keys.wrap_key.as_slice(),
            LINK,
            OWNER,
            2,
        )
        .unwrap();
        assert_eq!(key.as_slice(), &[2; 32]);
    }

    #[test]
    fn neither_alone_opens_it() {
        let protection = protected("correct horse");
        for (secret, password) in [([9u8; 32], "correct horse"), ([1u8; 32], "correct horsf")] {
            let keys = derive(&secret, password, &[3; 16], &FAST, LINK).unwrap();
            assert!(!verify(keys.proof.as_slice(), &protection.verifier));
            assert!(open_link_key(
                &protection.link_key_envelope,
                keys.wrap_key.as_slice(),
                LINK,
                OWNER,
                2
            )
            .is_err());
        }
    }

    #[test]
    fn the_keys_are_bound_to_the_link_and_its_revision() {
        let protection = protected("pw");
        let keys = derive(&[1; 32], "pw", &[3; 16], &FAST, LINK).unwrap();
        let other = derive(&[1; 32], "pw", &[3; 16], &FAST, OWNER).unwrap();
        assert_ne!(keys.proof.as_slice(), other.proof.as_slice());
        assert!(open_link_key(
            &protection.link_key_envelope,
            keys.wrap_key.as_slice(),
            LINK,
            OWNER,
            3
        )
        .is_err());
    }

    #[test]
    fn passwords_are_compared_composed() {
        let composed = derive(&[1; 32], "\u{e7}", &[3; 16], &FAST, LINK).unwrap();
        let decomposed = derive(&[1; 32], "c\u{327}", &[3; 16], &FAST, LINK).unwrap();
        assert_eq!(composed.proof.as_slice(), decomposed.proof.as_slice());
    }

    #[test]
    fn costs_and_inputs_are_bounded() {
        assert!(check_params(0, MIN_MEMORY as u64).is_err());
        assert!(check_params(11, MIN_MEMORY as u64).is_err());
        assert!(check_params(1, MIN_MEMORY as u64 - 1).is_err());
        assert!(check_params(1, MAX_MEMORY as u64 + 1).is_err());
        assert!(check_params(3, PARAMS_V1.memory as u64).is_ok());
        assert!(derive(&[1; 32], "", &[3; 16], &FAST, LINK).is_err());
        assert!(derive(&[1; 31], "pw", &[3; 16], &FAST, LINK).is_err());
        assert!(normalize(&"a".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
        assert!(!verify(&[0; 31], &[0; 32]));
        // The link key must not be the URL secret.
        assert!(
            protect_with(&[1; 32], "pw", &[1; 32], LINK, OWNER, 2, &FAST, &[3; 16], &[4; 24])
                .is_err()
        );
    }

    #[test]
    fn the_owner_keeps_the_secret_and_password() {
        let root = DriveRoot::from_slice(&[7; 32]).unwrap();
        let generation = RootGeneration::new(1).unwrap();
        let sealed = seal_owner_secret(&[1; 32], "şifre", &root, LINK, OWNER, generation).unwrap();
        let opened = open_owner_secret(&sealed, &root, LINK, OWNER, generation).unwrap();
        assert_eq!(opened.secret.as_slice(), &[1; 32]);
        assert_eq!(opened.password.as_str(), "şifre");
        // Padded: a short and a long password seal to one length.
        let longer =
            seal_owner_secret(&[1; 32], &"x".repeat(100), &root, LINK, OWNER, generation).unwrap();
        assert_eq!(sealed.len(), longer.len());
        assert!(open_owner_secret(&sealed, &root, OWNER, OWNER, generation).is_err());
    }
}
