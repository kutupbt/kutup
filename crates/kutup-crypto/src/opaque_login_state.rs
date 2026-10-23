//! The server's half of an OPAQUE sign-in between its start and its finish
//! (docs/plans/opaque.md §5), sealed while it waits in the database: the
//! expected key-confirmation MAC and the session key are never there in the
//! clear.
//!
//! `seal = magic ‖ nonce ‖ XChaCha20-Poly1305(key, state, aad)` with
//! `key = HKDF-SHA256(setup key, info = "kutup/opaque-login-state/v1\0")` (a
//! key of its own, not the setup's) and `aad = "kutup/opaque-login-state/v1\0"
//! ‖ login id (16 bytes)`, so a state opens only for the login it was made
//! for.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

const LABEL: &[u8] = b"kutup/opaque-login-state/v1\0";
const MAGIC: &[u8; 4] = b"KOL1";
const NONCE_LEN: usize = 24;

fn key(setup_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, setup_key)
        .expand(LABEL, key.as_mut_slice())
        .map_err(|_| CryptoError::Backend("opaque login state HKDF".into()))?;
    Ok(key)
}

fn aad(login_id: &[u8; 16]) -> Vec<u8> {
    [LABEL, login_id.as_slice()].concat()
}

/// Seals `state` for login `login_id` under the setup key.
pub fn seal(setup_key: &[u8; 32], login_id: &[u8; 16], state: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::primitives::random(&mut nonce);
    let key = key(setup_key)?;
    let sealed = XChaCha20Poly1305::new(key.as_slice().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: state,
                aad: &aad(login_id),
            },
        )
        .map_err(|_| CryptoError::Backend("opaque login state seal".into()))?;
    Ok([MAGIC.as_slice(), &nonce, &sealed].concat())
}

/// Opens a state sealed by [`seal`] for the same login.
pub fn open(
    setup_key: &[u8; 32],
    login_id: &[u8; 16],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let header = MAGIC.len() + NONCE_LEN;
    if sealed.len() <= header || &sealed[..MAGIC.len()] != MAGIC {
        return Err(CryptoError::InvalidInput("not a sealed login state".into()));
    }
    let key = key(setup_key)?;
    XChaCha20Poly1305::new(key.as_slice().into())
        .decrypt(
            XNonce::from_slice(&sealed[MAGIC.len()..header]),
            Payload {
                msg: &sealed[header..],
                aad: &aad(login_id),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_opens_only_for_its_login_and_key() {
        let (key, login) = ([1u8; 32], [2u8; 16]);
        let sealed = seal(&key, &login, b"state").unwrap();
        assert_eq!(open(&key, &login, &sealed).unwrap().as_slice(), b"state");
        assert!(open(&key, &[3u8; 16], &sealed).is_err(), "another login");
        assert!(open(&[4u8; 32], &login, &sealed).is_err(), "another key");
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&key, &login, &tampered).is_err());
        assert!(
            !sealed.windows(5).any(|w| w == b"state"),
            "not in the clear"
        );
    }
}
