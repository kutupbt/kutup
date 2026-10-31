//! The server's half of an OPAQUE sign-in between its start and its finish
//! (docs/plans/opaque.md §5), sealed while it waits in the database: the
//! expected key-confirmation MAC and the session key are never there in the
//! clear.
//!
//! `seal = magic ‖ nonce ‖ XChaCha20-Poly1305(key, state, aad)` with
//! `key = HKDF-SHA256(setup key, salt = "kutup/opaque/login-state/v1\0")` (a
//! key of its own, not the setup's) and `aad = "kutup/opaque/login-state/v1\0"
//! ‖ login id (16 bytes)`, so a state opens only for the login it was made
//! for.

use crate::primitives::{Aead, Kdf, Suite};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

const LABEL: &[u8] = crate::labels::OPAQUE_LOGIN_STATE_V1;
const MAGIC: &[u8; 4] = b"KOL1";
const NONCE_LEN: usize = 24;

fn key(setup_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Kdf::new(Suite::V1, LABEL, setup_key)
        .expand(&[], key.as_mut_slice())
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
    let sealed = Aead::new(Suite::V1, key.as_ref())?
        .seal_with_nonce(&nonce, &aad(login_id), state)
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
    Aead::new(Suite::V1, key.as_ref())?
        .open_with_nonce(
            &sealed[MAGIC.len()..header],
            &aad(login_id),
            &sealed[header..],
        )
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
