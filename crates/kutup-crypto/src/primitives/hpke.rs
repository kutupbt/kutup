use hpke_rs::{HpkePrivateKey, HpkePublicKey};
use zeroize::Zeroizing;

use super::Suite;
use crate::error::{CryptoError, Result};

/// What sealing to a key gives: the encapsulation and the ciphertext.
pub struct HpkeSealed {
    pub encapsulated: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// The suite's public key for a private seed.
pub fn hpke_public_key(suite: Suite, seed: &[u8; 32]) -> Vec<u8> {
    match suite {
        Suite::V1 => crate::hpke_xwing::public_key(seed).to_vec(),
    }
}

/// Seals `plaintext` to `public_key` (base mode), bound to `info` and `aad`.
pub fn hpke_seal(
    suite: Suite,
    public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed> {
    match suite {
        Suite::V1 => {
            if public_key.len() != suite.params().hpke_public_key_len {
                return Err(CryptoError::InvalidLength {
                    expected: suite.params().hpke_public_key_len,
                    got: public_key.len(),
                });
            }
            let mut hpke = crate::hpke_xwing::suite();
            let (encapsulated, ciphertext) = hpke
                .seal(
                    &HpkePublicKey::new(public_key.to_vec()),
                    info,
                    aad,
                    plaintext,
                    None,
                    None,
                    None,
                )
                .map_err(|_| CryptoError::Backend("hpke seal".into()))?;
            Ok(HpkeSealed {
                encapsulated,
                ciphertext,
            })
        }
    }
}

/// Opens what [`hpke_seal`] sealed to `seed`'s public key.
pub fn hpke_open(
    suite: Suite,
    seed: &[u8],
    encapsulated: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    match suite {
        Suite::V1 => crate::hpke_xwing::suite()
            .open(
                encapsulated,
                &HpkePrivateKey::new(seed.to_vec()),
                info,
                aad,
                ciphertext,
                None,
                None,
                None,
            )
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::AuthFailed),
    }
}
