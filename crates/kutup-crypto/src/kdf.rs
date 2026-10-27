//! The recovery path's derivation: the proof a client sends the server for
//! an account's recovery, derived from the 32-byte recovery entropy (which
//! itself only ever opens the recovery wrap of the master key).
//!
//! The password path is OPAQUE (`opaque`): its Argon2id runs inside the
//! OPAQUE key-stretching function. The Argon2id account-protection
//! derivation that came before it has no caller and is gone
//! (docs/plans/w6-key-hierarchy.md, §4).

use crate::primitives::{Kdf, Suite};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// The recovery entropy's and the proof's length in bytes.
pub const KEY_LEN: usize = 32;

const RECOVERY_AUTH_SALT: &[u8] = b"kutup/account-recovery/auth-proof/v1\0";

/// Derive the server-visible recovery authorization proof. The 32-byte raw
/// recovery entropy continues to encrypt the recovery master-key wrap and is
/// never sent to the server.
pub fn derive_recovery_auth_proof(
    recovery_entropy: &[u8],
    binding: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if recovery_entropy.len() != KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "recovery entropy must be 32 bytes".into(),
        ));
    }
    let canonical = crate::key_binding::check(binding)
        .map_err(|_| CryptoError::InvalidInput("recovery binding is not a key binding".into()))?;
    let hkdf = Kdf::new(Suite::V1, RECOVERY_AUTH_SALT, recovery_entropy);
    let mut proof = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(canonical.as_bytes(), proof.as_mut_slice())
        .map_err(|_| CryptoError::Backend("recovery proof HKDF expand".into()))?;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_proof_is_bound_to_a_key_binding_and_not_raw_entropy() {
        let entropy = [9u8; 32];
        let first =
            derive_recovery_auth_proof(&entropy, "0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90").unwrap();
        assert_ne!(first.as_slice(), entropy.as_slice());
        assert_ne!(
            first.as_slice(),
            derive_recovery_auth_proof(&entropy, "1c9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e91")
                .unwrap()
                .as_slice()
        );
        // Only a key binding: no address, no other case, no padding.
        for other in [
            "alice@example.com",
            "0B9F4C0E-6A51-4D2F-9A33-5E1F6C7D8E90",
            " 0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90",
            "",
        ] {
            assert!(
                derive_recovery_auth_proof(&entropy, other).is_err(),
                "{other}"
            );
        }
    }
}
