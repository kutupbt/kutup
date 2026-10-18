//! The one HPKE suite Kutup seals to a key with: the X-Wing KEM (X25519 +
//! ML-KEM-768, draft-connolly-cfrg-xwing-kem-06, HPKE KEM 0x647a),
//! HKDF-SHA256 and ChaCha20-Poly1305 (docs/plans/pq-shares.md). Every
//! envelope sealed to a person (Drive, Photos and Office shares, profile
//! keys, shared mailboxes' secrets) and the groups' gateway route
//! ([`crate::oblivious`]) use it; there is no other KEM.
//!
//! A private key is its 32-byte X-Wing seed and the public key is derived
//! from it ([`public_key`]). hpke-rs's `derive_key_pair` is never used: it
//! hashes its input first, so its keys are not the seed's.

use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::{Hpke, Mode};
use hpke_rs_rust_crypto::HpkeRustCrypto;

/// The HPKE registry's X-Wing KEM id (not the draft's earlier 0x004D).
pub const KEM_ID: u16 = 0x647a;
/// An X-Wing encapsulation key: ML-KEM-768's 1184 bytes and an X25519 key.
pub const PUBLIC_KEY_LEN: usize = 1216;
/// An X-Wing decapsulation key is its 32-byte seed.
pub const SEED_LEN: usize = 32;
/// An X-Wing ciphertext: ML-KEM-768's 1088 bytes and an X25519 share.
pub const ENCAPSULATED_KEY_LEN: usize = 1120;

/// The suite, in HPKE's base mode.
pub(crate) fn suite() -> Hpke<HpkeRustCrypto> {
    Hpke::new(
        Mode::Base,
        KemAlgorithm::XWingDraft06,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    )
}

/// X-Wing's GenerateKeyPairDerand: the encapsulation key of `seed`.
pub fn public_key(seed: &[u8; SEED_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    use x_wing::{Decapsulator as _, KeyExport as _};
    let key = x_wing::DecapsulationKey::from(*seed);
    let mut public_key = [0u8; PUBLIC_KEY_LEN];
    public_key.copy_from_slice(key.encapsulation_key().to_bytes().as_slice());
    public_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke_rs::{HpkePrivateKey, HpkePublicKey};

    /// The KEM through hpke-rs's backend, the path every envelope takes:
    /// a seal to a seed's public key opens with the seed, and nothing else
    /// opens it.
    #[test]
    fn a_seal_through_the_suite_opens_only_with_its_seed() {
        let seed = [9u8; SEED_LEN];
        let public = public_key(&seed);
        let (encapsulated, ciphertext) = suite()
            .seal(
                &HpkePublicKey::new(public.to_vec()),
                b"info",
                b"aad",
                b"secret",
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(encapsulated.len(), ENCAPSULATED_KEY_LEN);
        let opened = suite()
            .open(
                &encapsulated,
                &HpkePrivateKey::new(seed.to_vec()),
                b"info",
                b"aad",
                &ciphertext,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(opened, b"secret");
        assert!(suite()
            .open(
                &encapsulated,
                &HpkePrivateKey::new([8u8; SEED_LEN].to_vec()),
                b"info",
                b"aad",
                &ciphertext,
                None,
                None,
                None,
            )
            .is_err());
    }
}
