//! The suite table: every algorithm and every parameter of a suite, listed
//! once. A new suite is a new row here (and its vectors), so the difference
//! between two suites is a plain diff of two rows.

/// A whole tuple of algorithms, never mixed with another suite's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Suite {
    /// SHA-256, HMAC/HKDF-SHA256, XChaCha20-Poly1305, Ed25519, X-Wing HPKE.
    V1,
}

/// What a suite is, exactly.
#[derive(Debug, PartialEq, Eq)]
pub struct SuiteParams {
    /// The hash (`hash`, `Hasher`) and its digest length.
    pub hash: &'static str,
    pub digest_len: usize,
    /// The MAC (`mac`, `subkey`: `subkey(root, label) = MAC(root, label)`)
    /// and its tag length.
    pub mac: &'static str,
    pub mac_tag_len: usize,
    /// The KDF (`kdf(ikm, salt, info)`): an empty salt is the hash's zero
    /// key (RFC 5869 §2.2); `info` is the caller's label,
    /// `kutup/<area>/<purpose>/vN\0`.
    pub kdf: &'static str,
    pub kdf_max_output: usize,
    /// The AEAD (`Aead`): key, nonce and tag lengths. Nonces are random per
    /// message (24 bytes leave collisions out of reach), never counters.
    pub aead: &'static str,
    pub aead_key_len: usize,
    pub aead_nonce_len: usize,
    pub aead_tag_len: usize,
    /// Signatures (`SigningKey`, `VerifyingKey`): key and signature lengths,
    /// and how a signature is checked.
    pub signature: &'static str,
    pub signature_verification: &'static str,
    pub signing_seed_len: usize,
    pub verifying_key_len: usize,
    pub signature_len: usize,
    /// Sealing to a public key (`hpke_seal`): RFC 9180's base mode with
    /// these ids, and its key and encapsulation lengths.
    pub hpke: &'static str,
    pub hpke_kem_id: u16,
    pub hpke_kdf_id: u16,
    pub hpke_aead_id: u16,
    pub hpke_seed_len: usize,
    pub hpke_public_key_len: usize,
    pub hpke_encapsulated_len: usize,
    /// Password hashing (`pwhash`): its parameters are stored with what it
    /// protects (an account's), never implied.
    pub pwhash: &'static str,
    /// The one random source.
    pub random: &'static str,
}

/// Suite V1.
pub const V1: SuiteParams = SuiteParams {
    hash: "SHA-256 (FIPS 180-4)",
    digest_len: 32,
    mac: "HMAC-SHA256 (RFC 2104)",
    mac_tag_len: 32,
    kdf: "HKDF-SHA256 (RFC 5869), extract then expand",
    kdf_max_output: 255 * 32,
    aead: "XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03)",
    aead_key_len: 32,
    aead_nonce_len: 24,
    aead_tag_len: 16,
    signature: "Ed25519 (RFC 8032), pure",
    signature_verification: "strict: canonical S, A and R not of small order, no non-canonical points (ed25519-dalek verify_strict)",
    signing_seed_len: 32,
    verifying_key_len: 32,
    signature_len: 64,
    hpke: "HPKE base mode (RFC 9180): X-Wing KEM (draft-connolly-cfrg-xwing-kem-06), HKDF-SHA256, ChaCha20-Poly1305; the private key is the 32-byte X-Wing seed",
    hpke_kem_id: 0x647a,
    hpke_kdf_id: 0x0001,
    hpke_aead_id: 0x0003,
    hpke_seed_len: 32,
    hpke_public_key_len: 1216,
    hpke_encapsulated_len: 1120,
    pwhash: "Argon2id v1.3 as libsodium's crypto_pwhash (one lane); operations and memory stored with the hash",
    random: "the operating system's (getrandom; in the browser, crypto.getRandomValues)",
};

impl Suite {
    /// The suite's row.
    pub const fn params(self) -> &'static SuiteParams {
        match self {
            Suite::V1 => &V1,
        }
    }
}
