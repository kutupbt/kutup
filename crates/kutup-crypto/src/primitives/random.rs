use zeroize::Zeroizing;

/// Fills `out` from the one random source (`SuiteParams::random`).
pub fn random(out: &mut [u8]) {
    getrandom::fill(out).expect("the operating system's random source");
}

/// `N` random bytes.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    random(&mut out);
    out
}

/// A random 32-byte key.
pub fn random_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    random(key.as_mut());
    key
}

/// The one random source as an RNG value, for the adapters that take one
/// (OpenPGP, DKIM's RSA keys, OPAQUE).
#[derive(Clone, Copy, Debug, Default)]
pub struct Rng;

impl rand_core::RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(random_array())
    }
    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(random_array())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        random(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        random(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for Rng {}
