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

/// A uniform number below `bound` (not zero), for choices that aren't keys:
/// code characters, digits, jitter. Draws past the last whole multiple of
/// `bound` are drawn again, so no value is likelier than another.
pub fn random_below(bound: u64) -> u64 {
    assert!(bound > 0, "random_below needs a bound above zero");
    let limit = u64::MAX - u64::MAX % bound;
    loop {
        let draw = u64::from_le_bytes(random_array());
        if draw < limit {
            return draw % bound;
        }
    }
}

/// The one random source as an RNG value, for the adapters that take one
/// (OpenPGP, DKIM's RSA keys, OPAQUE, P-256; libsignal through rand_core
/// 0.9's traits).
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

impl rand_core09::RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(random_array())
    }
    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(random_array())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        random(dest);
    }
}

impl rand_core09::CryptoRng for Rng {}
