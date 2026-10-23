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
