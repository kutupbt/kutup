use subtle::ConstantTimeEq as _;

/// Whether `a` and `b` are equal, in time that depends only on their lengths.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
