//! The account's key binding (docs/plans/account-identity.md, "Binding"):
//! a random, permanent id (UUID v4, lowercase and hyphenated) that the
//! account's own seals bind instead of a name, so no seal ever depends on a
//! username, a Kutup address or an email, which may change.

use crate::error::{CryptoError, Result};

/// The binding's length: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`.
pub const KEY_BINDING_LEN: usize = 36;

/// Checks that `value` is a key binding in its one canonical form (a UUID v4,
/// lowercase, hyphenated) and returns it. Nothing is normalised: a binding
/// that is not already canonical is refused.
pub fn check(value: &str) -> Result<&str> {
    let bytes = value.as_bytes();
    let canonical = bytes.len() == KEY_BINDING_LEN
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        })
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b');
    if canonical {
        Ok(value)
    } else {
        Err(CryptoError::InvalidInput(
            "key binding is not a canonical UUID v4".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_canonical_v4_bindings_pass() {
        let binding = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
        assert_eq!(check(binding).unwrap(), binding);
        assert_eq!(binding.len(), KEY_BINDING_LEN);
        for bad in [
            "",
            "alice@kutup.dev",
            "0B6B5E0C-4C1E-4B8E-9C2D-6A1F3E5D7C9B",
            " 0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b",
            "0b6b5e0c4c1e4b8e9c2d6a1f3e5d7c9b",
            "0b6b5e0c-4c1e-1b8e-9c2d-6a1f3e5d7c9b",
            "{0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b}",
        ] {
            assert!(check(bad).is_err(), "{bad:?}");
        }
    }
}
