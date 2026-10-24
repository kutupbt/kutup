//! The Yjs client id a file's first content (its seed) is made under
//! (docs/plans/cli-yjs-sync.md). Every peer seeding a file from the same
//! content must make the same items, so the id is derived, not drawn; and it
//! is bound to that content as well as to the file, so two peers seeding from
//! different content never make different items under one id (Yjs would
//! keep whichever arrived first, and the peers would differ for good). At
//! worst, two different seeds both land, side by side.
//!
//! `content` is the seed's own update made under client id 0 (its items and
//! nothing else), so the binding is to what the seed holds, not to how the
//! file's bytes spelled it.

use crate::primitives::{hash, Hasher, Suite};

const LABEL: &[u8] = b"kutup/yjs-seed/v1\0";

/// The seed's client id: the first 53 bits of
/// SHA-256(label ‖ file id ‖ 0 ‖ SHA-256(content)), a whole number
/// JavaScript holds exactly.
pub fn seed_client_id(file_id: &str, content: &[u8]) -> u64 {
    let digest = Hasher::new(Suite::V1)
        .chain(LABEL)
        .chain(file_id.as_bytes())
        .chain([0u8])
        .chain(hash(Suite::V1, content))
        .finish();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first) >> 11
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_to_the_file_and_the_content() {
        let a = seed_client_id("f", b"one");
        assert_eq!(a, seed_client_id("f", b"one"));
        assert_ne!(a, seed_client_id("f", b"two"));
        assert_ne!(a, seed_client_id("g", b"one"));
        assert!(a < 1 << 53);
    }
}
