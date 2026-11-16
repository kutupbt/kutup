//! Backup-specific outer encryption for already-E2EE Chat-media ciphertext:
//! the context and the padding every backup media object shares.
//!
//! The inner Chat-media object is never opened by the server. It is padded to
//! deterministic 1.05-growth buckets and wrapped in the block format
//! (`chat_backup_media_blocks`) under a key derived exclusively from
//! `ChatBackupRootV1` by the client.

use crate::chat_backup::ChatBackupProtectionDomainV1;
use crate::error::{CryptoError, Result};

pub const CHAT_BACKUP_MEDIA_MINIMUM_BUCKET_BYTES: u64 = 541;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatBackupMediaContextV1 {
    pub account_incarnation_id: [u8; 32],
    pub backup_incarnation_id: [u8; 16],
    pub protection_domain: ChatBackupProtectionDomainV1,
    pub media_id: [u8; 32],
}

/// Smallest member of the V1 `ceil(previous * 1.05)` sequence that contains
/// `source_bytes`, with a 541-byte minimum.
pub fn padded_media_plaintext_bytes(source_bytes: u64) -> Result<u64> {
    if source_bytes == 0 {
        return Err(CryptoError::InvalidInput(
            "backup media source cannot be empty".into(),
        ));
    }
    let mut bucket = CHAT_BACKUP_MEDIA_MINIMUM_BUCKET_BYTES;
    while bucket < source_bytes {
        let growth = bucket
            .checked_add(19)
            .and_then(|value| value.checked_div(20))
            .ok_or_else(|| CryptoError::InvalidInput("backup media padding overflow".into()))?;
        bucket = bucket
            .checked_add(growth.max(1))
            .ok_or_else(|| CryptoError::InvalidInput("backup media padding overflow".into()))?;
    }
    Ok(bucket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_is_canonical() {
        assert!(padded_media_plaintext_bytes(0).is_err());
        assert_eq!(padded_media_plaintext_bytes(1).unwrap(), 541);
        assert_eq!(padded_media_plaintext_bytes(541).unwrap(), 541);
        let next = padded_media_plaintext_bytes(542).unwrap();
        assert_eq!(next, 541 + 28);
        assert_eq!(padded_media_plaintext_bytes(next).unwrap(), next);
    }
}
