//! Backup-specific outer encryption for already-E2EE Chat-media ciphertext.
//!
//! The inner Chat-media object is never opened by the server. It is padded to
//! deterministic 1.05-growth buckets and wrapped in a typed secretstream whose
//! key is derived exclusively from `ChatBackupRootV1` by the client.

use crate::chat_backup::{ChatBackupProtectionDomainV1, ChatBackupSuiteId};
use crate::error::{CryptoError, Result};
use crate::stream::{ABYTES, CHUNK_SIZE, HEADER_BYTES};

const MAGIC: &[u8; 8] = b"KUTPBM1\0";
pub const CHAT_BACKUP_MEDIA_HEADER_BYTES: usize = 8 + 2 + 1 + 32 + 16 + 32 + 8 + 8;
pub const CHAT_BACKUP_MEDIA_MINIMUM_BUCKET_BYTES: u64 = 541;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatBackupMediaContextV1 {
    pub account_incarnation_id: [u8; 32],
    pub backup_incarnation_id: [u8; 16],
    pub protection_domain: ChatBackupProtectionDomainV1,
    pub media_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatBackupMediaHeaderV1 {
    pub suite: ChatBackupSuiteId,
    pub context: ChatBackupMediaContextV1,
    pub source_ciphertext_bytes: u64,
    pub padded_plaintext_bytes: u64,
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

pub fn build_media_header(
    context: ChatBackupMediaContextV1,
    source_ciphertext_bytes: u64,
) -> Result<[u8; CHAT_BACKUP_MEDIA_HEADER_BYTES]> {
    let padded_plaintext_bytes = padded_media_plaintext_bytes(source_ciphertext_bytes)?;
    let mut header = [0u8; CHAT_BACKUP_MEDIA_HEADER_BYTES];
    let mut cursor = 0;
    header[cursor..cursor + 8].copy_from_slice(MAGIC);
    cursor += 8;
    header[cursor..cursor + 2].copy_from_slice(
        &ChatBackupSuiteId::HkdfSha256XChaCha20Poly1305V1
            .as_u16()
            .to_be_bytes(),
    );
    cursor += 2;
    header[cursor] = context.protection_domain.as_u8();
    cursor += 1;
    header[cursor..cursor + 32].copy_from_slice(&context.account_incarnation_id);
    cursor += 32;
    header[cursor..cursor + 16].copy_from_slice(&context.backup_incarnation_id);
    cursor += 16;
    header[cursor..cursor + 32].copy_from_slice(&context.media_id);
    cursor += 32;
    header[cursor..cursor + 8].copy_from_slice(&source_ciphertext_bytes.to_be_bytes());
    cursor += 8;
    header[cursor..cursor + 8].copy_from_slice(&padded_plaintext_bytes.to_be_bytes());
    Ok(header)
}

pub fn inspect_media_header(header: &[u8]) -> Result<ChatBackupMediaHeaderV1> {
    if header.len() != CHAT_BACKUP_MEDIA_HEADER_BYTES || &header[..8] != MAGIC {
        return Err(CryptoError::InvalidInput(
            "invalid Chat backup media header".into(),
        ));
    }
    let mut cursor = 8;
    let suite = ChatBackupSuiteId::try_from(u16::from_be_bytes(
        header[cursor..cursor + 2].try_into().expect("bounded"),
    ))?;
    cursor += 2;
    let protection_domain = ChatBackupProtectionDomainV1::try_from(header[cursor])?;
    cursor += 1;
    let account_incarnation_id = header[cursor..cursor + 32].try_into().expect("bounded");
    cursor += 32;
    let backup_incarnation_id = header[cursor..cursor + 16].try_into().expect("bounded");
    cursor += 16;
    let media_id = header[cursor..cursor + 32].try_into().expect("bounded");
    cursor += 32;
    let source_ciphertext_bytes =
        u64::from_be_bytes(header[cursor..cursor + 8].try_into().expect("bounded"));
    cursor += 8;
    let padded_plaintext_bytes =
        u64::from_be_bytes(header[cursor..cursor + 8].try_into().expect("bounded"));
    if padded_plaintext_bytes != padded_media_plaintext_bytes(source_ciphertext_bytes)? {
        return Err(CryptoError::InvalidInput(
            "invalid Chat backup media padding bucket".into(),
        ));
    }
    Ok(ChatBackupMediaHeaderV1 {
        suite,
        context: ChatBackupMediaContextV1 {
            account_incarnation_id,
            backup_incarnation_id,
            protection_domain,
            media_id,
        },
        source_ciphertext_bytes,
        padded_plaintext_bytes,
    })
}

pub fn media_object_ciphertext_bytes(padded_plaintext_bytes: u64) -> Result<u64> {
    if padded_plaintext_bytes == 0 {
        return Err(CryptoError::InvalidInput(
            "backup media padded length cannot be empty".into(),
        ));
    }
    let chunk_size = CHUNK_SIZE as u64;
    let chunks = padded_plaintext_bytes
        .checked_add(chunk_size - 1)
        .and_then(|value| value.checked_div(chunk_size))
        .ok_or_else(|| CryptoError::InvalidInput("backup media length overflow".into()))?;
    (CHAT_BACKUP_MEDIA_HEADER_BYTES as u64)
        .checked_add(HEADER_BYTES as u64)
        .and_then(|value| value.checked_add(padded_plaintext_bytes))
        .and_then(|value| value.checked_add(chunks * ABYTES as u64))
        .ok_or_else(|| CryptoError::InvalidInput("backup media length overflow".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_and_header_are_canonical() {
        assert_eq!(padded_media_plaintext_bytes(1).unwrap(), 541);
        assert_eq!(padded_media_plaintext_bytes(541).unwrap(), 541);
        assert!(padded_media_plaintext_bytes(542).unwrap() > 542);
        let context = ChatBackupMediaContextV1 {
            account_incarnation_id: [1; 32],
            backup_incarnation_id: [2; 16],
            protection_domain: ChatBackupProtectionDomainV1::StandardChat,
            media_id: [3; 32],
        };
        let header = build_media_header(context, 10_000).unwrap();
        let parsed = inspect_media_header(&header).unwrap();
        assert_eq!(parsed.context, context);
        assert_eq!(parsed.source_ciphertext_bytes, 10_000);
        assert!(media_object_ciphertext_bytes(parsed.padded_plaintext_bytes).unwrap() > 10_000);
    }
}
