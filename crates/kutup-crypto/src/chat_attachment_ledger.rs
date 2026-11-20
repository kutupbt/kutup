//! The Chat attachment reference ledger (docs/chat-media.md): one account
//! record (`account_record`, purpose `ChatAttachmentLedger`) per entity,
//! under the master key, bound to the account's key binding, kept in the
//! account-records store's `chatAttachments` scope
//! (docs/plans/account-records.md).
//!
//! Its object is the entity's random id (the scope's id form), and its
//! revision is in the authenticated header: the account head covers the
//! scope, so a server can't roll an entity back, drop it or swap two. Only
//! the newest revision of each entity is kept. Conversation, message, media
//! class and display metadata stay inside the ciphertext, padded to 256-byte
//! buckets.

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::error::{CryptoError, Result};

const PURPOSE: AccountRecordPurpose = AccountRecordPurpose::ChatAttachmentLedger;
const NONCE_LEN: usize = account_record::NONCE_LEN;
/// An entity id's bytes (`IdForm::Random`).
pub const ENTITY_ID_LEN: usize = 32;
pub const MAX_CHAT_ATTACHMENT_LEDGER_PLAINTEXT_BYTES: usize = 16 * 1024;

fn check_plaintext(plaintext: &[u8]) -> Result<()> {
    if plaintext.is_empty() || plaintext.len() > MAX_CHAT_ATTACHMENT_LEDGER_PLAINTEXT_BYTES {
        return Err(CryptoError::InvalidInput(
            "Chat attachment-ledger plaintext length is invalid".into(),
        ));
    }
    Ok(())
}

/// Seals `plaintext` as revision `revision` of the entity `entity_id`.
pub fn seal(
    plaintext: &[u8],
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    entity_id: &[u8; ENTITY_ID_LEN],
    revision: u64,
) -> Result<Vec<u8>> {
    check_plaintext(plaintext)?;
    account_record::seal_revision(
        plaintext, master_key, PURPOSE, generation, binding, entity_id, revision,
    )
}

/// Deterministic-nonce entry point for canonical vectors only.
pub fn seal_with_nonce(
    plaintext: &[u8],
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    entity_id: &[u8; ENTITY_ID_LEN],
    revision: u64,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    check_plaintext(plaintext)?;
    account_record::seal_suite(
        account_record::AccountRecordSuiteId::V1,
        plaintext,
        master_key,
        PURPOSE,
        generation,
        binding,
        entity_id,
        Some(revision),
        nonce,
    )
}

/// Opens the entity `entity_id`'s record of the account bound by `binding`:
/// its plaintext and the revision it was sealed at (the caller checks it is
/// the one the verified index lists).
pub fn open(
    envelope: &[u8],
    master_key: &[u8; 32],
    binding: &str,
    entity_id: &[u8; ENTITY_ID_LEN],
) -> Result<(Vec<u8>, u64)> {
    account_record::open_revision(envelope, master_key, PURPOSE, binding, entity_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
    const MASTER: [u8; 32] = [0x42; 32];
    const ENTITY: [u8; ENTITY_ID_LEN] = [0x22; ENTITY_ID_LEN];

    fn sealed(revision: u64, plaintext: &[u8]) -> Vec<u8> {
        seal_with_nonce(
            plaintext,
            &MASTER,
            MasterKeyGeneration::FIRST,
            BINDING,
            &ENTITY,
            revision,
            &[0x11; 24],
        )
        .unwrap()
    }

    #[test]
    fn a_record_round_trips_and_its_header_is_public() {
        let envelope = sealed(1, b"canonical ledger entry");
        assert_eq!(
            open(&envelope, &MASTER, BINDING, &ENTITY).unwrap(),
            (b"canonical ledger entry".to_vec(), 1)
        );
        let header = account_record::validate_for(&envelope, PURPOSE, BINDING, &ENTITY).unwrap();
        assert_eq!(header.revision, Some(1));
        // Padded to a 256-byte bucket, plus the tag.
        assert_eq!(header.ciphertext_len, 256 + 16);
        assert_eq!(
            open(&sealed(7, b"later"), &MASTER, BINDING, &ENTITY)
                .unwrap()
                .1,
            7
        );
    }

    #[test]
    fn another_entity_account_or_key_is_refused() {
        let envelope = sealed(1, b"entry");
        assert!(open(&envelope, &MASTER, BINDING, &[0x33; ENTITY_ID_LEN]).is_err());
        assert!(
            account_record::validate_for(&envelope, PURPOSE, BINDING, &[0x33; ENTITY_ID_LEN])
                .is_err()
        );
        let elsewhere = "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d";
        assert!(account_record::validate_for(&envelope, PURPOSE, elsewhere, &ENTITY).is_err());
        assert!(open(&envelope, &MASTER, elsewhere, &ENTITY).is_err());
        assert!(open(&envelope, &[0x43; 32], BINDING, &ENTITY).is_err());
        let mut trailing = envelope;
        trailing.push(0);
        assert!(account_record::inspect(&trailing).is_err());
        assert!(seal(
            &[],
            &MASTER,
            MasterKeyGeneration::FIRST,
            BINDING,
            &ENTITY,
            1
        )
        .is_err());
    }
}
