//! The Chat attachment reference ledger (docs/chat-media.md): one account
//! record (`account_record`, purpose `ChatAttachmentLedger`) per entity,
//! under the master key, bound to the account's key binding.
//!
//! Its object is the account incarnation and the entity id (48 bytes), both
//! of which the server already knows (the entity id is in the URL), so it
//! checks them exactly. Each entity's records form a chain: each names the
//! digest of the one before, which the server checks for compare-and-swap
//! without reading anything. Conversation, message, media class and display
//! metadata stay inside the ciphertext, padded to 256-byte buckets.

use base64::Engine as _;

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};

const PURPOSE: AccountRecordPurpose = AccountRecordPurpose::ChatAttachmentLedger;
const NONCE_LEN: usize = 24;
const DIGEST_LEN: usize = 32;
pub const MAX_CHAT_ATTACHMENT_LEDGER_PLAINTEXT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatAttachmentLedgerContextV1 {
    pub account_incarnation_id: [u8; 32],
    pub entity_id: [u8; 16],
    pub revision: u64,
    pub previous_envelope_digest: [u8; DIGEST_LEN],
}

impl ChatAttachmentLedgerContextV1 {
    pub fn new(
        account_incarnation_id: &str,
        entity_id: &str,
        revision: u64,
        previous_envelope_digest: Option<&str>,
    ) -> Result<Self> {
        if revision == 0 {
            return Err(CryptoError::InvalidInput(
                "Chat attachment-ledger revision must be non-zero".into(),
            ));
        }
        let previous_envelope_digest = match previous_envelope_digest {
            None if revision == 1 => [0u8; DIGEST_LEN],
            Some(value) if revision > 1 => parse_digest(value)?,
            _ => {
                return Err(CryptoError::InvalidInput(
                    "Chat attachment-ledger predecessor does not match revision".into(),
                ))
            }
        };
        if revision > 1 && previous_envelope_digest == [0u8; DIGEST_LEN] {
            return Err(CryptoError::InvalidInput(
                "Chat attachment-ledger predecessor must be non-zero".into(),
            ));
        }
        Ok(Self {
            account_incarnation_id: parse_lower_hex_32(
                account_incarnation_id,
                "Chat attachment-ledger account incarnation",
            )?,
            entity_id: parse_canonical_uuid(entity_id, "Chat attachment-ledger entity")?,
            revision,
            previous_envelope_digest,
        })
    }
}

fn parse_lower_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value)
        .map_err(|_| CryptoError::InvalidInput(format!("{field} must be lowercase hex")))?;
    if decoded.len() != 32 || hex::encode(&decoded) != value {
        return Err(CryptoError::InvalidInput(format!(
            "{field} must be canonical 32-byte lowercase hex"
        )));
    }
    decoded
        .try_into()
        .map_err(|_| CryptoError::InvalidInput(format!("{field} length is invalid")))
}

/// A record's object: the account incarnation, then the entity id.
fn object_of(context: &ChatAttachmentLedgerContextV1) -> [u8; 48] {
    let mut object = [0u8; 48];
    object[..32].copy_from_slice(&context.account_incarnation_id);
    object[32..].copy_from_slice(&context.entity_id);
    object
}

/// What a record's header says: whose entity, which revision, after which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatAttachmentLedgerHeaderV1 {
    pub context: ChatAttachmentLedgerContextV1,
    pub ciphertext_len: u32,
}

fn parse_digest(value: &str) -> Result<[u8; DIGEST_LEN]> {
    let decoded = hex::decode(value)
        .map_err(|_| CryptoError::InvalidInput("ledger digest must be lowercase hex".into()))?;
    if decoded.len() != DIGEST_LEN || hex::encode(&decoded) != value {
        return Err(CryptoError::InvalidInput(
            "ledger digest must be canonical SHA-256 hex".into(),
        ));
    }
    decoded
        .try_into()
        .map_err(|_| CryptoError::InvalidInput("ledger digest length is invalid".into()))
}

pub fn seal(
    plaintext: &[u8],
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    context: ChatAttachmentLedgerContextV1,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::primitives::random(&mut nonce);
    seal_with_nonce(plaintext, master_key, generation, binding, context, &nonce)
}

/// Deterministic-nonce entry point for canonical vectors only.
pub fn seal_with_nonce(
    plaintext: &[u8],
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    context: ChatAttachmentLedgerContextV1,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() > MAX_CHAT_ATTACHMENT_LEDGER_PLAINTEXT_BYTES {
        return Err(CryptoError::InvalidInput(
            "Chat attachment-ledger plaintext length is invalid".into(),
        ));
    }
    account_record::seal_chained(
        plaintext,
        master_key,
        PURPOSE,
        generation,
        binding,
        &object_of(&context),
        context.revision,
        &context.previous_envelope_digest,
        Some(nonce),
    )
}

fn header_of(header: &account_record::AccountRecordHeader) -> Result<ChatAttachmentLedgerHeaderV1> {
    let invalid = || CryptoError::InvalidInput("not a Chat attachment-ledger record".into());
    if header.purpose != PURPOSE || header.object_id.len() != 48 {
        return Err(invalid());
    }
    Ok(ChatAttachmentLedgerHeaderV1 {
        context: ChatAttachmentLedgerContextV1 {
            account_incarnation_id: header.object_id[..32].try_into().map_err(|_| invalid())?,
            entity_id: header.object_id[32..].try_into().map_err(|_| invalid())?,
            revision: header.revision.ok_or_else(invalid)?,
            previous_envelope_digest: header.previous.ok_or_else(invalid)?,
        },
        ciphertext_len: header.ciphertext_len,
    })
}

/// The public header of a well-formed ledger record.
pub fn inspect(envelope: &[u8]) -> Result<ChatAttachmentLedgerHeaderV1> {
    header_of(&account_record::inspect(envelope)?)
}

/// What the server checks before storing a record: a well-formed ledger
/// record of the account bound by `binding`, for its current incarnation and
/// the entity it is filed under.
pub fn validate(
    envelope: &[u8],
    binding: &str,
    account_incarnation_id: &[u8; 32],
    entity_id: &[u8; 16],
) -> Result<ChatAttachmentLedgerHeaderV1> {
    let mut object = [0u8; 48];
    object[..32].copy_from_slice(account_incarnation_id);
    object[32..].copy_from_slice(entity_id);
    header_of(&account_record::validate_for(
        envelope, PURPOSE, binding, &object,
    )?)
}

/// SHA-256 of a well-formed record, lowercase hex: the next one's predecessor.
pub fn envelope_digest(envelope: &[u8]) -> Result<String> {
    inspect(envelope)?;
    Ok(hex::encode(account_record::record_digest(envelope)))
}

/// Opens a record as exactly the entity, revision and predecessor `expected`
/// names, for the account bound by `binding`.
pub fn open(
    envelope: &[u8],
    master_key: &[u8; 32],
    binding: &str,
    expected: ChatAttachmentLedgerContextV1,
) -> Result<Vec<u8>> {
    let (plain, revision, previous) = account_record::open_chained(
        envelope,
        master_key,
        PURPOSE,
        binding,
        &object_of(&expected),
    )?;
    if revision != expected.revision || previous != expected.previous_envelope_digest {
        return Err(CryptoError::AuthFailed);
    }
    Ok(plain)
}

pub fn seal_b64(
    plaintext: &[u8],
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    context: ChatAttachmentLedgerContextV1,
) -> Result<String> {
    Ok(base64::engine::general_purpose::STANDARD
        .encode(seal(plaintext, master_key, generation, binding, context)?))
}

pub fn decode_canonical_b64(value: &str) -> Result<Vec<u8>> {
    if value.len() > account_record::max_record_b64_len(PURPOSE) {
        return Err(CryptoError::InvalidInput(
            "Chat attachment-ledger envelope is too long".into(),
        ));
    }
    let decoded = base64::engine::general_purpose::STANDARD.decode(value)?;
    if base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
        return Err(CryptoError::InvalidInput(
            "Chat attachment-ledger envelope must use canonical base64".into(),
        ));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
    const MASTER: [u8; 32] = [0x42; 32];

    fn first_context() -> ChatAttachmentLedgerContextV1 {
        ChatAttachmentLedgerContextV1::new(
            &"11".repeat(32),
            "22222222-2222-4222-8222-222222222222",
            1,
            None,
        )
        .unwrap()
    }

    fn sealed(context: ChatAttachmentLedgerContextV1, plaintext: &[u8]) -> Vec<u8> {
        seal_with_nonce(
            plaintext,
            &MASTER,
            MasterKeyGeneration::FIRST,
            BINDING,
            context,
            &[0x11; 24],
        )
        .unwrap()
    }

    #[test]
    fn a_record_round_trips_and_its_header_is_public() {
        let envelope = sealed(first_context(), b"canonical ledger entry");
        assert_eq!(
            open(&envelope, &MASTER, BINDING, first_context()).unwrap(),
            b"canonical ledger entry"
        );
        let header = inspect(&envelope).unwrap();
        assert_eq!(header.context, first_context());
        // Padded to a 256-byte bucket, plus the tag.
        assert_eq!(header.ciphertext_len, 256 + 16);
        assert_eq!(envelope_digest(&envelope).unwrap().len(), 64);
        validate(&envelope, BINDING, &[0x11; 32], &first_context().entity_id).unwrap();
    }

    #[test]
    fn another_entity_account_incarnation_or_chain_place_is_refused() {
        let envelope = sealed(first_context(), b"entry");
        let other = ChatAttachmentLedgerContextV1::new(
            &"11".repeat(32),
            "33333333-3333-4333-8333-333333333333",
            1,
            None,
        )
        .unwrap();
        assert!(open(&envelope, &MASTER, BINDING, other).is_err());
        assert!(validate(&envelope, BINDING, &[0x11; 32], &other.entity_id).is_err());
        assert!(validate(&envelope, BINDING, &[0x12; 32], &first_context().entity_id).is_err());
        let elsewhere = "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d";
        assert!(validate(
            &envelope,
            elsewhere,
            &[0x11; 32],
            &first_context().entity_id
        )
        .is_err());
        assert!(open(&envelope, &MASTER, elsewhere, first_context()).is_err());
        assert!(open(&envelope, &[0x43; 32], BINDING, first_context()).is_err());

        // The second record names the first; opened as another place in the
        // chain, it is refused.
        let digest = envelope_digest(&envelope).unwrap();
        let second_context = ChatAttachmentLedgerContextV1::new(
            &"11".repeat(32),
            "22222222-2222-4222-8222-222222222222",
            2,
            Some(&digest),
        )
        .unwrap();
        let second = sealed(second_context, b"entry, later");
        assert_eq!(inspect(&second).unwrap().context, second_context);
        let mut wrong_previous = second_context;
        wrong_previous.previous_envelope_digest[0] ^= 1;
        assert!(open(&second, &MASTER, BINDING, wrong_previous).is_err());
        let mut trailing = second;
        trailing.push(0);
        assert!(inspect(&trailing).is_err());
    }

    #[test]
    fn revision_requires_exact_predecessor_shape() {
        assert!(ChatAttachmentLedgerContextV1::new(
            &"11".repeat(32),
            "22222222-2222-4222-8222-222222222222",
            2,
            None,
        )
        .is_err());
        let previous = "11".repeat(32);
        assert!(ChatAttachmentLedgerContextV1::new(
            &"11".repeat(32),
            "22222222-2222-4222-8222-222222222222",
            2,
            Some(&previous),
        )
        .is_ok());
    }
}
