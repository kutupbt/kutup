//! Device-authenticated ephemeral encryption for V1 history transfer.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use kutup_chat_proto::{
    chat_history_transfer_transcript_hash, AccountManifestV1, ChatHistoryArchiveFinalV1,
    ChatHistoryArchiveFramePlaintextV1, ChatHistoryArchiveHeaderV1, ChatHistoryArchiveRecordV1,
    ChatHistoryArchiveRecordsV1, ChatHistoryTransferAcceptanceV1, ChatHistoryTransferFrameV1,
    ChatHistoryTransferRequestV1, CHAT_HISTORY_TRANSFER_VERSION,
    MAX_CHAT_HISTORY_TRANSFER_FRAMES, MAX_CHAT_HISTORY_TRANSFER_FRAME_PLAINTEXT,
};
use libsignal_protocol::{IdentityKeyPair, PublicKey};
use rand::{CryptoRng, Rng};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{ChatError, Result};

const KEY_INFO: &[u8] = b"kutup/chat/history-transfer-key/v1\0";
const ARCHIVE_DIGEST_DOMAIN: &[u8] = b"kutup/chat/history-archive-plaintext/v1\0";

pub struct HistoryTransferEphemeralSecret(Zeroizing<[u8; 32]>);

impl HistoryTransferEphemeralSecret {
    fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    fn public_key(&self) -> [u8; 32] {
        X25519PublicKey::from(&StaticSecret::from(*self.0)).to_bytes()
    }
}

pub struct PreparedHistoryTransferRequest {
    pub request: ChatHistoryTransferRequestV1,
    pub ephemeral_secret: HistoryTransferEphemeralSecret,
}

pub struct PreparedHistoryTransferAcceptance {
    pub acceptance: ChatHistoryTransferAcceptanceV1,
    pub ephemeral_secret: HistoryTransferEphemeralSecret,
    pub transcript_hash: [u8; 32],
}

pub struct PreparedHistoryArchiveV1 {
    pub frames: Vec<ChatHistoryTransferFrameV1>,
    pub plaintext_digest: [u8; 32],
    pub record_count: u32,
}

pub struct VerifiedHistoryArchiveV1 {
    pub header: ChatHistoryArchiveHeaderV1,
    pub records: Vec<crate::ImportedHistoryRecordV1>,
    pub plaintext_digest: [u8; 32],
}

pub(crate) fn prepare_history_transfer_request<R: Rng + CryptoRng>(
    identity: &IdentityKeyPair,
    account: &str,
    device_id: u32,
    manifest_sequence: u64,
    now_unix: i64,
    rng: &mut R,
) -> Result<PreparedHistoryTransferRequest> {
    let secret = HistoryTransferEphemeralSecret::generate(rng);
    let mut nonce = [0u8; 32];
    let mut uuid = [0u8; 16];
    rng.fill(&mut nonce);
    rng.fill(&mut uuid);
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    let mut request = ChatHistoryTransferRequestV1 {
        version: CHAT_HISTORY_TRANSFER_VERSION,
        transfer_id: Uuid::from_bytes(uuid).to_string(),
        account: account.into(),
        requesting_device_id: device_id,
        manifest_sequence,
        ephemeral_public_key: STANDARD.encode(secret.public_key()),
        request_nonce: STANDARD.encode(nonce),
        created_at_unix: now_unix,
        expires_at_unix: now_unix
            .checked_add(15 * 60)
            .ok_or_else(|| ChatError::Invalid("history transfer timestamp overflow".into()))?,
        device_signature: STANDARD.encode([0u8; 64]),
    };
    let signature = identity
        .private_key()
        .calculate_signature(&request.signing_bytes().map_err(ChatError::Invalid)?, rng)
        .map_err(|error| ChatError::Protocol(error.to_string()))?;
    request.device_signature = STANDARD.encode(signature);
    request.validate(now_unix).map_err(ChatError::Invalid)?;
    Ok(PreparedHistoryTransferRequest {
        request,
        ephemeral_secret: secret,
    })
}

pub fn verify_history_transfer_request(
    request: &ChatHistoryTransferRequestV1,
    manifest: &AccountManifestV1,
    now_unix: i64,
) -> Result<()> {
    manifest.verify().map_err(ChatError::Trust)?;
    request.validate(now_unix).map_err(ChatError::Invalid)?;
    let device = exact_manifest_device(
        manifest,
        &request.account,
        request.manifest_sequence,
        request.requesting_device_id,
    )?;
    verify_device_signature(
        &device.identity_key,
        &request.signing_bytes().map_err(ChatError::Invalid)?,
        &request.device_signature,
    )
}

pub(crate) fn prepare_history_transfer_acceptance<R: Rng + CryptoRng>(
    identity: &IdentityKeyPair,
    request: &ChatHistoryTransferRequestV1,
    responding_device_id: u32,
    record_limit: u32,
    plaintext_byte_limit: u64,
    now_unix: i64,
    rng: &mut R,
) -> Result<PreparedHistoryTransferAcceptance> {
    let secret = HistoryTransferEphemeralSecret::generate(rng);
    let mut acceptance = ChatHistoryTransferAcceptanceV1 {
        version: CHAT_HISTORY_TRANSFER_VERSION,
        transfer_id: request.transfer_id.clone(),
        account: request.account.clone(),
        requesting_device_id: request.requesting_device_id,
        responding_device_id,
        manifest_sequence: request.manifest_sequence,
        request_hash: hex::encode(request.signed_hash().map_err(ChatError::Invalid)?),
        ephemeral_public_key: STANDARD.encode(secret.public_key()),
        created_at_unix: now_unix,
        expires_at_unix: request.expires_at_unix,
        record_limit,
        plaintext_byte_limit,
        device_signature: STANDARD.encode([0u8; 64]),
    };
    let signature = identity
        .private_key()
        .calculate_signature(&acceptance.signing_bytes().map_err(ChatError::Invalid)?, rng)
        .map_err(|error| ChatError::Protocol(error.to_string()))?;
    acceptance.device_signature = STANDARD.encode(signature);
    let transcript_hash = chat_history_transfer_transcript_hash(request, &acceptance, now_unix)
        .map_err(ChatError::Invalid)?;
    Ok(PreparedHistoryTransferAcceptance {
        acceptance,
        ephemeral_secret: secret,
        transcript_hash,
    })
}

pub fn verify_history_transfer_acceptance(
    request: &ChatHistoryTransferRequestV1,
    acceptance: &ChatHistoryTransferAcceptanceV1,
    manifest: &AccountManifestV1,
    now_unix: i64,
) -> Result<[u8; 32]> {
    manifest.verify().map_err(ChatError::Trust)?;
    acceptance.validate(request, now_unix).map_err(ChatError::Invalid)?;
    let device = exact_manifest_device(
        manifest,
        &acceptance.account,
        acceptance.manifest_sequence,
        acceptance.responding_device_id,
    )?;
    verify_device_signature(
        &device.identity_key,
        &acceptance.signing_bytes().map_err(ChatError::Invalid)?,
        &acceptance.device_signature,
    )?;
    chat_history_transfer_transcript_hash(request, acceptance, now_unix)
        .map_err(ChatError::Invalid)
}

pub fn derive_history_transfer_key(
    secret: &HistoryTransferEphemeralSecret,
    peer_public_key: &str,
    transcript_hash: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let peer: [u8; 32] = decode_exact("history transfer ephemeral key", peer_public_key)?;
    let shared = StaticSecret::from(*secret.0).diffie_hellman(&X25519PublicKey::from(peer));
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ChatError::Trust("history transfer DH produced the all-zero secret".into()));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(transcript_hash), shared.as_bytes())
        .expand(KEY_INFO, key.as_mut_slice())
        .map_err(|_| ChatError::Protocol("history transfer HKDF failed".into()))?;
    Ok(key)
}

pub fn seal_history_transfer_frame<R: Rng + CryptoRng>(
    transfer_id: &str,
    transcript_hash: &[u8; 32],
    index: u32,
    final_frame: bool,
    plaintext: &[u8],
    key: &[u8; 32],
    rng: &mut R,
) -> Result<ChatHistoryTransferFrameV1> {
    if plaintext.len() > MAX_CHAT_HISTORY_TRANSFER_FRAME_PLAINTEXT as usize {
        return Err(ChatError::Invalid("history transfer frame is too large".into()));
    }
    let mut nonce = [0u8; 24];
    rng.fill(&mut nonce);
    let mut frame = ChatHistoryTransferFrameV1 {
        version: CHAT_HISTORY_TRANSFER_VERSION,
        transfer_id: transfer_id.into(),
        transcript_hash: hex::encode(transcript_hash),
        index,
        final_frame,
        plaintext_bytes: plaintext.len() as u32,
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(vec![0u8; plaintext.len() + 16]),
    };
    let aad = frame.aad().map_err(ChatError::Invalid)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| ChatError::Protocol("history transfer key length".into()))?;
    frame.ciphertext = STANDARD.encode(cipher.encrypt(
        XNonce::from_slice(&nonce),
        Payload { msg: plaintext, aad: &aad },
    ).map_err(|_| ChatError::Protocol("history transfer frame seal failed".into()))?);
    Ok(frame)
}

pub fn open_history_transfer_frame(
    frame: &ChatHistoryTransferFrameV1,
    expected_transfer_id: &str,
    expected_transcript_hash: &[u8; 32],
    key: &[u8; 32],
) -> Result<Vec<u8>> {
    frame.validate().map_err(ChatError::Invalid)?;
    if frame.transfer_id != expected_transfer_id
        || frame.transcript_hash != hex::encode(expected_transcript_hash)
    {
        return Err(ChatError::Trust("history transfer frame transcript mismatch".into()));
    }
    let nonce: [u8; 24] = decode_exact("history transfer nonce", &frame.nonce)?;
    let ciphertext = STANDARD.decode(&frame.ciphertext)
        .map_err(|_| ChatError::Invalid("history transfer ciphertext base64".into()))?;
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| ChatError::Protocol("history transfer key length".into()))?
        .decrypt(XNonce::from_slice(&nonce), Payload {
            msg: &ciphertext,
            aad: &frame.aad().map_err(ChatError::Invalid)?,
        })
        .map_err(|_| ChatError::Trust("history transfer frame authentication failed".into()))
}

pub fn prepare_history_archive<R: Rng + CryptoRng>(
    acceptance: &ChatHistoryTransferAcceptanceV1,
    transcript_hash: &[u8; 32],
    records: Vec<ChatHistoryArchiveRecordV1>,
    created_at_unix: i64,
    key: &[u8; 32],
    rng: &mut R,
) -> Result<PreparedHistoryArchiveV1> {
    acceptance.signing_bytes().map_err(ChatError::Invalid)?;
    let record_count = u32::try_from(records.len())
        .map_err(|_| ChatError::Invalid("history archive has too many records".into()))?;
    if record_count > acceptance.record_limit {
        return Err(ChatError::Invalid(
            "history archive exceeds the accepted record limit".into(),
        ));
    }
    let mut ids = std::collections::HashSet::with_capacity(records.len());
    for record in &records {
        record.validate().map_err(ChatError::Invalid)?;
        if !ids.insert(record.source_record_id.as_str()) {
            return Err(ChatError::Trust(
                "history archive contains duplicate source record ids".into(),
            ));
        }
    }

    let header = ChatHistoryArchiveHeaderV1 {
        version: CHAT_HISTORY_TRANSFER_VERSION,
        transfer_id: acceptance.transfer_id.clone(),
        account: acceptance.account.clone(),
        source_device_id: acceptance.responding_device_id,
        destination_device_id: acceptance.requesting_device_id,
        manifest_sequence: acceptance.manifest_sequence,
        transcript_hash: hex::encode(transcript_hash),
        created_at_unix,
        record_count,
        media_plaintext_bytes: 0,
    };
    header
        .validate(acceptance, transcript_hash)
        .map_err(ChatError::Invalid)?;

    let mut plaintexts = vec![
        ChatHistoryArchiveFramePlaintextV1::Header(header.clone())
            .canonical_bytes()
            .map_err(ChatError::Content)?,
    ];
    let mut batch = Vec::new();
    for record in records {
        batch.push(record);
        let candidate = records_plaintext(batch.clone())?;
        if candidate.len() > MAX_CHAT_HISTORY_TRANSFER_FRAME_PLAINTEXT as usize {
            let last = batch.pop().expect("batch was just populated");
            if batch.is_empty() {
                return Err(ChatError::Invalid(
                    "one history record exceeds the frame plaintext limit".into(),
                ));
            }
            plaintexts.push(records_plaintext(std::mem::take(&mut batch))?);
            batch.push(last);
        }
    }
    if !batch.is_empty() {
        plaintexts.push(records_plaintext(batch)?);
    }

    let mut digest = Sha256::new();
    digest.update(ARCHIVE_DIGEST_DOMAIN);
    let mut total_plaintext = 0u64;
    for plaintext in &plaintexts {
        update_archive_digest(&mut digest, plaintext)?;
        total_plaintext = total_plaintext
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| ChatError::Invalid("history archive size overflow".into()))?;
    }
    let plaintext_digest: [u8; 32] = digest.finalize().into();
    let frame_count = u32::try_from(plaintexts.len() + 1)
        .map_err(|_| ChatError::Invalid("history archive has too many frames".into()))?;
    if frame_count > MAX_CHAT_HISTORY_TRANSFER_FRAMES {
        return Err(ChatError::Invalid(
            "history archive exceeds the frame-count limit".into(),
        ));
    }
    let final_plaintext = ChatHistoryArchiveFramePlaintextV1::Final(ChatHistoryArchiveFinalV1 {
        version: CHAT_HISTORY_TRANSFER_VERSION,
        transfer_id: header.transfer_id.clone(),
        transcript_hash: header.transcript_hash.clone(),
        frame_count,
        record_count,
        media_plaintext_bytes: 0,
        plaintext_digest: hex::encode(plaintext_digest),
    })
    .canonical_bytes()
    .map_err(ChatError::Content)?;
    total_plaintext = total_plaintext
        .checked_add(final_plaintext.len() as u64)
        .ok_or_else(|| ChatError::Invalid("history archive size overflow".into()))?;
    if total_plaintext > acceptance.plaintext_byte_limit {
        return Err(ChatError::Invalid(
            "history archive exceeds the accepted plaintext limit".into(),
        ));
    }
    plaintexts.push(final_plaintext);

    let mut frames = Vec::with_capacity(plaintexts.len());
    for (index, plaintext) in plaintexts.iter().enumerate() {
        frames.push(seal_history_transfer_frame(
            &acceptance.transfer_id,
            transcript_hash,
            index as u32,
            index + 1 == plaintexts.len(),
            plaintext,
            key,
            rng,
        )?);
    }
    Ok(PreparedHistoryArchiveV1 {
        frames,
        plaintext_digest,
        record_count,
    })
}

pub fn verify_history_archive(
    acceptance: &ChatHistoryTransferAcceptanceV1,
    transcript_hash: &[u8; 32],
    frames: &[ChatHistoryTransferFrameV1],
    key: &[u8; 32],
) -> Result<VerifiedHistoryArchiveV1> {
    acceptance.signing_bytes().map_err(ChatError::Invalid)?;
    if frames.len() < 2 || frames.len() > MAX_CHAT_HISTORY_TRANSFER_FRAMES as usize {
        return Err(ChatError::Invalid(
            "history archive frame count is outside the V1 bounds".into(),
        ));
    }
    let mut header = None;
    let mut records = Vec::new();
    let mut source_ids = std::collections::HashSet::new();
    let mut digest = Sha256::new();
    digest.update(ARCHIVE_DIGEST_DOMAIN);
    let mut total_plaintext = 0u64;

    for (position, frame) in frames.iter().enumerate() {
        if frame.index as usize != position
            || frame.final_frame != (position + 1 == frames.len())
        {
            return Err(ChatError::Trust(
                "history archive frames are not exactly contiguous".into(),
            ));
        }
        let plaintext = open_history_transfer_frame(
            frame,
            &acceptance.transfer_id,
            transcript_hash,
            key,
        )?;
        total_plaintext = total_plaintext
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| ChatError::Invalid("history archive size overflow".into()))?;
        if total_plaintext > acceptance.plaintext_byte_limit {
            return Err(ChatError::Invalid(
                "history archive exceeds the accepted plaintext limit".into(),
            ));
        }
        let decoded = ChatHistoryArchiveFramePlaintextV1::from_canonical_bytes(&plaintext)
            .map_err(ChatError::Invalid)?;
        match (position, decoded) {
            (0, ChatHistoryArchiveFramePlaintextV1::Header(value)) => {
                value
                    .validate(acceptance, transcript_hash)
                    .map_err(ChatError::Trust)?;
                update_archive_digest(&mut digest, &plaintext)?;
                header = Some(value);
            }
            (_, ChatHistoryArchiveFramePlaintextV1::Records(batch))
                if position + 1 < frames.len() =>
            {
                batch.validate().map_err(ChatError::Invalid)?;
                for record in batch.records {
                    if !source_ids.insert(record.source_record_id.clone()) {
                        return Err(ChatError::Trust(
                            "history archive repeats a source record id".into(),
                        ));
                    }
                    records.push(record);
                }
                update_archive_digest(&mut digest, &plaintext)?;
            }
            (_, ChatHistoryArchiveFramePlaintextV1::Final(final_value))
                if position + 1 == frames.len() =>
            {
                let header = header.as_ref().ok_or_else(|| {
                    ChatError::Trust("history archive is missing its header".into())
                })?;
                final_value.validate(header).map_err(ChatError::Trust)?;
                let computed: [u8; 32] = digest.finalize().into();
                if final_value.frame_count != frames.len() as u32
                    || final_value.record_count != records.len() as u32
                    || final_value.plaintext_digest != hex::encode(computed)
                {
                    return Err(ChatError::Trust(
                        "history archive final commitment does not verify".into(),
                    ));
                }
                let imported = records
                    .into_iter()
                    .map(|record| archive_record_to_imported(header, record))
                    .collect::<Result<Vec<_>>>()?;
                return Ok(VerifiedHistoryArchiveV1 {
                    header: header.clone(),
                    records: imported,
                    plaintext_digest: computed,
                });
            }
            _ => {
                return Err(ChatError::Trust(
                    "history archive frame kind appears out of order".into(),
                ))
            }
        }
    }
    Err(ChatError::Trust(
        "history archive is missing its final commitment".into(),
    ))
}

fn records_plaintext(records: Vec<ChatHistoryArchiveRecordV1>) -> Result<Vec<u8>> {
    let batch = ChatHistoryArchiveRecordsV1 {
        version: CHAT_HISTORY_TRANSFER_VERSION,
        records,
    };
    batch.validate().map_err(ChatError::Invalid)?;
    ChatHistoryArchiveFramePlaintextV1::Records(batch)
        .canonical_bytes()
        .map_err(ChatError::Content)
}

fn update_archive_digest(digest: &mut Sha256, plaintext: &[u8]) -> Result<()> {
    let length = u32::try_from(plaintext.len())
        .map_err(|_| ChatError::Invalid("history archive frame length overflow".into()))?;
    digest.update(length.to_be_bytes());
    digest.update(plaintext);
    Ok(())
}

fn archive_record_to_imported(
    header: &ChatHistoryArchiveHeaderV1,
    record: ChatHistoryArchiveRecordV1,
) -> Result<crate::ImportedHistoryRecordV1> {
    record.validate().map_err(ChatError::Invalid)?;
    Ok(crate::ImportedHistoryRecordV1 {
        transfer_id: header.transfer_id.clone(),
        source_record_id: record.source_record_id,
        source_device_id: header.source_device_id,
        conversation: record.conversation,
        sender: record.sender,
        sender_device_id: record.sender_device_id,
        outgoing: record.outgoing,
        content: serde_json::to_vec(&record.content)
            .map_err(|error| ChatError::Content(error.to_string()))?,
        timestamp_ms: record.timestamp_ms,
        delivered: record.delivered,
    })
}

fn exact_manifest_device<'a>(
    manifest: &'a AccountManifestV1,
    account: &str,
    sequence: u64,
    device_id: u32,
) -> Result<&'a kutup_chat_proto::AccountManifestDeviceV1> {
    if manifest.account != account || manifest.sequence != sequence {
        return Err(ChatError::Trust("history transfer manifest binding mismatch".into()));
    }
    manifest.devices.iter().find(|device| device.device_id == device_id)
        .ok_or_else(|| ChatError::Trust("history transfer device is absent from the manifest".into()))
}

fn verify_device_signature(identity_key: &str, message: &[u8], signature: &str) -> Result<()> {
    let public = PublicKey::deserialize(&STANDARD.decode(identity_key)
        .map_err(|_| ChatError::Trust("manifest identity key is not base64".into()))?)
        .map_err(|error| ChatError::Trust(error.to_string()))?;
    let signature: [u8; 64] = decode_exact("history transfer signature", signature)?;
    if !public.verify_signature(message, &signature) {
        return Err(ChatError::Trust("history transfer device signature is invalid".into()));
    }
    Ok(())
}

fn decode_exact<const N: usize>(label: &str, value: &str) -> Result<[u8; N]> {
    STANDARD.decode(value)
        .map_err(|_| ChatError::Invalid(format!("{label} is not base64")))?
        .try_into().map_err(|_| ChatError::Invalid(format!("{label} has the wrong length")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_chat_proto::{AccountManifestDeviceV1, DirectChatSuiteId};
    use libsignal_protocol::IdentityKeyPair;
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    #[test]
    fn two_manifest_devices_sign_derive_and_authenticate_frames() {
        let mut rng = OsRng.unwrap_err();
        let old_identity = IdentityKeyPair::generate(&mut rng);
        let new_identity = IdentityKeyPair::generate(&mut rng);
        let authority = crate::AccountAuthority::derive(&[9u8; 32]).unwrap();
        let manifest = authority
            .sign_manifest(
                "alice@a.test",
                1,
                None,
                vec![
                    AccountManifestDeviceV1 {
                        device_id: 1,
                        direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                        identity_key: STANDARD.encode(old_identity.identity_key().serialize()),
                        registration_id: 11,
                        mls: None,
                    },
                    AccountManifestDeviceV1 {
                        device_id: 2,
                        direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                        identity_key: STANDARD.encode(new_identity.identity_key().serialize()),
                        registration_id: 22,
                        mls: None,
                    },
                ],
                "2026-08-09T00:00:00Z",
            )
            .unwrap();

        let prepared_request = prepare_history_transfer_request(
            &new_identity,
            "alice@a.test",
            2,
            1,
            1_000,
            &mut rng,
        )
        .unwrap();
        verify_history_transfer_request(&prepared_request.request, &manifest, 1_001).unwrap();
        let mut forged_request = prepared_request.request.clone();
        forged_request.device_signature = STANDARD.encode([0u8; 64]);
        assert!(verify_history_transfer_request(&forged_request, &manifest, 1_001).is_err());
        let prepared_acceptance = prepare_history_transfer_acceptance(
            &old_identity,
            &prepared_request.request,
            1,
            100,
            1024 * 1024,
            1_001,
            &mut rng,
        )
        .unwrap();
        let transcript = verify_history_transfer_acceptance(
            &prepared_request.request,
            &prepared_acceptance.acceptance,
            &manifest,
            1_001,
        )
        .unwrap();
        assert_eq!(transcript, prepared_acceptance.transcript_hash);

        let sender_key = derive_history_transfer_key(
            &prepared_acceptance.ephemeral_secret,
            &prepared_request.request.ephemeral_public_key,
            &transcript,
        )
        .unwrap();
        let recipient_key = derive_history_transfer_key(
            &prepared_request.ephemeral_secret,
            &prepared_acceptance.acceptance.ephemeral_public_key,
            &transcript,
        )
        .unwrap();
        assert_eq!(&*sender_key, &*recipient_key);

        let archive = prepare_history_archive(
            &prepared_acceptance.acceptance,
            &transcript,
            vec![ChatHistoryArchiveRecordV1 {
                source_record_id: "in:mailbox-1".into(),
                conversation: kutup_chat_proto::ConversationId::direct(
                    kutup_chat_proto::AccountAddress::federated("bob", "b.test").unwrap(),
                ),
                sender: "bob@b.test".into(),
                sender_device_id: 1,
                outgoing: false,
                content: kutup_chat_proto::ChatContent::text(
                    "2026-08-09T00:00:00Z",
                    1,
                    "hello from history",
                ),
                timestamp_ms: 1_700_000_000_000,
                delivered: true,
            }],
            1_002,
            &sender_key,
            &mut rng,
        )
        .unwrap();
        assert_eq!(archive.frames.len(), 3);
        let verified = verify_history_archive(
            &prepared_acceptance.acceptance,
            &transcript,
            &archive.frames,
            &recipient_key,
        )
        .unwrap();
        assert_eq!(verified.records.len(), 1);
        assert_eq!(verified.records[0].source_device_id, 1);
        assert_eq!(verified.plaintext_digest, archive.plaintext_digest);
        let mut reordered = archive.frames.clone();
        reordered.swap(0, 1);
        assert!(verify_history_archive(
            &prepared_acceptance.acceptance,
            &transcript,
            &reordered,
            &recipient_key,
        )
        .is_err());

        let frame = seal_history_transfer_frame(
            &prepared_request.request.transfer_id,
            &transcript,
            0,
            true,
            b"normalized archive",
            &sender_key,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            open_history_transfer_frame(
                &frame,
                &prepared_request.request.transfer_id,
                &transcript,
                &recipient_key,
            )
            .unwrap(),
            b"normalized archive"
        );

        let mut tampered = frame;
        tampered.final_frame = false;
        assert!(open_history_transfer_frame(
            &tampered,
            &prepared_request.request.transfer_id,
            &transcript,
            &recipient_key,
        )
        .is_err());
    }
}
