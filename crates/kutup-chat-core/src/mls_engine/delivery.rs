//! RFC 9180 outer protection for anonymous MLS mailbox delivery.
//!
//! OpenMLS ciphertext remains the inner message. A fresh Base-mode HPKE
//! context encrypts one padded copy to each transparency-verified destination
//! device key, so the destination server stores no sender or conversation
//! metadata and cannot inspect the MLS routing fields.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use kutup_chat_proto::{
    anonymous_mls_delivery_aad, derive_group_delivery_capability, AccountAddress,
    AnonymousMlsDeviceEnvelopeV1, AnonymousMlsSubmissionV1, MlsAnonymousDeliverySuiteV1,
    ANONYMOUS_MLS_DELIVERY_CONTEXT, MLS_PROTOCOL_VERSION,
};
use openmls::prelude::{GroupId, MlsGroup};
use openmls_traits::OpenMlsProvider;
use p256::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use super::{ensure_v1_group, validate_group_id, ChatError, MlsClient, Result};

const PAD_BLOCK_BYTES: usize = 1024;
const MAX_ANONYMOUS_REQUEST_BYTES: usize = 1024 * 1024;
const HPKE_TAG_BYTES: usize = 16;
const P256_ENCAPSULATED_KEY_BYTES: usize = 65;
const PAYLOAD_CONTEXT: &[u8] = b"kutup/anonymous-mls-payload/v1\0";
const PAYLOAD_HEADER_BYTES: usize = PAYLOAD_CONTEXT.len() + 4;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousMlsRecipientDevice {
    pub device_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DerivedMlsDeliveryCapability {
    pub epoch: u64,
    pub capability: [u8; 16],
    pub verifier_hash: [u8; 32],
}

impl AnonymousMlsRecipientDevice {
    pub fn new(device_id: u32, public_key: Vec<u8>) -> Result<Self> {
        if device_id == 0
            || public_key.len() != 65
            || public_key.first() != Some(&4)
            || PublicKey::from_sec1_bytes(&public_key).is_err()
        {
            return Err(ChatError::Invalid(
                "anonymous MLS recipient requires a device id and uncompressed P-256 key".into(),
            ));
        }
        Ok(Self {
            device_id,
            public_key,
        })
    }
}

impl MlsClient {
    /// Derive the recipient-specific contacts-only capability from the current
    /// MLS epoch exporter. Any membership change rotates it automatically.
    pub async fn derive_delivery_capability(
        &self,
        mls_group_id: &[u8],
        conversation_id: Uuid,
        incarnation: u64,
        recipient: &AccountAddress,
    ) -> Result<DerivedMlsDeliveryCapability> {
        validate_group_id(mls_group_id)?;
        if conversation_id.is_nil() || incarnation == 0 || recipient.server.is_none() {
            return Err(ChatError::Invalid(
                "MLS delivery capability identifiers are invalid".into(),
            ));
        }
        let (provider, _) = self.load_provider().await?;
        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(mls_group_id))
            .map_err(|error| ChatError::Protocol(format!("load MLS group: {error}")))?
            .ok_or_else(|| {
                ChatError::MissingKeyMaterial("MLS group state is unavailable".into())
            })?;
        ensure_v1_group(&group)?;
        if group.pending_commit().is_some() {
            return Err(ChatError::Trust(
                "delivery capability cannot advance before the pending MLS Commit is finalized"
                    .into(),
            ));
        }
        let epoch = group.epoch().as_u64();
        let mut exporter = group
            .export_secret(
                provider.crypto(),
                "kutup group delivery capability v1",
                &[],
                32,
            )
            .map_err(|error| {
                ChatError::Protocol(format!("export MLS delivery capability secret: {error}"))
            })?;
        let capability = derive_group_delivery_capability(
            &exporter,
            conversation_id,
            incarnation,
            epoch,
            recipient,
        )
        .map_err(ChatError::Protocol)?;
        exporter.zeroize();
        let verifier_hash = Sha256::digest(capability).into();
        Ok(DerivedMlsDeliveryCapability {
            epoch,
            capability,
            verifier_hash,
        })
    }

    /// Wrap one exact OpenMLS PrivateMessage for anonymous contacts-only
    /// delivery. Device keys must come from one transparency-verified manifest.
    pub async fn create_anonymous_submission(
        &self,
        recipient: AccountAddress,
        send_id: Uuid,
        capability: [u8; 16],
        devices: &[AnonymousMlsRecipientDevice],
        mls_ciphertext: &[u8],
    ) -> Result<AnonymousMlsSubmissionV1> {
        if recipient.server.is_none()
            || send_id.is_nil()
            || devices.is_empty()
            || devices.len() > 32
            || mls_ciphertext.is_empty()
        {
            return Err(ChatError::Invalid(
                "anonymous MLS delivery identifiers are invalid".into(),
            ));
        }
        let mut previous_device = None;
        for device in devices {
            AnonymousMlsRecipientDevice::new(device.device_id, device.public_key.clone())?;
            if previous_device.is_some_and(|previous| device.device_id <= previous) {
                return Err(ChatError::Invalid(
                    "anonymous MLS destination devices must be strictly ordered".into(),
                ));
            }
            previous_device = Some(device.device_id);
        }
        let padded = pad_payload(mls_ciphertext, devices.len())?;
        let suite = MlsAnonymousDeliverySuiteV1::DhKemP256HkdfSha256Aes128Gcm;
        let mut envelopes = Vec::with_capacity(devices.len());
        for device in devices {
            let aad = anonymous_mls_delivery_aad(&recipient, send_id, suite, device.device_id)
                .map_err(ChatError::Invalid)?;
            let mut hpke = hpke_suite();
            let (encapsulated_key, ciphertext) = hpke
                .seal(
                    &HpkePublicKey::new(device.public_key.clone()),
                    ANONYMOUS_MLS_DELIVERY_CONTEXT,
                    &aad,
                    &padded,
                    None,
                    None,
                    None,
                )
                .map_err(|error| {
                    ChatError::Protocol(format!("anonymous MLS HPKE seal: {error}"))
                })?;
            if encapsulated_key.len() != P256_ENCAPSULATED_KEY_BYTES {
                return Err(ChatError::Protocol(
                    "HPKE produced a non-canonical P-256 encapsulation".into(),
                ));
            }
            envelopes.push(AnonymousMlsDeviceEnvelopeV1 {
                device_id: device.device_id,
                encapsulated_key: BASE64.encode(encapsulated_key),
                ciphertext: BASE64.encode(ciphertext),
            });
        }
        let submission = AnonymousMlsSubmissionV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            recipient,
            send_id,
            capability: BASE64.encode(capability),
            suite,
            envelopes,
        };
        submission.validate().map_err(ChatError::Invalid)?;
        Ok(submission)
    }

    /// Open this device's outer anonymous envelope. The returned bytes are
    /// still an MLS message and must pass the normal group/epoch/manifest
    /// verification before its application plaintext is processed.
    pub async fn open_anonymous_envelope(
        &self,
        recipient: &AccountAddress,
        send_id: Uuid,
        envelope: &AnonymousMlsDeviceEnvelopeV1,
    ) -> Result<Vec<u8>> {
        if recipient.server.is_none() || send_id.is_nil() || envelope.device_id == 0 {
            return Err(ChatError::Invalid(
                "anonymous MLS envelope identifiers are invalid".into(),
            ));
        }
        let (_, metadata) = self.load_provider().await?;
        let encapsulated_key =
            decode_canonical_base64("HPKE encapsulated key", &envelope.encapsulated_key)?;
        let ciphertext = decode_canonical_base64("anonymous MLS ciphertext", &envelope.ciphertext)?;
        if encapsulated_key.len() != P256_ENCAPSULATED_KEY_BYTES
            || ciphertext.len() < HPKE_TAG_BYTES + PAYLOAD_HEADER_BYTES
            || ciphertext.len() > MAX_ANONYMOUS_REQUEST_BYTES
        {
            return Err(ChatError::Invalid(
                "anonymous MLS envelope size is invalid".into(),
            ));
        }
        let suite = MlsAnonymousDeliverySuiteV1::DhKemP256HkdfSha256Aes128Gcm;
        let aad = anonymous_mls_delivery_aad(recipient, send_id, suite, envelope.device_id)
            .map_err(ChatError::Invalid)?;
        let hpke = hpke_suite();
        let plaintext = hpke
            .open(
                &encapsulated_key,
                &HpkePrivateKey::new(metadata.anonymous_delivery_private_key.clone()),
                ANONYMOUS_MLS_DELIVERY_CONTEXT,
                &aad,
                &ciphertext,
                None,
                None,
                None,
            )
            .map_err(|_| ChatError::Trust("anonymous MLS HPKE authentication failed".into()))?;
        unpad_payload(&plaintext)
    }
}

fn hpke_suite() -> Hpke<HpkeRustCrypto> {
    Hpke::new(
        Mode::Base,
        KemAlgorithm::DhKemP256,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes128Gcm,
    )
}

fn pad_payload(ciphertext: &[u8], device_count: usize) -> Result<Vec<u8>> {
    let per_device_budget = MAX_ANONYMOUS_REQUEST_BYTES
        .checked_div(device_count)
        .and_then(|budget| budget.checked_sub(P256_ENCAPSULATED_KEY_BYTES + HPKE_TAG_BYTES))
        .ok_or_else(|| ChatError::Invalid("anonymous MLS device fanout is too large".into()))?;
    let required = PAYLOAD_HEADER_BYTES
        .checked_add(ciphertext.len())
        .ok_or_else(|| ChatError::Invalid("anonymous MLS payload size overflow".into()))?;
    let padded_len = required
        .checked_add(PAD_BLOCK_BYTES - 1)
        .map(|length| length / PAD_BLOCK_BYTES * PAD_BLOCK_BYTES)
        .ok_or_else(|| ChatError::Invalid("anonymous MLS payload size overflow".into()))?;
    if padded_len > per_device_budget {
        return Err(ChatError::Invalid(
            "MLS ciphertext is too large for anonymous device fanout".into(),
        ));
    }
    let ciphertext_len = u32::try_from(ciphertext.len())
        .map_err(|_| ChatError::Invalid("MLS ciphertext length overflow".into()))?;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(PAYLOAD_CONTEXT);
    padded.extend_from_slice(&ciphertext_len.to_be_bytes());
    padded.extend_from_slice(ciphertext);
    padded.resize(padded_len, 0);
    Ok(padded)
}

fn unpad_payload(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < PAYLOAD_HEADER_BYTES
        || payload.len() % PAD_BLOCK_BYTES != 0
        || !payload.starts_with(PAYLOAD_CONTEXT)
    {
        return Err(ChatError::Trust(
            "anonymous MLS padded payload is malformed".into(),
        ));
    }
    let length_offset = PAYLOAD_CONTEXT.len();
    let length = u32::from_be_bytes(
        payload[length_offset..length_offset + 4]
            .try_into()
            .expect("four-byte length"),
    ) as usize;
    let end = PAYLOAD_HEADER_BYTES
        .checked_add(length)
        .ok_or_else(|| ChatError::Trust("anonymous MLS payload length overflow".into()))?;
    if length == 0 || end > payload.len() || payload[end..].iter().any(|byte| *byte != 0) {
        return Err(ChatError::Trust(
            "anonymous MLS padded payload length or padding is invalid".into(),
        ));
    }
    Ok(payload[PAYLOAD_HEADER_BYTES..end].to_vec())
}

fn decode_canonical_base64(label: &str, value: &str) -> Result<Vec<u8>> {
    let bytes = BASE64
        .decode(value)
        .map_err(|_| ChatError::Invalid(format!("{label} is not canonical base64")))?;
    if BASE64.encode(&bytes) != value {
        return Err(ChatError::Invalid(format!(
            "{label} is not canonical base64"
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChatDb, SqliteChatDb};
    use std::rc::Rc;

    #[test]
    fn padding_is_bounded_and_strict() {
        let padded = pad_payload(b"MLS", 2).unwrap();
        assert_eq!(padded.len(), PAD_BLOCK_BYTES);
        assert_eq!(unpad_payload(&padded).unwrap(), b"MLS");
        let mut malformed = padded;
        *malformed.last_mut().unwrap() = 1;
        assert!(matches!(
            unpad_payload(&malformed),
            Err(ChatError::Trust(_))
        ));
    }

    #[test]
    fn group_id_validator_remains_private_boundary() {
        assert!(validate_group_id(b"0123456789abcdef").is_ok());
    }

    #[test]
    fn hpke_submission_round_trips_and_binds_aad() {
        futures_executor::block_on(async {
            let alice_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
            let bob_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
            let alice = MlsClient::new(alice_db);
            let bob = MlsClient::new(bob_db);
            alice.initialize("alice@a.example#1").await.unwrap();
            let bob_public = bob.initialize("bob@b.example#1").await.unwrap();
            let recipient: AccountAddress = "bob@b.example".parse().unwrap();
            let send_id = Uuid::from_u128(7);
            let submission = alice
                .create_anonymous_submission(
                    recipient.clone(),
                    send_id,
                    [9; 16],
                    &[AnonymousMlsRecipientDevice::new(
                        1,
                        bob_public.anonymous_delivery_public_key,
                    )
                    .unwrap()],
                    b"exact OpenMLS ciphertext",
                )
                .await
                .unwrap();
            submission.validate().unwrap();
            assert_eq!(
                bob.open_anonymous_envelope(
                    &recipient,
                    send_id,
                    submission.envelopes.first().unwrap(),
                )
                .await
                .unwrap(),
                b"exact OpenMLS ciphertext"
            );
            assert!(matches!(
                bob.open_anonymous_envelope(
                    &recipient,
                    Uuid::from_u128(8),
                    submission.envelopes.first().unwrap(),
                )
                .await,
                Err(ChatError::Trust(_))
            ));
        });
    }
}
