//! Contacts-only sealed delivery wire structures and capability derivation.

use base64::Engine as _;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{AccountRef, DirectChatSuiteId};

pub const DELIVERY_CAPABILITY_CONTEXT: &[u8] = b"kutup/sealed-delivery-capability/v1";

/// The capability to deliver sealed mail to `recipient`, from their profile
/// key: salted with their account (server and permanent id), never a name
/// (docs/plans/account-ids.md).
pub fn derive_delivery_capability(
    profile_key: &[u8; 32],
    recipient: &AccountRef,
) -> Result<[u8; 16], String> {
    let hkdf = Hkdf::<Sha256>::new(Some(&recipient.bytes()), profile_key);
    let mut output = [0u8; 16];
    hkdf.expand(DELIVERY_CAPABILITY_CONTEXT, &mut output)
        .map_err(|_| "sealed delivery capability derivation failed".to_string())?;
    Ok(output)
}

pub fn capability_hash(capability: &[u8; 16]) -> [u8; 32] {
    Sha256::digest(capability).into()
}

pub fn constant_time_capability_hash_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedOutgoingEnvelopeV1 {
    pub device_id: u32,
    pub registration_id: u32,
    pub suite: DirectChatSuiteId,
    /// Serialized libsignal sealed-sender message, canonical padded base64.
    pub content: String,
}

impl SealedOutgoingEnvelopeV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.device_id == 0 || self.device_id > 127 || self.registration_id >= 16_384 {
            return Err("sealed envelope has an invalid device or registration id".into());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.content)
            .map_err(|_| "sealed envelope content must be canonical padded base64")?;
        if bytes.is_empty()
            || bytes.len() > 1024 * 1024
            || base64::engine::general_purpose::STANDARD.encode(bytes) != self.content
        {
            return Err("sealed envelope content is empty, oversized, or non-canonical".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedMessageSubmissionV1 {
    pub send_id: String,
    /// Raw 16-byte capability, canonical padded base64. It is never persisted.
    pub capability: String,
    pub envelopes: Vec<SealedOutgoingEnvelopeV1>,
}

/// Body for the cookie- and bearer-free anonymous prekey endpoint. Keeping the
/// capability in the body prevents it from entering access-log URLs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousPreKeyRequestV1 {
    pub capability: String,
}

impl AnonymousPreKeyRequestV1 {
    pub fn capability_bytes(&self) -> Result<[u8; 16], String> {
        SealedMessageSubmissionV1 {
            send_id: "00000000-0000-0000-0000-000000000000".into(),
            capability: self.capability.clone(),
            envelopes: Vec::new(),
        }
        .capability_bytes()
    }
}

impl SealedMessageSubmissionV1 {
    pub fn capability_bytes(&self) -> Result<[u8; 16], String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.capability)
            .map_err(|_| "delivery capability must be canonical padded base64")?;
        if base64::engine::general_purpose::STANDARD.encode(&bytes) != self.capability {
            return Err("delivery capability must be canonical padded base64".into());
        }
        bytes
            .try_into()
            .map_err(|_| "delivery capability must be exactly 16 bytes".into())
    }

    pub fn validate(&self) -> Result<(), String> {
        if uuid_shape(&self.send_id).is_none() {
            return Err("sealed sendId must be a lowercase hyphenated UUID".into());
        }
        self.capability_bytes()?;
        if self.envelopes.is_empty() || self.envelopes.len() > 32 {
            return Err("sealed send requires 1-32 envelopes".into());
        }
        let mut devices = std::collections::BTreeSet::new();
        let mut total = 0usize;
        for envelope in &self.envelopes {
            envelope.validate()?;
            if !devices.insert(envelope.device_id) {
                return Err("sealed send repeats a device".into());
            }
            total = total.saturating_add(envelope.content.len());
        }
        if total > 1024 * 1024 {
            return Err("sealed send exceeds the 1 MiB encoded envelope budget".into());
        }
        Ok(())
    }
}

/// The sealed federation wire's version, in every transaction and batch.
/// 2: every final answer uses up its sequence, a device mismatch included,
/// and a corrected resend goes under a new one (docs/chat-protocol.md §7).
/// Servers on another version refuse each other's sealed sends outright, as
/// final refusals named by sequence, so nothing waits on a peer that reads
/// sequences differently: federating servers upgrade together.
pub const SEALED_FEDERATION_VERSION: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedSealedTransactionV1 {
    pub version: u16,
    pub origin: String,
    /// The recipient's account on the destination, never a sender identity.
    #[cfg_attr(feature = "openapi", schema(value_type = crate::AccountRefSchema))]
    pub recipient: AccountRef,
    pub sequence: u64,
    pub send_id: String,
    pub capability: String,
    pub envelopes: Vec<SealedOutgoingEnvelopeV1>,
}

impl FederatedSealedTransactionV1 {
    pub fn validate(
        &self,
        expected_origin: &str,
        expected_destination: &str,
    ) -> Result<(), String> {
        if self.version != SEALED_FEDERATION_VERSION
            || self.sequence == 0
            || self.origin != expected_origin
        {
            return Err(
                "sealed federation transaction version, origin, or sequence is invalid".into(),
            );
        }
        kutup_federation_proto::validate_server_name(expected_destination)
            .map_err(|error| error.to_string())?;
        SealedMessageSubmissionV1 {
            send_id: self.send_id.clone(),
            capability: self.capability.clone(),
            envelopes: self.envelopes.clone(),
        }
        .validate()?;
        if self.recipient.server != expected_destination {
            return Err("sealed federation recipient must belong to the destination".into());
        }
        Ok(())
    }
}

/// The most recipients one sealed batch carries, and the most transactions
/// one federated batch does.
pub const MAX_SEALED_BATCH_ITEMS: usize = 64;
/// The most one batch weighs, encoded: requests and federated batches alike.
pub const MAX_SEALED_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// One recipient of a sealed batch: an account on the batch's destination
/// server, with its own capability and per-device envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedBatchRecipientV1 {
    pub account_id: String,
    pub submission: SealedMessageSubmissionV1,
}

/// Several sealed sends to accounts of one server, in one anonymous request
/// (docs/plans/pairwise-groups.md §1): a group message goes to each member
/// device without one request per member. It carries no sender; each
/// recipient's capability is checked and counted on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedBatchSubmissionV1 {
    pub recipients: Vec<SealedBatchRecipientV1>,
}

impl SealedBatchSubmissionV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.recipients.is_empty() || self.recipients.len() > MAX_SEALED_BATCH_ITEMS {
            return Err(format!(
                "a sealed batch carries 1-{MAX_SEALED_BATCH_ITEMS} recipients"
            ));
        }
        let mut sends = std::collections::BTreeSet::new();
        for recipient in &self.recipients {
            if uuid_shape(&recipient.account_id).is_none() {
                return Err("a batch recipient's accountId must be a lowercase UUID".into());
            }
            recipient.submission.validate()?;
            if !sends.insert((&recipient.account_id, &recipient.submission.send_id)) {
                return Err("a sealed batch repeats a recipient's send".into());
            }
        }
        Ok(())
    }
}

/// What became of one recipient of a sealed batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", tag = "outcome", deny_unknown_fields)]
pub enum SealedBatchOutcomeV1 {
    /// Stored for the recipient's devices (or already, for a repeat).
    #[serde(rename_all = "camelCase")]
    Delivered { stored: usize, deduplicated: bool },
    /// The device list changed: resend to exactly these devices.
    #[serde(rename_all = "camelCase")]
    DeviceMismatch { mismatch: crate::DeviceListMismatch },
    /// The same answer as a wrong capability: not delivered, not retried.
    Unavailable,
    /// Queued for the recipient's server; it goes when that server answers.
    Pending,
    /// The recipient's server refused this message for good.
    Refused,
    /// The recipient's server doesn't take sealed mail yet.
    PeerUnsupported,
    /// Over a rate limit (this address's, or the capability's or the
    /// recipient's); nothing was stored or queued. Resend later.
    RateLimited,
    /// A send with this sendId and other content is still queued for the
    /// recipient's server; nothing was queued. Resend once it is answered.
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
// No deny_unknown_fields: serde can't combine it with the flattened outcome,
// whose own variants still refuse unknown fields.
#[serde(rename_all = "camelCase")]
pub struct SealedBatchResultV1 {
    pub account_id: String,
    pub send_id: String,
    #[serde(flatten)]
    pub outcome: SealedBatchOutcomeV1,
}

/// The answer to a sealed batch: one result per recipient, in its order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedBatchResponseV1 {
    pub results: Vec<SealedBatchResultV1>,
}

/// Several of one origin's sealed transactions for one destination, in
/// sequence order, in one federated request. The destination applies them
/// one by one exactly as single transactions, and stops after the first
/// answer that doesn't use up its sequence: the later ones would only meet a
/// gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedSealedBatchV1 {
    pub version: u16,
    pub origin: String,
    pub transactions: Vec<FederatedSealedTransactionV1>,
}

impl FederatedSealedBatchV1 {
    /// The batch's shape: its count, one origin, and consecutive sequences.
    /// Each transaction's own checks are the single route's, item by item.
    pub fn validate_shape(&self, expected_origin: &str) -> Result<(), String> {
        if self.version != SEALED_FEDERATION_VERSION || self.origin != expected_origin {
            return Err("sealed federation batch version or origin is invalid".into());
        }
        if self.transactions.is_empty() || self.transactions.len() > MAX_SEALED_BATCH_ITEMS {
            return Err(format!(
                "a sealed federation batch carries 1-{MAX_SEALED_BATCH_ITEMS} transactions"
            ));
        }
        let mut previous: Option<u64> = None;
        for transaction in &self.transactions {
            if transaction.origin != self.origin {
                return Err("a sealed federation batch mixes origins".into());
            }
            if let Some(previous) = previous {
                if previous.checked_add(1) != Some(transaction.sequence) {
                    return Err("a sealed federation batch's sequences must be consecutive".into());
                }
            }
            previous = Some(transaction.sequence);
        }
        Ok(())
    }
}

/// One transaction's answer in a federated batch: the status and body the
/// single route would have given it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedSealedBatchItemV1 {
    pub sequence: u64,
    pub status: u16,
    pub response: serde_json::Value,
}

/// The destination's answers, in order, up to and including the first that
/// left its sequence open; the rest weren't tried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedSealedBatchResponseV1 {
    pub results: Vec<FederatedSealedBatchItemV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SenderCertificateResponseV1 {
    pub suite: crate::SealedSenderSuiteId,
    pub certificate: String,
    pub expires_at: i64,
    pub service_policy_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedDeliveryResponseV1 {
    pub stored: usize,
    pub deduplicated: bool,
}

/// The most accounts one multi-recipient send may name, whatever a server's
/// own limit (an administrator's setting, at most this).
pub const MAX_SEALED_MULTI_RECIPIENTS: usize = 1000;
/// The largest decoded multi-recipient payload the format takes; a server's
/// own limit is lower (docs/plans/pairwise-groups.md, slice 2 §1).
pub const MAX_SEALED_MULTI_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// One group message to member accounts of one server, sent once
/// (docs/plans/pairwise-groups.md, slice 2 §1; Signal's
/// `PUT /v1/messages/multi_recipient`): libsignal's sent multi-recipient
/// message, and each recipient account's group capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedMultiSubmissionV1 {
    /// Dedup and the client's retry key, per recipient account.
    pub send_id: String,
    /// libsignal's sent sealed-sender v2 message (version `0x23`),
    /// canonical padded base64.
    pub payload: String,
    /// Each recipient account's raw 16-byte group capability (canonical
    /// padded base64), by account id: exactly the payload's recipients.
    pub capabilities: std::collections::BTreeMap<String, String>,
    /// `false` (receipts and the like) only nudges connected devices and
    /// never wakes one by web push.
    #[serde(default = "urgent_by_default")]
    pub urgent: bool,
}

fn urgent_by_default() -> bool {
    true
}

impl SealedMultiSubmissionV1 {
    /// The payload's bytes.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.payload)
            .map_err(|_| "payload must be canonical padded base64")?;
        if base64::engine::general_purpose::STANDARD.encode(&bytes) != self.payload {
            return Err("payload must be canonical padded base64".into());
        }
        if bytes.is_empty() || bytes.len() > MAX_SEALED_MULTI_PAYLOAD_BYTES {
            return Err("payload is empty or too large".into());
        }
        Ok(bytes)
    }

    /// The raw capability given for `account_id`.
    pub fn capability_for(&self, account_id: &str) -> Option<[u8; 16]> {
        let value = self.capabilities.get(account_id)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value)
            .ok()?;
        if base64::engine::general_purpose::STANDARD.encode(&bytes) != *value {
            return None;
        }
        bytes.try_into().ok()
    }

    /// Its shape: the sendId, 1 to [`MAX_SEALED_MULTI_RECIPIENTS`] accounts
    /// by lowercase UUID, each with a 16-byte capability. The payload itself
    /// is parsed by the server.
    pub fn validate(&self) -> Result<(), String> {
        if uuid_shape(&self.send_id).is_none() {
            return Err("sendId must be a lowercase hyphenated UUID".into());
        }
        if self.capabilities.is_empty() || self.capabilities.len() > MAX_SEALED_MULTI_RECIPIENTS {
            return Err(format!(
                "a multi-recipient send names 1-{MAX_SEALED_MULTI_RECIPIENTS} accounts"
            ));
        }
        for account in self.capabilities.keys() {
            if uuid_shape(account).is_none() {
                return Err("a recipient's accountId must be a lowercase UUID".into());
            }
            if self.capability_for(account).is_none() {
                return Err("a group capability is 16 bytes, canonical padded base64".into());
            }
        }
        self.payload_bytes().map(|_| ())
    }
}

/// A recipient account whose device list the send got wrong (`409`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedMultiDevicesV1 {
    pub account_id: String,
    pub missing_devices: Vec<u32>,
    pub extra_devices: Vec<u32>,
}

/// A recipient account with devices whose registration changed (`410`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedMultiStaleV1 {
    pub account_id: String,
    pub stale_devices: Vec<u32>,
}

/// The answer to a multi-recipient send: `200` with who was refused or over
/// a budget (the rest delivered); `409` with `devices`, or `410` with
/// `stale`, when nothing was stored, those lists carried as well so the
/// client handles them in the same retry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedMultiResponseV1 {
    /// Accounts not delivered to: not an active account here, or a
    /// capability that doesn't hold (one answer for all).
    #[serde(default)]
    pub refused: Vec<String>,
    /// Accounts over their capability's budget: send them later.
    #[serde(default)]
    pub rate_limited: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<SealedMultiDevicesV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale: Vec<SealedMultiStaleV1>,
}

fn uuid_shape(value: &str) -> Option<()> {
    if value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
    {
        Some(())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multi(capabilities: &[(&str, [u8; 16])]) -> SealedMultiSubmissionV1 {
        SealedMultiSubmissionV1 {
            send_id: "0a0a0a0a-0000-4000-8000-000000000001".into(),
            payload: base64::engine::general_purpose::STANDARD.encode([0x23, 1, 2, 3]),
            capabilities: capabilities
                .iter()
                .map(|(account, capability)| {
                    (
                        (*account).to_owned(),
                        base64::engine::general_purpose::STANDARD.encode(capability),
                    )
                })
                .collect(),
            urgent: true,
        }
    }

    #[test]
    fn a_multi_recipient_send_is_checked_for_shape() {
        let account = "6f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b";
        let ok = multi(&[(account, [7; 16])]);
        assert!(ok.validate().is_ok());
        assert_eq!(ok.capability_for(account), Some([7; 16]));
        assert_eq!(ok.payload_bytes().unwrap(), vec![0x23, 1, 2, 3]);
        assert!(multi(&[]).validate().is_err(), "no recipients");
        assert!(multi(&[("Not-A-Uuid", [7; 16])]).validate().is_err());
        let mut short = ok.clone();
        short.capabilities.insert(
            account.into(),
            base64::engine::general_purpose::STANDARD.encode([7u8; 15]),
        );
        assert!(short.validate().is_err(), "a 15-byte capability");
        let mut empty = ok.clone();
        empty.payload = String::new();
        assert!(empty.validate().is_err());
        let mut send = ok.clone();
        send.send_id = "nope".into();
        assert!(send.validate().is_err());
        // urgent defaults to true on the wire.
        let parsed: SealedMultiSubmissionV1 = serde_json::from_str(&format!(
            r#"{{"sendId":"{}","payload":"{}","capabilities":{{}}}}"#,
            ok.send_id, ok.payload
        ))
        .unwrap();
        assert!(parsed.urgent);
    }

    #[test]
    fn capability_vector_is_domain_and_recipient_bound() {
        let alice: AccountRef = "aci:0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b@example.com"
            .parse()
            .unwrap();
        let first = derive_delivery_capability(&[7; 32], &alice).unwrap();
        assert_eq!(hex::encode(first), "0017a2dbfb9b23d85fc735e3ea889233");
        // Another account on the same server, or the same id on another server.
        let bob: AccountRef = "aci:5b0e7f3a-1d2c-4b8e-9f6a-7c3d2e1f0a9b@example.com"
            .parse()
            .unwrap();
        let second = derive_delivery_capability(&[7; 32], &bob).unwrap();
        let elsewhere: AccountRef = "aci:0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b@example.org"
            .parse()
            .unwrap();
        assert_ne!(
            first,
            derive_delivery_capability(&[7; 32], &elsewhere).unwrap()
        );
        assert_ne!(first, second);
        assert!(constant_time_capability_hash_eq(
            &capability_hash(&first),
            &capability_hash(&first)
        ));
        assert!(!constant_time_capability_hash_eq(
            &capability_hash(&first),
            &capability_hash(&second)
        ));
    }

    #[test]
    fn anonymous_prekey_request_has_a_minimal_exact_shape() {
        let request = AnonymousPreKeyRequestV1 {
            capability: "SZcLD3yoaFOTO+f4/XQffw==".into(),
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"capability":"SZcLD3yoaFOTO+f4/XQffw=="}"#
        );
        assert_eq!(
            serde_json::from_str::<AnonymousPreKeyRequestV1>(
                r#"{"capability":"SZcLD3yoaFOTO+f4/XQffw=="}"#
            )
            .unwrap(),
            request
        );
        assert!(serde_json::from_str::<AnonymousPreKeyRequestV1>(
            r#"{"capability":"SZcLD3yoaFOTO+f4/XQffw==","transparencyTreeSize":"0"}"#
        )
        .is_err());
    }

    fn submission(send: u8) -> SealedMessageSubmissionV1 {
        SealedMessageSubmissionV1 {
            send_id: format!("0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c{send:02x}"),
            capability: base64::engine::general_purpose::STANDARD.encode([3u8; 16]),
            envelopes: vec![SealedOutgoingEnvelopeV1 {
                device_id: 1,
                registration_id: 7,
                suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
                content: base64::engine::general_purpose::STANDARD.encode([9u8; 64]),
            }],
        }
    }

    fn recipient(account: u8, send: u8) -> SealedBatchRecipientV1 {
        SealedBatchRecipientV1 {
            account_id: format!("5b0e7f3a-1d2c-4b8e-9f6a-7c3d2e1f0a{account:02x}"),
            submission: submission(send),
        }
    }

    #[test]
    fn a_sealed_batch_carries_one_to_64_distinct_sends() {
        let batch = |recipients| SealedBatchSubmissionV1 { recipients };
        assert!(batch(vec![recipient(1, 1), recipient(2, 1)])
            .validate()
            .is_ok());
        assert!(batch(Vec::new()).validate().is_err());
        assert!(batch((0..65).map(|i| recipient(i, i)).collect())
            .validate()
            .is_err());
        assert!(batch((0..64).map(|i| recipient(i, i)).collect())
            .validate()
            .is_ok());
        // The same send to the same account twice is a mistake.
        assert!(batch(vec![recipient(1, 1), recipient(1, 1)])
            .validate()
            .is_err());
        let mut upper = recipient(1, 1);
        upper.account_id = upper.account_id.to_uppercase();
        assert!(batch(vec![upper]).validate().is_err());
        let mut empty = recipient(1, 1);
        empty.submission.envelopes.clear();
        assert!(batch(vec![empty]).validate().is_err());
    }

    fn transaction(sequence: u64) -> FederatedSealedTransactionV1 {
        let submission = submission(1);
        FederatedSealedTransactionV1 {
            version: SEALED_FEDERATION_VERSION,
            origin: "origin.example".into(),
            recipient: "aci:5b0e7f3a-1d2c-4b8e-9f6a-7c3d2e1f0a9b@dest.example"
                .parse()
                .unwrap(),
            sequence,
            send_id: submission.send_id,
            capability: submission.capability,
            envelopes: submission.envelopes,
        }
    }

    #[test]
    fn a_federated_batch_is_one_origins_consecutive_run() {
        let batch = |transactions| FederatedSealedBatchV1 {
            version: SEALED_FEDERATION_VERSION,
            origin: "origin.example".into(),
            transactions,
        };
        assert!(batch(vec![transaction(4), transaction(5), transaction(6)])
            .validate_shape("origin.example")
            .is_ok());
        assert!(batch(vec![transaction(4), transaction(6)])
            .validate_shape("origin.example")
            .is_err());
        assert!(batch(vec![transaction(5), transaction(4)])
            .validate_shape("origin.example")
            .is_err());
        assert!(batch(vec![transaction(4)])
            .validate_shape("other.example")
            .is_err());
        let mut mixed = transaction(5);
        mixed.origin = "other.example".into();
        assert!(batch(vec![transaction(4), mixed])
            .validate_shape("origin.example")
            .is_err());
        assert!(batch(Vec::new()).validate_shape("origin.example").is_err());
        assert!(batch(vec![transaction(u64::MAX), transaction(0)])
            .validate_shape("origin.example")
            .is_err());
    }

    #[test]
    fn batch_results_name_their_outcome() {
        let result = SealedBatchResultV1 {
            account_id: "5b0e7f3a-1d2c-4b8e-9f6a-7c3d2e1f0a9b".into(),
            send_id: "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c01".into(),
            outcome: SealedBatchOutcomeV1::Delivered {
                stored: 2,
                deduplicated: false,
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["outcome"], "delivered");
        assert_eq!(json["stored"], 2);
        assert_eq!(
            serde_json::from_value::<SealedBatchResultV1>(json).unwrap(),
            result
        );
        let pending = serde_json::to_value(SealedBatchResultV1 {
            outcome: SealedBatchOutcomeV1::Pending,
            ..result
        })
        .unwrap();
        assert_eq!(pending["outcome"], "pending");
    }
}
