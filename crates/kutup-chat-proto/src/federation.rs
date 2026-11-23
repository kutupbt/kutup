//! Chat feature-protocol transaction and response DTOs.
//!
//! Federation authenticates mailbox servers, not message plaintext. Clients
//! still verify account-signed device manifests and libsignal identities. The
//! common server identity, discovery, and HTTP authentication protocol is owned
//! by `kutup-federation-proto` rather than this feature-specific crate.

use serde::{Deserialize, Serialize};

use crate::{AccountRef, DeviceListMismatch, SendMessagesRequest};

/// Common-stack feature identifier for every transaction in this module.
pub const FEDERATED_CHAT_FEATURE: kutup_federation_proto::FederationFeature =
    kutup_federation_proto::FederationFeature::ChatV2;

/// One in-order ciphertext delivery from an origin mailbox server to a
/// destination mailbox server. No room state is replicated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FederatedChatTransaction {
    pub fed_version: u16,
    pub transaction_id: String,
    pub sequence: u64,
    pub origin: String,
    pub destination: String,
    /// The recipient's account on `destination` (server and account id).
    #[cfg_attr(feature = "openapi", schema(value_type = crate::AccountRefSchema))]
    pub recipient: AccountRef,
    /// The sender's account on `origin`; plaintext until sealed sender lands
    /// as a complete abuse-controlled system.
    #[cfg_attr(feature = "openapi", schema(value_type = crate::AccountRefSchema))]
    pub sender: AccountRef,
    pub message: SendMessagesRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FederationDeliveryResponse {
    pub stored: usize,
    pub deduplicated: bool,
    pub accepted_sequence: u64,
    /// A terminal delivery failure still consumes the in-order sequence so one
    /// unavailable account cannot poison every later send to that server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection: Option<FederationDeliveryRejection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub enum FederationDeliveryRejection {
    RecipientUnavailable,
}

/// Typed 409 response. Device mismatch is relayed to the originating client so
/// it can re-fetch the signed manifest and re-encrypt under the same send id;
/// a sequence gap tells the origin server which durable transaction must lead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(
    tag = "code",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum FederationDeliveryError {
    DeviceListMismatch {
        #[serde(flatten)]
        mismatch: DeviceListMismatch,
    },
    SequenceGap {
        expected_sequence: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_conflicts_are_typed() {
        let error = FederationDeliveryError::DeviceListMismatch {
            mismatch: DeviceListMismatch {
                missing_devices: vec![2],
                stale_devices: vec![3],
                extra_devices: vec![],
            },
        };
        assert_eq!(
            serde_json::to_string(&error).unwrap(),
            r#"{"code":"deviceListMismatch","missingDevices":[2],"staleDevices":[3],"extraDevices":[]}"#
        );
        let gap = FederationDeliveryError::SequenceGap {
            expected_sequence: 9,
        };
        assert_eq!(
            serde_json::to_string(&gap).unwrap(),
            r#"{"code":"sequenceGap","expectedSequence":9}"#
        );
    }

    #[test]
    fn terminal_rejection_is_additive_and_sequence_advancing() {
        let response = FederationDeliveryResponse {
            stored: 0,
            deduplicated: false,
            accepted_sequence: 9,
            rejection: Some(FederationDeliveryRejection::RecipientUnavailable),
        };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({
                "stored": 0,
                "deduplicated": false,
                "acceptedSequence": 9,
                "rejection": "recipientUnavailable"
            })
        );
    }
}

/// The version of [`FederatedStreamControlV1`].
pub const FEDERATION_STREAM_CONTROL_VERSION: u16 = 1;

/// [`FederatedStreamControlV1::control`]: the sequence's transaction was
/// withdrawn before it left (its account turned its federation off;
/// docs/plans/server-personal-data.md, the federation switch). No `data`.
pub const STREAM_CONTROL_WITHDRAWN: u16 = 1;

/// The first must-understand control code. The code space:
///
/// - `0` is invalid: refused.
/// - `1..=0x7fff` are skip-safe: a destination that doesn't know the code
///   still uses the sequence up and answers as it does for a withdrawn one.
/// - `0x8000..=0xffff` must be understood: a destination that doesn't know
///   the code refuses it (`400 unknownStreamControl`) and doesn't use the
///   sequence up.
///
/// `data` is never needed to use a sequence up: a skip-safe code's sequence
/// is used up whatever its `data` says.
pub const STREAM_CONTROL_MUST_UNDERSTAND: u16 = 0x8000;

/// How a destination that doesn't know a control code treats it (see
/// [`STREAM_CONTROL_MUST_UNDERSTAND`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamControlRange {
    /// `0`.
    Invalid,
    /// `1..=0x7fff`: unknown, it still uses the sequence up.
    SkipSafe,
    /// `0x8000..=0xffff`: unknown, it is refused.
    MustUnderstand,
}

impl StreamControlRange {
    /// The range `control` is in.
    pub fn of(control: u16) -> Self {
        match control {
            0 => Self::Invalid,
            code if code < STREAM_CONTROL_MUST_UNDERSTAND => Self::SkipSafe,
            _ => Self::MustUnderstand,
        }
    }
}

/// The sequenced federation stream a control message belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub enum FederationStreamV1 {
    /// Plain Chat sends (`/api/fed/v2/chat/messages`).
    Chat,
    /// Chat media offers (`/api/fed/v2/chat/media/offers`).
    Media,
    /// Sealed-sender Chat sends (`/api/fed/v2/chat/sealed/messages` and
    /// `…/batch`).
    Sealed,
}

/// A control message on a sequenced federation stream: it uses up one
/// sequence of `stream` with no delivery. `control` says why
/// ([`STREAM_CONTROL_WITHDRAWN`], the one defined today; the code ranges are
/// on [`STREAM_CONTROL_MUST_UNDERSTAND`]), so a new one needs no new
/// version. The destination answers a repeat (same `transactionId`) the
/// same, and the stream goes on with no gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedStreamControlV1 {
    pub version: u16,
    /// The control code.
    pub control: u16,
    /// The transaction id the sequence was queued under.
    pub transaction_id: String,
    pub stream: FederationStreamV1,
    pub sequence: u64,
    pub origin: String,
    pub destination: String,
    /// What the code carries, if anything; never needed to use the sequence
    /// up. A withdrawal has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// The destination's answer to [`FederatedStreamControlV1`]: the sequence
/// used up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FederationStreamControlResponseV1 {
    pub accepted_sequence: u64,
}

#[cfg(test)]
mod stream_control_tests {
    use super::*;

    #[test]
    fn control_codes_fall_in_their_ranges() {
        assert_eq!(StreamControlRange::of(0), StreamControlRange::Invalid);
        assert_eq!(
            StreamControlRange::of(STREAM_CONTROL_WITHDRAWN),
            StreamControlRange::SkipSafe
        );
        assert_eq!(StreamControlRange::of(0x7fff), StreamControlRange::SkipSafe);
        assert_eq!(
            StreamControlRange::of(0x8000),
            StreamControlRange::MustUnderstand
        );
        assert_eq!(
            StreamControlRange::of(0xffff),
            StreamControlRange::MustUnderstand
        );
    }

    #[test]
    fn a_withdrawal_has_no_data_on_the_wire() {
        let message = FederatedStreamControlV1 {
            version: FEDERATION_STREAM_CONTROL_VERSION,
            control: STREAM_CONTROL_WITHDRAWN,
            transaction_id: "10000000-0000-4000-8000-0000000000aa".into(),
            stream: FederationStreamV1::Media,
            sequence: 7,
            origin: "a.example".into(),
            destination: "b.example".into(),
            data: None,
        };
        let wire = serde_json::to_value(&message).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({
                "version": 1,
                "control": 1,
                "transactionId": "10000000-0000-4000-8000-0000000000aa",
                "stream": "media",
                "sequence": 7,
                "origin": "a.example",
                "destination": "b.example"
            })
        );
        assert_eq!(
            serde_json::from_value::<FederatedStreamControlV1>(wire).unwrap(),
            message
        );
    }

    #[test]
    fn data_is_carried_and_unknown_fields_are_refused() {
        let with_data: FederatedStreamControlV1 = serde_json::from_value(serde_json::json!({
            "version": 1, "control": 2, "transactionId": "t", "stream": "chat",
            "sequence": 1, "origin": "a", "destination": "b", "data": { "x": 1 }
        }))
        .unwrap();
        assert_eq!(with_data.data, Some(serde_json::json!({ "x": 1 })));
        assert!(
            serde_json::from_value::<FederatedStreamControlV1>(serde_json::json!({
                "version": 1, "control": 1, "transactionId": "t", "stream": "chat",
                "sequence": 1, "origin": "a", "destination": "b", "extra": true
            }))
            .is_err()
        );
    }
}
