//! Chat feature-protocol transaction and response DTOs.
//!
//! Federation authenticates mailbox servers, not message plaintext. Clients
//! still verify account-signed device manifests and libsignal identities. The
//! common server identity, discovery, and HTTP authentication protocol is owned
//! by `kutup-federation-proto` rather than this feature-specific crate.

use serde::{Deserialize, Serialize};

use crate::{DeviceListMismatch, SendMessagesRequest};

/// Common-stack feature identifier for every transaction in this module.
pub const FEDERATED_CHAT_FEATURE: kutup_federation_proto::FederationFeature =
    kutup_federation_proto::FederationFeature::ChatV1;

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
    /// Canonical `username@destination`.
    pub recipient: String,
    /// Canonical `username@origin`; plaintext until sealed sender lands as a
    /// complete abuse-controlled system.
    pub sender: String,
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
