//! Group invite links (docs/chat-invite-links.md).
//!
//! A link carries a 32-byte secret and the domain of the server that keeps
//! the link's mailbox (its host). From the secret, clients derive the link id
//! the host files it under, a management token, and the key that seals what
//! the host stores: the group's preview (sealed by administrators) and each
//! request to join (sealed by whoever asks). The host sees ids, sizes, times
//! and the domain a request came from; never a group's name or a requester.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::mls::decode_canonical_base64;
use crate::{AccountAddress, MlsGroupAvatarV1, MlsGroupInfoV1};

/// Link ids and tokens: standard base64 of 32 bytes.
pub const INVITE_LINK_TOKEN_BYTES: usize = 32;
/// A sealed preview: room for the largest group picture and description.
pub const MAX_INVITE_PREVIEW_SEALED_BYTES: usize = 80 * 1024;
/// A sealed request to join.
pub const MAX_INVITE_REQUEST_SEALED_BYTES: usize = 1024;
/// Requests a link holds at once; further requests wait for a decision.
pub const MAX_PENDING_INVITE_REQUESTS: usize = 256;

fn validate_token(name: &str, value: &str) -> Result<(), String> {
    decode_canonical_base64(
        name,
        value,
        INVITE_LINK_TOKEN_BYTES,
        INVITE_LINK_TOKEN_BYTES,
    )
    .map(drop)
}

fn validate_sealed(name: &str, value: &str, maximum: usize) -> Result<(), String> {
    // A nonce and a tag at least.
    decode_canonical_base64(name, value, 24 + 16 + 1, maximum).map(drop)
}

/// What someone holding the link sees before asking to join.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InviteLinkPreviewV1 {
    pub conversation_id: Uuid,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<MlsGroupAvatarV1>,
    pub member_count: u32,
    pub approval_required: bool,
}

impl InviteLinkPreviewV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.conversation_id.is_nil()
            || self.member_count == 0
            || self.member_count as usize > crate::MAX_MLS_GROUP_ACCOUNTS
        {
            return Err("invite link preview has an invalid group".into());
        }
        // The same limits as the group information it shows.
        MlsGroupInfoV1 {
            sequence: 1,
            name: self.name.clone(),
            description: self.description.clone(),
            avatar: self.avatar.clone(),
            invite_link: None,
        }
        .validate()
    }
}

/// Who asks to join. The host cannot read it; administrators check that
/// `requester` belongs to the domain the host saw the request come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InviteJoinRequestV1 {
    pub requester: AccountAddress,
    pub created_at_ms: i64,
}

impl InviteJoinRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        let canonical: AccountAddress = self
            .requester
            .canonical()
            .parse()
            .map_err(|error: crate::AddressError| error.to_string())?;
        if canonical != self.requester || self.requester.server.is_none() {
            return Err("an invite request names a canonical account".into());
        }
        if !(0..=crate::MAX_SAFE_CLOCK_MS).contains(&self.created_at_ms) {
            return Err("an invite request time is out of range".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub enum InviteRequestStatusV1 {
    Pending,
    Approved,
    Denied,
}

/// One operation on a link's mailbox, the same whether it reaches the host
/// from one of its own accounts or through another server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", tag = "op")]
pub enum InviteLinkOperationV1 {
    /// Create the mailbox, or replace its preview.
    #[serde(rename_all = "camelCase")]
    Put {
        link_id: String,
        manage_token: String,
        preview: String,
    },
    #[serde(rename_all = "camelCase")]
    Delete {
        link_id: String,
        manage_token: String,
    },
    #[serde(rename_all = "camelCase")]
    Preview { link_id: String },
    #[serde(rename_all = "camelCase")]
    Request {
        link_id: String,
        request: String,
        /// The requester's own proof, to read or cancel its request later.
        status_token: String,
    },
    #[serde(rename_all = "camelCase")]
    Requests {
        link_id: String,
        manage_token: String,
    },
    #[serde(rename_all = "camelCase")]
    Decide {
        link_id: String,
        manage_token: String,
        request_id: Uuid,
        approve: bool,
    },
    #[serde(rename_all = "camelCase")]
    Status {
        link_id: String,
        request_id: Uuid,
        status_token: String,
    },
    #[serde(rename_all = "camelCase")]
    Cancel {
        link_id: String,
        request_id: Uuid,
        status_token: String,
    },
}

impl InviteLinkOperationV1 {
    pub fn link_id(&self) -> &str {
        match self {
            Self::Put { link_id, .. }
            | Self::Delete { link_id, .. }
            | Self::Preview { link_id }
            | Self::Request { link_id, .. }
            | Self::Requests { link_id, .. }
            | Self::Decide { link_id, .. }
            | Self::Status { link_id, .. }
            | Self::Cancel { link_id, .. } => link_id,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_token("linkId", self.link_id())?;
        match self {
            Self::Put {
                manage_token,
                preview,
                ..
            } => {
                validate_token("manageToken", manage_token)?;
                validate_sealed("preview", preview, MAX_INVITE_PREVIEW_SEALED_BYTES)
            }
            Self::Delete { manage_token, .. } | Self::Requests { manage_token, .. } => {
                validate_token("manageToken", manage_token)
            }
            Self::Decide {
                manage_token,
                request_id,
                ..
            } => {
                if request_id.is_nil() {
                    return Err("invite request id is nil".into());
                }
                validate_token("manageToken", manage_token)
            }
            Self::Preview { .. } => Ok(()),
            Self::Request {
                request,
                status_token,
                ..
            } => {
                validate_token("statusToken", status_token)?;
                validate_sealed("request", request, MAX_INVITE_REQUEST_SEALED_BYTES)
            }
            Self::Status {
                request_id,
                status_token,
                ..
            }
            | Self::Cancel {
                request_id,
                status_token,
                ..
            } => {
                if request_id.is_nil() {
                    return Err("invite request id is nil".into());
                }
                validate_token("statusToken", status_token)
            }
        }
    }
}

/// An operation from one of this server's accounts, for the link's host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InviteLinkCallV1 {
    pub host: String,
    pub operation: InviteLinkOperationV1,
}

impl InviteLinkCallV1 {
    pub fn validate(&self) -> Result<(), String> {
        kutup_federation_proto::validate_server_name(&self.host)
            .map_err(|error| format!("invite link host: {error}"))?;
        self.operation.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InviteLinkRequestEntryV1 {
    pub request_id: Uuid,
    /// The server the request came through: the requester's own.
    pub origin_domain: String,
    pub request: String,
    pub status: InviteRequestStatusV1,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", tag = "result")]
pub enum InviteLinkResultV1 {
    Done,
    #[serde(rename_all = "camelCase")]
    Preview {
        preview: String,
    },
    #[serde(rename_all = "camelCase")]
    Requested {
        request_id: Uuid,
    },
    #[serde(rename_all = "camelCase")]
    Requests {
        requests: Vec<InviteLinkRequestEntryV1>,
    },
    #[serde(rename_all = "camelCase")]
    Status {
        status: InviteRequestStatusV1,
    },
}

impl InviteLinkResultV1 {
    /// The result has the shape `operation` expects.
    pub fn answers(&self, operation: &InviteLinkOperationV1) -> bool {
        use InviteLinkOperationV1 as Op;
        match (operation, self) {
            (
                Op::Put { .. } | Op::Delete { .. } | Op::Decide { .. } | Op::Cancel { .. },
                Self::Done,
            ) => true,
            (Op::Preview { .. }, Self::Preview { preview }) => {
                validate_sealed("preview", preview, MAX_INVITE_PREVIEW_SEALED_BYTES).is_ok()
            }
            (Op::Request { .. }, Self::Requested { request_id }) => !request_id.is_nil(),
            (Op::Requests { .. }, Self::Requests { requests }) => {
                requests.len() <= MAX_PENDING_INVITE_REQUESTS * 2
                    && requests.iter().all(|entry| {
                        kutup_federation_proto::validate_server_name(&entry.origin_domain).is_ok()
                            && validate_sealed(
                                "request",
                                &entry.request,
                                MAX_INVITE_REQUEST_SEALED_BYTES,
                            )
                            .is_ok()
                    })
            }
            (Op::Status { .. }, Self::Status { .. }) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn token(byte: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    #[test]
    fn operations_round_trip_and_validate() {
        let operation = InviteLinkOperationV1::Request {
            link_id: token(1),
            request: base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
            status_token: token(2),
        };
        let json = serde_json::to_value(&operation).unwrap();
        assert_eq!(json["op"], "request");
        assert_eq!(json["statusToken"], token(2));
        let back: InviteLinkOperationV1 = serde_json::from_value(json).unwrap();
        assert_eq!(back, operation);
        back.validate().unwrap();

        let short = InviteLinkOperationV1::Preview {
            link_id: base64::engine::general_purpose::STANDARD.encode([1u8; 16]),
        };
        assert!(short.validate().is_err());
        let nil = InviteLinkOperationV1::Status {
            link_id: token(1),
            request_id: Uuid::nil(),
            status_token: token(2),
        };
        assert!(nil.validate().is_err());
    }

    #[test]
    fn results_must_answer_their_operation() {
        let preview = InviteLinkOperationV1::Preview { link_id: token(1) };
        assert!(!InviteLinkResultV1::Done.answers(&preview));
        let sealed = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        assert!(InviteLinkResultV1::Preview { preview: sealed }.answers(&preview));
    }

    #[test]
    fn requests_name_a_canonical_account() {
        let request = InviteJoinRequestV1 {
            requester: "bob@b.test".parse().unwrap(),
            created_at_ms: 1,
        };
        request.validate().unwrap();
        let local = InviteJoinRequestV1 {
            requester: AccountAddress {
                username: "bob".into(),
                server: None,
            },
            created_at_ms: 1,
        };
        assert!(local.validate().is_err());
    }
}
