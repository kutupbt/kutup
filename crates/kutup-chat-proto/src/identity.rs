//! Stable account and conversation identifiers shared by every chat client.
//!
//! A person is their account ([`AccountRef`]: server and permanent account id,
//! Signal's ACI, docs/plans/account-ids.md). Conversations, stores and every
//! durable record key on it. An address, `username@server`, is a handle: what
//! a person types to find someone, and what the app shows. It can change
//! (a rename) and later belong to someone else, so nothing durable keys on it
//! or carries it. Display names and avatars are profile data; they never
//! participate in routing or trust.

use std::fmt;
use std::str::FromStr;

use kutup_crypto::account_ref::AccountRef;
use serde::{Deserialize, Serialize};

/// An account's handle: what a person types and sees, never a key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AccountAddress {
    pub username: String,
    /// The account's home server, a canonical lowercase DNS name. Required.
    pub server: String,
}

impl AccountAddress {
    pub fn federated(
        username: impl Into<String>,
        server: impl Into<String>,
    ) -> Result<Self, AddressError> {
        let username = username.into();
        let server = server.into().to_ascii_lowercase();
        validate_username(&username)?;
        validate_server(&server)?;
        Ok(Self { username, server })
    }

    /// The canonical form people type and see.
    pub fn canonical(&self) -> String {
        format!("{}@{}", self.username, self.server)
    }
}

impl FromStr for AccountAddress {
    type Err = AddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.matches('@').count() > 1 {
            return Err(AddressError(
                "account address contains more than one @".into(),
            ));
        }
        match value.split_once('@') {
            Some((username, server)) => Self::federated(username, server),
            None => Err(AddressError(
                "account address must be username@server".into(),
            )),
        }
    }
}

impl fmt::Display for AccountAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical())
    }
}

/// A stable conversation identity. Groups are included now so persisted UI
/// state and public client APIs do not bake in a direct-message-only string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ConversationId {
    Direct {
        #[cfg_attr(feature = "openapi", schema(value_type = AccountRefSchema))]
        account: AccountRef,
    },
    Group {
        #[serde(rename = "groupId")]
        group_id: String,
    },
}

impl ConversationId {
    pub fn direct(account: AccountRef) -> Self {
        Self::Direct { account }
    }

    /// Stable key suitable for IndexedDB indexes and frontend selection
    /// state: `direct:aci:<uuid>@<server>` or `group:<uuid>`.
    pub fn key(&self) -> String {
        match self {
            Self::Direct { account } => format!("direct:{account}"),
            Self::Group { group_id } => format!("group:{group_id}"),
        }
    }
}

/// The OpenAPI shape of [`AccountRef`] (kutup-crypto has no utoipa).
#[cfg(feature = "openapi")]
#[derive(utoipa::ToSchema)]
#[schema(as = AccountRef)]
#[allow(dead_code)]
pub struct AccountRefSchema {
    /// The account's home server: a lowercase DNS name.
    server: String,
    /// Its permanent id: a lowercase hyphenated UUID.
    #[schema(rename = "accountId")]
    account_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressError(pub String);

impl fmt::Display for AddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AddressError {}

fn validate_username(username: &str) -> Result<(), AddressError> {
    if !(3..=32).contains(&username.len())
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
    {
        return Err(AddressError(
            "username must be 3-32 lowercase ASCII letters, digits, _ or -".into(),
        ));
    }
    Ok(())
}

/// One rule for every server name Kutup routes to: the federation stack's
/// (a canonical lowercase DNS name with at least one dot, no IP literal).
fn validate_server(server: &str) -> Result<(), AddressError> {
    kutup_federation_proto::validate_server_name(server)
        .map_err(|_| AddressError("server is not a canonical DNS name".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";

    fn alice() -> AccountRef {
        AccountRef::new("example.org", ID).unwrap()
    }

    #[test]
    fn parses_addresses_canonically_and_refuses_bare_usernames() {
        assert!("alice_42".parse::<AccountAddress>().is_err());
        assert!(serde_json::from_value::<AccountAddress>(
            serde_json::json!({ "username": "alice_42" })
        )
        .is_err());
        assert!(serde_json::from_value::<AccountAddress>(
            serde_json::json!({ "username": "alice_42", "server": null })
        )
        .is_err());
        let remote: AccountAddress = "alice_42@Chat.Example".parse().unwrap();
        assert_eq!(remote.canonical(), "alice_42@chat.example");
    }

    #[test]
    fn rejects_alias_like_or_ambiguous_addresses() {
        for invalid in [
            "Alice@example.org",
            "al@example.org",
            "alice@@example.org",
            "alice@example.org.",
            "alice@127.0.0.1",
            "alice@-example.org",
            "alice@example_org",
            "aci:0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b@example.org",
        ] {
            assert!(invalid.parse::<AccountAddress>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn a_direct_conversation_is_an_account_never_an_address() {
        let conversation = ConversationId::direct(alice());
        assert_eq!(conversation.key(), format!("direct:aci:{ID}@example.org"));
        assert_eq!(
            serde_json::to_value(&conversation).unwrap(),
            serde_json::json!({
                "kind": "direct",
                "account": { "server": "example.org", "accountId": ID }
            })
        );
        for refused in [
            serde_json::json!({ "kind": "direct", "address": { "username": "alice", "server": "example.org" } }),
            serde_json::json!({ "kind": "direct", "account": "alice@example.org" }),
            serde_json::json!({ "kind": "direct", "account": format!("aci:{ID}@example.org") }),
            serde_json::json!({ "kind": "direct", "account": { "server": "example.org", "accountId": ID.to_uppercase() } }),
        ] {
            assert!(
                serde_json::from_value::<ConversationId>(refused.clone()).is_err(),
                "{refused}"
            );
        }
        assert_eq!(
            serde_json::to_value(ConversationId::Group {
                group_id: "11111111-1111-4111-8111-111111111111".into(),
            })
            .unwrap(),
            serde_json::json!({
                "kind": "group",
                "groupId": "11111111-1111-4111-8111-111111111111"
            })
        );
    }
}
