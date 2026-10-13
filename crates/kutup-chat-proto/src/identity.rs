//! Stable account and conversation identifiers shared by every chat client.
//!
//! A Kutup account has exactly one routing identity, `username@server`, on the
//! wire, in server mailboxes and in client stores alike: there is no bare
//! username form. Display names and avatars are profile data; they never
//! participate in routing or trust.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The stable routing identity of one Kutup account.
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

    /// The canonical routing form used as the libsignal account name and UI
    /// contact address.
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
        address: AccountAddress,
    },
    Group {
        #[serde(rename = "groupId")]
        group_id: String,
    },
}

impl ConversationId {
    pub fn direct(address: AccountAddress) -> Self {
        Self::Direct { address }
    }

    /// Stable key suitable for IndexedDB indexes and frontend selection state.
    pub fn key(&self) -> String {
        match self {
            Self::Direct { address } => format!("direct:{}", address.canonical()),
            Self::Group { group_id } => format!("group:{group_id}"),
        }
    }
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

fn validate_server(server: &str) -> Result<(), AddressError> {
    if server.is_empty()
        || server.len() > 253
        || server.ends_with('.')
        || server.parse::<IpAddr>().is_ok()
    {
        return Err(AddressError("server is not a canonical DNS name".into()));
    }
    for label in server.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(AddressError("server is not a canonical DNS name".into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_accounts_canonically_and_refuses_bare_usernames() {
        assert!("alice_42".parse::<AccountAddress>().is_err());
        assert!(serde_json::from_value::<AccountAddress>(
            serde_json::json!({ "username": "alice_42" })
        )
        .is_err());
        assert!(serde_json::from_value::<AccountAddress>(
            serde_json::json!({ "username": "alice_42", "server": null })
        )
        .is_err());
        assert!(serde_json::from_value::<ConversationId>(
            serde_json::json!({ "kind": "direct", "address": { "username": "alice_42" } })
        )
        .is_err());

        let remote: AccountAddress = "alice_42@Chat.Example".parse().unwrap();
        assert_eq!(remote.canonical(), "alice_42@chat.example");
        assert_eq!(
            ConversationId::direct(remote).key(),
            "direct:alice_42@chat.example"
        );
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
        ] {
            assert!(invalid.parse::<AccountAddress>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn conversation_shape_is_stable() {
        let conversation = ConversationId::direct("alice@example.org".parse().unwrap());
        assert_eq!(
            serde_json::to_value(conversation).unwrap(),
            serde_json::json!({
                "kind": "direct",
                "address": { "username": "alice", "server": "example.org" }
            })
        );
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
