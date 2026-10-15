//! A person across servers (docs/plans/account-ids.md): the server they are
//! on and their permanent account id, as Signal names an account by its ACI.
//!
//! The account id is the server's `users.id`, a random UUID minted once,
//! kept through renames and resets; names are lookup handles only. In JSON it
//! is `{ "server", "accountId" }`, two fields. Where one string is needed
//! (a libsignal `ProtocolAddress` name, an MLS credential identity, a local
//! store key) it is `aci:<uuid>@<server>`, prefixed so that no address parser
//! takes it for a `username@server`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};

/// The string form's prefix.
pub const PREFIX: &str = "aci:";

/// A person: their server and their permanent account id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, try_from = "Wire")]
pub struct AccountRef {
    pub server: String,
    /// Lowercase hyphenated UUID.
    pub account_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Wire {
    server: String,
    account_id: String,
}

impl TryFrom<Wire> for AccountRef {
    type Error = CryptoError;

    fn try_from(wire: Wire) -> Result<Self> {
        AccountRef::new(&wire.server, &wire.account_id)
    }
}

fn invalid(what: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("account ref: {what}"))
}

impl AccountRef {
    /// Checks both parts: a canonical server name and a canonical account id.
    pub fn new(server: &str, account_id: &str) -> Result<Self> {
        if !valid_server(server) {
            return Err(invalid("server is not a canonical DNS name"));
        }
        if !valid_account_id(account_id) {
            return Err(invalid("account id is not a lowercase hyphenated UUID"));
        }
        Ok(Self {
            server: server.to_owned(),
            account_id: account_id.to_owned(),
        })
    }

    /// The bytes signed or bound for this person: length-prefixed server,
    /// then the 16 bytes of the account id.
    pub fn bytes(&self) -> Vec<u8> {
        let id = hex::decode(self.account_id.replace('-', "")).expect("checked when made");
        let mut out = Vec::with_capacity(2 + self.server.len() + 16);
        out.extend_from_slice(&(self.server.len() as u16).to_be_bytes());
        out.extend_from_slice(self.server.as_bytes());
        out.extend_from_slice(&id);
        out
    }
}

impl fmt::Display for AccountRef {
    /// `aci:<uuid>@<server>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}@{}", self.account_id, self.server)
    }
}

impl FromStr for AccountRef {
    type Err = CryptoError;

    /// Exactly `aci:<lowercase hyphenated uuid>@<canonical server>`.
    fn from_str(value: &str) -> Result<Self> {
        let rest = value
            .strip_prefix(PREFIX)
            .ok_or_else(|| invalid("missing the aci: prefix"))?;
        let (account_id, server) = rest
            .split_once('@')
            .ok_or_else(|| invalid("missing @server"))?;
        Self::new(server, account_id)
    }
}

/// A lowercase hyphenated UUID (8-4-4-4-12 hex), as `users.id` prints.
pub fn valid_account_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// A canonical server name: what servers require of their own name
/// (`kutup_federation_proto::validate_server_name`, which the server checks
/// agrees with this): 1-253 ASCII bytes, at least two labels, no IP, each
/// label 1-63 of `a-z 0-9 -`, not starting or ending with `-`.
pub fn valid_server(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.contains('.')
        && value.parse::<std::net::IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70";

    #[test]
    fn two_fields_in_json_and_one_prefixed_string() {
        let person = AccountRef::new("kutup.dev", ID).unwrap();
        let json = serde_json::to_value(&person).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "server": "kutup.dev", "accountId": ID })
        );
        assert_eq!(serde_json::from_value::<AccountRef>(json).unwrap(), person);
        assert_eq!(person.to_string(), format!("aci:{ID}@kutup.dev"));
        assert_eq!(person.to_string().parse::<AccountRef>().unwrap(), person);
    }

    #[test]
    fn only_the_canonical_form_parses() {
        for bad in [
            format!("{ID}@kutup.dev"),     // no prefix: could be a name
            format!("ACI:{ID}@kutup.dev"), // prefix case
            format!("aci:{}@kutup.dev", ID.to_uppercase()),
            format!("aci:{}@kutup.dev", ID.replace('-', "")),
            format!("aci:{ID}@Kutup.dev"),
            format!("aci:{ID}@localhost"), // a single label
            format!("aci:{ID}@127.0.0.1"),
            format!("aci:{ID}@kutup.dev."),
            format!("aci:{ID}@-kutup.dev"),
            format!("aci:{ID}"),
            format!("aci:{ID}@kutup.dev@x.dev"),
            "aci:alice@kutup.dev".to_owned(), // a name is not an id
        ] {
            assert!(bad.parse::<AccountRef>().is_err(), "{bad}");
        }
        // JSON refuses the same, and unknown fields.
        assert!(serde_json::from_value::<AccountRef>(
            serde_json::json!({ "server": "kutup.dev", "accountId": "alice" })
        )
        .is_err());
        assert!(serde_json::from_value::<AccountRef>(
            serde_json::json!({ "server": "kutup.dev", "accountId": ID, "name": "x" })
        )
        .is_err());
    }

    #[test]
    fn its_bytes_are_the_server_and_the_ids_sixteen_bytes() {
        let person = AccountRef::new("a.test", ID).unwrap();
        let bytes = person.bytes();
        assert_eq!(&bytes[..2], &[0, 6]);
        assert_eq!(&bytes[2..8], b"a.test");
        assert_eq!(bytes[8..].len(), 16);
        assert_eq!(hex::encode(&bytes[8..]), ID.replace('-', ""),);
    }
}
