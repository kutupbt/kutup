//! Passkeys as KeePassXC keeps them (`EntryAttributes::KPEX_PASSKEY_*`): an
//! entry's custom fields naming the relying party, the user, the credential
//! and its private key (a PEM, protected).
//!
//! The page never gets the private key: the view leaves every passkey field
//! out of an entry's fields and gives a summary without it ([`PasskeyView`]),
//! a placeholder naming it resolves to nothing, and an edit made from the
//! view keeps the passkey fields it couldn't see (`edit::fill_entry`). Only
//! exports, which are the whole vault by intent, and the KeePass file itself
//! hold it.

use keepass::db::Entry;
use serde::Serialize;

/// The prefix of every passkey field (KeePassXC's `PasskeyAttribute`).
pub const PREFIX: &str = "KPEX_PASSKEY";
pub const USERNAME: &str = "KPEX_PASSKEY_USERNAME";
pub const CREDENTIAL_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
pub const PRIVATE_KEY_PEM: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
pub const RELYING_PARTY: &str = "KPEX_PASSKEY_RELYING_PARTY";
pub const USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";

/// Whether `key` is one of an entry's passkey fields.
pub fn is_passkey_field(key: &str) -> bool {
    key.starts_with(PREFIX)
}

/// What the page shows of an entry's passkey: everything but the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyView {
    pub relying_party: String,
    pub username: String,
    pub credential_id: String,
    pub user_handle: String,
    /// Whether the entry holds the private key (it never leaves the vault).
    pub has_private_key: bool,
}

/// The entry's passkey, when it has one (a relying party or a private key).
pub fn passkey(entry: &Entry) -> Option<PasskeyView> {
    let text = |key: &str| {
        entry
            .fields
            .get(key)
            .map_or(String::new(), |v| v.get().clone())
    };
    let has_private_key = entry
        .fields
        .get(PRIVATE_KEY_PEM)
        .is_some_and(|v| !v.get().trim().is_empty());
    let relying_party = text(RELYING_PARTY);
    if relying_party.is_empty() && !has_private_key {
        return None;
    }
    Some(PasskeyView {
        relying_party,
        username: text(USERNAME),
        credential_id: text(CREDENTIAL_ID),
        user_handle: text(USER_HANDLE),
        has_private_key,
    })
}
