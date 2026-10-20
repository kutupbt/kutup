//! An entry of the account's Chat contact list
//! (docs/plans/chat-contacts-sync.md): what one device needs to restore its
//! relationship with one person after every device was lost, as Signal's
//! storage service keeps a `ContactRecord`. The entry is sealed
//! (`kutup_crypto::chat_contact_list`); the server sees only its size.
//!
//! A device keeps the fields it doesn't know and writes them back as they
//! were, so a later version's additions (a nickname, a note) survive an
//! older device's rewrite.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_ref::AccountRef;
use serde::{Deserialize, Serialize};

use crate::ContactState;

pub const CONTACT_ENTRY_VERSION: u16 = 1;
/// A profile key's length (docs/chat-protocol.md §7).
const PROFILE_KEY_LEN: usize = 32;

/// The contact control's order inside the entry: the same
/// `(revision, sourceDeviceId)` devices agree on over Note to Self.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactEntryControlV1 {
    pub revision: u64,
    pub source_device_id: u32,
    pub updated_at_ms: i64,
}

/// One person this account accepted, asked, rejected or blocked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatContactEntryV1 {
    pub version: u16,
    /// The contact: an account, so a block follows the person, never a name.
    pub account: AccountRef,
    /// Never `pendingIncoming`: a request someone else sent is theirs.
    pub state: ContactState,
    /// What an unblock returns to; only on a block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state: Option<ContactState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_at_ms: Option<i64>,
    /// The contact's profile key (base64), as Signal keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_key: Option<String>,
    pub control: ContactEntryControlV1,
    /// Fields of a later version, kept and written back as they came.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

impl ChatContactEntryV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != CONTACT_ENTRY_VERSION {
            return Err(format!("unknown contact entry version {}", self.version));
        }
        if self.state == ContactState::PendingIncoming {
            return Err("a contact entry is never an incoming request".into());
        }
        let blocked = self.state == ContactState::Blocked;
        if self.previous_state.is_some() && !blocked {
            return Err("only a block keeps what an unblock returns to".into());
        }
        if self.blocked_at_ms.is_some() && !blocked {
            return Err("only a block has a time it was blocked".into());
        }
        if matches!(
            self.previous_state,
            Some(ContactState::Blocked | ContactState::PendingIncoming)
        ) {
            return Err("an unblock returns to an accepted, asked or rejected state".into());
        }
        if let Some(key) = &self.profile_key {
            let bytes = STANDARD
                .decode(key)
                .map_err(|_| "profileKey must be base64".to_string())?;
            if bytes.len() != PROFILE_KEY_LEN || STANDARD.encode(&bytes) != *key {
                return Err("profileKey must be 32 bytes, canonical base64".into());
            }
        }
        Ok(())
    }

    /// What this device writes: the known fields, then the unknown ones by
    /// name (one spelling for one entry).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    /// An entry as another device (perhaps a later version) wrote it: any
    /// valid JSON spelling (the seal already vouches for the bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid contact entry: {error}"))?;
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> ChatContactEntryV1 {
        ChatContactEntryV1 {
            version: CONTACT_ENTRY_VERSION,
            account: AccountRef::new("a.test", "00000000-0000-4000-8000-0000000000b2").unwrap(),
            state: ContactState::Accepted,
            previous_state: None,
            blocked_at_ms: None,
            profile_key: Some(STANDARD.encode([7u8; 32])),
            control: ContactEntryControlV1 {
                revision: 3,
                source_device_id: 2,
                updated_at_ms: 1_700_000_000_000,
            },
            unknown: BTreeMap::new(),
        }
    }

    #[test]
    fn an_entry_round_trips() {
        let bytes = entry().canonical_bytes().unwrap();
        assert_eq!(ChatContactEntryV1::from_bytes(&bytes).unwrap(), entry());
        // Within the plan's budget, far below the 2048-byte sealed size.
        assert!(bytes.len() < 400, "{}", bytes.len());
    }

    #[test]
    fn a_later_versions_fields_survive_a_rewrite() {
        let mut value = serde_json::to_value(entry()).unwrap();
        value["nickname"] = serde_json::json!({ "given": "Ada" });
        value["note"] = serde_json::json!("met at the conference");
        let read = ChatContactEntryV1::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(read.unknown.len(), 2);
        let mut changed = read.clone();
        changed.state = ContactState::Blocked;
        changed.previous_state = Some(ContactState::Accepted);
        changed.blocked_at_ms = Some(1);
        let again = ChatContactEntryV1::from_bytes(&changed.canonical_bytes().unwrap()).unwrap();
        assert_eq!(again.unknown, read.unknown);
        assert_eq!(again.state, ContactState::Blocked);
    }

    #[test]
    fn what_no_entry_says_is_refused() {
        let refused = |change: fn(&mut ChatContactEntryV1)| {
            let mut bad = entry();
            change(&mut bad);
            bad.canonical_bytes().is_err()
        };
        assert!(refused(|e| e.version = 2));
        assert!(refused(|e| e.state = ContactState::PendingIncoming));
        assert!(refused(|e| e.previous_state = Some(ContactState::Accepted)));
        assert!(refused(|e| e.blocked_at_ms = Some(1)));
        assert!(refused(|e| {
            e.state = ContactState::Blocked;
            e.previous_state = Some(ContactState::Blocked);
        }));
        assert!(refused(|e| e.profile_key = Some(STANDARD.encode([1u8; 31]))));
        assert!(refused(|e| e.profile_key = Some("not base64".into())));
    }
}
