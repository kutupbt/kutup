//! A contact group (Proton's contact label) as the account keeps it: one
//! record of the `contactGroups` scope (docs/plans/account-records.md, W3),
//! sealed under the master key ([`AccountRecordPurpose::ContactGroup`]), so
//! the server sees neither its name nor its colour. Contacts name their
//! groups by record id in their signed summaries; the server only checks
//! that each one is a record the account keeps.
//!
//! The plaintext follows docs/plans/format-evolution.md: `v` first, an
//! optional `min`, and the fields a newer writer added kept and written back.
//!
//! [`AccountRecordPurpose::ContactGroup`]: crate::account_record::AccountRecordPurpose::ContactGroup

use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};
use crate::format::{self, Extra};

/// The newest version this reader knows.
pub const CONTACT_GROUP_VERSION: u16 = 1;
/// The longest plaintext: the record pads every one to one more byte than
/// this, so its length says nothing of the name.
pub const MAX_PLAIN_LEN: usize = 1023;
/// The longest name, in characters.
pub const MAX_NAME_CHARS: usize = 100;

const WHAT: &str = "contact group";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactGroupV1 {
    pub v: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u16>,
    pub name: String,
    /// `#rrggbb`, lowercase.
    pub color: String,
    #[serde(flatten, default, skip_serializing_if = "Extra::is_empty")]
    pub extra: Extra,
}

/// A colour as the apps' palettes write it: `#rrggbb`, lowercase.
pub fn is_hex_colour(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value[1..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl ContactGroupV1 {
    pub fn new(name: impl Into<String>, color: impl Into<String>) -> Self {
        Self {
            v: CONTACT_GROUP_VERSION,
            min: None,
            name: name.into(),
            color: color.into(),
            extra: Extra::new(),
        }
    }

    fn check(&self) -> Result<()> {
        format::check_version(WHAT, self.v, self.min, CONTACT_GROUP_VERSION)?;
        format::check_extra(WHAT, &self.extra)?;
        let name_ok = !self.name.is_empty()
            && self.name == self.name.trim()
            && self.name.chars().count() <= MAX_NAME_CHARS
            && !self.name.chars().any(char::is_control);
        if !name_ok {
            return Err(CryptoError::InvalidInput(format!(
                "{WHAT}: the name is 1 to {MAX_NAME_CHARS} characters"
            )));
        }
        if !is_hex_colour(&self.color) {
            return Err(CryptoError::InvalidInput(format!(
                "{WHAT}: the colour is #rrggbb"
            )));
        }
        Ok(())
    }

    /// Reads an opened record. A newer version than this reader's is
    /// `NewerThanMe`, never corrupt.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        format::check_json_version(WHAT, bytes, CONTACT_GROUP_VERSION)?;
        let group: Self = serde_json::from_slice(bytes)
            .map_err(|_| CryptoError::InvalidInput(format!("{WHAT} does not decode")))?;
        group.check()?;
        Ok(group)
    }

    /// The plaintext to seal, unknown fields kept.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| CryptoError::InvalidInput(format!("{WHAT} does not encode")))?;
        if bytes.len() > MAX_PLAIN_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "{WHAT} is longer than {MAX_PLAIN_LEN} bytes"
            )));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_round_trips_and_keeps_a_newer_writers_fields() {
        let group = ContactGroupV1::new("Family", "#8080ff");
        let bytes = group.encode().unwrap();
        assert!(bytes.starts_with(br#"{"v":1,"#));
        assert_eq!(ContactGroupV1::decode(&bytes).unwrap(), group);
        let later = br##"{"v":1,"name":"Work","color":"#179fd9","icon":"briefcase"}"##;
        let read = ContactGroupV1::decode(later).unwrap();
        assert_eq!(read.extra["icon"], "briefcase");
        let renamed = ContactGroupV1 {
            name: "Office".into(),
            ..read
        };
        assert!(String::from_utf8(renamed.encode().unwrap())
            .unwrap()
            .contains(r#""icon":"briefcase""#));
    }

    #[test]
    fn newer_and_corrupt_groups_are_told_apart() {
        let newer = br##"{"v":2,"title":{"en":"Family"},"color":"#8080ff"}"##;
        assert!(matches!(
            ContactGroupV1::decode(newer),
            Err(CryptoError::NewerThanMe(_))
        ));
        // A newer writer that an older reader may still open.
        let readable = br##"{"v":3,"min":1,"name":"Family","color":"#8080ff"}"##;
        assert_eq!(ContactGroupV1::decode(readable).unwrap().v, 3);
        for corrupt in [
            &b"garbage"[..],
            br##"{"v":1,"name":"","color":"#8080ff"}"##,
            br##"{"v":1,"name":" padded ","color":"#8080ff"}"##,
            br##"{"v":1,"name":"Family","color":"#8080FF"}"##,
            br##"{"v":1,"name":"Family","color":"blue"}"##,
            br##"{"v":0,"name":"Family","color":"#8080ff"}"##,
        ] {
            assert!(
                matches!(
                    ContactGroupV1::decode(corrupt),
                    Err(CryptoError::InvalidInput(_))
                ),
                "{}",
                String::from_utf8_lossy(corrupt)
            );
        }
        let long = ContactGroupV1::new("x".repeat(MAX_NAME_CHARS + 1), "#8080ff");
        assert!(long.encode().is_err());
    }
}
