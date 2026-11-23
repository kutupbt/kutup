//! The account's own settings for one calendar it belongs to: one record of
//! the `calendarSettings` scope (docs/plans/account-records.md, W3), sealed
//! under the master key ([`AccountRecordPurpose::CalendarSettings`]) and
//! filed under `hashed_object` of the calendar id, so the server can't tie
//! it to its calendar. It holds what only the member's own devices read:
//! the calendar's colour and whether it is shown.
//!
//! The member's default reminders stay on the server's member row: the
//! server computes and fires the alarms (email and push) from them, as
//! Proton's server reads its calendars' notification defaults.
//!
//! The plaintext follows docs/plans/format-evolution.md: `v` first, an
//! optional `min`, and the fields a newer writer added kept and written back.
//!
//! [`AccountRecordPurpose::CalendarSettings`]: crate::account_record::AccountRecordPurpose::CalendarSettings

use serde::{Deserialize, Serialize};

use crate::contact_group::is_hex_colour;
use crate::error::{CryptoError, Result};
use crate::format::{self, Extra};

/// The newest version this reader knows.
pub const CALENDAR_SETTINGS_VERSION: u16 = 1;
/// The longest plaintext: the record pads every one to one more byte.
pub const MAX_PLAIN_LEN: usize = 511;

const WHAT: &str = "calendar settings";
/// One roster tag's length, in base64url characters (6 bytes).
pub const ROSTER_TAG_CHARS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarSettingsV1 {
    pub v: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u16>,
    /// `#rrggbb`, lowercase.
    pub color: String,
    /// The calendar's events are shown.
    pub display: bool,
    /// The owner's roster (docs/plans/calendar-e3.md, "Roster"): everyone it
    /// gave the calendar's key to, each as a keyed tag (the first 6 bytes of
    /// `hashed_object` of the calendar id and the account id, base64url, 8
    /// characters), concatenated. Kept where the server can't change it, so
    /// a key change goes unasked only to people on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "Extra::is_empty")]
    pub extra: Extra,
}

impl CalendarSettingsV1 {
    pub fn new(color: impl Into<String>, display: bool) -> Self {
        Self {
            v: CALENDAR_SETTINGS_VERSION,
            min: None,
            color: color.into(),
            display,
            roster: None,
            extra: Extra::new(),
        }
    }

    fn check(&self) -> Result<()> {
        format::check_version(WHAT, self.v, self.min, CALENDAR_SETTINGS_VERSION)?;
        format::check_extra(WHAT, &self.extra)?;
        if !is_hex_colour(&self.color) {
            return Err(CryptoError::InvalidInput(format!(
                "{WHAT}: the colour is #rrggbb"
            )));
        }
        if let Some(roster) = &self.roster {
            if roster.len() % ROSTER_TAG_CHARS != 0
                || !roster
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(CryptoError::InvalidInput(format!(
                    "{WHAT}: the roster is {ROSTER_TAG_CHARS}-character base64url tags"
                )));
            }
        }
        Ok(())
    }

    /// Reads an opened record. A newer version than this reader's is
    /// `NewerThanMe`, never corrupt.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        format::check_json_version(WHAT, bytes, CALENDAR_SETTINGS_VERSION)?;
        let settings: Self = serde_json::from_slice(bytes)
            .map_err(|_| CryptoError::InvalidInput(format!("{WHAT} do not decode")))?;
        settings.check()?;
        Ok(settings)
    }

    /// The plaintext to seal, unknown fields kept.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| CryptoError::InvalidInput(format!("{WHAT} do not encode")))?;
        if bytes.len() > MAX_PLAIN_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "{WHAT} are longer than {MAX_PLAIN_LEN} bytes"
            )));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_and_keep_a_newer_writers_fields() {
        let settings = CalendarSettingsV1::new("#1da583", false);
        let bytes = settings.encode().unwrap();
        assert!(bytes.starts_with(br#"{"v":1,"#));
        assert_eq!(CalendarSettingsV1::decode(&bytes).unwrap(), settings);
        let later = br##"{"v":1,"color":"#1da583","display":true,"order":3}"##;
        let read = CalendarSettingsV1::decode(later).unwrap();
        let hidden = CalendarSettingsV1 {
            display: false,
            ..read
        };
        assert!(String::from_utf8(hidden.encode().unwrap())
            .unwrap()
            .contains(r#""order":3"#));
    }

    #[test]
    fn a_roster_is_whole_tags_and_round_trips() {
        let mut settings = CalendarSettingsV1::new("#1da583", true);
        settings.roster = Some("AAAAAAAA_-zz0099".into());
        let bytes = settings.encode().unwrap();
        assert_eq!(CalendarSettingsV1::decode(&bytes).unwrap(), settings);
        for bad in ["AAAAAAA", "AAAAAAA+", "AAAA AAA"] {
            settings.roster = Some(bad.into());
            assert!(settings.encode().is_err(), "{bad}");
        }
    }

    #[test]
    fn newer_and_corrupt_settings_are_told_apart() {
        let newer = br##"{"v":2,"colour":{"light":"#1da583"},"display":true}"##;
        assert!(matches!(
            CalendarSettingsV1::decode(newer),
            Err(CryptoError::NewerThanMe(_))
        ));
        for corrupt in [
            &b"[]"[..],
            br##"{"v":1,"color":"#1DA583","display":true}"##,
            br##"{"v":1,"color":"#1da583"}"##,
            br##"{"v":1,"min":1,"color":"#1da583","display":true}"##,
        ] {
            assert!(
                matches!(
                    CalendarSettingsV1::decode(corrupt),
                    Err(CryptoError::InvalidInput(_))
                ),
                "{}",
                String::from_utf8_lossy(corrupt)
            );
        }
    }
}
