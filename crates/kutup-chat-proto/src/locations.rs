//! A place sent once (docs/plans/maps.md): coordinates and an optional
//! label, end-to-end encrypted like any message. Each viewer's own map
//! settings decide whether it is drawn on a map or shown as coordinates.

use serde::{Deserialize, Serialize};

use crate::content::{kind, ChatContent};

pub const MAX_LOCATION_LABEL_CHARS: usize = 100;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocationBody {
    /// Degrees, −90 to 90.
    pub lat: f64,
    /// Degrees, −180 to 180.
    pub lon: f64,
    /// What the place is ("Home", "Kadıköy pier"), if the sender named it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl LocationBody {
    pub fn validate(&self) -> Result<(), String> {
        if !self.lat.is_finite()
            || !self.lon.is_finite()
            || !(-90.0..=90.0).contains(&self.lat)
            || !(-180.0..=180.0).contains(&self.lon)
        {
            return Err(
                "a Chat location needs a latitude of -90 to 90 and a longitude of -180 to 180"
                    .into(),
            );
        }
        if let Some(label) = &self.label {
            let trimmed = label.trim();
            if trimmed.is_empty()
                || trimmed != label
                || label.chars().count() > MAX_LOCATION_LABEL_CHARS
                || label.chars().any(char::is_control)
            {
                return Err("a Chat location label is 1 to 100 characters on one line".into());
            }
        }
        Ok(())
    }
}

impl ChatContent {
    pub fn location_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: &LocationBody,
    ) -> Result<Self, String> {
        body.validate()?;
        Self::structured(kind::LOCATION, message_id, sent_at, seq, body)
    }

    pub fn as_location(&self) -> Option<LocationBody> {
        let body: LocationBody = self.structured_body(kind::LOCATION)?;
        body.validate().ok()?;
        Some(body)
    }

    /// For a location: whether its body is valid; `None` for other kinds.
    /// Receivers refuse a location that does not validate.
    pub fn location_content_is_valid(&self) -> Option<bool> {
        (self.kind == kind::LOCATION).then(|| self.as_location().is_some())
    }
}

/// A live location being shared (docs/plans/maps.md "Live location"): the
/// short-lived stream on the sharer's server that holds only the latest
/// position, and the secrets to read it. Generation 1 starts the share and
/// shows in the chat; each later generation is a new stream and key (every
/// hour, and at once when someone leaves), folded into the same share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveLocationBody {
    /// Stable across generations: which share this is.
    pub share_id: String,
    pub generation: u32,
    /// The sharer's server, which holds the stream.
    pub server: String,
    /// 16 random bytes, lowercase hex.
    pub stream_id: String,
    /// The stream's 32-byte XChaCha20-Poly1305 key, standard base64.
    pub key: String,
    /// 32 random bytes the server asks for before handing out the update.
    pub read_capability: String,
    /// When the share ends, Unix milliseconds.
    pub until_ms: u64,
}

/// The sharer ended a live location early.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveLocationStopBody {
    pub share_id: String,
}

/// A share lasts at most 8 hours.
pub const MAX_LIVE_LOCATION_MS: u64 = 8 * 3600 * 1000;

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

fn canonical_b64_32(value: &str) -> bool {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    engine
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32 && engine.encode(&bytes) == value)
}

fn server_name(value: &str) -> bool {
    (3..=253).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b':')
        })
        && value.contains('.')
}

impl LiveLocationBody {
    pub fn validate(&self) -> Result<(), String> {
        if !canonical_uuid(&self.share_id)
            || self.generation == 0
            || !server_name(&self.server)
            || self.stream_id.len() != 32
            || !self
                .stream_id
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || !canonical_b64_32(&self.key)
            || !canonical_b64_32(&self.read_capability)
            || self.until_ms == 0
        {
            return Err("a Chat live location is malformed".into());
        }
        Ok(())
    }
}

impl ChatContent {
    pub fn live_location_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: &LiveLocationBody,
    ) -> Result<Self, String> {
        body.validate()?;
        Self::structured(kind::LIVE_LOCATION, message_id, sent_at, seq, body)
    }

    pub fn as_live_location(&self) -> Option<LiveLocationBody> {
        let body: LiveLocationBody = self.structured_body(kind::LIVE_LOCATION)?;
        body.validate().ok()?;
        Some(body)
    }

    pub fn live_location_stop_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: &LiveLocationStopBody,
    ) -> Result<Self, String> {
        if !canonical_uuid(&body.share_id) {
            return Err("a Chat live location stop names its share".into());
        }
        Self::structured(kind::LIVE_LOCATION_STOP, message_id, sent_at, seq, body)
    }

    pub fn as_live_location_stop(&self) -> Option<LiveLocationStopBody> {
        let body: LiveLocationStopBody = self.structured_body(kind::LIVE_LOCATION_STOP)?;
        canonical_uuid(&body.share_id).then_some(body)
    }

    /// For a structured kind (polls, places, live locations): whether its
    /// body is valid; `None` for other kinds. Every receive path refuses a
    /// structured message that does not validate.
    pub fn structured_content_is_valid(&self) -> Option<bool> {
        self.poll_content_is_valid()
            .or_else(|| self.location_content_is_valid())
            .or_else(|| match self.kind.as_str() {
                kind::LIVE_LOCATION => Some(self.as_live_location().is_some()),
                kind::LIVE_LOCATION_STOP => Some(self.as_live_location_stop().is_some()),
                _ => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0b0f6a8e-35f5-4a8e-9f5a-0a8f3c2d1e4b";
    const AT: &str = "2026-09-26T12:00:00Z";

    fn place(lat: f64, lon: f64, label: Option<&str>) -> LocationBody {
        LocationBody {
            lat,
            lon,
            label: label.map(str::to_owned),
        }
    }

    #[test]
    fn a_location_round_trips_and_is_visible() {
        let body = place(41.0082, 28.9784, Some("Kadıköy pier"));
        let content = ChatContent::location_with_id(ID, AT, 1, &body).unwrap();
        assert!(content.is_known_kind());
        assert_eq!(content.as_location(), Some(body));
        assert_eq!(content.location_content_is_valid(), Some(true));
        let bytes = serde_json::to_vec(&content).unwrap();
        let back: ChatContent = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            back.as_location().unwrap().label.as_deref(),
            Some("Kadıköy pier")
        );
        // Places can disappear like other visible messages.
        let timed = content.with_disappearing_after(3600).unwrap();
        assert_eq!(timed.disappearing_after_seconds(), Ok(Some(3600)));
        assert_eq!(
            ChatContent::text(AT, 1, "hi").location_content_is_valid(),
            None
        );
    }

    #[test]
    fn bad_places_are_refused() {
        for body in [
            place(91.0, 0.0, None),
            place(0.0, -180.5, None),
            place(f64::NAN, 0.0, None),
            place(0.0, f64::INFINITY, None),
            place(1.0, 1.0, Some("")),
            place(1.0, 1.0, Some(" padded")),
            place(1.0, 1.0, Some("two\nlines")),
            place(1.0, 1.0, Some(&"x".repeat(MAX_LOCATION_LABEL_CHARS + 1))),
        ] {
            assert!(
                ChatContent::location_with_id(ID, AT, 1, &body).is_err(),
                "{body:?}"
            );
        }
        // A tampered body fails closed on receive.
        let mut content = ChatContent::location_with_id(ID, AT, 1, &place(1.0, 1.0, None)).unwrap();
        content.body = serde_json::json!({ "lat": 1.0, "lon": 1.0, "extra": true });
        assert_eq!(content.location_content_is_valid(), Some(false));
    }

    fn live(generation: u32) -> LiveLocationBody {
        LiveLocationBody {
            share_id: ID.into(),
            generation,
            server: "kutup.example.org".into(),
            stream_id: "6465666768696a6b6c6d6e6f70717273".into(),
            key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into(),
            read_capability: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=".into(),
            until_ms: 1_790_000_000_000,
        }
    }

    #[test]
    fn a_live_location_and_its_stop_round_trip() {
        let content = ChatContent::live_location_with_id(ID, AT, 1, &live(1)).unwrap();
        assert!(content.is_known_kind());
        assert_eq!(content.as_live_location(), Some(live(1)));
        assert_eq!(content.structured_content_is_valid(), Some(true));
        assert!(content.with_disappearing_after(3600).is_ok());
        let stop = ChatContent::live_location_stop_with_id(
            "1b0f6a8e-35f5-4a8e-9f5a-0a8f3c2d1e4b",
            AT,
            2,
            &LiveLocationStopBody {
                share_id: ID.into(),
            },
        )
        .unwrap();
        assert!(stop.is_known_kind());
        assert_eq!(stop.as_live_location_stop().unwrap().share_id, ID);
        assert_eq!(stop.structured_content_is_valid(), Some(true));
        assert!(
            stop.with_disappearing_after(3600).is_err(),
            "a stop is not visible"
        );
    }

    #[test]
    fn bad_live_locations_are_refused() {
        let mut cases = Vec::new();
        for edit in [
            |b: &mut LiveLocationBody| b.generation = 0,
            |b: &mut LiveLocationBody| b.share_id = "not-a-uuid".into(),
            |b: &mut LiveLocationBody| b.server = "Example.org".into(),
            |b: &mut LiveLocationBody| b.stream_id = "6465".into(),
            |b: &mut LiveLocationBody| b.stream_id = "6465666768696A6B6C6D6E6F70717273".into(),
            |b: &mut LiveLocationBody| b.key = "AAEC".into(),
            |b: &mut LiveLocationBody| b.read_capability = String::new(),
            |b: &mut LiveLocationBody| b.until_ms = 0,
        ] {
            let mut body = live(1);
            edit(&mut body);
            cases.push(body);
        }
        for body in cases {
            assert!(
                ChatContent::live_location_with_id(ID, AT, 1, &body).is_err(),
                "{body:?}"
            );
        }
        let mut content = ChatContent::live_location_with_id(ID, AT, 1, &live(2)).unwrap();
        content.body["key"] = serde_json::json!("x");
        assert_eq!(content.structured_content_is_valid(), Some(false));
    }
}
