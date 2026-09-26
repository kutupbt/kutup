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
}
