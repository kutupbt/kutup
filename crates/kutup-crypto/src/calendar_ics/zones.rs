//! A `TZID` as others write it, mapped to an IANA zone of the bundled
//! database, as Proton's `getSupportedTimezone` (`packages/shared/lib/date/
//! timezone.ts`): the name itself (or an alias the database has); then,
//! with a `(UTC+01:00) ` prefix or ` (GMT+01:00)` suffix taken off and
//! lower-cased without dots, Windows' and others' names
//! ([`super::zone_names`]); then an IANA name found inside it
//! (`/mozilla.org/20050126_1/Europe/Berlin`), the longest first.
//!
//! Unlike Proton, every zone the database has is kept as it is: Proton maps
//! some (`Asia/Singapore` to `Asia/Shanghai`) only because its server lacks
//! them. And the search inside a name only takes names with a `/`, so a
//! short alias (`EST`, `GB`) never matches inside an unrelated word.

use std::sync::OnceLock;

use super::zone_names::LINKS;

/// The database's names, longest first (for the search inside a name).
fn names() -> &'static [String] {
    static NAMES: OnceLock<Vec<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        let mut names: Vec<String> = jiff::tz::db()
            .available()
            .map(|name| name.as_str().to_owned())
            .collect();
        names.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        names
    })
}

/// The database's own spelling of `tzid`, any case.
fn exact(tzid: &str) -> Option<String> {
    if tzid.is_empty() || tzid.len() > 64 {
        return None;
    }
    if matches!(tzid.to_ascii_uppercase().as_str(), "Z" | "UTC" | "GMT") {
        return Some("UTC".into());
    }
    names()
        .iter()
        .find(|name| name.eq_ignore_ascii_case(tzid))
        .cloned()
}

/// The IANA zone `tzid` names, if any.
pub fn supported_time_zone(tzid: &str) -> Option<String> {
    let tzid = tzid.trim().trim_matches('"').trim();
    if tzid.is_empty() || tzid.len() > 256 {
        return None;
    }
    if let Some(found) = exact(tzid) {
        return Some(found);
    }
    let stripped = strip_offset(tzid);
    let normalized = stripped.to_lowercase().replace('.', "");
    if let Ok(at) = LINKS.binary_search_by(|(name, _)| (*name).cmp(normalized.as_str())) {
        return Some(LINKS[at].1.to_owned());
    }
    let lower = stripped.to_lowercase();
    names()
        .iter()
        .filter(|name| name.contains('/'))
        .find(|name| lower.contains(&name.to_lowercase()))
        .cloned()
}

/// `(UTC+01:00) Amsterdam, Berlin` or `Amsterdam (GMT+01:00)`: the name
/// alone (Proton's offset regex).
fn strip_offset(tzid: &str) -> &str {
    let starts_offset = |text: &str| {
        let upper = text.get(..3).map(str::to_ascii_uppercase);
        matches!(upper.as_deref(), Some("UTC" | "GMT"))
    };
    if let Some(rest) = tzid.strip_prefix('(') {
        if let Some(close) = rest.find(") ") {
            if starts_offset(rest) {
                return &rest[close + 2..];
            }
        }
    }
    if let Some(open) = tzid.find(" (") {
        let inner = &tzid[open + 2..];
        if inner.ends_with(')') && starts_offset(inner) {
            return &tzid[..open];
        }
    }
    tzid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sorted_for_the_search() {
        assert!(LINKS.windows(2).all(|pair| pair[0].0 < pair[1].0));
        // Every zone Proton maps to is in the bundled database.
        for (name, zone) in LINKS {
            assert!(
                crate::calendar_event::time_zone(zone).is_ok(),
                "{name} maps to {zone}, which the database lacks"
            );
        }
    }

    #[test]
    fn others_zone_names_map_as_protons() {
        let cases = [
            ("Europe/Istanbul", Some("Europe/Istanbul")),
            ("europe/berlin", Some("Europe/Berlin")),
            ("US/Eastern", Some("US/Eastern")),
            ("Z", Some("UTC")),
            ("W. Europe Standard Time", Some("Europe/Berlin")),
            ("Pacific Standard Time", Some("America/Los_Angeles")),
            ("Turkey Standard Time", Some("Europe/Istanbul")),
            (
                "(UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna",
                Some("Europe/Berlin"),
            ),
            ("/mozilla.org/20050126_1/Europe/Paris", Some("Europe/Paris")),
            ("\"America/New_York\"", Some("America/New_York")),
            ("Customized Time Zone", None),
            ("Mars/Olympus", None),
            ("", None),
        ];
        for (tzid, want) in cases {
            assert_eq!(supported_time_zone(tzid).as_deref(), want, "{tzid}");
        }
    }
}
