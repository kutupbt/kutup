//! Platform wall-clock boundary.
//!
//! `std::time::SystemTime::now()` panics in a browser. Keep the workaround in
//! one place so protocol code never accidentally reaches that unsupported API.

use std::time::{Duration, SystemTime};

/// Current wall time as a `SystemTime`, including on `wasm32-unknown-unknown`.
pub(crate) fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(unix_millis() as u64)
}

/// Current Unix-epoch time in milliseconds.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

/// Browsers expose wall time through JavaScript's `Date.now()`.
#[cfg(target_arch = "wasm32")]
pub(crate) fn unix_millis() -> i64 {
    js_sys::Date::now().max(0.0).min(i64::MAX as f64) as i64
}

/// `unix_millis` as RFC 3339 in UTC with millisecond precision, the form
/// every `sentAt` uses.
pub(crate) fn rfc3339(unix_millis: i64) -> String {
    let millis = unix_millis.rem_euclid(1000);
    let seconds = unix_millis.div_euclid(1000);
    let day_seconds = seconds.rem_euclid(86_400);
    // Civil date from a day count (Howard Hinnant's algorithm).
    let z = seconds.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        day_seconds / 3_600,
        day_seconds % 3_600 / 60,
        day_seconds % 60,
    )
}

#[cfg(test)]
mod tests {
    use super::rfc3339;

    #[test]
    fn formats_utc_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(1_791_072_000_123), "2026-10-04T00:00:00.123Z");
        assert_eq!(rfc3339(1_798_761_599_999), "2026-12-31T23:59:59.999Z");
    }
}
