//! Human-readable formatting helpers — mirror `whoami.go` / `session.go`.

/// Formats a byte count like Go's `formatBytes` (e.g. `1.5 MB`, `12 B`).
pub fn format_bytes(b: i64) -> String {
    const UNIT: i64 = 1024;
    if b < UNIT {
        return format!("{b} B");
    }
    let (mut div, mut exp) = (UNIT, 0usize);
    let mut n = b / UNIT;
    while n >= UNIT {
        div *= UNIT;
        exp += 1;
        n /= UNIT;
    }
    let suffix = b"KMGTPE"[exp] as char;
    format!("{:.1} {}B", b as f64 / div as f64, suffix)
}

/// Formats an RFC3339 timestamp as `YYYY-MM-DD HH:MM`, mirroring Go's
/// `formatTime`. Falls back to the raw string if the shape is unexpected
/// (matching the Go behavior of returning the input on parse failure).
pub fn format_time(ts: &str) -> String {
    let bytes = ts.as_bytes();
    if ts.len() >= 16 && bytes[10] == b'T' {
        let date = &ts[..10];
        let time = &ts[11..16]; // HH:MM
        if date.as_bytes()[4] == b'-' && time.as_bytes()[2] == b':' {
            return format!("{date} {time}");
        }
    }
    ts.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        assert_eq!(format_bytes(12), "12 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn time() {
        assert_eq!(format_time("2026-06-06T12:34:56Z"), "2026-06-06 12:34");
        assert_eq!(format_time("2026-06-06T12:34:56+02:00"), "2026-06-06 12:34");
        assert_eq!(format_time("not-a-time"), "not-a-time");
    }
}
