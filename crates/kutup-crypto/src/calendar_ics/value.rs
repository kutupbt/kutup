//! Values as others write them, read leniently: text with RFC 5545
//! escaping, dates and date-times with the repairs of Proton's
//! `reformatDateTimes` (ISO spellings, a missing `VALUE=DATE`, missing or
//! extra digits, fractions of a second, a repeated `Z`), and durations.

use jiff::civil;

use super::reader::Property;

/// A date or date-time value, before any time zone is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Moment {
    /// `VALUE=DATE`, or eight digits alone.
    Date(civil::Date),
    /// A wall-clock time: floating, or in the property's `TZID`.
    Local(civil::DateTime),
    /// A UTC time (`Z`, or an offset some writers add, applied).
    Utc(civil::DateTime),
}

impl Moment {
    pub fn date(&self) -> civil::Date {
        match self {
            Moment::Date(date) => *date,
            Moment::Local(time) | Moment::Utc(time) => time.date(),
        }
    }
}

/// Reads a date or date-time value.
#[inline(never)]
pub fn moment(value: &str, value_type: Option<&str>) -> Option<Moment> {
    let mut text = value.trim().to_owned();
    // A UTC offset some writers add (`+03:00`, `-0500`), not RFC 5545's.
    let mut offset_seconds = None;
    if let Some(t) = text.find(['T', 't']) {
        let time = &text[t + 1..];
        if let Some(sign_at) = time.rfind(['+', '-']) {
            let digits: String = time[sign_at + 1..].chars().filter(|c| *c != ':').collect();
            if digits.len() == 4 && digits.bytes().all(|b| b.is_ascii_digit()) {
                let hours: i64 = digits[..2].parse().ok()?;
                let minutes: i64 = digits[2..].parse().ok()?;
                let sign = if time.as_bytes()[sign_at] == b'-' {
                    -1
                } else {
                    1
                };
                offset_seconds = Some(sign * (hours * 3600 + minutes * 60));
                text.truncate(t + 1 + sign_at);
            }
        }
    }
    let trimmed = text.trim_end_matches(['Z', 'z']);
    let utc = trimmed.len() != text.len() || offset_seconds.is_some();
    let (date, time) = match trimmed.find(['T', 't']) {
        Some(t) => (&trimmed[..t], Some(&trimmed[t + 1..])),
        None => (trimmed, None),
    };
    let date: String = date.chars().filter(|c| *c != '-').collect();
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let day = civil::Date::new(
        date[..4].parse().ok()?,
        date[4..6].parse().ok()?,
        date[6..].parse().ok()?,
    )
    .ok()?;
    let time = match time {
        None => return Some(Moment::Date(day)),
        // A date written with a time it shouldn't have: the date.
        Some(_) if value_type.is_some_and(|t| t.eq_ignore_ascii_case("DATE")) => {
            return Some(Moment::Date(day))
        }
        Some(time) => time,
    };
    // Fractions of a second go; missing digits are zeros; extra ones go.
    let whole = time.split(['.', ',']).next().unwrap_or("");
    let mut digits: String = whole.chars().filter(|c| *c != ':').collect();
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.truncate(6);
    while digits.len() < 6 {
        digits.push('0');
    }
    let at = civil::Time::new(
        digits[..2].parse().ok()?,
        digits[2..4].parse().ok()?,
        // A leap second is the minute's last.
        digits[4..].parse::<i8>().ok()?.min(59),
        0,
    )
    .ok()?;
    let mut local = day.to_datetime(at);
    if let Some(offset) = offset_seconds {
        local = local
            .checked_sub(jiff::SignedDuration::from_secs(offset))
            .ok()?;
    }
    Some(if utc {
        Moment::Utc(local)
    } else {
        Moment::Local(local)
    })
}

/// Every value of a property that may list several (`EXDATE`, `RDATE`).
pub fn moments(prop: &Property) -> Vec<Option<Moment>> {
    prop.value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| moment(part, prop.param("VALUE")))
        .collect()
}

/// A text value, unescaped (RFC 5545 §3.3.11). An escape the RFC doesn't
/// name is kept as written.
#[inline(never)]
pub fn text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.peek() {
            Some('\\') | Some(';') | Some(',') | Some(':') | Some('"') => {
                out.push(chars.next().expect("peeked"));
            }
            Some('n') | Some('N') => {
                chars.next();
                out.push('\n');
            }
            _ => out.push('\\'),
        }
    }
    out
}

/// A duration (`-PT15M`, `P1DT2H`, `P2W`) in seconds, negative before.
#[inline(never)]
pub fn duration(value: &str) -> Option<i64> {
    let value = value.trim();
    let (negative, rest) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value.strip_prefix('+').unwrap_or(value)),
    };
    let rest = rest.strip_prefix(['P', 'p'])?;
    let mut seconds: i64 = 0;
    let mut number = String::new();
    let mut in_time = false;
    let mut units = 0;
    for ch in rest.chars() {
        let ch = ch.to_ascii_uppercase();
        if ch.is_ascii_digit() {
            number.push(ch);
            continue;
        }
        if ch == 'T' {
            if in_time || !number.is_empty() {
                return None;
            }
            in_time = true;
            continue;
        }
        if number.is_empty() || number.len() > 9 {
            return None;
        }
        let n: i64 = number.parse().ok()?;
        number.clear();
        let scale = match (ch, in_time) {
            ('W', false) => 7 * 86_400,
            ('D', false) => 86_400,
            ('H', true) => 3600,
            ('M', true) => 60,
            ('S', true) => 1,
            _ => return None,
        };
        seconds = seconds.checked_add(n.checked_mul(scale)?)?;
        units += 1;
    }
    if !number.is_empty() || units == 0 {
        return None;
    }
    Some(if negative { -seconds } else { seconds })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(text: &str) -> civil::DateTime {
        text.parse().unwrap()
    }

    #[test]
    fn dates_and_times_in_others_spellings() {
        assert_eq!(
            moment("20261022", None),
            Some(Moment::Date(civil::date(2026, 10, 22)))
        );
        assert_eq!(
            moment("20261022T093000", None),
            Some(Moment::Local(local("2026-10-22T09:30:00")))
        );
        // ISO, fractions, a short time, a double Z, an offset.
        assert_eq!(
            moment(" 2026-10-22T09:30:00.123ZZ ", None),
            Some(Moment::Utc(local("2026-10-22T09:30:00")))
        );
        assert_eq!(
            moment("20261022T0930", None),
            Some(Moment::Local(local("2026-10-22T09:30:00")))
        );
        assert_eq!(
            moment("2026-10-22T09:30:00+03:00", None),
            Some(Moment::Utc(local("2026-10-22T06:30:00")))
        );
        assert_eq!(
            moment("20261022T093000", Some("DATE")),
            Some(Moment::Date(civil::date(2026, 10, 22)))
        );
        assert_eq!(moment("2026-13-01", None), None);
        assert_eq!(moment("tomorrow", None), None);
        assert_eq!(moment("20261022T09ab00", None), None);
    }

    #[test]
    fn text_unescapes_leniently() {
        assert_eq!(text(r"a\, b\; c\\d\nnext\Nlast"), "a, b; c\\d\nnext\nlast");
        assert_eq!(text(r"C:\Users"), r"C:\Users");
    }

    #[test]
    fn durations() {
        assert_eq!(duration("-PT15M"), Some(-900));
        assert_eq!(duration("P1DT2H"), Some(93_600));
        assert_eq!(duration("P2W"), Some(1_209_600));
        assert_eq!(duration("PT0S"), Some(0));
        assert_eq!(duration("P"), None);
        assert_eq!(duration("PT"), None);
        assert_eq!(duration("P1H"), None);
        assert_eq!(duration("15M"), None);
    }
}
