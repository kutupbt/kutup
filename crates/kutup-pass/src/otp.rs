//! One-time codes (docs/plans/pass-gaps-3.md, A2), read as KeePassXC reads
//! them (`src/core/Totp.cpp`): the `otp` field's `otpauth://` URI (with
//! `encoder=steam` for Steam Guard), KeePassXC's older `TOTP Seed` and
//! `TOTP Settings` fields (`30;6`, `30;S`), and KeePass 2's `TimeOtp-*`
//! fields. Steam codes are five characters of Steam's alphabet from the
//! same HMAC-SHA1 truncation.

use keepass::db::Entry;
// Adapter (docs/plans/crypto-primitives.md, "Lint exceptions"): RFC 6238
// one-time codes are HMAC-SHA-1, -256 or -512 by definition.
#[allow(clippy::disallowed_types)]
use totp_lite::{totp_custom, Sha1, Sha256, Sha512};

/// Steam Guard's alphabet (KeePassXC's `STEAM_CHARS`).
const STEAM_CHARS: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";
const STEAM_DIGITS: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// How an entry makes its codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpSettings {
    pub secret: Vec<u8>,
    pub period: u64,
    pub digits: u32,
    pub algorithm: Algorithm,
    pub steam: bool,
}

fn base32(secret: &str) -> Option<Vec<u8>> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)?;
    (!bytes.is_empty()).then_some(bytes)
}

fn algorithm(name: &str) -> Option<Algorithm> {
    match name.to_ascii_uppercase().replace(['-', '_'], "").as_str() {
        "SHA1" | "HMACSHA1" => Some(Algorithm::Sha1),
        "SHA256" | "HMACSHA256" => Some(Algorithm::Sha256),
        "SHA512" | "HMACSHA512" => Some(Algorithm::Sha512),
        _ => None,
    }
}

fn from_uri(uri: &str) -> Option<OtpSettings> {
    let url = url::Url::parse(uri.trim()).ok()?;
    if url.scheme() != "otpauth" || url.host_str() != Some("totp") {
        return None;
    }
    let mut settings = OtpSettings {
        secret: Vec::new(),
        period: 30,
        digits: 6,
        algorithm: Algorithm::Sha1,
        steam: false,
    };
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => settings.secret = base32(&value)?,
            "period" => settings.period = value.parse().ok()?,
            "digits" => settings.digits = value.parse().ok()?,
            "algorithm" => settings.algorithm = algorithm(&value)?,
            "encoder" => settings.steam = value.eq_ignore_ascii_case("steam"),
            _ => {}
        }
    }
    if settings.steam {
        settings.digits = STEAM_DIGITS;
        settings.algorithm = Algorithm::Sha1;
    }
    (!settings.secret.is_empty()).then_some(settings)
}

/// The entry's code settings, from the first form it has.
pub fn settings(entry: &Entry) -> Option<OtpSettings> {
    let get = |key: &str| entry.fields.get(key).map(|v| v.get().as_str());
    let found = if let Some(uri) = get("otp").filter(|v| !v.trim().is_empty()) {
        from_uri(uri)
    } else if let Some(seed) = get("TOTP Seed") {
        // KeePassXC's older fields: "period;digits", digits "S" for Steam.
        let mut parts = get("TOTP Settings").unwrap_or("30;6").split(';');
        let period = parts
            .next()
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or(30);
        let digits = parts.next().map(str::trim).unwrap_or("6");
        let steam = digits.eq_ignore_ascii_case("S");
        Some(OtpSettings {
            secret: base32(seed)?,
            period,
            digits: if steam {
                STEAM_DIGITS
            } else {
                digits.parse().ok()?
            },
            algorithm: Algorithm::Sha1,
            steam,
        })
    } else if let Some(secret) = get("TimeOtp-Secret-Base32") {
        // KeePass 2's own fields.
        Some(OtpSettings {
            secret: base32(secret)?,
            period: get("TimeOtp-Period")
                .and_then(|p| p.parse().ok())
                .unwrap_or(30),
            digits: get("TimeOtp-Length")
                .and_then(|d| d.parse().ok())
                .unwrap_or(6),
            algorithm: get("TimeOtp-Algorithm")
                .and_then(algorithm)
                .unwrap_or(Algorithm::Sha1),
            steam: false,
        })
    } else {
        None
    };
    found.filter(|s| (1..=3600).contains(&s.period) && (s.steam || (6..=10).contains(&s.digits)))
}

/// The code at `unix_seconds`.
// Adapter: the standard's own HMACs (RFC 6238).
#[allow(clippy::disallowed_types)]
pub fn code(settings: &OtpSettings, unix_seconds: u64) -> String {
    let (period, secret) = (settings.period, settings.secret.as_slice());
    if settings.steam {
        // Ten decimal digits hold the whole 31-bit truncation.
        let mut value: u64 = totp_custom::<Sha1>(period, 10, secret, unix_seconds)
            .parse()
            .unwrap_or_default();
        let mut out = String::new();
        for _ in 0..STEAM_DIGITS {
            out.push(char::from(
                STEAM_CHARS[(value % STEAM_CHARS.len() as u64) as usize],
            ));
            value /= STEAM_CHARS.len() as u64;
        }
        return out;
    }
    match settings.algorithm {
        Algorithm::Sha1 => totp_custom::<Sha1>(period, settings.digits, secret, unix_seconds),
        Algorithm::Sha256 => totp_custom::<Sha256>(period, settings.digits, secret, unix_seconds),
        Algorithm::Sha512 => totp_custom::<Sha512>(period, settings.digits, secret, unix_seconds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::Value;

    fn entry(fields: &[(&str, &str)]) -> Entry {
        let mut db = keepass::Database::new();
        let id = db.root_mut().add_entry().id();
        let entry = db.entries.get_mut(&id).unwrap();
        for (k, v) in fields {
            entry
                .fields
                .insert((*k).into(), Value::protected((*v).to_string()));
        }
        entry.clone()
    }

    #[test]
    fn steam_codes_match_keepassxcs_vectors() {
        // tests/TestTotp.cpp, testSteamTotp: from the Steam app itself.
        let uri = "otpauth://totp/test:test@example.com?secret=63BEDWCQZKTQWPESARIERL5DTTQFCJTK&issuer=Valve&algorithm=SHA1&digits=5&period=30&encoder=steam";
        for e in [
            entry(&[("otp", uri)]),
            entry(&[
                ("TOTP Seed", "63BEDWCQZKTQWPESARIERL5DTTQFCJTK"),
                ("TOTP Settings", "30;S"),
            ]),
        ] {
            let s = settings(&e).unwrap();
            assert!(s.steam);
            assert_eq!(code(&s, 1_511_200_518), "FR8RV");
            assert_eq!(code(&s, 1_511_200_714), "9P3VP");
        }
    }

    #[test]
    fn rfc_6238_codes_for_each_algorithm() {
        // RFC 6238 appendix B, eight digits, at 59 s.
        let cases = [
            ("SHA1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "94287082"),
            ("SHA256", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA", "46119246"),
            (
                "SHA512",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
                "90693936",
            ),
        ];
        for (alg, secret, expected) in cases {
            let uri = format!("otpauth://totp/x?secret={secret}&digits=8&algorithm={alg}");
            let s = settings(&entry(&[("otp", &uri)])).unwrap();
            assert_eq!(code(&s, 59), expected, "{alg}");
        }
        // KeePass 2's own fields.
        let s = settings(&entry(&[
            ("TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            ("TimeOtp-Length", "8"),
        ]))
        .unwrap();
        assert_eq!(code(&s, 59), "94287082");
    }

    #[test]
    fn unreadable_settings_give_no_code() {
        for fields in [
            vec![("otp", "otpauth://hotp/x?secret=GEZDGNBV&counter=1")],
            vec![("otp", "otpauth://totp/x?secret=!!!")],
            vec![("otp", "otpauth://totp/x?secret=GEZDGNBV&digits=4")],
            vec![("otp", "not a uri")],
            vec![("TOTP Seed", "GEZDGNBV"), ("TOTP Settings", "30;x")],
        ] {
            assert_eq!(settings(&entry(&fields)), None, "{fields:?}");
        }
    }
}
