//! What a session's browser is, as its owner sees it in the session list and
//! security log (docs/plans/server-personal-data.md, A10): a browser family,
//! its major version and an operating system, parsed once from the
//! `User-Agent` header. The raw header is never stored; the family is sealed
//! under the account's data key (`crate::account_data`).

use serde::{Deserialize, Serialize};

/// A browser and system, as few words as the session list needs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClientFamily {
    /// Firefox, Chrome, Edge, Safari, Opera, Samsung Internet, Kutup CLI; absent
    /// when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    /// The browser's major version, when it says one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_major: Option<u16>,
    /// Windows, macOS, Linux, Android, iOS, ChromeOS; absent when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
}

/// The major version after `marker` (`Firefox/` in `Firefox/128.0`).
fn major_after(user_agent: &str, marker: &str) -> Option<u16> {
    let start = user_agent.find(marker)? + marker.len();
    let digits: String = user_agent[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Parses a `User-Agent` header. Order matters: browsers built on another
/// name it too (Edge says Chrome and Safari; Chrome says Safari).
pub fn parse(user_agent: &str) -> ClientFamily {
    let ua = user_agent;
    let browser = [
        ("kutup-cli/", "Kutup CLI"),
        ("EdgA/", "Edge"),
        ("EdgiOS/", "Edge"),
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("SamsungBrowser/", "Samsung Internet"),
        ("FxiOS/", "Firefox"),
        ("Firefox/", "Firefox"),
        ("CriOS/", "Chrome"),
        ("Chrome/", "Chrome"),
    ]
    .iter()
    .find(|(marker, _)| ua.contains(marker))
    .map(|(marker, name)| (name.to_string(), major_after(ua, marker)))
    .or_else(|| {
        (ua.contains("Safari/") && ua.contains("Version/"))
            .then(|| ("Safari".to_string(), major_after(ua, "Version/")))
    });
    let os = if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iPod") {
        Some("iOS")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("CrOS") {
        Some("ChromeOS")
    } else if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Some("macOS")
    } else if ua.contains("Linux") || ua.contains("X11") {
        Some("Linux")
    } else {
        None
    };
    let (browser, browser_major) = match browser {
        Some((name, major)) => (Some(name), major),
        None => (None, None),
    };
    ClientFamily {
        browser,
        browser_major,
        os: os.map(str::to_string),
    }
}

/// "Firefox 128 on Linux": what feedback carries; None when nothing is known.
pub fn describe(family: &ClientFamily) -> Option<String> {
    let browser = family
        .browser
        .as_ref()
        .map(|name| match family.browser_major {
            Some(major) if name != "Kutup CLI" => format!("{name} {major}"),
            _ => name.clone(),
        });
    let parts: Vec<String> = browser.into_iter().chain(family.os.clone()).collect();
    (!parts.is_empty()).then(|| parts.join(" on "))
}

const BROWSER_NAMES: [&str; 7] = [
    "Kutup CLI",
    "Edge",
    "Opera",
    "Samsung Internet",
    "Firefox",
    "Chrome",
    "Safari",
];
const OS_NAMES: [&str; 6] = ["Windows", "macOS", "Linux", "Android", "iOS", "ChromeOS"];

/// What a client sent as its browser, as the family [`describe`] would name:
/// a description ("Firefox 128 on Linux") is read back, a raw User-Agent is
/// parsed; anything else is nothing. Only known names pass, so a free text
/// (or a whole User-Agent) is never kept as it came.
pub fn from_client(text: &str) -> Option<ClientFamily> {
    // A User-Agent names its products as `name/version`; a text without one
    // is a description or nothing.
    from_description(text).or_else(|| {
        Some(parse(text)).filter(|family| text.contains('/') && family != &ClientFamily::default())
    })
}

/// A [`describe`]d family read back; None for any other text.
fn from_description(text: &str) -> Option<ClientFamily> {
    let (browser_part, os) = match text.rsplit_once(" on ") {
        Some((browser, os)) => (Some(browser), Some(os)),
        None if OS_NAMES.contains(&text) => (None, Some(text)),
        None => (Some(text), None),
    };
    if os.is_some_and(|os| !OS_NAMES.contains(&os)) {
        return None;
    }
    let (browser, browser_major) = match browser_part {
        None => (None, None),
        Some(part) => {
            let (name, major) = match part.rsplit_once(' ') {
                Some((name, major)) if major.chars().all(|c| c.is_ascii_digit()) => {
                    (name, Some(major.parse::<u16>().ok()?))
                }
                _ => (part, None),
            };
            if !BROWSER_NAMES.contains(&name) {
                return None;
            }
            (Some(name.to_owned()), major)
        }
    };
    Some(ClientFamily {
        browser,
        browser_major,
        os: os.map(str::to_owned),
    })
}

/// The server key list, or None (with a warning) before it is installed:
/// only unit tests run without it.
fn keys() -> Option<&'static crate::opaque_setup::OpaqueSetupKeys> {
    let keys = crate::account_data::installed();
    if keys.is_none() {
        tracing::warn!("client family: the server key list is not installed; nothing is sealed");
    }
    keys
}

/// The account's data keys (every generation), to open its families with
/// ([`open_with`]); none when it has none (nothing of it opens) or the key
/// list is not installed. Never makes a key.
pub async fn account_key(
    conn: &mut sqlx::PgConnection,
    user_id: uuid::Uuid,
) -> crate::error::AppResult<Vec<kutup_crypto::server_data::DataKey>> {
    match keys() {
        Some(keys) => crate::account_data::load_all_in(conn, keys, user_id).await,
        None => Ok(Vec::new()),
    }
}

/// Seals `family` for the account's `table` row `row` (column `client`). None
/// when it says nothing, or before the server's key list is installed.
pub async fn seal_in(
    conn: &mut sqlx::PgConnection,
    user_id: uuid::Uuid,
    table: &str,
    row: uuid::Uuid,
    family: &ClientFamily,
) -> crate::error::AppResult<Option<Vec<u8>>> {
    if family == &ClientFamily::default() {
        return Ok(None);
    }
    let Some(keys) = keys() else {
        return Ok(None);
    };
    let json = serde_json::to_vec(family)
        .map_err(|_| crate::error::AppError::internal("encode a client family"))?;
    let key = crate::account_data::key_in(conn, keys, user_id).await?;
    let row = row.to_string();
    key.seal(
        &kutup_crypto::server_data::Field {
            table,
            column: "client",
            row: &row,
            account_id: user_id.as_bytes(),
        },
        &json,
    )
    .map(Some)
    .map_err(|_| crate::error::AppError::internal("seal a client family"))
}

/// Opens a family [`seal_in`] sealed, under the account's key of the
/// generation it names (`keys`: [`account_key`], one load for a whole list).
/// One that does not open (its account's key gone, or altered) reads as
/// unknown.
pub fn open_with(
    keys: &[kutup_crypto::server_data::DataKey],
    user_id: uuid::Uuid,
    table: &str,
    row: uuid::Uuid,
    sealed: Option<&[u8]>,
) -> ClientFamily {
    let Some(sealed) = sealed else {
        return ClientFamily::default();
    };
    let generation = kutup_crypto::server_data::sealed_generation(sealed).ok();
    let Some(key) = keys.iter().find(|key| Some(key.generation()) == generation) else {
        return ClientFamily::default();
    };
    let row = row.to_string();
    key.open(
        &kutup_crypto::server_data::Field {
            table,
            column: "client",
            row: &row,
            account_id: user_id.as_bytes(),
        },
        sealed,
    )
    .ok()
    .and_then(|json| serde_json::from_slice(&json).ok())
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn family(browser: &str, major: u16, os: &str) -> ClientFamily {
        ClientFamily {
            browser: Some(browser.into()),
            browser_major: Some(major),
            os: Some(os.into()),
        }
    }

    #[test]
    fn the_common_browsers_are_named_with_their_major_version() {
        for (ua, expected) in [
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                family("Firefox", 128, "Linux"),
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                family("Chrome", 131, "Windows"),
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86",
                family("Edge", 131, "Windows"),
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
                family("Safari", 18, "macOS"),
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
                family("Safari", 18, "iOS"),
            ),
            (
                "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
                family("Samsung Internet", 26, "Android"),
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0",
                family("Opera", 115, "Linux"),
            ),
            (
                "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                family("Chrome", 131, "ChromeOS"),
            ),
        ] {
            assert_eq!(parse(ua), expected, "{ua}");
        }
    }

    /// The vectors the browser's parser checks too
    /// (frontend/packages/session/src/userAgent.ts).
    #[test]
    fn the_shared_vectors_parse_as_in_the_browser() {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Vector {
            ua: String,
            browser: Option<String>,
            browser_major: Option<u16>,
            os: Option<String>,
        }
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../frontend/packages/session/src/userAgent.vectors.json"
        );
        let vectors: Vec<Vector> =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(vectors.len() >= 10);
        for v in vectors {
            assert_eq!(
                parse(&v.ua),
                ClientFamily {
                    browser: v.browser,
                    browser_major: v.browser_major,
                    os: v.os,
                },
                "{}",
                v.ua
            );
        }
    }

    #[test]
    fn a_clients_text_is_kept_only_as_a_known_family() {
        let firefox = family("Firefox", 128, "Linux");
        assert_eq!(describe(&firefox).as_deref(), Some("Firefox 128 on Linux"));
        assert_eq!(from_client("Firefox 128 on Linux"), Some(firefox.clone()));
        assert_eq!(
            from_client("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"),
            Some(firefox)
        );
        assert_eq!(
            from_client("Samsung Internet on Android"),
            Some(ClientFamily {
                browser: Some("Samsung Internet".into()),
                browser_major: None,
                os: Some("Android".into()),
            })
        );
        assert_eq!(
            from_client("macOS").and_then(|f| describe(&f)).as_deref(),
            Some("macOS")
        );
        for refused in [
            "my secret note",
            "Firefox 128 on Plan9",
            "NetSurf 3 on Linux",
            "Firefox 99999999 on Linux",
            "",
        ] {
            assert_eq!(from_client(refused), None, "{refused}");
        }
    }

    #[test]
    fn the_cli_and_unknown_clients_say_what_they_can() {
        assert_eq!(
            parse("kutup-cli/0.0.7"),
            ClientFamily {
                browser: Some("Kutup CLI".into()),
                browser_major: Some(0),
                os: None
            }
        );
        assert_eq!(parse("curl/8.5.0"), ClientFamily::default());
        assert_eq!(parse(""), ClientFamily::default());
    }
}
