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

/// Seals `family` for the account's `table` row `row` (column `client`). None
/// when it says nothing, or before the server's key list is installed.
pub async fn seal_in(
    conn: &mut sqlx::PgConnection,
    user_id: uuid::Uuid,
    table: &str,
    row: uuid::Uuid,
    family: &ClientFamily,
) -> crate::error::AppResult<Option<Vec<u8>>> {
    let Some(keys) = crate::account_data::installed() else {
        return Ok(None);
    };
    if family == &ClientFamily::default() {
        return Ok(None);
    }
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

/// Opens a family [`seal_in`] sealed; one that does not open (its account's
/// key gone, or altered) reads as unknown.
pub async fn open_in(
    conn: &mut sqlx::PgConnection,
    user_id: uuid::Uuid,
    table: &str,
    row: uuid::Uuid,
    sealed: Option<&[u8]>,
) -> crate::error::AppResult<ClientFamily> {
    let (Some(sealed), Some(keys)) = (sealed, crate::account_data::installed()) else {
        return Ok(ClientFamily::default());
    };
    let key = crate::account_data::key_in(conn, keys, user_id).await?;
    let row = row.to_string();
    let opened = key.open(
        &kutup_crypto::server_data::Field {
            table,
            column: "client",
            row: &row,
            account_id: user_id.as_bytes(),
        },
        sealed,
    );
    Ok(opened
        .ok()
        .and_then(|json| serde_json::from_slice(&json).ok())
        .unwrap_or_default())
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
