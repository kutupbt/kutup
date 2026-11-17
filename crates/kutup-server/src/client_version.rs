//! Client versions and "client too old" (docs/plans/api-surface.md §1).
//!
//! Every Kutup client says what it is and which version in `X-Kutup-Client`
//! (`<clientType>/<version>`: `web-drive/2026.1120.0`, `cli/0.0.14`); a
//! WebSocket upgrade, which a browser can't give headers, says it in
//! `?client=`. A client older than the minimum for its type gets `426` with
//! the code `clientTooOld`, which every client latches. The minimum is the
//! higher of the floor compiled in here ([`MIN_CLIENT_VERSIONS`], raised by a
//! developer in the commit that stops the server accepting what older clients
//! do) and the site setting `server.min_client_version.<type>`, which an
//! administrator may raise.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sqlx::PgPool;

use crate::error::AppError;
use crate::sessions::ClientType;
use crate::AppState;

/// This build's release version: CalVer in semver shape, `YYYY.MDD.N` (the
/// month without a leading zero, as semver wants: `2026.1120.0`,
/// `2027.105.2`), stamped by `scripts/publish-images.sh` through
/// `KUTUP_RELEASE`. A build without it is `0.0.0-dev`.
pub const RELEASE: &str = match option_env!("KUTUP_RELEASE") {
    Some(release) if !release.is_empty() => release,
    _ => "0.0.0-dev",
};

/// The API versions this server serves under `/api/v{n}/`.
pub const API_VERSIONS: &[u32] = &[1];

/// The header every Kutup client sends, and the one a refusal names the
/// minimum in.
pub const CLIENT_HEADER: &str = "x-kutup-client";
pub const MIN_CLIENT_HEADER: &str = "x-kutup-min-client";

/// The floor per client type: empty until a change leaves an older client
/// unable to work with this server.
pub const MIN_CLIENT_VERSIONS: &[(ClientType, &str)] = &[];

/// The site setting holding an administrator's minimum for `client`.
pub fn setting_key(client: ClientType) -> String {
    format!("server.min_client_version.{}", client.as_str())
}

/// A semver-shaped version: `major.minor.patch`, an optional `-pre` part
/// (which sorts before the release it precedes) and no build metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    numbers: [u64; 3],
    pre: Option<String>,
}

impl Version {
    pub const ZERO: Version = Version {
        numbers: [0, 0, 0],
        pre: None,
    };

    pub fn parse(value: &str) -> Option<Version> {
        let (core, pre) = match value.split_once('-') {
            Some((core, pre)) if !pre.is_empty() => (core, Some(pre.to_owned())),
            Some(_) => return None,
            None => (value, None),
        };
        let mut numbers = [0u64; 3];
        let mut parts = core.split('.');
        for slot in &mut numbers {
            let part = parts.next()?;
            if part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return None;
            }
            *slot = part.parse().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        Some(Version { numbers, pre })
    }

    /// A developer's build (`-dev`): never too old, so a local web build
    /// works against any server.
    pub fn is_dev(&self) -> bool {
        self.pre.as_deref() == Some("dev")
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.numbers
            .cmp(&other.numbers)
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => a.cmp(b),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [a, b, c] = self.numbers;
        write!(f, "{a}.{b}.{c}")?;
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        Ok(())
    }
}

/// What a client said it is: its type, and its version (`0.0.0` when it
/// named none, which only a minimum makes too old).
pub fn parse_client(value: &str) -> Option<(ClientType, Version)> {
    let (kind, version) = match value.split_once('/') {
        Some((kind, version)) => (kind, Version::parse(version)?),
        None => (value, Version::ZERO),
    };
    Some((ClientType::parse(kind)?, version))
}

/// The minimums in force: the compiled floor raised by the site settings.
/// Read at startup and after an administrator changes one, so the check on
/// every request needs no query.
#[derive(Clone, Default)]
pub struct ClientMinimums(Arc<RwLock<BTreeMap<&'static str, Version>>>);

impl ClientMinimums {
    pub async fn load(pool: &PgPool) -> Result<ClientMinimums, sqlx::Error> {
        let minimums = ClientMinimums::default();
        minimums.reload(pool).await?;
        Ok(minimums)
    }

    pub async fn reload(&self, pool: &PgPool) -> Result<(), sqlx::Error> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT key, value FROM site_settings WHERE key LIKE 'server.min_client_version.%'",
        )
        .fetch_all(pool)
        .await?;
        let mut next = floors();
        for (key, value) in rows {
            let Some(kind) = key.strip_prefix("server.min_client_version.") else {
                continue;
            };
            let (Some(client), Some(version)) = (ClientType::parse(kind), Version::parse(&value))
            else {
                continue;
            };
            let slot = next.entry(client.as_str()).or_insert(Version::ZERO);
            if version > *slot {
                *slot = version;
            }
        }
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = next;
        Ok(())
    }

    pub fn get(&self, client: ClientType) -> Option<Version> {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(client.as_str())
            .cloned()
    }

    /// Every type with a minimum, for `GET /api/health`.
    pub fn snapshot(&self) -> BTreeMap<String, String> {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(kind, version)| (kind.to_string(), version.to_string()))
            .collect()
    }
}

/// The compiled floor as a map.
pub fn floors() -> BTreeMap<&'static str, Version> {
    MIN_CLIENT_VERSIONS
        .iter()
        .map(|(client, version)| {
            (
                client.as_str(),
                Version::parse(version).expect("MIN_CLIENT_VERSIONS holds valid versions"),
            )
        })
        .collect()
}

/// The lowest version an administrator may set for `client`.
pub fn floor(client: ClientType) -> Option<Version> {
    floors().remove(client.as_str())
}

/// `426 clientTooOld`, naming the minimum.
pub fn too_old(client: ClientType, minimum: &Version) -> Response {
    let mut response = AppError::new(StatusCode::UPGRADE_REQUIRED, "client too old")
        .with_details(serde_json::json!({
            "code": "clientTooOld",
            "clientType": client.as_str(),
            "minimum": minimum.to_string(),
        }))
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&format!("{}/{minimum}", client.as_str())) {
        response.headers_mut().insert(MIN_CLIENT_HEADER, value);
    }
    response
}

/// The client a request names: the header, else `?client=` (WebSockets).
fn named_client(req: &Request) -> Option<String> {
    if let Some(value) = req
        .headers()
        .get(CLIENT_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        return Some(value.to_owned());
    }
    let query = req.uri().query()?;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "client")
        .map(|(_, value)| value.into_owned())
}

/// Paths a client of any version may call: how it learns the minimums.
fn exempt(path: &str) -> bool {
    path == "/api/health" || path.starts_with("/api/health/") || path == "/api/csp-report"
}

/// Refuses an `/api/` request from a client older than its type's minimum.
/// A request that names no client (curl, an `<img>`, a crawler) or a type
/// this server doesn't know is not checked here.
pub async fn client_version_gate(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path();
    if !path.starts_with("/api/") || path.starts_with("/api/fed/") || exempt(path) {
        return next.run(req).await;
    }
    if let Some((client, version)) = named_client(&req).as_deref().and_then(parse_client) {
        if !version.is_dev() {
            if let Some(minimum) = state.client_minimums.get(client) {
                if version < minimum {
                    return too_old(client, &minimum);
                }
            }
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_order() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(v("0.0.14") > v("0.0.9"));
        assert!(v("2026.1120.0") > v("2026.1119.3"));
        assert!(v("2027.105.0") > v("2026.1231.9"));
        assert!(v("1.0.0") > v("1.0.0-rc1"));
        assert!(v("0.0.0-dev").is_dev());
        for bad in [
            "", "1", "1.2", "1.2.3.4", "01.2.3", "1.2.x", "1.2.3-", "a.b.c",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_client_names_its_type_and_version() {
        let (client, version) = parse_client("cli/0.0.14").unwrap();
        assert_eq!(client, ClientType::Cli);
        assert_eq!(version.to_string(), "0.0.14");
        // The type alone: version zero, too old once a minimum exists.
        assert_eq!(parse_client("web-drive").unwrap().1, Version::ZERO);
        assert!(parse_client("nope/1.0.0").is_none());
        assert!(parse_client("cli/one").is_none());
    }

    #[test]
    fn the_compiled_floor_is_valid() {
        let _ = floors();
    }

    #[test]
    fn the_release_is_a_version() {
        assert!(Version::parse(RELEASE).is_some(), "{RELEASE}");
    }
}
