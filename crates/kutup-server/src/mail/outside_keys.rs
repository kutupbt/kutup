//! Outside correspondents' OpenPGP keys (docs/plans/mail.md, C3), looked up
//! by the server as Proton's servers do: a browser cannot read other
//! domains' Web Key Directories. In order: WKD (advanced, then direct),
//! Proton's key server for Proton's own domains, keys.openpgp.org (verified
//! addresses only). Each answer is checked (`inspect_external_public_keys`)
//! before it is used; answers are cached for an hour (misses for 15
//! minutes). The fetcher is as narrow as Chat's link previews: https only,
//! every address public, the connection pinned to the checked address,
//! redirects followed by hand and checked again, small size and time limits.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use kutup_crypto::mail_key::{inspect_external_public_keys_all, ExternalKeyInfo};
use serde::Serialize;
use url::Url;
use utoipa::ToSchema;

use crate::AppState;

/// Where a key was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum KeySource {
    Wkd,
    Proton,
    KeysOpenpgp,
}

#[derive(Clone, Debug)]
pub struct OutsideKey {
    pub source: KeySource,
    /// The newest usable key, which mail is encrypted to.
    pub key: ExternalKeyInfo,
    /// Every usable key the source served, newest first (`key` among them),
    /// for a contact's key table (docs/plans/contact-keys.md).
    pub keys: Vec<ExternalKeyInfo>,
}

/// Proton's own domains, whose users' keys Proton serves over HKP (it serves
/// no WKD for them; custom domains on Proton publish WKD).
const PROTON_DOMAINS: [&str; 4] = ["proton.me", "protonmail.com", "protonmail.ch", "pm.me"];
const PROTON_HKP: &str = "https://mail-api.proton.me/pks/lookup";
const KEYS_OPENPGP: &str = "https://keys.openpgp.org/vks/v1/by-email/";

const HIT_TTL: Duration = Duration::from_secs(3600);
const MISS_TTL: Duration = Duration::from_secs(900);
const CACHE_MAX: usize = 10_000;
const KEY_LIMIT_BYTES: usize = 256 * 1024;
pub(crate) const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const USER_AGENT: &str = "Kutup mail key lookup (+https://kutup.dev)";

type Cache = HashMap<String, (Instant, Option<OutsideKey>)>;
static CACHE: LazyLock<Mutex<Cache>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// `local@domain`, lowercase, or `None` for what is not an address.
pub fn split(address: &str) -> Option<(String, String)> {
    let address = address.trim().to_lowercase();
    let (local, domain) = address.rsplit_once('@')?;
    let valid = !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !address.chars().any(|c| c.is_whitespace() || c.is_control());
    valid.then(|| (local.to_string(), domain.to_string()))
}

/// The URLs to ask, in order.
fn candidates(local: &str, domain: &str, address: &str) -> Vec<(KeySource, String)> {
    let hash = crate::handlers::mail_keys::wkd_hash(local);
    let l: String = url::form_urlencoded::byte_serialize(local.as_bytes()).collect();
    let mut urls = vec![
        (
            KeySource::Wkd,
            format!("https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}?l={l}"),
        ),
        (
            KeySource::Wkd,
            format!("https://{domain}/.well-known/openpgpkey/hu/{hash}?l={l}"),
        ),
    ];
    let encoded: String = url::form_urlencoded::byte_serialize(address.as_bytes()).collect();
    if PROTON_DOMAINS.contains(&domain) {
        urls.push((
            KeySource::Proton,
            format!("{PROTON_HKP}?op=get&search={encoded}"),
        ));
    }
    urls.push((KeySource::KeysOpenpgp, format!("{KEYS_OPENPGP}{encoded}")));
    urls
}

/// The usable keys of an outside address, from the first source that has any.
pub async fn lookup(state: &AppState, address: &str) -> Option<OutsideKey> {
    let (local, domain) = split(address)?;
    let address = format!("{local}@{domain}");
    if let Some((at, found)) = CACHE.lock().expect("cache").get(&address) {
        let ttl = if found.is_some() { HIT_TTL } else { MISS_TTL };
        if at.elapsed() < ttl {
            return found.clone();
        }
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
    let mut found = None;
    for (source, url) in candidates(&local, &domain, &address) {
        let Ok(body) = fetch(state, &url).await else {
            continue;
        };
        if let Ok(keys) = inspect_external_public_keys_all(&body, &address, now) {
            found = Some(OutsideKey {
                source,
                key: keys[0].clone(),
                keys,
            });
            break;
        }
    }
    let mut cache = CACHE.lock().expect("cache");
    if cache.len() >= CACHE_MAX {
        cache.retain(|_, (at, _)| at.elapsed() < MISS_TTL);
        if cache.len() >= CACHE_MAX {
            cache.clear();
        }
    }
    cache.insert(address, (Instant::now(), found.clone()));
    found
}

#[derive(Debug)]
pub(crate) struct Unusable;

/// Fetches `url` within the limits above. On a test stack
/// (`APP_ENV=test` and `MAIL_TEST_KEY_ORIGIN`), every lookup goes to that
/// origin instead, as `{origin}/{host}{path}?{query}`, so the gate can serve
/// keys without the internet.
async fn fetch(state: &AppState, url: &str) -> Result<Vec<u8>, Unusable> {
    let config = &state.config;
    if config.app_env == "test" && !config.mail_test_key_origin.is_empty() {
        let original = Url::parse(url).map_err(|_| Unusable)?;
        let redirected = format!(
            "{}/{}{}{}",
            config.mail_test_key_origin.trim_end_matches('/'),
            original.host_str().unwrap_or_default(),
            original.path(),
            original
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default()
        );
        let response = reqwest::Client::builder()
            .timeout(TOTAL_TIMEOUT)
            .build()
            .map_err(|_| Unusable)?
            .get(redirected)
            .send()
            .await
            .map_err(|_| Unusable)?;
        return read(response).await;
    }
    // The one narrow fetcher (https on 443, public addresses only, the
    // connection pinned, redirects checked again, no environment proxy).
    let url = crate::public_fetch::parse_public_https(url).map_err(|_| Unusable)?;
    let fetched = crate::public_fetch::get(
        url,
        &crate::public_fetch::Request {
            accept: "application/pgp-keys, application/octet-stream;q=0.9, */*;q=0.5",
            user_agent: USER_AGENT,
            timeout: TOTAL_TIMEOUT,
            limit: KEY_LIMIT_BYTES,
            truncate: false,
            // Keyservers answer under many types; the bytes are checked
            // as OpenPGP keys afterwards.
            wanted: &|_| true,
            body: None,
        },
    )
    .await
    .map_err(|_| Unusable)?;
    Ok(fetched.body)
}

async fn read(response: reqwest::Response) -> Result<Vec<u8>, Unusable> {
    if !response.status().is_success() {
        return Err(Unusable);
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| Unusable)?;
        if body.len() + chunk.len() > KEY_LIMIT_BYTES {
            return Err(Unusable);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_split_and_refuse_junk() {
        assert_eq!(
            split(" Dave@Example.ORG "),
            Some(("dave".into(), "example.org".into()))
        );
        assert_eq!(split("dave@localhost"), None);
        assert_eq!(split("dave@exa mple.org"), None);
        assert_eq!(split("dave@.org"), None);
        assert_eq!(split("@example.org"), None);
        assert_eq!(split("dave@ex_ample.org"), None);
    }

    #[test]
    fn sources_come_in_order() {
        let urls = candidates("dave.k", "proton.me", "dave.k@proton.me");
        assert_eq!(urls.len(), 4);
        assert!(urls[0]
            .1
            .starts_with("https://openpgpkey.proton.me/.well-known/openpgpkey/proton.me/hu/"));
        assert!(urls[0].1.ends_with("?l=dave.k"));
        assert!(urls[1]
            .1
            .starts_with("https://proton.me/.well-known/openpgpkey/hu/"));
        assert_eq!(
            urls[2],
            (
                KeySource::Proton,
                format!("{PROTON_HKP}?op=get&search=dave.k%40proton.me")
            )
        );
        assert_eq!(urls[3].0, KeySource::KeysOpenpgp);
        // Elsewhere, no Proton key server.
        assert!(candidates("a", "example.org", "a@example.org")
            .iter()
            .all(|(source, _)| *source != KeySource::Proton));
    }
}
