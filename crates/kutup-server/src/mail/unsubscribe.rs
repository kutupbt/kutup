//! One-click unsubscribe (RFC 8058; docs/plans/mail-parity.md, P3), sent by
//! the server as Proton's servers send it, so the list never learns the
//! reader's address or browser: a POST of `List-Unsubscribe=One-Click` to
//! the message's https `List-Unsubscribe` URL, through the same narrow
//! fetcher as key lookups (https only, every address public, the
//! connection pinned to the checked one, no redirects followed).

use super::outside_keys::{public_https, resolve_public, Unusable, CONNECT_TIMEOUT, TOTAL_TIMEOUT};
use crate::AppState;

const USER_AGENT: &str = "Kutup mail unsubscribe (+https://kutup.dev)";
const BODY: &str = "List-Unsubscribe=One-Click";

/// POSTs the one-click request to `url`; a 2xx or 3xx answer counts as
/// taken (RFC 8058 senders need not answer more). On a test stack
/// (`APP_ENV=test` and `MAIL_TEST_KEY_ORIGIN`) it goes to that origin, as
/// `{origin}/{host}{path}?{query}`, as key lookups do.
pub async fn one_click(state: &AppState, url: &str) -> Result<(), Unusable> {
    let config = &state.config;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .user_agent(USER_AGENT);
    let (client, target) = if config.app_env == "test" && !config.mail_test_key_origin.is_empty() {
        let original = url::Url::parse(url).map_err(|_| Unusable)?;
        let target = format!(
            "{}/{}{}{}",
            config.mail_test_key_origin.trim_end_matches('/'),
            original.host_str().unwrap_or_default(),
            original.path(),
            original
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default()
        );
        (client, target)
    } else {
        let checked = public_https(url)?;
        let address = resolve_public(&checked).await?;
        let host = checked.host_str().ok_or(Unusable)?.to_owned();
        (client.resolve(&host, address), checked.to_string())
    };
    let response = client
        .build()
        .map_err(|_| Unusable)?
        .post(target)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(BODY)
        .send()
        .await
        .map_err(|_| Unusable)?;
    if response.status().is_success() || response.status().is_redirection() {
        Ok(())
    } else {
        Err(Unusable)
    }
}
