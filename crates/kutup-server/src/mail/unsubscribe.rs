//! One-click unsubscribe (RFC 8058; docs/plans/mail-parity.md, P3), sent by
//! the server as Proton's servers send it, so the list never learns the
//! reader's address or browser: a POST of `List-Unsubscribe=One-Click` to
//! the message's https `List-Unsubscribe` URL, through the one narrow
//! fetcher (`public_fetch`: https only, every address public, the
//! connection pinned to the checked one, no environment proxy), redirects
//! not followed.

use super::outside_keys::{Unusable, TOTAL_TIMEOUT};
use crate::AppState;

const USER_AGENT: &str = "Kutup mail unsubscribe (+https://kutup.dev)";
const BODY: &str = "List-Unsubscribe=One-Click";

/// POSTs the one-click request to `url`; a 2xx or 3xx answer counts as
/// taken (RFC 8058 senders need not answer more). On a test stack
/// (`APP_ENV=test` and `MAIL_TEST_KEY_ORIGIN`) it goes to that origin, as
/// `{origin}/{host}{path}?{query}`, as key lookups do.
pub async fn one_click(state: &AppState, url: &str) -> Result<(), Unusable> {
    let config = &state.config;
    if config.app_env == "test" && !config.mail_test_key_origin.is_empty() {
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
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TOTAL_TIMEOUT)
            .user_agent(USER_AGENT)
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
        return if response.status().is_success() || response.status().is_redirection() {
            Ok(())
        } else {
            Err(Unusable)
        };
    }
    let target = crate::public_fetch::parse_public_https(url).map_err(|_| Unusable)?;
    crate::public_fetch::get_with(
        target,
        &crate::public_fetch::Request {
            accept: "*/*",
            user_agent: USER_AGENT,
            timeout: TOTAL_TIMEOUT,
            limit: 64 * 1024,
            // The answer's body does not matter: a 2xx or a redirect is taken.
            truncate: true,
            wanted: &|_| true,
            body: Some(("application/x-www-form-urlencoded", BODY.as_bytes())),
        },
        &crate::public_fetch::Options {
            redirects: crate::public_fetch::Redirects::Stop,
            ..Default::default()
        },
    )
    .await
    .map_err(|_| Unusable)
    .and_then(|answer| {
        // A 2xx, or a redirect (not followed): the request was taken.
        if answer.status.is_success() || answer.status.is_redirection() {
            Ok(())
        } else {
            Err(Unusable)
        }
    })
}
