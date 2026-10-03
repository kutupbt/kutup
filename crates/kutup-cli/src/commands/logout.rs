//! `kutup logout` — ends this sign-in on the server, then clears the local session.

use anyhow::Result;

use crate::api::Client;
use crate::session::Store;

pub fn run(profile: &str, json: bool) -> Result<()> {
    let store = Store::open(profile)?;
    // Revoke server-side first so the refresh token stops working everywhere it
    // may have been copied. The local session is cleared either way: logging out
    // must not depend on the server being reachable.
    let revoked = match store.load_session()? {
        Some(session) => {
            let client = Client::new(&session.server, &session.access_token);
            let refreshed = if session.refresh_token.is_empty() {
                None
            } else {
                client.refresh_token(&session.refresh_token).ok()
            };
            if let Some(r) = refreshed.filter(|r| !r.access_token.is_empty()) {
                client.set_token(&r.access_token);
            }
            match client.logout() {
                Ok(()) => true,
                Err(err) => {
                    eprintln!("warning: could not end the session on the server: {err}");
                    false
                }
            }
        }
        None => false,
    };
    store.clear_session()?;
    if json {
        crate::output::print_json(&serde_json::json!({
            "loggedOut": true,
            "revokedOnServer": revoked,
            "profile": profile,
        }))?;
    } else {
        println!("Logged out.");
    }
    Ok(())
}
