//! Session loading + proactive token refresh — mirrors `session.go`.

use anyhow::Result;

use crate::api::Client;
use crate::errors::NotLoggedIn;
use crate::session::{Session, Store};

/// An authenticated command context: the API client, the loaded session, and
/// the open store (kept alive so its DB handle stays valid; closed on drop).
pub struct Ctx {
    pub client: Client,
    pub session: Session,
    pub store: Store,
}

/// Loads the session for `profile`, builds a client, and proactively refreshes
/// the access token (persisting it) — mirroring `requireSessionWithStore`.
pub fn require_session(profile: &str) -> Result<Ctx> {
    let mut store = Store::open(profile)?;
    let Some(mut session) = store.load_session()? else {
        return Err(NotLoggedIn("not logged in — run 'kutup login' first".into()).into());
    };

    let client = Client::new(&session.server, &session.access_token);

    // Proactively refresh to avoid clock-skew issues; ignore refresh failures.
    if !session.refresh_token.is_empty() {
        if let Ok(refreshed) = client.refresh_token(&session.refresh_token) {
            if !refreshed.access_token.is_empty() {
                session.access_token = refreshed.access_token.clone();
                client.set_token(&refreshed.access_token);
                let _ = store.save_session(&session);
            }
        }
    }

    Ok(Ctx {
        client,
        session,
        store,
    })
}
