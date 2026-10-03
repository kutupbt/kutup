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

    // Proactively refresh (refresh tokens rotate on every use, so the new one is
    // persisted). A 401 means the server ended this sign-in — revoked from
    // another device, signed out everywhere, or the password was reset — so the
    // local session is cleared rather than failing later with a confusing error.
    // Network errors are left for the command itself to report.
    if !session.refresh_token.is_empty() {
        match client.refresh_token(&session.refresh_token) {
            Ok(refreshed) => {
                if !refreshed.access_token.is_empty() {
                    session.access_token = refreshed.access_token.clone();
                    client.set_token(&refreshed.access_token);
                }
                if !refreshed.refresh_token.is_empty() {
                    session.refresh_token = refreshed.refresh_token;
                }
                store.save_session(&session)?;
            }
            Err(err)
                if err
                    .downcast_ref::<crate::api::ApiError>()
                    .is_some_and(|e| e.status == 401) =>
            {
                store.clear_session()?;
                return Err(
                    NotLoggedIn("this sign-in has ended — run 'kutup login' again".into()).into(),
                );
            }
            Err(_) => {}
        }
    }

    Ok(Ctx {
        client,
        session,
        store,
    })
}
