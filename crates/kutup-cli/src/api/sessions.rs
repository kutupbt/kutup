//! Server-side sessions: sign-out and the session list
//! (`docs/plans/multi-app-web-rewrite.md`).

use anyhow::Result;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::Client;

/// One live sign-in of the account. Timestamps are the server's RFC 3339 strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    /// `web-account`, `web-drive`, `web-chat`, `cli`, …
    pub client_type: String,
    /// The sign-in a web app's session was forked from.
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    pub created_at: String,
    pub last_used_at: String,
    /// Part of this client's own sign-in.
    #[serde(default)]
    pub current: bool,
}

impl Client {
    pub fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
        let resp = self.request(Method::GET, "/auth/sessions").send()?;
        super::decode_json(resp)
    }

    pub fn revoke_session(&self, id: &str) -> Result<()> {
        let path = format!("/auth/sessions/{}", super::path_segment(id));
        let resp = self.request(Method::DELETE, &path).send()?;
        super::check_ok(resp)
    }

    /// Sign out everywhere else: every session except this sign-in.
    pub fn revoke_other_sessions(&self) -> Result<()> {
        let resp = self.request(Method::DELETE, "/auth/sessions").send()?;
        super::check_ok(resp)
    }

    /// End this sign-in on the server.
    pub fn logout(&self) -> Result<()> {
        let resp = self.request(Method::POST, "/auth/logout").send()?;
        super::check_ok(resp)
    }
}
