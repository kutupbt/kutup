//! Device management — mirrors `internal/api/devices.go`.

use anyhow::Result;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::Client;

/// Mirrors `backend/handlers/devices.go:deviceRow`. Timestamps are kept as the
/// server's RFC3339 strings (no local-tz reformatting).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDevice {
    pub device_id: i64,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub is_active: bool,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub last_seen_at: Option<String>,
}

impl Client {
    /// Lists every device for the authenticated user (server orders newest-first).
    pub fn list_user_devices(&self) -> Result<Vec<UserDevice>> {
        let resp = self.request(Method::GET, "/devices").send()?;
        super::decode_json(resp)
    }

    /// Revokes a device, closing any in-flight WebSocket sessions signed by it.
    pub fn revoke_user_device(&self, device_id: i64) -> Result<()> {
        let resp = self
            .request(Method::DELETE, &format!("/devices/{device_id}"))
            .send()?;
        super::check_ok(resp)
    }
}
