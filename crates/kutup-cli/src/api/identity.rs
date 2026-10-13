//! Drive identity (docs/plans/drive-identity-pins.md): the account's Drive
//! key binding and its synced identity pins.

use anyhow::Result;
use reqwest::header::CONTENT_TYPE;
use reqwest::Method;

use super::types::{IdentityPinsRecord, IdentityPinsWrite};
use super::Client;

impl Client {
    /// The account's sealed pin list; `None` before the first.
    pub fn get_identity_pins(&self) -> Result<Option<IdentityPinsRecord>> {
        let resp = self.get("/user/identity-pins")?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        super::decode_json(resp).map(Some)
    }

    /// Stores `write` if the server still holds its base revision; `false`
    /// when another app stored a list first.
    pub fn put_identity_pins(&self, write: &IdentityPinsWrite) -> Result<bool> {
        let resp = self
            .request(Method::PUT, "/user/identity-pins")
            .header(CONTENT_TYPE, "application/json")
            .json(write)
            .send()?;
        if resp.status().as_u16() == 409 {
            return Ok(false);
        }
        super::check_ok(resp)?;
        Ok(true)
    }

    /// Whether the account has signed its Drive key binding.
    pub fn has_drive_key_binding(&self) -> Result<bool> {
        let me: serde_json::Value = super::decode_json(self.get("/user/me")?)?;
        Ok(me["hasDriveKeyBinding"].as_bool().unwrap_or(true))
    }

    /// Stores the account's Drive key binding (checked by the server).
    pub fn put_drive_key_binding(&self, binding: &str) -> Result<()> {
        let resp = self
            .request(Method::PUT, "/user/drive-key-binding")
            .header(CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({ "driveKeyBinding": binding }))
            .send()?;
        super::check_ok(resp)
    }
}
