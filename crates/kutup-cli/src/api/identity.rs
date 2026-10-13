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
}
