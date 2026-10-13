//! Drive identity (docs/plans/drive-identity-pins.md): the account's Drive
//! key binding and its synced identity pins.

use anyhow::Result;
use reqwest::header::CONTENT_TYPE;
use reqwest::Method;

use super::types::IdentityPinsRecord;
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

    /// Stores `record` (its revision follows the stored one); `false` when
    /// another app stored that revision first.
    pub fn put_identity_pins(&self, record: &IdentityPinsRecord) -> Result<bool> {
        let resp = self
            .request(Method::PUT, "/user/identity-pins")
            .header(CONTENT_TYPE, "application/json")
            .json(record)
            .send()?;
        if resp.status().as_u16() == 409 {
            return Ok(false);
        }
        super::check_ok(resp)?;
        Ok(true)
    }

}
