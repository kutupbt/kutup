//! Whiteboard asset blobs — `PUT/GET /files/{id}/assets/{assetId}`.
//! Companion to `crates/kutup-server/src/handlers/file_assets.rs`.

use anyhow::Result;
use reqwest::blocking::multipart::{Form, Part};
use reqwest::Method;

use super::Client;

impl Client {
    /// Uploads an encrypted asset blob (multipart part name `file`).
    /// Idempotent server-side (`INSERT … ON CONFLICT DO NOTHING`).
    pub fn upload_asset(&self, file_id: &str, asset_id: &str, ciphertext: Vec<u8>) -> Result<()> {
        let part = Part::bytes(ciphertext)
            .file_name("asset")
            .mime_str("application/octet-stream")?;
        let form = Form::new().part("file", part);
        let resp = self
            .request(Method::PUT, &format!("/files/{file_id}/assets/{asset_id}"))
            .multipart(form)
            .send()?;
        super::check_ok(resp)
    }

    /// Downloads an encrypted asset blob.
    pub fn download_asset(&self, file_id: &str, asset_id: &str) -> Result<Vec<u8>> {
        let resp = self
            .request(Method::GET, &format!("/files/{file_id}/assets/{asset_id}"))
            .send()?;
        if resp.status().as_u16() >= 400 {
            return Err(super::api_error(resp));
        }
        Ok(resp.bytes()?.to_vec())
    }
}
