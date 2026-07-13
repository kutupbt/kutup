//! Public-share consumption — mirrors `internal/api/public.go`.

use anyhow::Result;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::{Client, File};

/// Metadata for `GET /share/{token}` (unauthenticated).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicShare {
    pub id: String,
    #[serde(default)]
    pub share_type: String,
    #[serde(default)]
    pub target_id: String,
    #[serde(default)]
    pub encrypted_collection_key: Option<String>,
    #[serde(default)]
    pub encrypted_collection_key_nonce: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl Client {
    /// Fetches public-share metadata. Mirrors `GetPublicShare`.
    pub fn get_public_share(&self, token: &str) -> Result<PublicShare> {
        let resp = self
            .request(Method::GET, &format!("/share/{token}"))
            .send()?;
        super::decode_json(resp)
    }

    /// Lists files in a collection-type public share. Mirrors `ListPublicShareFiles`.
    pub fn list_public_share_files(&self, token: &str) -> Result<Vec<File>> {
        let resp = self
            .request(Method::GET, &format!("/share/{token}/files"))
            .send()?;
        super::decode_json(resp)
    }

    /// Streams the encrypted blob of a file in a public share (no total
    /// timeout — large blobs must survive slow links). Anonymous: the token
    /// is the capability.
    pub fn public_share_download_stream(
        &self,
        token: &str,
        file_id: &str,
    ) -> Result<reqwest::blocking::Response> {
        let resp = self
            .upload_request(Method::GET, &format!("/share/{token}/download/{file_id}"))
            .send()?;
        if resp.status().as_u16() >= 400 {
            return Err(super::api_error(resp));
        }
        Ok(resp)
    }
}
