//! Public-share consumption — mirrors `internal/api/public.go`.

use anyhow::{bail, Result};
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

#[derive(Debug, Deserialize)]
pub struct DownloadUrlResponse {
    #[serde(default)]
    pub url: String,
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

    /// Returns the presigned URL for a file in a public share. Mirrors
    /// `PublicShareDownloadURL`.
    pub fn public_share_download_url(
        &self,
        token: &str,
        file_id: &str,
    ) -> Result<DownloadUrlResponse> {
        let resp = self
            .request(Method::GET, &format!("/share/{token}/download/{file_id}"))
            .send()?;
        super::decode_json(resp)
    }
}

/// Fetches bytes from an absolute presigned URL (no auth header — the URL
/// carries short-lived authorization). Mirrors `FetchPresignedURL`.
pub fn fetch_presigned_url(presigned: &str) -> Result<Vec<u8>> {
    let insecure = matches!(
        std::env::var("KUTUP_INSECURE_TLS").as_deref(),
        Ok("1") | Ok("true")
    );
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build()?;
    let resp = client.get(presigned).send()?;
    if resp.status().as_u16() >= 400 {
        let code = resp.status().as_u16();
        bail!("HTTP {}: {}", code, resp.text().unwrap_or_default());
    }
    Ok(resp.bytes()?.to_vec())
}
