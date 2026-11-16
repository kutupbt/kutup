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
    pub collection_key_envelope: String,
    #[serde(default)]
    pub collection_key_epoch: u32,
    #[serde(default)]
    pub owner_user_id: String,
    /// Signs the folder's key history.
    #[serde(default)]
    pub owner_authority_public_key: String,
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
}
