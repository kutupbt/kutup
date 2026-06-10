//! Federation (incoming shares + fed-proxy) — mirrors `internal/api/federation.go`.

use anyhow::Result;
use reqwest::blocking::multipart::{Form, Part};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::{Client, File};

/// Mirrors `backend/handlers/fedproxy.go:IncomingShare`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingShare {
    pub id: String,
    #[serde(default)]
    pub remote_server: String,
    #[serde(default)]
    pub encrypted_collection_key: String,
    #[serde(default)]
    pub encrypted_name: String,
    #[serde(default)]
    pub name_nonce: String,
    #[serde(default)]
    pub can_upload: bool,
    #[serde(default)]
    pub can_delete: bool,
    #[serde(default)]
    pub upload_quota_bytes: Option<i64>,
    #[serde(default)]
    pub created_at: String,
}

/// Mirrors the remote `UploadShareFile` response (`{id}` or empty).
#[derive(Debug, Default, Deserialize)]
pub struct ProxyUploadResponse {
    #[serde(default)]
    pub id: String,
}

impl Client {
    /// Lists accepted federated shares. Mirrors `ListIncomingShares`.
    pub fn list_incoming_shares(&self) -> Result<Vec<IncomingShare>> {
        let resp = self.request(Method::GET, "/fed-proxy/incoming").send()?;
        super::decode_json(resp)
    }

    /// Accepts a federated invite URL. Mirrors `AddIncomingShare`.
    pub fn add_incoming_share(&self, invite_url: &str) -> Result<IncomingShare> {
        let resp = self
            .request(Method::POST, "/fed-proxy/incoming")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({ "inviteUrl": invite_url }))
            .send()?;
        super::decode_json(resp)
    }

    /// Forgets a local federated-share pointer. Mirrors `RemoveIncomingShare`.
    pub fn remove_incoming_share(&self, share_id: &str) -> Result<()> {
        let resp = self
            .request(Method::DELETE, &format!("/fed-proxy/incoming/{share_id}"))
            .send()?;
        super::check_ok(resp)
    }

    /// Lists files inside a federated share. Mirrors `ProxyListFiles`.
    pub fn proxy_list_files(&self, share_id: &str) -> Result<Vec<File>> {
        let resp = self
            .request(Method::GET, &format!("/fed-proxy/{share_id}/files"))
            .send()?;
        super::decode_json(resp)
    }

    /// Downloads encrypted bytes of a file in a federated share. Mirrors `ProxyDownload`.
    pub fn proxy_download(&self, share_id: &str, file_id: &str) -> Result<Vec<u8>> {
        let resp = self
            .upload_request(
                Method::GET,
                &format!("/fed-proxy/{share_id}/files/{file_id}/download"),
            )
            .send()?;
        if resp.status().as_u16() >= 400 {
            let code = resp.status().as_u16();
            anyhow::bail!("HTTP {}: {}", code, resp.text().unwrap_or_default());
        }
        Ok(resp.bytes()?.to_vec())
    }

    /// Uploads an encrypted file to a federated share (fed-proxy pass-through).
    /// Mirrors `ProxyUploadFile`.
    pub fn proxy_upload_file(
        &self,
        share_id: &str,
        encrypted_metadata: &str,
        metadata_nonce: &str,
        encrypted_file_key: &str,
        file_key_nonce: &str,
        encrypted_content: Vec<u8>,
    ) -> Result<ProxyUploadResponse> {
        let part = Part::bytes(encrypted_content)
            .file_name("blob")
            .mime_str("application/octet-stream")?;
        let form = Form::new()
            .text("encryptedMetadata", encrypted_metadata.to_string())
            .text("metadataNonce", metadata_nonce.to_string())
            .text("encryptedFileKey", encrypted_file_key.to_string())
            .text("fileKeyNonce", file_key_nonce.to_string())
            .part("file", part);
        let resp = self
            .request(Method::POST, &format!("/fed-proxy/{share_id}/upload"))
            .multipart(form)
            .send()?;
        if resp.status().as_u16() >= 400 {
            let code = resp.status().as_u16();
            anyhow::bail!("HTTP {}: {}", code, resp.text().unwrap_or_default());
        }
        Ok(resp.json().unwrap_or_default())
    }
}
