//! Incoming Drive shares through the local unified-federation adapter.

use anyhow::Result;
use reqwest::blocking::multipart::{Form, Part};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::{Client, File};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingShare {
    pub id: String,
    #[serde(default)]
    pub remote_domain: String,
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
        let resp = self
            .request(Method::GET, "/drive/federation/shares")
            .send()?;
        super::decode_json(resp)
    }

    /// Accepts a parsed canonical-domain/capability invite.
    pub fn add_incoming_share(&self, server: &str, capability: &str) -> Result<IncomingShare> {
        let resp = self
            .request(Method::POST, "/drive/federation/shares")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({ "server": server, "capability": capability }))
            .send()?;
        super::decode_json(resp)
    }

    /// Forgets a local federated-share pointer. Mirrors `RemoveIncomingShare`.
    pub fn remove_incoming_share(&self, share_id: &str) -> Result<()> {
        let resp = self
            .request(
                Method::DELETE,
                &format!("/drive/federation/shares/{share_id}"),
            )
            .send()?;
        super::check_ok(resp)
    }

    /// Lists files inside a federated share. Mirrors `ProxyListFiles`.
    pub fn proxy_list_files(&self, share_id: &str) -> Result<Vec<File>> {
        let resp = self
            .request(
                Method::GET,
                &format!("/drive/federation/shares/{share_id}/files"),
            )
            .send()?;
        super::decode_json(resp)
    }

    /// Streams the encrypted bytes of a file in a federated share (no total
    /// timeout), for the bounded-memory download path.
    pub fn proxy_download_stream(
        &self,
        share_id: &str,
        file_id: &str,
    ) -> Result<reqwest::blocking::Response> {
        let resp = self
            .upload_request(
                Method::GET,
                &format!("/drive/federation/shares/{share_id}/files/{file_id}/content"),
            )
            .send()?;
        if resp.status().as_u16() >= 400 {
            return Err(super::api_error(resp));
        }
        Ok(resp)
    }

    /// Downloads encrypted bytes of a file in a federated share. Mirrors `ProxyDownload`.
    pub fn proxy_download(&self, share_id: &str, file_id: &str) -> Result<Vec<u8>> {
        let resp = self.proxy_download_stream(share_id, file_id)?;
        Ok(resp.bytes()?.to_vec())
    }

    /// Uploads an encrypted file through the signed Drive adapter.
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
            .request(
                Method::POST,
                &format!("/drive/federation/shares/{share_id}/files"),
            )
            .multipart(form)
            .send()?;
        if resp.status().as_u16() >= 400 {
            return Err(super::api_error(resp));
        }
        Ok(resp.json().unwrap_or_default())
    }
}
