//! In-memory file upload + latest-bytes helper — mirrors the `UploadFile` /
//! `LatestEncryptedBytes` parts of `internal/api/client.go` + `versions.go`.
//! Used by the sync engine (small whole-file transfers).

use anyhow::Result;
use reqwest::blocking::multipart::{Form, Part};
use reqwest::Method;

use super::{Client, UploadResponse};

impl Client {
    /// Multipart-uploads an already-encrypted blob to `/files/upload`.
    /// Mirrors `UploadFile`.
    pub fn upload_file(
        &self,
        collection_id: &str,
        encrypted_metadata: &str,
        metadata_nonce: &str,
        encrypted_file_key: &str,
        file_key_nonce: &str,
        encrypted_content: Vec<u8>,
    ) -> Result<UploadResponse> {
        let part = Part::bytes(encrypted_content)
            .file_name("blob")
            .mime_str("application/octet-stream")?;
        let form = Form::new()
            .text("collectionId", collection_id.to_string())
            .text("encryptedMetadata", encrypted_metadata.to_string())
            .text("metadataNonce", metadata_nonce.to_string())
            .text("encryptedFileKey", encrypted_file_key.to_string())
            .text("fileKeyNonce", file_key_nonce.to_string())
            .part("file", part);
        let resp = self
            .request(Method::POST, "/files/upload")
            .multipart(form)
            .send()?;
        super::decode_json(resp)
    }

    /// Reads the latest encrypted content fully into memory (snapshot-preferred).
    /// Mirrors `LatestEncryptedBytes`. The bool is true iff a snapshot won.
    pub fn latest_encrypted_bytes(&self, file_id: &str) -> Result<(Vec<u8>, bool)> {
        let (resp, from_version) = self.latest_encrypted_stream(file_id)?;
        Ok((resp.bytes()?.to_vec(), from_version))
    }
}
