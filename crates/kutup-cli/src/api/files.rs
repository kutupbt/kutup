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
        file_id: &str,
        collection_id: &str,
        metadata_envelope: &str,
        file_key_envelope: &str,
        encrypted_content: Vec<u8>,
    ) -> Result<UploadResponse> {
        let part = Part::bytes(encrypted_content)
            .file_name("blob")
            .mime_str("application/octet-stream")?;
        let form = Form::new()
            .text("fileId", file_id.to_string())
            .text("collectionId", collection_id.to_string())
            .text("metadataEnvelope", metadata_envelope.to_string())
            .text("fileKeyEnvelope", file_key_envelope.to_string())
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
