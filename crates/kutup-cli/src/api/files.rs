//! In-memory file upload + latest-bytes helper — mirrors the `UploadFile` /
//! `LatestEncryptedBytes` parts of `internal/api/client.go` + `versions.go`.
//! Used by the sync engine (small whole-file transfers).

use anyhow::Result;
use reqwest::blocking::multipart::{Form, Part};
use reqwest::Method;

use super::{Client, UploadResponse};

/// `POST /files/{id}/move` result.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveFileResponse {
    pub collection_id: String,
    pub key_epoch: u32,
}

/// What `POST /files/{id}/move` answered.
#[derive(Debug)]
pub enum MoveOutcome {
    Moved(MoveFileResponse),
    /// 409: the server's reason (`file needs a re-key`, `folder key
    /// changed`, `the file moved`).
    Conflict(String),
}

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

    /// Moves a file to its folder's current key (docs/plans/drive-share-revocation.md).
    /// `Ok(false)`: another editor moved it first; list it again.
    pub fn rekey_file(&self, file_id: &str, req: &super::RekeyRequest) -> Result<bool> {
        let resp = self.post_json(&format!("/files/{file_id}/rekey"), req)?;
        if resp.status().as_u16() == 409 {
            return Ok(false);
        }
        super::check_ok(resp)?;
        Ok(true)
    }

    /// Moves a file to another folder of the same owner
    /// (docs/plans/drive-move.md). A 409 — the file needs a re-key, the
    /// destination's key changed, or the file moved — comes back as
    /// `MoveOutcome::Conflict` so the caller can reload and seal again.
    pub fn move_file(&self, file_id: &str, req: &super::MoveFileRequest) -> Result<MoveOutcome> {
        let resp = self.post_json(&format!("/files/{file_id}/move"), req)?;
        if resp.status().as_u16() == 409 {
            let error: super::ApiError = super::api_error(resp).downcast()?;
            // A taken name is not cured by sealing again.
            if error.name_taken.is_some() {
                return Err(anyhow::Error::new(error));
            }
            return Ok(MoveOutcome::Conflict(error.message));
        }
        let moved: MoveFileResponse = super::decode_json(resp)?;
        Ok(MoveOutcome::Moved(moved))
    }

    /// Puts a folder under another of the owner's folders, or at the top
    /// level (`None`). Owner only.
    pub fn move_collection(
        &self,
        collection_id: &str,
        parent: Option<&str>,
        name_hash: Option<String>,
    ) -> Result<()> {
        let resp = self.post_json(
            &format!("/collections/{collection_id}/move"),
            &super::MoveCollectionRequest {
                parent_collection_id: parent.map(str::to_string),
                name_hash,
            },
        )?;
        super::check_ok(resp)
    }

    /// Reads the latest encrypted content fully into memory (snapshot-preferred).
    /// Mirrors `LatestEncryptedBytes`. The bool is true iff a snapshot won.
    pub fn latest_encrypted_bytes(&self, file_id: &str) -> Result<(Vec<u8>, bool)> {
        let (resp, from_version) = self.latest_encrypted_stream(file_id)?;
        Ok((resp.bytes()?.to_vec(), from_version))
    }
}
