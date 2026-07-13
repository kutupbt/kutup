//! File versions + streaming download — mirrors `internal/api/versions.go`
//! (the subset the CLI needs: listing, version/main streaming, latest-preferred).

use anyhow::{Context, Result};
use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::Response;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::Client;

/// Response of `POST /files/:id/snapshot-blob`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotBlobResponse {
    #[serde(default)]
    pub storage_path: String,
    #[serde(default)]
    pub s3_version_id: String,
}

/// Body for `POST /files/:id/versions` (record a snapshot).
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordSnapshotRequest {
    pub s3_version_id: String,
    pub storage_path: String,
    pub seq_at_snapshot: i64,
    pub doc_key_id: i64,
    pub size_bytes: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub keep_forever: bool,
}

/// Response of `POST /files/:id/versions`.
#[derive(Debug, Deserialize)]
pub struct RecordSnapshotResponse {
    pub id: String,
}

/// Body for `PATCH /files/:id/versions/:vid`. Absent fields are untouched.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchVersionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_forever: Option<bool>,
}

/// Mirrors `backend/handlers/file_versions.go:versionRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionRow {
    pub id: String,
    #[serde(default)]
    pub s3_version_id: String,
    #[serde(default)]
    pub storage_path: String,
    #[serde(default)]
    pub seq_at_snapshot: i64,
    #[serde(default)]
    pub doc_key_id: i64,
    #[serde(default)]
    pub author_user_id: String,
    #[serde(default)]
    pub size_bytes: i64,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub keep_forever: bool,
    #[serde(default)]
    pub created_at: String,
}

fn ok_stream(resp: Response, what: &'static str) -> Result<Response> {
    if resp.status().as_u16() >= 400 {
        return Err(super::api_error(resp)).context(what);
    }
    Ok(resp)
}

impl Client {
    /// Lists a file's snapshot versions, newest-first. Mirrors `ListVersions`.
    pub fn list_versions(&self, file_id: &str) -> Result<Vec<VersionRow>> {
        let resp = self
            .request(Method::GET, &format!("/files/{file_id}/versions"))
            .send()?;
        super::decode_json(resp)
    }

    /// Streams the main `/files/:id/download` blob (no total timeout).
    /// Mirrors `DownloadFileStream`.
    pub fn download_file_stream(&self, file_id: &str) -> Result<Response> {
        let resp = self
            .upload_request(Method::GET, &format!("/files/{file_id}/download"))
            .send()?;
        ok_stream(resp, "download")
    }

    /// Streams a specific version's blob. Mirrors `DownloadVersionStream`.
    pub fn download_version_stream(&self, file_id: &str, version_id: &str) -> Result<Response> {
        let resp = self
            .upload_request(
                Method::GET,
                &format!("/files/{file_id}/versions/{version_id}/download"),
            )
            .send()?;
        ok_stream(resp, "download version")
    }

    /// Returns a readable stream of the latest encrypted content, preferring the
    /// newest version snapshot and falling back to the main blob. The bool is
    /// true iff a snapshot won. Mirrors `LatestEncryptedStream`.
    pub fn latest_encrypted_stream(&self, file_id: &str) -> Result<(Response, bool)> {
        if let Ok(versions) = self.list_versions(file_id) {
            if let Some(newest) = versions.first() {
                if let Ok(rc) = self.download_version_stream(file_id, &newest.id) {
                    return Ok((rc, true));
                }
            }
        }
        let rc = self.download_file_stream(file_id)?;
        Ok((rc, false))
    }

    /// Downloads a specific version's encrypted bytes into memory (snapshots are
    /// small). Mirrors `DownloadVersion`.
    pub fn download_version(&self, file_id: &str, version_id: &str) -> Result<Vec<u8>> {
        let resp = self.download_version_stream(file_id, version_id)?;
        Ok(resp.bytes()?.to_vec())
    }

    /// Multipart-POSTs an encrypted snapshot blob. Mirrors `UploadSnapshotBlob`.
    pub fn upload_snapshot_blob(
        &self,
        file_id: &str,
        encrypted_content: Vec<u8>,
    ) -> Result<SnapshotBlobResponse> {
        let part = Part::bytes(encrypted_content)
            .file_name("snapshot")
            .mime_str("application/octet-stream")?;
        let form = Form::new().part("file", part);
        let resp = self
            .request(Method::POST, &format!("/files/{file_id}/snapshot-blob"))
            .multipart(form)
            .send()?;
        super::decode_json(resp)
    }

    /// Records a snapshot row (gated on quota server-side). Mirrors `RecordSnapshot`.
    pub fn record_snapshot(
        &self,
        file_id: &str,
        body: &RecordSnapshotRequest,
    ) -> Result<RecordSnapshotResponse> {
        let resp = self
            .request(Method::POST, &format!("/files/{file_id}/versions"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(body)
            .send()?;
        super::decode_json(resp)
    }

    /// Updates a version's label / keep-forever pin. Mirrors `PatchVersion`.
    pub fn patch_version(
        &self,
        file_id: &str,
        version_id: &str,
        patch: &PatchVersionRequest,
    ) -> Result<VersionRow> {
        let resp = self
            .request(
                Method::PATCH,
                &format!("/files/{file_id}/versions/{version_id}"),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(patch)
            .send()?;
        super::decode_json(resp)
    }
}
