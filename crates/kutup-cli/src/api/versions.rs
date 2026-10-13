//! File versions + streaming download — mirrors `internal/api/versions.go`
//! (the subset the CLI needs: listing, version/main streaming, latest-preferred).

use anyhow::{Context, Result};
use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::Response;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::Client;

/// A version to store with `POST /files/:id/versions` (multipart, one request:
/// the server measures and charges the body; docs/plans/drive-versions-v2.md).
#[derive(Debug, Default)]
pub struct NewVersion {
    /// `file` (the whole file) or `yjs` (a note's collaboration state).
    pub kind: String,
    pub seq_at_snapshot: i64,
    pub doc_key_id: i64,
    pub label: String,
    pub keep_forever: bool,
    /// A conditional save: stored only if the file still holds this version
    /// (an id, or [`ORIGINAL`]); otherwise `409` with
    /// `ApiError::version_conflict`.
    pub based_on: Option<String>,
}

/// Names the original upload where a version id is expected.
pub const ORIGINAL: &str = "original";

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
    /// `file` or `yjs`.
    #[serde(default)]
    pub kind: String,
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
    /// The file key generation it was sealed at.
    pub key_generation: u32,
    /// A whole-file version: the version it replaced (none: the original
    /// upload, or not recorded).
    #[serde(default)]
    pub parent_version_id: Option<String>,
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

    /// Streams the file's current content with the version it is: an id, or
    /// [`ORIGINAL`] (`None` from a server that does not say).
    pub fn download_current_stream(&self, file_id: &str) -> Result<(Response, Option<String>)> {
        let resp = self.download_file_stream(file_id)?;
        let version = resp
            .headers()
            .get("x-kutup-version")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        Ok((resp, version))
    }

    /// The original upload's encrypted bytes, while the server keeps it.
    pub fn download_original(&self, file_id: &str) -> Result<Vec<u8>> {
        let resp = self
            .upload_request(Method::GET, &format!("/files/{file_id}/original"))
            .send()?;
        Ok(ok_stream(resp, "download original")?.bytes()?.to_vec())
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

    /// Stores a sealed version in one request; returns its row.
    pub fn create_version(
        &self,
        file_id: &str,
        encrypted_content: Vec<u8>,
        version: &NewVersion,
    ) -> Result<VersionRow> {
        let part = Part::bytes(encrypted_content)
            .file_name("version")
            .mime_str("application/octet-stream")?;
        let mut form = Form::new()
            .text("kind", version.kind.clone())
            .text("seqAtSnapshot", version.seq_at_snapshot.to_string())
            .text("docKeyId", version.doc_key_id.to_string())
            .text("keepForever", version.keep_forever.to_string());
        if !version.label.is_empty() {
            form = form.text("label", version.label.clone());
        }
        if let Some(based_on) = &version.based_on {
            form = form.text("basedOn", based_on.clone());
        }
        let resp = self
            .request(Method::POST, &format!("/files/{file_id}/versions"))
            .multipart(form.part("file", part))
            .send()?;
        super::decode_json(resp)
    }

    /// Stores a sealed whole-file version read from `encrypted` (`length`
    /// bytes) in one request, without holding it in memory.
    pub fn create_version_stream(
        &self,
        file_id: &str,
        encrypted: impl std::io::Read + Send + 'static,
        length: u64,
        version: &NewVersion,
    ) -> Result<VersionRow> {
        let part = Part::reader_with_length(encrypted, length)
            .file_name("version")
            .mime_str("application/octet-stream")?;
        let mut form = Form::new()
            .text("kind", version.kind.clone())
            .text("seqAtSnapshot", version.seq_at_snapshot.to_string())
            .text("docKeyId", version.doc_key_id.to_string())
            .text("keepForever", version.keep_forever.to_string());
        if !version.label.is_empty() {
            form = form.text("label", version.label.clone());
        }
        if let Some(based_on) = &version.based_on {
            form = form.text("basedOn", based_on.clone());
        }
        let resp = self
            .upload_request(Method::POST, &format!("/files/{file_id}/versions"))
            .multipart(form.part("file", part))
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
