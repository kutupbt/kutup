//! File versions + streaming download — mirrors `internal/api/versions.go`
//! (the subset the CLI needs: listing, version/main streaming, latest-preferred).

use anyhow::{bail, Result};
use reqwest::blocking::Response;
use reqwest::Method;
use serde::Deserialize;

use super::Client;

/// Mirrors `backend/handlers/file_versions.go:versionRow`.
#[derive(Debug, Clone, Deserialize)]
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

fn ok_stream(resp: Response, what: &str) -> Result<Response> {
    if resp.status().as_u16() >= 400 {
        let code = resp.status().as_u16();
        bail!("{what}: HTTP {}: {}", code, resp.text().unwrap_or_default());
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
}
