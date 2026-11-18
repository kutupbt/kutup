//! File versions + streaming download — mirrors `internal/api/versions.go`
//! (the subset the CLI needs: listing, version/main streaming, latest-preferred).

use anyhow::{Context, Result};
use reqwest::blocking::multipart::{Form, Part};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::Client;
use crate::transfer::{ByteRange, Ranged};

/// A version to store with `POST /files/:id/versions` (multipart, one request:
/// the server measures and charges the body; docs/plans/drive-versions-v2.md).
#[derive(Debug, Default, Clone)]
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
    /// The block-format revision it is (`revisionId`), its sealed content
    /// record, and the file's next metadata committing to it (a whole file)
    /// or naming it as the saved state (`yjs`): the save commits inline.
    pub revision_id: String,
    pub revision_content_envelope: String,
    pub metadata_envelope: String,
    pub metadata_revision: u64,
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
    pub author_account_id: String,
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
    /// A block-format version's sealed content record (`RevisionContent`):
    /// opened first, then the version's object against it.
    #[serde(default)]
    pub revision_content_envelope: Option<String>,
}

/// Where a revision of a file is read from.
#[derive(Clone, Debug)]
pub enum ContentRoute<'a> {
    /// `/drive/files/{id}/download`: the current content.
    Current(&'a str),
    /// `/drive/files/{id}/versions/{vid}/download`.
    Version(&'a str, &'a str),
    /// `/drive/files/{id}/original`: the original upload.
    Original(&'a str),
    /// A file in a folder shared from another server.
    Federated { share_id: &'a str, file_id: &'a str },
    /// A file behind a public link (anonymous: the token is the capability).
    Public { token: &'a str, file_id: &'a str },
}

impl ContentRoute<'_> {
    fn path(&self) -> String {
        match self {
            ContentRoute::Current(id) => format!("/drive/files/{id}/download"),
            ContentRoute::Version(id, vid) => format!("/drive/files/{id}/versions/{vid}/download"),
            ContentRoute::Original(id) => format!("/drive/files/{id}/original"),
            ContentRoute::Federated { share_id, file_id } => {
                format!("/drive/federation/folder-shares/{share_id}/files/{file_id}/content")
            }
            ContentRoute::Public { token, file_id } => {
                format!("/drive/public-links/{token}/files/{file_id}/download")
            }
        }
    }
}

/// `bytes a-b/total` → total.
fn content_range_total(value: &str) -> Option<u64> {
    value
        .strip_prefix("bytes ")?
        .rsplit_once('/')?
        .1
        .parse()
        .ok()
}

impl Client {
    /// One ranged read of a revision's object (docs/api.md, "Ranges"): a
    /// `206` with its part and the whole length, or a `200` with the whole
    /// object, cut to the range here.
    pub fn get_range(&self, route: &ContentRoute<'_>, range: ByteRange) -> Result<Ranged> {
        let ByteRange::Span(a, b) = range;
        let value = format!("bytes={a}-{b}");
        let resp = self
            .upload_request(Method::GET, &route.path())
            .header(reqwest::header::RANGE, value)
            .send()?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(super::api_error(resp)).context("download");
        }
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let revision = header("x-kutup-revision");
        let revision_content = header("x-kutup-revision-content");
        let version = header("x-kutup-version");
        let total = header("content-range")
            .as_deref()
            .and_then(content_range_total);
        let bytes = resp.bytes().context("download")?.to_vec();
        let mut ranged = if status == 206 {
            Ranged {
                bytes,
                total: total.ok_or_else(|| anyhow::anyhow!("a 206 without Content-Range"))?,
                ..Default::default()
            }
        } else {
            crate::transfer::slice_whole(&bytes, range)
        };
        ranged.revision = revision;
        ranged.revision_content = revision_content;
        ranged.version = version;
        Ok(ranged)
    }

    /// Lists a file's snapshot versions, newest-first. Mirrors `ListVersions`.
    pub fn list_versions(&self, file_id: &str) -> Result<Vec<VersionRow>> {
        let resp = self
            .request(Method::GET, &format!("/drive/files/{file_id}/versions"))
            .send()?;
        super::decode_json(resp)
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
        form = form
            .text("revisionId", version.revision_id.clone())
            .text(
                "revisionContentEnvelope",
                version.revision_content_envelope.clone(),
            )
            .text("metadataEnvelope", version.metadata_envelope.clone())
            .text("metadataRevision", version.metadata_revision.to_string());
        let resp = self
            .request(Method::POST, &format!("/drive/files/{file_id}/versions"))
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
                &format!("/drive/files/{file_id}/versions/{version_id}"),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(patch)
            .send()?;
        super::decode_json(resp)
    }
}
