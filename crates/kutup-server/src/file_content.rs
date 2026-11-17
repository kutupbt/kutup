//! What a Drive file holds now (docs/plans/drive-versions-v2.md): its latest
//! whole-file version when it has one — office documents and whiteboards save
//! the complete file, sealed exactly like the upload — otherwise the original
//! upload. Every path that serves a file's bytes asks here, so the owner's
//! download, public links and federated reads all see edited content.
//! Notes' versions are Yjs state (`kind = 'yjs'`), never served as the file.

use aws_sdk_s3::primitives::ByteStream;
use axum::http::{HeaderMap, HeaderName};
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

use crate::content_range;
use crate::error::AppResult;
use crate::storage::StorageService;

/// Where a revision of a file is stored (docs/plans/drive-block-format.md
/// §3): the original upload and every version alike, under the file's own
/// prefix beside its assets and thumbnails (`files/{id}/…`), whoever
/// uploaded it and from wherever (a peer's upload too). Rows stored before
/// keep the paths they name (`original`, `versions/{id}`).
pub fn revision_path(file_id: Uuid, revision: Uuid) -> String {
    format!("files/{file_id}/revisions/{revision}")
}

pub struct CurrentContent {
    pub path: String,
    pub size: i64,
    /// The `drive_file_versions` row it came from; `None` for the original upload.
    pub version: Option<Uuid>,
    /// Its revision id: the version's id, or the original's
    /// `content_revision_id`. Its bytes never change, so it is the ETag.
    pub revision: Uuid,
    /// A block-format revision's sealed content record
    /// (docs/plans/drive-block-format.md §2): served with it, so a reader
    /// that is not reading the current content (the original upload, a
    /// version) opens it against a committed digest.
    pub revision_content_envelope: Option<String>,
}

/// The response header naming the revision served.
pub const REVISION_HEADER: &str = "x-kutup-revision";
/// The response header carrying the revision's sealed content record.
pub const REVISION_CONTENT_HEADER: &str = "x-kutup-revision-content";

/// The headers naming a revision and, in the block format, its sealed
/// content record.
pub fn revision_headers(
    revision: Uuid,
    revision_content_envelope: Option<&str>,
) -> Vec<(HeaderName, String)> {
    let mut headers = vec![(
        HeaderName::from_static(REVISION_HEADER),
        revision.to_string(),
    )];
    if let Some(envelope) = revision_content_envelope {
        headers.push((
            HeaderName::from_static(REVISION_CONTENT_HEADER),
            envelope.to_owned(),
        ));
    }
    headers
}

pub async fn current_content(pool: &PgPool, file_id: Uuid) -> sqlx::Result<Option<CurrentContent>> {
    let version: Option<(Uuid, String, i64, Option<String>)> = sqlx::query_as(
        "SELECT id, storage_path, size_bytes, revision_content_envelope FROM drive_file_versions
         WHERE file_id = $1 AND kind = 'file'
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await?;
    if let Some((id, path, size, revision_content_envelope)) = version {
        return Ok(Some(CurrentContent {
            path,
            size,
            version: Some(id),
            revision: id,
            revision_content_envelope,
        }));
    }
    original_content(pool, file_id).await
}

/// The original upload, while it is kept (retention prunes it once versions
/// cover it). An office editing session that began before the first save
/// loads it as its base (docs/onlyoffice.md, "Collaboration sessions").
pub async fn original_content(
    pool: &PgPool,
    file_id: Uuid,
) -> sqlx::Result<Option<CurrentContent>> {
    let original: Option<(String, i64, Uuid, Option<String>)> = sqlx::query_as(
        "SELECT storage_path, encrypted_size_bytes, content_revision_id, revision_content_envelope
         FROM drive_files
         WHERE id = $1 AND deleted_at IS NULL AND NOT original_pruned",
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await?;
    Ok(original.map(
        |(path, size, revision, revision_content_envelope)| CurrentContent {
            path,
            size,
            version: None,
            revision,
            revision_content_envelope,
        },
    ))
}

impl CurrentContent {
    pub async fn open(&self, storage: &StorageService) -> anyhow::Result<(ByteStream, i64)> {
        storage.get_object(&self.path).await
    }

    /// Serves it whole, or the one range `headers` ask for (its ETag the
    /// revision id), naming the revision and carrying its sealed content
    /// record.
    pub async fn serve(
        &self,
        pool: &PgPool,
        storage: &StorageService,
        headers: &HeaderMap,
        extra: &[(HeaderName, String)],
    ) -> AppResult<Response> {
        let mut named = revision_headers(self.revision, self.revision_content_envelope.as_deref());
        named.extend_from_slice(extra);
        content_range::serve_revision(
            pool,
            storage,
            &self.path,
            self.size,
            self.revision,
            headers,
            &named,
        )
        .await
    }
}
