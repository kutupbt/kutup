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
    /// The `file_versions` row it came from; `None` for the original upload.
    pub version: Option<Uuid>,
    /// Its revision id: the version's id, or the original's
    /// `content_revision_id`. Its bytes never change, so it is the ETag.
    pub revision: Uuid,
}

pub async fn current_content(pool: &PgPool, file_id: Uuid) -> sqlx::Result<Option<CurrentContent>> {
    let version: Option<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT id, storage_path, size_bytes FROM file_versions
         WHERE file_id = $1 AND kind = 'file'
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await?;
    if let Some((id, path, size)) = version {
        return Ok(Some(CurrentContent {
            path,
            size,
            version: Some(id),
            revision: id,
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
    let original: Option<(String, i64, Uuid)> = sqlx::query_as(
        "SELECT storage_path, encrypted_size_bytes, content_revision_id FROM files
         WHERE id = $1 AND deleted_at IS NULL AND NOT original_pruned",
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await?;
    Ok(original.map(|(path, size, revision)| CurrentContent {
        path,
        size,
        version: None,
        revision,
    }))
}

impl CurrentContent {
    pub async fn open(&self, storage: &StorageService) -> anyhow::Result<(ByteStream, i64)> {
        storage.get_object(&self.path).await
    }

    /// Serves it whole, or the one range `headers` ask for (its ETag the
    /// revision id).
    pub async fn serve(
        &self,
        pool: &PgPool,
        storage: &StorageService,
        headers: &HeaderMap,
        extra: &[(HeaderName, String)],
    ) -> AppResult<Response> {
        content_range::serve_revision(
            pool,
            storage,
            &self.path,
            self.size,
            self.revision,
            headers,
            extra,
        )
        .await
    }
}
