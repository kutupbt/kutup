//! What a Drive file holds now (docs/plans/drive-versions-v2.md): its latest
//! whole-file version when it has one — office documents and whiteboards save
//! the complete file, sealed exactly like the upload — otherwise the original
//! upload. Every path that serves a file's bytes asks here, so the owner's
//! download, public links and federated reads all see edited content.
//! Notes' versions are Yjs state (`kind = 'yjs'`), never served as the file.

use aws_sdk_s3::primitives::ByteStream;
use sqlx::PgPool;
use uuid::Uuid;

use crate::storage::StorageService;

pub struct CurrentContent {
    pub path: String,
    /// Set for objects stored as S3 object versions (versions from before v2).
    pub s3_version_id: Option<String>,
    pub size: i64,
    /// The `file_versions` row it came from; `None` for the original upload.
    pub version: Option<Uuid>,
}

pub async fn current_content(pool: &PgPool, file_id: Uuid) -> sqlx::Result<Option<CurrentContent>> {
    let version: Option<(Uuid, String, String, i64)> = sqlx::query_as(
        "SELECT id, storage_path, s3_version_id, size_bytes FROM file_versions
         WHERE file_id = $1 AND kind = 'file'
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await?;
    if let Some((id, path, s3_version_id, size)) = version {
        return Ok(Some(CurrentContent {
            path,
            s3_version_id: Some(s3_version_id).filter(|v| !v.is_empty()),
            size,
            version: Some(id),
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
    let original: Option<(String, i64)> = sqlx::query_as(
        "SELECT storage_path, encrypted_size_bytes FROM files
         WHERE id = $1 AND deleted_at IS NULL AND NOT original_pruned",
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await?;
    Ok(original.map(|(path, size)| CurrentContent {
        path,
        s3_version_id: None,
        size,
        version: None,
    }))
}

impl CurrentContent {
    pub async fn open(&self, storage: &StorageService) -> anyhow::Result<(ByteStream, i64)> {
        match &self.s3_version_id {
            Some(id) => storage.get_object_version(&self.path, id).await,
            None => storage.get_object(&self.path).await,
        }
    }
}
