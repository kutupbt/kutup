//! S3 (SeaweedFS) storage service — mirrors `backend/services/storage.go`
//! (`aws-sdk-go-v2` → `aws-sdk-s3`).
//!
//! Path-style addressing + a static-credentials provider, exactly like the Go
//! `NewStorage`. Covers the object get/put/delete + prefix-wipe paths (files/versions/
//! assets), the multipart paths (tus), and presigned download (public shares). Go's
//! `CopyObject` is unported — it became dead after the tus temp→canonical-key change and
//! has no caller. Version-delete (cleanup) lands with slice 7.

use std::time::Duration;

use anyhow::{Context, Result};
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    CompletedMultipartUpload, CompletedPart as S3CompletedPart, Delete, ObjectIdentifier,
};
use aws_sdk_s3::Client;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// One object's metadata from a LIST — mirrors `services.ObjectInfo`. Used by the orphan
/// sweep to age-filter candidates.
#[derive(Clone, Debug)]
pub struct ObjectInfo {
    pub key: String,
    pub size: i64,
    pub last_modified: OffsetDateTime,
}

/// The `{PartNumber, ETag}` pair S3 needs at finalize time — mirrors
/// `services.CompletedPart`. Serialised into the `uploads.s3_part_etags` JSONB column;
/// the snake_case field names match the Go `json:"part_number"`/`json:"etag"` tags so a
/// row written by either backend round-trips through the other.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletedPart {
    pub part_number: i32,
    pub etag: String,
}

/// Wraps the S3 client + target bucket — mirrors `StorageService`.
#[derive(Clone)]
pub struct StorageService {
    client: Client,
    bucket: String,
}

impl StorageService {
    /// Builds the client with path-style addressing + static creds — mirrors `NewStorage`.
    pub fn new(
        endpoint: &str,
        access_key: &str,
        secret_key: &str,
        bucket: &str,
        region: &str,
    ) -> Self {
        let creds = Credentials::new(access_key, secret_key, None, None, "kutup-static");
        let conf = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region.to_string()))
            .credentials_provider(creds)
            .endpoint_url(endpoint)
            .force_path_style(true) // SeaweedFS requires path-style
            .build();
        StorageService {
            client: Client::from_conf(conf),
            bucket: bucket.to_string(),
        }
    }

    /// Streams data to S3 — mirrors `Upload`.
    pub async fn upload(&self, path: &str, body: ByteStream, size: i64) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(path)
            .body(body)
            .content_length(size)
            .send()
            .await
            .context("s3 put")?;
        Ok(())
    }

    /// Puts an object and returns the SeaweedFS version id (empty if unversioned) —
    /// mirrors `PutObjectVersioned`.
    pub async fn put_object_versioned(
        &self,
        key: &str,
        body: ByteStream,
        size: i64,
    ) -> Result<String> {
        let out = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .content_length(size)
            .send()
            .await
            .context("s3 put versioned")?;
        Ok(out.version_id().unwrap_or("").to_string())
    }

    /// Generates a presigned GET URL valid for 15 minutes — mirrors `PresignedDownload`.
    /// Used by the public-share download endpoint.
    pub async fn presigned_download(&self, path: &str) -> Result<String> {
        let cfg =
            PresigningConfig::expires_in(Duration::from_secs(15 * 60)).context("presign config")?;
        let req = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(path)
            .presigned(cfg)
            .await
            .context("presign")?;
        Ok(req.uri().to_string())
    }

    /// Fetches an object — mirrors `GetObject`. Returns the body stream + content length.
    pub async fn get_object(&self, path: &str) -> Result<(ByteStream, i64)> {
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await
            .context("s3 get")?;
        let size = out.content_length().unwrap_or(0);
        Ok((out.body, size))
    }

    /// Deletes a specific (noncurrent) object version — mirrors `DeleteObjectVersion`.
    /// Used by the version-cleanup job.
    pub async fn delete_object_version(&self, key: &str, version_id: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .version_id(version_id)
            .send()
            .await
            .context("s3 delete version")?;
        Ok(())
    }

    /// Lists one page (≤1000 keys) under `prefix`, returning the objects + the continuation
    /// token for the next page (`None` when exhausted) — the paged half of Go's
    /// `ListObjectsPaged`. The orphan sweep drives the loop so it can do per-page DB work +
    /// inter-page sleeps.
    pub async fn list_objects_page(
        &self,
        prefix: &str,
        token: Option<String>,
    ) -> Result<(Vec<ObjectInfo>, Option<String>)> {
        let out = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .set_continuation_token(token)
            .send()
            .await
            .context("s3 list")?;
        let objs = out
            .contents()
            .iter()
            .filter_map(|o| {
                let key = o.key()?.to_string();
                let size = o.size().unwrap_or(0);
                let last_modified = o
                    .last_modified()
                    .and_then(|d| OffsetDateTime::from_unix_timestamp(d.secs()).ok())
                    .unwrap_or(OffsetDateTime::UNIX_EPOCH);
                Some(ObjectInfo {
                    key,
                    size,
                    last_modified,
                })
            })
            .collect();
        let next = if out.is_truncated() == Some(true) {
            out.next_continuation_token().map(String::from)
        } else {
            None
        };
        Ok((objs, next))
    }

    /// Fetches a specific noncurrent version — mirrors `GetObjectVersion`.
    pub async fn get_object_version(
        &self,
        path: &str,
        version_id: &str,
    ) -> Result<(ByteStream, i64)> {
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(path)
            .version_id(version_id)
            .send()
            .await
            .context("s3 get version")?;
        let size = out.content_length().unwrap_or(0);
        Ok((out.body, size))
    }

    /// Removes an object — mirrors `Delete`.
    pub async fn delete(&self, path: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await
            .context("s3 delete")?;
        Ok(())
    }

    /// Deletes up to 1000 keys in one call — mirrors `DeleteObjectsBatch`.
    pub async fn delete_objects_batch(&self, keys: &[String]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let objects: Vec<ObjectIdentifier> = keys
            .iter()
            .map(|k| ObjectIdentifier::builder().key(k).build())
            .collect::<Result<_, _>>()
            .context("build delete identifiers")?;
        let delete = Delete::builder()
            .set_objects(Some(objects))
            .quiet(true)
            .build()
            .context("build delete")?;
        self.client
            .delete_objects()
            .bucket(&self.bucket)
            .delete(delete)
            .send()
            .await
            .context("s3 delete batch")?;
        Ok(())
    }

    /// Wipes every object under a prefix — mirrors `DeletePrefix` (+ the paged LIST loop).
    /// Best-effort: callers have already removed the DB rows, so a partial failure only
    /// leaks orphan blobs (recoverable by the admin orphan sweep).
    pub async fn delete_prefix(&self, prefix: &str) -> Result<()> {
        let mut continuation: Option<String> = None;
        loop {
            let out = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .set_continuation_token(continuation.clone())
                .send()
                .await
                .context("s3 list")?;
            let keys: Vec<String> = out
                .contents()
                .iter()
                .filter_map(|o| o.key().map(String::from))
                .collect();
            if !keys.is_empty() {
                self.delete_objects_batch(&keys).await?;
            }
            if out.is_truncated() != Some(true) {
                return Ok(());
            }
            continuation = out.next_continuation_token().map(String::from);
        }
    }

    /// Opens a new S3 multipart upload at `key`, returning the opaque UploadId —
    /// mirrors `CreateMultipart`.
    pub async fn create_multipart(&self, key: &str) -> Result<String> {
        let out = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .context("s3 create multipart")?;
        out.upload_id()
            .map(String::from)
            .context("s3 create multipart: empty upload id")
    }

    /// Streams one part of a multipart upload (1-based `part_number`); returns the ETag the
    /// caller must remember for `complete_multipart` — mirrors `UploadPart`. S3 requires
    /// every part except the last to be ≥ 5 MiB; the tus handler enforces that.
    pub async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: ByteStream,
        size: i64,
    ) -> Result<String> {
        let out = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(body)
            .content_length(size)
            .send()
            .await
            .with_context(|| format!("s3 upload part {part_number}"))?;
        out.e_tag()
            .map(String::from)
            .with_context(|| format!("s3 upload part {part_number}: empty etag"))
    }

    /// Finalises the multipart upload, producing one object at `key` — mirrors
    /// `CompleteMultipart`. Parts must be in `part_number` order.
    pub async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<()> {
        let sdk_parts: Vec<S3CompletedPart> = parts
            .iter()
            .map(|p| {
                S3CompletedPart::builder()
                    .part_number(p.part_number)
                    .e_tag(&p.etag)
                    .build()
            })
            .collect();
        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(sdk_parts))
            .build();
        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .context("s3 complete multipart")?;
        Ok(())
    }

    /// Discards a multipart upload (user cancel / stale-upload sweep) — mirrors
    /// `AbortMultipart`. Idempotent per the S3 spec.
    pub async fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
            .context("s3 abort multipart")?;
        Ok(())
    }
}
