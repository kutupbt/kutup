//! S3 storage service — mirrors `backend/services/storage.go`
//! (`aws-sdk-go-v2` → `aws-sdk-s3`). Any S3-compatible store works, not only the
//! bundled SeaweedFS; `kutup-server storage-check` (storage_check.rs) tests one.
//!
//! Path-style addressing + a static-credentials provider, exactly like the Go
//! `NewStorage`. Covers the object get/put/delete + prefix-wipe paths (files/versions/
//! assets) and the multipart paths (tus). Go's `CopyObject` is unported — it became dead
//! after the tus temp→canonical-key change and has no caller; `PresignedDownload` was
//! dropped too (the storage endpoint is unreachable from outside the deployment, so
//! public-share downloads stream through the backend like every other download).

use anyhow::{Context, Result};
use aws_sdk_s3::config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
};
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

/// S3's smallest multipart part, other than the last.
pub const MIN_PART_SIZE: i64 = 5 * 1024 * 1024;
/// S3's most parts in one multipart upload.
const MAX_PARTS: i64 = 10_000;

/// The size every part but the last has in an upload of `total_bytes`: 5 MiB,
/// or the next whole MiB that keeps the upload within S3's 10,000 parts.
/// Fixed by the total, so every request of one upload cuts the same way.
pub fn equal_part_size(total_bytes: i64) -> i64 {
    const MIB: i64 = 1024 * 1024;
    let needed = (total_bytes.max(0) + MAX_PARTS - 1) / MAX_PARTS;
    MIN_PART_SIZE.max((needed + MIB - 1) / MIB * MIB)
}

/// How `available` bytes are stored: the lengths of the parts to upload now
/// and how many bytes wait for the next request. Every part is `part_size`
/// long except, when the upload is ending, a shorter last one.
fn cut_parts(available: usize, part_size: usize, is_final: bool) -> (Vec<usize>, usize) {
    let mut lengths = vec![part_size; available / part_size];
    let rest = available % part_size;
    if is_final && rest > 0 {
        lengths.push(rest);
        return (lengths, 0);
    }
    (lengths, rest)
}

/// A multipart upload in progress: where it lands, the store's id for it,
/// and the size the client declared.
#[derive(Clone, Copy)]
pub struct MultipartUpload<'a> {
    pub key: &'a str,
    pub upload_id: &'a str,
    pub total_bytes: i64,
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
            // Checksums only where S3 itself demands one: the SDK's default
            // adds CRC trailers to every upload, which several
            // S3-compatible stores reject.
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
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

    /// Removes an object whose upload returned `version_id`: that exact
    /// version where the store deletes by version, otherwise the object.
    /// Some stores (Cloudflare R2) return a version id for every upload and
    /// then refuse to delete by it.
    pub async fn delete_stored(&self, key: &str, version_id: &str) -> Result<()> {
        if !version_id.is_empty() && self.delete_object_version(key, version_id).await.is_ok() {
            return Ok(());
        }
        self.delete(key).await
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

    /// Removes an object for good: every stored version of it and any delete
    /// markers. On a versioned bucket a plain DELETE only hides the bytes behind
    /// a marker, so "delete" would not delete (docs/plans/drive-versions-v2.md).
    pub async fn delete(&self, path: &str) -> Result<()> {
        match self.list_object_versions(path).await {
            Ok(versions) => {
                let exact: Vec<(String, String)> = versions
                    .into_iter()
                    .filter(|(key, _)| key == path)
                    .collect();
                if exact.is_empty() {
                    return Ok(());
                }
                self.delete_versions(&exact).await
            }
            // A store without version listing: an unversioned bucket, where a
            // plain delete is final.
            Err(_) => {
                self.client
                    .delete_object()
                    .bucket(&self.bucket)
                    .key(path)
                    .send()
                    .await
                    .context("s3 delete")?;
                Ok(())
            }
        }
    }

    /// Copies one stored version of `source` to `destination` (a new plain
    /// object), server-side.
    pub async fn copy_object_version(
        &self,
        source: &str,
        version_id: &str,
        destination: &str,
    ) -> Result<()> {
        self.client
            .copy_object()
            .bucket(&self.bucket)
            .copy_source(format!(
                "{}/{}?versionId={}",
                self.bucket, source, version_id
            ))
            .key(destination)
            .send()
            .await
            .context("s3 copy version")?;
        Ok(())
    }

    /// Every stored version and delete marker under `prefix`, as (key, version id).
    async fn list_object_versions(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        let mut key_marker: Option<String> = None;
        let mut version_marker: Option<String> = None;
        loop {
            let page = self
                .client
                .list_object_versions()
                .bucket(&self.bucket)
                .prefix(prefix)
                .set_key_marker(key_marker.clone())
                .set_version_id_marker(version_marker.clone())
                .send()
                .await
                .context("s3 list versions")?;
            for v in page.versions() {
                if let (Some(key), Some(id)) = (v.key(), v.version_id()) {
                    out.push((key.to_string(), id.to_string()));
                }
            }
            for m in page.delete_markers() {
                if let (Some(key), Some(id)) = (m.key(), m.version_id()) {
                    out.push((key.to_string(), id.to_string()));
                }
            }
            if page.is_truncated() != Some(true) {
                return Ok(out);
            }
            key_marker = page.next_key_marker().map(String::from);
            version_marker = page.next_version_id_marker().map(String::from);
        }
    }

    /// Deletes exact object versions, 1000 per request.
    async fn delete_versions(&self, versions: &[(String, String)]) -> Result<()> {
        for chunk in versions.chunks(1000) {
            let objects: Vec<ObjectIdentifier> = chunk
                .iter()
                .map(|(key, id)| ObjectIdentifier::builder().key(key).version_id(id).build())
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
                .context("s3 delete versions")?;
        }
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
        // Every version under the prefix, where the store can list them; the
        // plain key listing below is the fallback for one that cannot.
        if let Ok(versions) = self.list_object_versions(prefix).await {
            return self.delete_versions(&versions).await;
        }
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

    /// Adds a client's chunk to a multipart upload as equal-sized parts,
    /// whatever size the chunk is: some stores (Cloudflare R2) refuse an
    /// upload whose parts, other than the last, differ in length. `pending`
    /// is what earlier chunks left over; the returned bytes are what this one
    /// leaves (empty when `is_final`). New parts are appended to `parts`.
    /// On an error nothing the caller holds has changed, and a retry sends
    /// the same part numbers again.
    pub async fn append_equal_parts(
        &self,
        upload: MultipartUpload<'_>,
        parts: &mut Vec<CompletedPart>,
        pending: &[u8],
        chunk: &[u8],
        is_final: bool,
    ) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(pending.len() + chunk.len());
        bytes.extend_from_slice(pending);
        bytes.extend_from_slice(chunk);
        let part_size = equal_part_size(upload.total_bytes) as usize;
        let (lengths, rest) = cut_parts(bytes.len(), part_size, is_final);
        let mut added = Vec::with_capacity(lengths.len());
        let mut offset = 0;
        for length in lengths {
            let part_number = (parts.len() + added.len()) as i32 + 1;
            let etag = self
                .upload_part(
                    upload.key,
                    upload.upload_id,
                    part_number,
                    ByteStream::from(bytes[offset..offset + length].to_vec()),
                    length as i64,
                )
                .await?;
            added.push(CompletedPart { part_number, etag });
            offset += length;
        }
        parts.extend(added);
        Ok(bytes[bytes.len() - rest..].to_vec())
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

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: i64 = 1024 * 1024;

    #[test]
    fn part_size_is_five_mib_until_ten_thousand_parts_would_not_fit() {
        assert_eq!(equal_part_size(0), 5 * MIB);
        assert_eq!(equal_part_size(1), 5 * MIB);
        assert_eq!(equal_part_size(10_000 * 5 * MIB), 5 * MIB);
        assert_eq!(equal_part_size(10_000 * 5 * MIB + 1), 6 * MIB);
        let tib = 1024 * 1024 * MIB;
        let part = equal_part_size(tib);
        assert!((tib + part - 1) / part <= 10_000);
    }

    #[test]
    fn chunks_of_any_size_become_equal_parts() {
        let part = 5 * MIB as usize;
        // How Kutup's clients upload: a first chunk 24 bytes longer, then
        // chunks of 5 MiB + 17, then a short last one.
        let chunks = [part + 17 + 24, part + 17, part + 17, 1000];
        let mut pending = 0;
        let mut stored = Vec::new();
        for (index, chunk) in chunks.iter().enumerate() {
            let (lengths, rest) = cut_parts(pending + chunk, part, index == chunks.len() - 1);
            stored.extend(lengths);
            pending = rest;
        }
        assert_eq!(pending, 0);
        assert_eq!(stored.iter().sum::<usize>(), chunks.iter().sum::<usize>());
        let (last, others) = stored.split_last().unwrap();
        assert!(others.iter().all(|length| *length == part));
        assert_eq!(*last, 24 + 3 * 17 + 1000);
    }

    #[test]
    fn cutting_keeps_what_does_not_fill_a_part() {
        assert_eq!(cut_parts(0, 10, false), (vec![], 0));
        assert_eq!(cut_parts(9, 10, false), (vec![], 9));
        assert_eq!(cut_parts(25, 10, false), (vec![10, 10], 5));
        assert_eq!(cut_parts(25, 10, true), (vec![10, 10, 5], 0));
        assert_eq!(cut_parts(20, 10, true), (vec![10, 10], 0));
        assert_eq!(cut_parts(3, 10, true), (vec![3], 0));
    }
}
