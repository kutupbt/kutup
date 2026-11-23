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
/// `services.CompletedPart`. Serialised into the `drive_uploads.s3_part_etags` JSONB column;
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

/// How long the object store may take (docs/self-hosting.md, "Object
/// storage"): a stalled store fails a request with a clear error instead of
/// holding it, and whatever it holds (a database transaction), for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S3Timeouts {
    /// Opening a connection (`S3_CONNECT_TIMEOUT_SECONDS`).
    pub connect: std::time::Duration,
    /// Waiting for the store's answer once a request is sent
    /// (`S3_READ_TIMEOUT_SECONDS`).
    pub read: std::time::Duration,
    /// A transfer, up or down, that moves no bytes this long fails
    /// (`S3_STALL_SECONDS`): a slow link keeps going, a stuck one doesn't.
    /// Whole objects can be many gigabytes, so a transfer has no total limit.
    pub stall: std::time::Duration,
    /// One try of a request without a body (heads, deletes, lists, the
    /// multipart bookkeeping) (`S3_REQUEST_TIMEOUT_SECONDS`); all its tries
    /// together get `max_attempts` times this.
    pub request: std::time::Duration,
    /// Tries of a request, the first included (`S3_MAX_ATTEMPTS`).
    pub max_attempts: u32,
}

impl Default for S3Timeouts {
    fn default() -> Self {
        Self {
            connect: std::time::Duration::from_secs(10),
            read: std::time::Duration::from_secs(60),
            stall: std::time::Duration::from_secs(20),
            request: std::time::Duration::from_secs(30),
            max_attempts: 3,
        }
    }
}

/// Wraps the S3 client + target bucket — mirrors `StorageService`.
#[derive(Clone)]
pub struct StorageService {
    /// For requests that carry an object's bytes: connect, read and stall
    /// limits, no total (an object may be gigabytes).
    client: Client,
    /// For requests without a body: also a limit per try and in all.
    quick: Client,
    bucket: String,
    /// Where deletes wait before they reach the store (`None`: they go at
    /// once). The server defers them for at least the site setting
    /// `server.storage.deleted_blob_retention_seconds`, so a database dump restored
    /// from before a delete never names a purged blob
    /// (docs/plans/restore-drill-and-alerting.md, gap 5; `crate::blob_purge`).
    deferred: Option<sqlx::PgPool>,
}

/// What a deferred delete removes, as `storage_pending_deletions.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingKind {
    /// The key ([`StorageService::delete`]).
    Object,
    /// Every object under the prefix ([`StorageService::delete_prefix`]).
    Prefix,
}

impl PendingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PendingKind::Object => "object",
            PendingKind::Prefix => "prefix",
        }
    }

    pub fn parse(value: &str) -> Option<PendingKind> {
        Some(match value {
            "object" => PendingKind::Object,
            "prefix" => PendingKind::Prefix,
            _ => return None,
        })
    }
}

impl StorageService {
    /// Builds the client with path-style addressing + static creds — mirrors `NewStorage`.
    pub fn new(
        endpoint: &str,
        access_key: &str,
        secret_key: &str,
        bucket: &str,
        region: &str,
        timeouts: S3Timeouts,
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
            .timeout_config(
                aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                    .connect_timeout(timeouts.connect)
                    .read_timeout(timeouts.read)
                    .build(),
            )
            .stalled_stream_protection(
                aws_sdk_s3::config::StalledStreamProtectionConfig::enabled()
                    .upload_enabled(true)
                    .download_enabled(true)
                    .grace_period(timeouts.stall)
                    .build(),
            )
            .retry_config(
                aws_sdk_s3::config::retry::RetryConfig::standard()
                    .with_max_attempts(timeouts.max_attempts.max(1)),
            )
            .build();
        let quick = conf
            .to_builder()
            .timeout_config(
                aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                    .connect_timeout(timeouts.connect)
                    .read_timeout(timeouts.read)
                    .operation_attempt_timeout(timeouts.request)
                    .operation_timeout(timeouts.request * timeouts.max_attempts.max(1))
                    .build(),
            )
            .build();
        StorageService {
            client: Client::from_conf(conf),
            quick: Client::from_conf(quick),
            bucket: bucket.to_string(),
            deferred: None,
        }
    }

    /// This store with its deletes deferred through `pool`'s
    /// `storage_pending_deletions`: what the server and its subcommands use.
    pub fn with_deferred_deletes(mut self, pool: sqlx::PgPool) -> Self {
        self.deferred = Some(pool);
        self
    }

    /// This store with deletes that reach it at once: for the purge job
    /// itself and for `storage-check`, which removes only its own probes.
    pub fn immediate(&self) -> Self {
        StorageService {
            deferred: None,
            ..self.clone()
        }
    }

    /// Queues deletes for the purge job. A key already waiting keeps its
    /// first time (the earlier one is the one a dump could name).
    async fn defer(&self, pool: &sqlx::PgPool, kind: PendingKind, keys: &[String]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO storage_pending_deletions (kind, key)
             SELECT $1, key FROM UNNEST($2::text[]) AS key
             ON CONFLICT (kind, key) DO NOTHING",
        )
        .bind(kind.as_str())
        .bind(keys)
        .execute(pool)
        .await
        .context("queue storage delete")?;
        Ok(())
    }

    /// Before a write to `key`: a delete of the key still waiting would
    /// remove the new object, so it is called off. A purge already holding
    /// that row finishes first (the row lock), so the write lands after it.
    async fn cancel_pending(&self, key: &str) -> Result<()> {
        let Some(pool) = &self.deferred else {
            return Ok(());
        };
        sqlx::query(
            "DELETE FROM storage_pending_deletions
             WHERE key = $1 AND kind = 'object'",
        )
        .bind(key)
        .execute(pool)
        .await
        .context("cancel queued storage delete")?;
        Ok(())
    }

    /// Streams data to S3 — mirrors `Upload`.
    pub async fn upload(&self, path: &str, body: ByteStream, size: i64) -> Result<()> {
        self.cancel_pending(path).await?;
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

    /// An object's length as the store holds it now, or `None` when there is
    /// no such object (a HEAD): what a commit asks before it makes an
    /// uploaded revision a file's content.
    pub async fn object_len(&self, path: &str) -> Result<Option<i64>> {
        // A HEAD has no body: the per-try and total limits apply.
        match self
            .quick
            .head_object()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await
        {
            Ok(out) => Ok(Some(out.content_length().unwrap_or(0))),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_not_found()) =>
            {
                Ok(None)
            }
            Err(error) => Err(error).context("s3 head"),
        }
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

    /// Bytes `start..=end` of an object `total` bytes long (as recorded): the
    /// store must answer exactly that part of an object of that length, or
    /// this fails, so a changed or short object is never served as a part.
    pub async fn get_object_range(
        &self,
        path: &str,
        start: u64,
        end: u64,
        total: u64,
    ) -> Result<ByteStream> {
        anyhow::ensure!(start <= end && end < total, "range outside the object");
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(path)
            .range(format!("bytes={start}-{end}"))
            .send()
            .await
            .context("s3 get range")?;
        let expected = format!("bytes {start}-{end}/{total}");
        anyhow::ensure!(
            out.content_range() == Some(expected.as_str())
                && out.content_length() == Some((end - start + 1) as i64),
            "the store answered another range than {expected}"
        );
        Ok(out.body)
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
            .quick
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

    /// Removes an object. Every key holds one revision of something and is
    /// never overwritten (docs/architecture.md, "Object storage"), so the
    /// bucket needs no versioning and a plain delete is final.
    pub async fn delete(&self, path: &str) -> Result<()> {
        if let Some(pool) = &self.deferred {
            return self
                .defer(pool, PendingKind::Object, &[path.to_owned()])
                .await;
        }
        self.quick
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
        if let Some(pool) = &self.deferred {
            return self.defer(pool, PendingKind::Object, keys).await;
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
        self.quick
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
        if let Some(pool) = &self.deferred {
            return self
                .defer(pool, PendingKind::Prefix, &[prefix.to_owned()])
                .await;
        }
        let mut continuation: Option<String> = None;
        loop {
            let out = self
                .quick
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
        self.cancel_pending(key).await?;
        let out = self
            .quick
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
        self.quick
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

    /// Multipart uploads the store holds that were started before
    /// `before_unix_secs` (key, upload id), at most `limit`: what the sweep
    /// of incomplete uploads looks at (`jobs::sweep_incomplete_multipart`).
    pub async fn list_multipart_uploads_before(
        &self,
        before_unix_secs: i64,
        limit: usize,
    ) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        let mut key_marker: Option<String> = None;
        let mut upload_id_marker: Option<String> = None;
        loop {
            let page = self
                .quick
                .list_multipart_uploads()
                .bucket(&self.bucket)
                .set_key_marker(key_marker.take())
                .set_upload_id_marker(upload_id_marker.take())
                .send()
                .await
                .context("s3 list multipart uploads")?;
            for upload in page.uploads() {
                let (Some(key), Some(id), Some(initiated)) =
                    (upload.key(), upload.upload_id(), upload.initiated())
                else {
                    continue;
                };
                if initiated.secs() < before_unix_secs {
                    out.push((key.to_owned(), id.to_owned()));
                    if out.len() >= limit {
                        return Ok(out);
                    }
                }
            }
            if page.is_truncated() != Some(true) {
                return Ok(out);
            }
            key_marker = page.next_key_marker().map(str::to_owned);
            upload_id_marker = page.next_upload_id_marker().map(str::to_owned);
            if key_marker.is_none() && upload_id_marker.is_none() {
                return Ok(out);
            }
        }
    }

    /// Discards a multipart upload (user cancel / stale-upload sweep) — mirrors
    /// `AbortMultipart`. Idempotent per the S3 spec.
    /// Aborts a multipart upload. One the store no longer knows (aborted
    /// before, or completed) is gone already: that is success, so a row
    /// left behind can still be cleaned up.
    pub async fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
        match self
            .quick
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_no_such_upload()) =>
            {
                Ok(())
            }
            Err(error) => Err(anyhow::Error::new(error).context("s3 abort multipart")),
        }
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
