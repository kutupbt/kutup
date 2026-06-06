//! S3 (SeaweedFS) storage service — mirrors `backend/services/storage.go`
//! (`aws-sdk-go-v2` → `aws-sdk-s3`).
//!
//! Path-style addressing + a static-credentials provider, exactly like the Go
//! `NewStorage`. This slice ports the object get/put/delete + prefix-wipe paths used by
//! the files/versions/assets handlers; multipart (tus, slice 4), presign (shares, slice
//! 6), copy, and version-delete (cleanup, slice 7) are added with their slices.

use anyhow::{Context, Result};
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{Delete, ObjectIdentifier};
use aws_sdk_s3::Client;

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
}
