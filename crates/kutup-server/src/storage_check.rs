//! `kutup-server storage-check`: runs every kind of object-store request the
//! server makes against the configured bucket, so an operator can tell whether
//! an S3-compatible store (SeaweedFS, MinIO, Cloudflare R2, Backblaze B2,
//! Hetzner, AWS, …) works with Kutup before trusting it with data. It writes
//! only under its own `kutup-storage-check/<run>/` prefix and removes it.

use anyhow::{bail, ensure, Context, Result};
use aws_sdk_s3::primitives::ByteStream;
use uuid::Uuid;

use crate::storage::{CompletedPart, MultipartUpload, StorageService, MIN_PART_SIZE};

struct Report {
    failed: bool,
}

impl Report {
    fn record(&mut self, name: &str, outcome: Result<Option<String>>) {
        match outcome {
            Ok(None) => println!("ok       {name}"),
            Ok(Some(note)) => println!("ok       {name} ({note})"),
            Err(e) => {
                self.failed = true;
                println!("FAILED   {name}: {e:#}");
            }
        }
    }
}

/// Deterministic, non-repeating bytes: a store that returned the wrong part
/// or a truncated object does not compare equal.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 31 + i / 251) as u8).wrapping_add(seed))
        .collect()
}

async fn read(storage: &StorageService, key: &str) -> Result<Vec<u8>> {
    let (body, _) = storage.get_object(key).await?;
    Ok(body.collect().await.context("read body")?.to_vec())
}

async fn put(storage: &StorageService, key: &str, bytes: &[u8]) -> Result<()> {
    storage
        .upload(key, ByteStream::from(bytes.to_vec()), bytes.len() as i64)
        .await
}

async fn round_trip(storage: &StorageService, key: &str) -> Result<Option<String>> {
    let first = pattern(64 * 1024, 1);
    put(storage, key, &first).await?;
    ensure!(
        read(storage, key).await? == first,
        "read back different bytes"
    );
    let second = pattern(1024, 2);
    put(storage, key, &second).await?;
    ensure!(
        read(storage, key).await? == second,
        "an overwrite did not replace the object"
    );
    Ok(None)
}

async fn version_ids(storage: &StorageService, key: &str) -> Result<Option<String>> {
    let bytes = pattern(1024, 3);
    let id = storage
        .put_object_versioned(key, ByteStream::from(bytes.clone()), bytes.len() as i64)
        .await?;
    ensure!(
        read(storage, key).await? == bytes,
        "read back different bytes"
    );
    // How thumbnails are removed: by the version their upload returned
    // where the store can, otherwise as a plain object.
    storage.delete_stored(key, &id).await?;
    gone(storage, key).await?;
    Ok(None)
}

async fn listing(
    storage: &StorageService,
    prefix: &str,
    expected: usize,
) -> Result<Option<String>> {
    let mut seen = 0;
    let mut token = None;
    loop {
        let (page, next) = storage.list_objects_page(prefix, token).await?;
        seen += page.len();
        match next {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    ensure!(
        seen == expected,
        "listed {seen} objects, expected {expected}"
    );
    Ok(None)
}

/// A resumable upload: the client's chunks, stored the way the server stores
/// them (equal-sized parts, whatever sizes the chunks are).
async fn resumable(
    storage: &StorageService,
    key: &str,
    chunks: &[usize],
) -> Result<Option<String>> {
    let total: usize = chunks.iter().sum();
    let upload_id = storage.create_multipart(key).await?;
    let upload = MultipartUpload {
        key,
        upload_id: &upload_id,
        total_bytes: total as i64,
    };
    let mut whole = Vec::with_capacity(total);
    let mut parts: Vec<CompletedPart> = Vec::new();
    let mut pending = Vec::new();
    for (index, size) in chunks.iter().enumerate() {
        let chunk = pattern(*size, index as u8 + 10);
        let is_final = index == chunks.len() - 1;
        pending = match storage
            .append_equal_parts(upload, &mut parts, &pending, &chunk, is_final)
            .await
        {
            Ok(pending) => pending,
            Err(e) => {
                let _ = storage.abort_multipart(key, &upload_id).await;
                return Err(e);
            }
        };
        whole.extend_from_slice(&chunk);
    }
    if let Err(e) = storage.complete_multipart(key, &upload_id, &parts).await {
        let _ = storage.abort_multipart(key, &upload_id).await;
        return Err(e);
    }
    ensure!(
        read(storage, key).await? == whole,
        "the completed object is not the chunks in order"
    );
    Ok(Some(format!("{} parts", parts.len())))
}

async fn abort(storage: &StorageService, key: &str) -> Result<Option<String>> {
    let upload = storage.create_multipart(key).await?;
    let bytes = pattern(1024, 20);
    storage
        .upload_part(key, &upload, 1, ByteStream::from(bytes), 1024)
        .await?;
    storage.abort_multipart(key, &upload).await?;
    ensure!(
        storage.get_object(key).await.is_err(),
        "a cancelled upload left an object behind"
    );
    Ok(None)
}

async fn gone(storage: &StorageService, key: &str) -> Result<()> {
    if storage.get_object(key).await.is_ok() {
        bail!("{key} can still be read after it was deleted");
    }
    Ok(())
}

async fn delete_one(storage: &StorageService, key: &str) -> Result<Option<String>> {
    // Twice over, so a versioned bucket has more than one version to remove.
    put(storage, key, &pattern(512, 30)).await?;
    put(storage, key, &pattern(512, 31)).await?;
    storage.delete(key).await?;
    gone(storage, key).await?;
    Ok(None)
}

async fn delete_batch(storage: &StorageService, prefix: &str) -> Result<Option<String>> {
    let keys: Vec<String> = (0..3).map(|i| format!("{prefix}batch/{i}")).collect();
    for key in &keys {
        put(storage, key, &pattern(256, 40)).await?;
    }
    storage.delete_objects_batch(&keys).await?;
    for key in &keys {
        gone(storage, key).await?;
    }
    Ok(None)
}

async fn delete_prefix(storage: &StorageService, prefix: &str) -> Result<Option<String>> {
    storage.delete_prefix(prefix).await?;
    listing(storage, prefix, 0).await
}

/// Runs the checks and prints one line each. Returns the process exit code:
/// 0 when the store does everything Kutup requires.
pub async fn run(storage: &StorageService) -> i32 {
    let prefix = format!("kutup-storage-check/{}/", Uuid::new_v4());
    let part = MIN_PART_SIZE as usize;
    let mut report = Report { failed: false };
    println!("Checking the configured bucket under {prefix}");

    report.record(
        "store, read back and overwrite an object",
        round_trip(storage, &format!("{prefix}object")).await,
    );
    report.record(
        "store an object, then delete what was stored",
        version_ids(storage, &format!("{prefix}versioned")).await,
    );
    report.record(
        "list objects under a prefix",
        listing(storage, &prefix, 1).await,
    );
    report.record(
        "resumable upload in several chunks",
        resumable(
            storage,
            &format!("{prefix}upload"),
            &[part + 41, part + 17, part + 17, 1000],
        )
        .await,
    );
    report.record(
        "resumable upload in one small chunk",
        resumable(storage, &format!("{prefix}upload-small"), &[1000]).await,
    );
    report.record(
        "cancel a resumable upload",
        abort(storage, &format!("{prefix}upload-cancelled")).await,
    );
    report.record(
        "delete an object for good",
        delete_one(storage, &format!("{prefix}deleted")).await,
    );
    report.record(
        "delete several objects in one request",
        delete_batch(storage, &prefix).await,
    );
    report.record(
        "delete everything under a prefix",
        delete_prefix(storage, &prefix).await,
    );

    if report.failed {
        println!("This store does not do everything Kutup needs; see the failed lines above.");
        1
    } else {
        println!("This store does everything Kutup needs.");
        0
    }
}
