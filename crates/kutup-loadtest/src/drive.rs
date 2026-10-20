//! Drive as the apps use it: a folder of the user's own, files encrypted
//! client-side (the typed file blob, 5 MiB secretstream chunks) and uploaded
//! with tus one encrypted chunk per PATCH, as the web uploader sends them;
//! downloads decrypted and checked.

use anyhow::{ensure, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1, FILE_BLOB_PREFIX_BYTES};
use kutup_crypto::stream::{ABYTES, CHUNK_SIZE};
use rand_08::RngCore as _;
use serde_json::json;

use crate::account::User;
use crate::api::{self, Api};

pub struct Folder {
    pub id: String,
    pub key: [u8; 32],
}

/// A file this user uploaded, to download later.
pub struct Uploaded {
    pub id: String,
    pub key: [u8; 32],
    pub size: usize,
}

/// A stand-in name hash: the server keeps names' hashes apart, never reads
/// them, so any 64 hex digits unique to the file do.
fn name_hash(id: &str) -> String {
    id.replace('-', "").repeat(2)
}

fn context(
    purpose: DriveEnvelopePurpose,
    object: &str,
    parent: &str,
) -> Result<DriveEnvelopeContextV1> {
    Ok(DriveEnvelopeContextV1::new(purpose, 1, 1, object, parent)?)
}

pub async fn create_folder(api: &Api, user: &User) -> Result<Folder> {
    let id = uuid::Uuid::new_v4().to_string();
    let mut key = [0u8; 32];
    rand_08::thread_rng().fill_bytes(&mut key);
    let body = json!({
        "id": id,
        "ownerKeyEnvelope": drive_envelope::seal_b64(&key, &user.master_key, context(DriveEnvelopePurpose::CollectionKey, &id, &user.id)?)?,
        "nameEnvelope": drive_envelope::seal_b64(b"Load test", &key, context(DriveEnvelopePurpose::CollectionName, &id, &user.id)?)?,
        "epochStatement": CollectionEpochStatementV1::create(&id, &user.id, 1, None, &key, user.identity.authority_signing_key())?.encode_b64(),
        "parentCollectionId": null,
        "nameHash": name_hash(&id),
    });
    api::ok(
        api.post("/collections", &user.token)
            .json(&body)
            .send()
            .await?,
    )
    .await?;
    Ok(Folder { id, key })
}

/// Encrypts `size` random bytes and uploads them with tus.
pub async fn upload(api: &Api, user: &User, folder: &Folder, size: usize) -> Result<Uploaded> {
    let id = uuid::Uuid::new_v4().to_string();
    let mut key = [0u8; 32];
    let mut plain = vec![0u8; size];
    {
        let mut rng = rand_08::thread_rng();
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut plain);
    }
    // The encryption is the client's real cost: done off the async threads.
    let (blob, metadata_envelope, file_key_envelope) = {
        let (id, folder_id, folder_key) = (id.clone(), folder.id.clone(), folder.key);
        tokio::task::spawn_blocking(move || -> Result<_> {
            let blob = drive_object::encrypt_file_blob(
                &plain,
                &key,
                DriveFileBlobContextV1::new(&id, 1)?,
            )?;
            let metadata = json!({
                "name": format!("{id}.bin"), "mimeType": "application/octet-stream", "size": size,
            });
            let metadata_envelope = drive_envelope::seal_b64(
                metadata.to_string().as_bytes(),
                &key,
                DriveEnvelopeContextV1::file_metadata(&id, 1, 1)?,
            )?;
            let file_key_envelope = drive_envelope::seal_b64(
                &key,
                &folder_key,
                DriveEnvelopeContextV1::file_key(&id, &folder_id, 1, 1)?,
            )?;
            Ok((blob, metadata_envelope, file_key_envelope))
        })
        .await??
    };
    let name_hash = name_hash(&id);
    let meta = [
        ("fileId", id.as_str()),
        ("collectionId", folder.id.as_str()),
        ("metadataEnvelope", metadata_envelope.as_str()),
        ("fileKeyEnvelope", file_key_envelope.as_str()),
        ("nameHash", name_hash.as_str()),
    ]
    .iter()
    .map(|(k, v)| format!("{k} {}", STANDARD.encode(v.as_bytes())))
    .collect::<Vec<_>>()
    .join(",");
    let created = api::ok(
        api.post("/uploads", &user.token)
            .header("Tus-Resumable", "1.0.0")
            .header("Upload-Length", blob.len().to_string())
            .header("Upload-Metadata", meta)
            .send()
            .await?,
    )
    .await?;
    let location = created
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let upload_id = location.rsplit('/').next().unwrap_or_default().to_owned();
    ensure!(!upload_id.is_empty(), "tus create gave no Location");

    // One encrypted chunk per PATCH, the first with the blob's prefix.
    let mut offset = 0usize;
    while offset < blob.len() {
        let part = if offset == 0 {
            FILE_BLOB_PREFIX_BYTES + CHUNK_SIZE + ABYTES
        } else {
            CHUNK_SIZE + ABYTES
        };
        let end = (offset + part).min(blob.len());
        api::ok(
            api.http
                .patch(api.url(&format!("/uploads/{upload_id}")))
                .bearer_auth(&user.token)
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Offset", offset.to_string())
                .header("Content-Type", "application/offset+octet-stream")
                .body(blob[offset..end].to_vec())
                .send()
                .await?,
        )
        .await?;
        offset = end;
    }
    Ok(Uploaded { id, key, size })
}

/// Downloads a file and decrypts it, as opening it does.
pub async fn download(api: &Api, user: &User, file: &Uploaded) -> Result<()> {
    let blob = api::ok(
        api.get(&format!("/files/{}/download", file.id), &user.token)
            .send()
            .await?,
    )
    .await?
    .bytes()
    .await?;
    let (id, key, size) = (file.id.clone(), file.key, file.size);
    tokio::task::spawn_blocking(move || -> Result<()> {
        let plain =
            drive_object::decrypt_file_blob(&blob, &key, DriveFileBlobContextV1::new(&id, 1)?)?;
        ensure!(
            plain.len() == size,
            "the download decrypted to another size"
        );
        Ok(())
    })
    .await?
}

/// The folder's listing, as opening it does.
pub async fn list(api: &Api, user: &User, folder: &Folder) -> Result<()> {
    api::ok(
        api.get(&format!("/collections/{}/files", folder.id), &user.token)
            .send()
            .await?,
    )
    .await?;
    Ok(())
}
