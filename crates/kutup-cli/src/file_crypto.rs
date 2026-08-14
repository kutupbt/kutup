//! Canonical file-record construction and verification for the CLI.

use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore as _;
use uuid::Uuid;

use crate::api::{File, FileMetadata, UpdateFileMetadataRequest};
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};

pub struct CreatedFileRecord {
    pub id: String,
    pub file_key: [u8; 32],
    pub metadata_envelope: String,
    pub file_key_envelope: String,
    pub key_epoch: u32,
    pub metadata_revision: u64,
}

pub fn create(
    collection_id: &str,
    key_epoch: u32,
    collection_key: &[u8],
    metadata: &FileMetadata,
) -> Result<CreatedFileRecord> {
    validate_metadata(metadata)?;
    let id = Uuid::new_v4().to_string();
    let mut file_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut file_key);
    let file_key_envelope = drive_envelope::seal_b64(
        &file_key,
        collection_key,
        context(
            DriveEnvelopePurpose::FileKey,
            key_epoch,
            1,
            &id,
            collection_id,
        )?,
    )?;
    let metadata_envelope = drive_envelope::seal_b64(
        &serde_json::to_vec(metadata)?,
        &file_key,
        context(
            DriveEnvelopePurpose::FileMetadata,
            key_epoch,
            1,
            &id,
            collection_id,
        )?,
    )?;
    Ok(CreatedFileRecord {
        id,
        file_key,
        metadata_envelope,
        file_key_envelope,
        key_epoch,
        metadata_revision: 1,
    })
}

pub fn open(file: &File, collection_key: &[u8]) -> Result<([u8; 32], FileMetadata)> {
    let file_key = open_key(file, collection_key)?;
    let metadata = open_metadata(file, &file_key)?;
    Ok((file_key, metadata))
}

pub fn open_metadata(file: &File, file_key: &[u8]) -> Result<FileMetadata> {
    let metadata = drive_envelope::open_b64(
        &file.metadata_envelope,
        file_key,
        context(
            DriveEnvelopePurpose::FileMetadata,
            file.key_epoch,
            file.metadata_revision,
            &file.id,
            &file.collection_id,
        )?,
    )?;
    let metadata: FileMetadata = serde_json::from_slice(&metadata)?;
    validate_metadata(&metadata)?;
    Ok(metadata)
}

pub fn open_key(file: &File, collection_key: &[u8]) -> Result<[u8; 32]> {
    drive_envelope::open_b64(
        &file.file_key_envelope,
        collection_key,
        context(
            DriveEnvelopePurpose::FileKey,
            file.key_epoch,
            1,
            &file.id,
            &file.collection_id,
        )?,
    )?
    .try_into()
    .map_err(|_| anyhow!("file key has wrong length"))
}

pub fn rename_request(
    file: &File,
    file_key: &[u8],
    metadata: &FileMetadata,
) -> Result<UpdateFileMetadataRequest> {
    validate_metadata(metadata)?;
    let metadata_revision = file
        .metadata_revision
        .checked_add(1)
        .ok_or_else(|| anyhow!("file metadata revision exhausted"))?;
    let metadata_envelope = drive_envelope::seal_b64(
        &serde_json::to_vec(metadata)?,
        file_key,
        context(
            DriveEnvelopePurpose::FileMetadata,
            file.key_epoch,
            metadata_revision,
            &file.id,
            &file.collection_id,
        )?,
    )?;
    Ok(UpdateFileMetadataRequest {
        metadata_envelope,
        metadata_revision,
    })
}

fn validate_metadata(metadata: &FileMetadata) -> Result<()> {
    if metadata.name.is_empty() || metadata.size < 0 {
        bail!("invalid file metadata");
    }
    Ok(())
}

fn context(
    purpose: DriveEnvelopePurpose,
    epoch: u32,
    revision: u64,
    object_id: &str,
    parent_id: &str,
) -> Result<DriveEnvelopeContextV1> {
    DriveEnvelopeContextV1::new(purpose, epoch, revision, object_id, parent_id)
        .context("invalid file envelope context")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_record_round_trips_and_rejects_relocation() {
        let collection_id = "11111111-1111-4111-8111-111111111111";
        let collection_key = [7u8; 32];
        let metadata = FileMetadata {
            name: "notes.md".into(),
            mime_type: "text/markdown".into(),
            size: 42,
        };
        let created = create(collection_id, 1, &collection_key, &metadata).unwrap();
        let file = File {
            id: created.id,
            collection_id: collection_id.into(),
            metadata_envelope: created.metadata_envelope,
            file_key_envelope: created.file_key_envelope,
            key_epoch: created.key_epoch,
            metadata_revision: created.metadata_revision,
            encrypted_size_bytes: 0,
            created_at: String::new(),
        };
        let (opened_key, opened_metadata) = open(&file, &collection_key).unwrap();
        assert_eq!(opened_key, created.file_key);
        assert_eq!(opened_metadata.name, metadata.name);

        let mut relocated = file;
        relocated.collection_id = "22222222-2222-4222-8222-222222222222".into();
        assert!(open(&relocated, &collection_key).is_err());
    }
}
