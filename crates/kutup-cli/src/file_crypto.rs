//! Canonical file-record construction and verification for the CLI.
//!
//! Everything sealed under a file's key is bound to the file and the key's
//! generation; only the file-key wrap names the folder
//! (docs/plans/drive-move.md). Moving a file re-seals that one envelope.

use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore as _;
use uuid::Uuid;

use crate::api::{File, FileMetadata, MoveFileRequest, RekeyRequest, UpdateFileMetadataRequest};
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1};
use kutup_crypto::file_keyring;

/// The generation of a newly uploaded file's key.
pub const FIRST_GENERATION: u32 = 1;

pub struct CreatedFileRecord {
    pub id: String,
    pub file_key: [u8; 32],
    pub metadata_envelope: String,
    pub file_key_envelope: String,
    pub key_epoch: u32,
    pub key_generation: u32,
    pub metadata_revision: u64,
}

/// A new file record in `collection_id`: a random file key wrapped under the
/// folder key at `key_epoch`, and the metadata sealed under the file key.
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
    let file_key_envelope = seal_file_key(
        &file_key,
        &id,
        collection_id,
        key_epoch,
        FIRST_GENERATION,
        collection_key,
    )?;
    let metadata_envelope = seal_metadata(metadata, &file_key, &id, FIRST_GENERATION, 1)?;
    Ok(CreatedFileRecord {
        id,
        file_key,
        metadata_envelope,
        file_key_envelope,
        key_epoch,
        key_generation: FIRST_GENERATION,
        metadata_revision: 1,
    })
}

/// A file's key and metadata, with its folder key for the epoch the file key
/// is wrapped at (an older one when the folder rotated since).
pub fn open(file: &File, keys: &crate::keyring::Keyring) -> Result<([u8; 32], FileMetadata)> {
    let file_key = open_key(file, keys)?;
    let metadata = open_metadata(file, &file_key)?;
    Ok((file_key, metadata))
}

pub fn open_metadata(file: &File, file_key: &[u8]) -> Result<FileMetadata> {
    let metadata = drive_envelope::open_b64(
        &file.metadata_envelope,
        file_key,
        DriveEnvelopeContextV1::file_metadata(
            &file.id,
            file.key_generation,
            file.metadata_revision,
        )
        .context("invalid file envelope context")?,
    )?;
    let metadata = kutup_crypto::file_metadata::decode(&metadata)
        .map_err(|_| anyhow!("invalid file metadata"))?;
    Ok(metadata)
}

/// The file's current key, from its wrap under the folder key at the
/// file's `key_epoch`.
pub fn open_key(file: &File, keys: &crate::keyring::Keyring) -> Result<[u8; 32]> {
    open_file_key(
        &file.file_key_envelope,
        &file.id,
        &file.collection_id,
        file.key_epoch,
        file.key_generation,
        keys.at(file.key_epoch)?,
    )
}

/// Opens a file-key wrap sealed under `collection_key`.
pub fn open_file_key(
    envelope: &str,
    file_id: &str,
    collection_id: &str,
    key_epoch: u32,
    generation: u32,
    collection_key: &[u8],
) -> Result<[u8; 32]> {
    drive_envelope::open_b64(
        envelope,
        collection_key,
        DriveEnvelopeContextV1::file_key(file_id, collection_id, key_epoch, generation)
            .context("invalid file envelope context")?,
    )?
    .try_into()
    .map_err(|_| anyhow!("file key has wrong length"))
}

pub fn rename_request(
    file: &File,
    file_key: &[u8],
    metadata: &FileMetadata,
) -> Result<UpdateFileMetadataRequest> {
    let metadata_revision = file
        .metadata_revision
        .checked_add(1)
        .ok_or_else(|| anyhow!("file metadata revision exhausted"))?;
    let metadata_envelope = seal_metadata(
        metadata,
        file_key,
        &file.id,
        file.key_generation,
        metadata_revision,
    )?;
    Ok(UpdateFileMetadataRequest {
        metadata_envelope,
        metadata_revision,
        name_hash: None,
    })
}

fn validate_metadata(metadata: &FileMetadata) -> Result<()> {
    metadata
        .validate()
        .map_err(|_| anyhow!("invalid file metadata"))
}

fn seal_file_key(
    file_key: &[u8],
    file_id: &str,
    collection_id: &str,
    key_epoch: u32,
    generation: u32,
    collection_key: &[u8],
) -> Result<String> {
    Ok(drive_envelope::seal_b64(
        file_key,
        collection_key,
        DriveEnvelopeContextV1::file_key(file_id, collection_id, key_epoch, generation)
            .context("invalid file envelope context")?,
    )?)
}

fn seal_metadata(
    metadata: &FileMetadata,
    file_key: &[u8],
    file_id: &str,
    generation: u32,
    revision: u64,
) -> Result<String> {
    validate_metadata(metadata)?;
    Ok(drive_envelope::seal_b64(
        &kutup_crypto::file_metadata::encode(metadata)
            .map_err(|_| anyhow!("invalid file metadata"))?,
        file_key,
        DriveEnvelopeContextV1::file_metadata(file_id, generation, revision)
            .context("invalid file envelope context")?,
    )?)
}

/// The file key of generation `wanted`, walked down from the file's current
/// key through its own history (whichever folder the file is in).
pub fn key_at(file: &File, file_key: &[u8; 32], wanted: u32) -> Result<[u8; 32]> {
    if wanted == file.key_generation {
        return Ok(*file_key);
    }
    let chain: Vec<file_keyring::FileKeyLinkV1> = file
        .key_history
        .iter()
        .map(|entry| file_keyring::FileKeyLinkV1 {
            generation: entry.generation,
            previous_key_envelope: entry.previous_key_envelope.clone(),
        })
        .collect();
    let key = file_keyring::key_at(file_key, &file.id, file.key_generation, &chain, wanted)
        .with_context(|| format!("no file key for generation {wanted}"))?;
    key.as_slice()
        .try_into()
        .map_err(|_| anyhow!("file key has wrong length"))
}

/// The file key and generation what `/files/{id}/download` serves was
/// sealed at.
pub fn content_key(file: &File, file_key: &[u8; 32]) -> Result<([u8; 32], u32)> {
    let generation = file.content_key_generation;
    Ok((key_at(file, file_key, generation)?, generation))
}

/// A new file key (generation + 1) wrapped at the folder's current epoch,
/// the metadata re-sealed under it, and the key being left sealed under the
/// new one (docs/plans/drive-share-revocation.md, docs/plans/drive-move.md):
/// the request that moves a file past a folder rotation before anything new
/// is written to it, or before it moves.
pub fn rekey_request(
    file: &File,
    file_key: &[u8; 32],
    metadata: &FileMetadata,
    folder_key: &[u8],
    folder_epoch: u32,
) -> Result<(RekeyRequest, [u8; 32])> {
    let generation = file
        .key_generation
        .checked_add(1)
        .ok_or_else(|| anyhow!("file key generation exhausted"))?;
    let mut new_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut new_key);
    let file_key_envelope = seal_file_key(
        &new_key,
        &file.id,
        &file.collection_id,
        folder_epoch,
        generation,
        folder_key,
    )?;
    let metadata_envelope = seal_metadata(
        metadata,
        &new_key,
        &file.id,
        generation,
        file.metadata_revision,
    )?;
    let previous_key_envelope =
        file_keyring::seal_previous_key(file_key, &new_key, &file.id, generation)?;
    Ok((
        RekeyRequest {
            from_generation: file.key_generation,
            file_key_envelope,
            metadata_envelope,
            previous_key_envelope,
        },
        new_key,
    ))
}

/// The request that moves `file` to `to_collection_id`: its current key
/// sealed under the destination's key at the destination's current epoch.
/// Nothing else about the file changes.
pub fn move_request(
    file: &File,
    file_key: &[u8; 32],
    to_collection_id: &str,
    to_key_epoch: u32,
    to_collection_key: &[u8],
) -> Result<MoveFileRequest> {
    if to_collection_id == file.collection_id {
        bail!("the file is already in that folder");
    }
    Ok(MoveFileRequest {
        from_collection_id: file.collection_id.clone(),
        to_collection_id: to_collection_id.to_string(),
        to_key_epoch,
        file_key_envelope: seal_file_key(
            file_key,
            &file.id,
            to_collection_id,
            to_key_epoch,
            file.key_generation,
            to_collection_key,
        )?,
        name_hash: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::tests_support::keyring;
    use crate::keyring::Keyring;
    use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};

    const FOLDER: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_FOLDER: &str = "22222222-2222-4222-8222-222222222222";

    fn metadata() -> FileMetadata {
        FileMetadata {
            name: "notes.md".into(),
            mime_type: "text/markdown".into(),
            size: 42,
            media: None,
        }
    }

    /// A new file in FOLDER at epoch 1, as the server lists it.
    fn uploaded(folder_key: &[u8; 32]) -> (File, [u8; 32]) {
        let created = create(FOLDER, 1, folder_key, &metadata()).unwrap();
        assert_eq!(created.key_generation, FIRST_GENERATION);
        (
            File {
                content_hash: None,
                name_hash: None,
                id: created.id,
                collection_id: FOLDER.into(),
                metadata_envelope: created.metadata_envelope,
                file_key_envelope: created.file_key_envelope,
                key_epoch: created.key_epoch,
                key_generation: created.key_generation,
                metadata_revision: created.metadata_revision,
                encrypted_size_bytes: 0,
                created_at: String::new(),
                content_key_generation: 1,
                key_history: Vec::new(),
            },
            created.file_key,
        )
    }

    /// `file` after the server accepted `request` (generation + 1).
    fn after_rekey(file: &File, request: &RekeyRequest, epoch: u32) -> File {
        let mut key_history = file.key_history.clone();
        key_history.push(crate::api::FileKeyHistoryEntry {
            generation: file.key_generation + 1,
            previous_key_envelope: request.previous_key_envelope.clone(),
        });
        File {
            file_key_envelope: request.file_key_envelope.clone(),
            metadata_envelope: request.metadata_envelope.clone(),
            key_epoch: epoch,
            key_generation: file.key_generation + 1,
            key_history,
            ..file.clone()
        }
    }

    #[test]
    fn file_record_round_trips_and_the_wrap_alone_names_the_folder() {
        let folder_key = [7u8; 32];
        let (file, file_key) = uploaded(&folder_key);
        let keys = Keyring::current_only(&folder_key, 1);
        let (opened_key, opened_metadata) = open(&file, &keys).unwrap();
        assert_eq!(opened_key, file_key);
        assert_eq!(opened_metadata.name, "notes.md");

        // The wrap is bound to its folder, epoch and generation…
        let relocated = File {
            collection_id: OTHER_FOLDER.into(),
            ..file.clone()
        };
        assert!(open_key(&relocated, &keys).is_err());
        let wrong_generation = File {
            key_generation: 2,
            ..file.clone()
        };
        assert!(open_key(&wrong_generation, &keys).is_err());
        // …the metadata to the file alone: it opens in any folder.
        assert_eq!(
            open_metadata(&relocated, &file_key).unwrap().name,
            "notes.md"
        );
    }

    #[test]
    fn rename_seals_at_the_current_generation() {
        let folder_key = [7u8; 32];
        let (file, file_key) = uploaded(&folder_key);
        let mut renamed = metadata();
        renamed.name = "renamed.md".into();
        let request = rename_request(&file, &file_key, &renamed).unwrap();
        assert_eq!(request.metadata_revision, 2);
        let file = File {
            metadata_envelope: request.metadata_envelope,
            metadata_revision: 2,
            ..file
        };
        assert_eq!(open_metadata(&file, &file_key).unwrap().name, "renamed.md");
    }

    #[test]
    fn rename_keeps_a_photos_details() {
        let folder_key = [7u8; 32];
        let (file, file_key) = uploaded(&folder_key);
        let mut photo = metadata();
        photo.media = Some(kutup_crypto::file_metadata::MediaMetadataV1 {
            taken_at: Some(1_719_835_200_000),
            taken_from: Some(kutup_crypto::file_metadata::TakenFrom::Exif),
            lat: Some(41.0082),
            lon: Some(28.9784),
            ..Default::default()
        });
        let request = rename_request(&file, &file_key, &photo).unwrap();
        let file = File {
            metadata_envelope: request.metadata_envelope,
            metadata_revision: 2,
            ..file
        };
        // What `kutup mv` does: open, change the name, seal.
        let mut opened = open_metadata(&file, &file_key).unwrap();
        opened.name = "istanbul.jpg".into();
        let request = rename_request(&file, &file_key, &opened).unwrap();
        let file = File {
            metadata_envelope: request.metadata_envelope,
            metadata_revision: 3,
            ..file
        };
        let reopened = open_metadata(&file, &file_key).unwrap();
        assert_eq!(reopened.name, "istanbul.jpg");
        assert_eq!(reopened.media, photo.media);
    }

    #[test]
    fn rekey_adds_a_generation_reachable_from_the_new_key() {
        let old_folder_key = [7u8; 32];
        let (file, first_key) = uploaded(&old_folder_key);
        // Content sealed under generation 1.
        let blob = drive_object::encrypt_file_blob(
            b"hello",
            &first_key,
            DriveFileBlobContextV1::new(&file.id, 1).unwrap(),
        )
        .unwrap();

        // The folder rotates to epoch 2; the file moves to generation 2 there.
        let new_folder_key = [9u8; 32];
        let (request, second_key) =
            rekey_request(&file, &first_key, &metadata(), &new_folder_key, 2).unwrap();
        assert_eq!(request.from_generation, 1);
        assert_ne!(second_key, first_key);
        let file = after_rekey(&file, &request, 2);
        let keys = keyring(&[(1, old_folder_key), (2, new_folder_key)], 2);
        let (key_now, metadata_now) = open(&file, &keys).unwrap();
        assert_eq!(key_now, second_key);
        assert_eq!(metadata_now.name, "notes.md");

        // And once more, to generation 3 at epoch 3.
        let third_folder_key = [11u8; 32];
        let (request, third_key) =
            rekey_request(&file, &second_key, &metadata(), &third_folder_key, 3).unwrap();
        assert_eq!(request.from_generation, 2);
        let file = after_rekey(&file, &request, 3);
        assert_eq!(file.key_history.len(), 2);

        // Every older key is reached from the current one alone.
        assert_eq!(key_at(&file, &third_key, 3).unwrap(), third_key);
        assert_eq!(key_at(&file, &third_key, 2).unwrap(), second_key);
        assert_eq!(key_at(&file, &third_key, 1).unwrap(), first_key);
        assert!(key_at(&file, &third_key, 4).is_err());
        assert!(key_at(&file, &third_key, 0).is_err());

        // The upload still opens: served content is at generation 1.
        let (content, generation) = content_key(&file, &third_key).unwrap();
        assert_eq!(generation, 1);
        let plain = drive_object::decrypt_file_blob(
            &blob,
            &content,
            DriveFileBlobContextV1::new(&file.id, generation).unwrap(),
        )
        .unwrap();
        assert_eq!(plain, b"hello");

        // A history with a gap is refused, not skipped over.
        let broken = File {
            key_history: file.key_history[1..].to_vec(),
            ..file
        };
        assert!(key_at(&broken, &third_key, 1).is_err());
    }

    #[test]
    fn move_reseals_only_the_wrap_for_the_destination() {
        let source_key = [7u8; 32];
        let (file, file_key) = uploaded(&source_key);
        let dest_key = [5u8; 32];
        let request = move_request(&file, &file_key, OTHER_FOLDER, 4, &dest_key).unwrap();
        assert_eq!(request.from_collection_id, FOLDER);
        assert_eq!(request.to_collection_id, OTHER_FOLDER);
        assert_eq!(request.to_key_epoch, 4);

        // As the server stores it: the new wrap, folder and epoch; the same
        // metadata envelope, generation and content.
        let moved = File {
            collection_id: OTHER_FOLDER.into(),
            key_epoch: 4,
            file_key_envelope: request.file_key_envelope.clone(),
            ..file.clone()
        };
        let (key, metadata) = open(&moved, &Keyring::current_only(&dest_key, 4)).unwrap();
        assert_eq!(key, file_key);
        assert_eq!(metadata.name, "notes.md");
        // Sealed for the destination only.
        assert!(open(&moved, &Keyring::current_only(&source_key, 4)).is_err());
        assert!(open(
            &File {
                key_epoch: 3,
                ..moved.clone()
            },
            &keyring(&[(3, dest_key)], 3)
        )
        .is_err());

        // Not to the folder it is in.
        assert!(move_request(&file, &file_key, FOLDER, 1, &source_key).is_err());

        // Wire shape the server's MoveFileRequest (deny_unknown_fields) takes.
        let wire = serde_json::to_value(&request).unwrap();
        let mut keys: Vec<_> = wire.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "fileKeyEnvelope",
                "fromCollectionId",
                "toCollectionId",
                "toKeyEpoch"
            ]
        );
    }

    #[test]
    fn rekey_request_wire_shape() {
        let (file, file_key) = uploaded(&[7u8; 32]);
        let (request, _) = rekey_request(&file, &file_key, &metadata(), &[9u8; 32], 2).unwrap();
        let wire = serde_json::to_value(&request).unwrap();
        let mut keys: Vec<_> = wire.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "fileKeyEnvelope",
                "fromGeneration",
                "metadataEnvelope",
                "previousKeyEnvelope"
            ]
        );
    }
}
