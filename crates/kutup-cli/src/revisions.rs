//! Committing a Drive revision, and reading one
//! (docs/plans/drive-block-format.md §10 slice 3, "The commit, as Proton's";
//! docs/api.md, "Uploaded revisions and the commit"). The web's
//! `upload/commit.ts`, `streamUpload.ts` (`commitUpload`) and drive-core
//! `metadataCommit.ts`, for the CLI.
//!
//! A block-format upload lands as an uploaded revision; the file's next
//! metadata (`FileMetadata`), committing to the revision and its
//! manifest's digest, makes it current. A new file's first commit names its
//! original upload (`originalRevisionId`); every later one carries what the
//! file's metadata names. A whole-buffer save (a note's state, a restored
//! version, a federated upload) commits inline with its multipart request.

use anyhow::{Context, Result};
use kutup_crypto::file_metadata::{ContentCommitmentV1, MediaMetadataV1};

use crate::api::tus::CommitRevision;
use crate::api::{ApiError, Client, File, FileMetadata};
use crate::transfer::{Expect, Opened};

/// What a file's new metadata says besides the content it commits to (the
/// web's `FileMetadataDraftV1`).
#[derive(Clone, Debug, PartialEq)]
pub struct Draft {
    pub name: String,
    pub mime_type: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub media: Option<MediaMetadataV1>,
    pub original_revision_id: Option<String>,
    pub state_revision_id: Option<String>,
    /// The metadata's version, its minimum reader and what a newer writer
    /// added (docs/plans/format-evolution.md): carried by every rewrite.
    pub v: u16,
    pub min: Option<u16>,
    pub extra: kutup_crypto::format::Extra,
}

impl Draft {
    /// `metadata` with a new size and SHA-256: what a new version of it says.
    pub fn of(metadata: &FileMetadata) -> Self {
        Self {
            name: metadata.name.clone(),
            mime_type: metadata.mime_type.clone(),
            size: metadata.size,
            sha256: metadata.sha256.clone(),
            media: metadata.media.clone(),
            original_revision_id: metadata.original_revision_id.clone(),
            state_revision_id: metadata.state_revision_id.clone(),
            v: metadata.v,
            min: metadata.min,
            extra: metadata.extra.clone(),
        }
    }

    pub fn with_content(&self, content: &ContentCommitmentV1) -> FileMetadata {
        FileMetadata {
            name: self.name.clone(),
            mime_type: self.mime_type.clone(),
            size: self.size,
            content: content.clone(),
            original_revision_id: self.original_revision_id.clone(),
            state_revision_id: self.state_revision_id.clone(),
            sha256: self.sha256.clone(),
            media: self.media.clone(),
            v: self.v,
            min: self.min,
            extra: self.extra.clone(),
        }
    }

    /// Written on top of `current` (someone else's metadata landed first):
    /// its name, and the revisions it names.
    fn on_top_of(&self, current: &FileMetadata) -> Self {
        Self {
            name: current.name.clone(),
            original_revision_id: current.original_revision_id.clone(),
            state_revision_id: current.state_revision_id.clone(),
            ..self.clone()
        }
    }
}

/// What a commit is made on top of.
#[derive(Clone, Debug)]
pub enum Base {
    /// A new file: metadata revision 1, naming this revision its original.
    NewFile,
    /// A version: the file's metadata revision the upload started from, and
    /// its folder, to read it again from when someone committed meanwhile.
    Version {
        metadata_revision: u64,
        collection_id: String,
    },
}

/// The calls a commit makes.
pub trait Commits {
    fn commit(&self, file_id: &str, revision_id: &str, body: &CommitRevision) -> Result<()>;
    /// The file's row as it is now, from its folder's listing.
    fn file_row(&self, collection_id: &str, file_id: &str) -> Result<File>;
}

impl Commits for Client {
    fn commit(&self, file_id: &str, revision_id: &str, body: &CommitRevision) -> Result<()> {
        self.commit_revision(file_id, revision_id, body)
    }
    fn file_row(&self, collection_id: &str, file_id: &str) -> Result<File> {
        current_row(self, collection_id, file_id)
    }
}

/// The file's row as it is now (there is no route for one file).
pub fn current_row(client: &Client, collection_id: &str, file_id: &str) -> Result<File> {
    client
        .list_files(collection_id)?
        .into_iter()
        .find(|f| f.id == file_id)
        .context("the file is no longer in its folder")
}

/// The `code` of a 409, if the error is one.
pub fn conflict_code(error: &anyhow::Error) -> Option<&str> {
    error
        .chain()
        .find_map(|c| c.downcast_ref::<ApiError>())
        .filter(|api| api.status == 409)
        .and_then(|api| api.code.as_deref())
}

/// The status of the server's refusal, if the error is one.
pub fn status_of(error: &anyhow::Error) -> Option<u16> {
    error
        .chain()
        .find_map(|c| c.downcast_ref::<ApiError>())
        .map(|api| api.status)
}

/// The next free name to commit a new file under when its own was taken:
/// `taken` → its `(name, name hash)`.
pub type FreeName<'a> = &'a dyn Fn(&str) -> Result<(String, String)>;

/// One revision's commit.
pub struct CommitUpload<'a> {
    pub file_id: &'a str,
    pub revision_id: &'a str,
    pub file_key: &'a [u8; 32],
    pub key_generation: u32,
    pub content: &'a ContentCommitmentV1,
    pub draft: Draft,
    pub base: Base,
    /// A new file whose name was taken while it uploaded commits under the
    /// next free one (at most [`MAX_COMMIT_RENAMES`] times).
    pub free_name: Option<FreeName<'a>>,
}

/// How many other names a new file's commit tries.
pub const MAX_COMMIT_RENAMES: usize = 3;

/// Commits an uploaded revision; the name it was committed under. A `409
/// revision_conflict` reads the file again and seals on top of it, once
/// (a version keeps a name changed meanwhile); `alreadyCommitted` is
/// success; a new file's taken name moves to the next free one. Anything
/// else is returned as it came: the caller settles the upload.
pub fn commit_upload(server: &impl Commits, opts: &CommitUpload<'_>) -> Result<String> {
    let mut draft = opts.draft.clone();
    let mut name_hash = None;
    let mut renames = 0;
    loop {
        match commit_once(server, opts, &draft, name_hash.clone()) {
            Ok(name) => return Ok(name),
            Err(error) => {
                let taken = conflict_code(&error) == Some("name_taken");
                let renamable = matches!(opts.base, Base::NewFile) && renames < MAX_COMMIT_RENAMES;
                let Some(free_name) = opts.free_name.filter(|_| taken && renamable) else {
                    return Err(error);
                };
                let (name, hash) = free_name(&draft.name)?;
                draft.name = name;
                name_hash = Some(hash);
                renames += 1;
            }
        }
    }
}

fn commit_once(
    server: &impl Commits,
    opts: &CommitUpload<'_>,
    draft: &Draft,
    name_hash: Option<String>,
) -> Result<String> {
    let revision_content_envelope = crate::transfer::seal_revision_content(
        opts.file_key,
        opts.file_id,
        opts.key_generation,
        opts.content,
        draft.size,
    )?;
    let seal = |draft: &Draft, metadata_revision: u64| -> Result<CommitRevision> {
        let metadata = match opts.base {
            // A new file's first commit names its original upload.
            Base::NewFile => Draft {
                original_revision_id: Some(opts.revision_id.to_string()),
                ..draft.clone()
            }
            .with_content(opts.content),
            Base::Version { .. } => draft.with_content(opts.content),
        };
        Ok(CommitRevision {
            metadata_envelope: crate::file_crypto::seal_metadata(
                &metadata,
                opts.file_key,
                opts.file_id,
                opts.key_generation,
                metadata_revision,
            )?,
            metadata_revision,
            revision_content_envelope: revision_content_envelope.clone(),
            name_hash: name_hash.clone(),
        })
    };
    let first = match &opts.base {
        Base::NewFile => 1,
        Base::Version {
            metadata_revision, ..
        } => metadata_revision + 1,
    };
    let error = match server.commit(opts.file_id, opts.revision_id, &seal(draft, first)?) {
        Ok(()) => return Ok(draft.name.clone()),
        Err(error) => error,
    };
    match conflict_code(&error) {
        Some("alreadyCommitted") => return Ok(draft.name.clone()),
        Some("revision_conflict") => {}
        _ => return Err(error),
    }
    let Base::Version { collection_id, .. } = &opts.base else {
        return Err(error);
    };
    // Someone wrote the file meanwhile: on top of what it is now, once.
    let row = server.file_row(collection_id, opts.file_id)?;
    if row.key_generation != opts.key_generation {
        return Err(error.context("the file's key changed since the upload started"));
    }
    let current = crate::file_crypto::open_metadata(&row, opts.file_key)
        .context("decrypt the file's current metadata")?;
    let draft = draft.on_top_of(&current);
    match server.commit(
        opts.file_id,
        opts.revision_id,
        &seal(&draft, row.metadata_revision + 1)?,
    ) {
        Ok(()) => Ok(draft.name),
        Err(error) if conflict_code(&error) == Some("alreadyCommitted") => Ok(draft.name),
        Err(error) => Err(error),
    }
}

/// The next free name in a folder for `taken`: `stem (n).ext`, the first
/// whose hash no file or subfolder there holds (as "Keep both" picks it).
pub fn free_name_in(
    client: &Client,
    collection_id: &str,
    hash_key: &[u8; 32],
    taken: &str,
) -> Result<(String, String)> {
    let mut held: std::collections::HashSet<String> = client
        .list_files(collection_id)?
        .into_iter()
        .filter_map(|f| f.name_hash)
        .collect();
    held.extend(
        client
            .list_collections()?
            .into_iter()
            .filter(|c| c.parent_collection_id.as_deref() == Some(collection_id))
            .filter_map(|c| c.name_hash),
    );
    let (stem, extension) = split_name(taken);
    for n in 2..1000 {
        let name = format!("{stem} ({n}){extension}");
        let hash = crate::names::name_hash(hash_key, &name)?;
        if !held.contains(&hash) {
            return Ok((name, hash));
        }
    }
    anyhow::bail!("no free name for {taken} in its folder")
}

/// `report (2).pdf` → (`report`, `.pdf`): the stem without a clash's number.
fn split_name(name: &str) -> (String, String) {
    let (stem, extension) = match name.rfind('.') {
        Some(dot) if dot > 0 => (&name[..dot], &name[dot..]),
        _ => (name, ""),
    };
    let stem = match stem.rfind(" (") {
        Some(at) if stem.ends_with(')') && stem[at + 2..stem.len() - 1].parse::<u32>().is_ok() => {
            &stem[..at]
        }
        _ => stem,
    };
    (stem.to_string(), extension.to_string())
}

// ------------------------------------------------------------- whole saves

/// The file a save commits its next metadata on top of (drive-core's
/// `MetadataTarget`): its row as last known and its current key.
pub struct Target<'a> {
    pub file: &'a File,
    pub file_key: &'a [u8; 32],
}

/// Saves `plaintext` as a new version of `target.file` in one multipart
/// request, committing the file's next metadata with it: `change` turns the
/// file's metadata into the next (a whole file's new content and size, or a
/// note's state naming `stateRevisionId`). When someone else's metadata
/// landed first (`409 revision_conflict`), `change` is applied to theirs and
/// the save sent again, once. Returns the version's row.
pub fn save_version(
    client: &Client,
    target: &Target<'_>,
    plaintext: &[u8],
    version: crate::api::versions::NewVersion,
    change: impl Fn(&FileMetadata, &crate::transfer::SealedRevision, &str) -> FileMetadata,
) -> Result<crate::api::versions::VersionRow> {
    let identity = crate::drive_signer::identity(client)?;
    let file = target.file;
    let revision_id = uuid::Uuid::new_v4().to_string();
    let sealed = crate::transfer::seal_revision(
        plaintext,
        target.file_key,
        &file.id,
        &revision_id,
        file.key_generation,
        identity.signer(),
    )?;
    let attempt = |row: &File| -> Result<crate::api::versions::VersionRow> {
        if row.key_generation != file.key_generation {
            anyhow::bail!("the file's key changed since the save started");
        }
        let current = crate::file_crypto::open_metadata(row, target.file_key)
            .context("decrypt the file's metadata")?;
        let next = change(&current, &sealed, &revision_id);
        let metadata_revision = row.metadata_revision + 1;
        let request = crate::api::versions::NewVersion {
            revision_id: revision_id.clone(),
            revision_content_envelope: sealed.revision_content_envelope.clone(),
            metadata_envelope: crate::file_crypto::seal_metadata(
                &next,
                target.file_key,
                &file.id,
                file.key_generation,
                metadata_revision,
            )?,
            metadata_revision,
            ..version.clone()
        };
        client.create_version(&file.id, sealed.bytes.clone(), &request)
    };
    match attempt(file) {
        Err(error) if conflict_code(&error) == Some("revision_conflict") => {
            attempt(&current_row(client, &file.collection_id, &file.id)?)
        }
        other => other,
    }
}

// ----------------------------------------------------------------- reading

/// Reads a revision of `file_id` through `route` into `dst`, opened against
/// `expect` under `file_key` of `generation`, and checks its signer (a
/// warning, never a refusal).
#[allow(clippy::too_many_arguments)]
pub fn read(
    client: &Client,
    route: &crate::api::versions::ContentRoute<'_>,
    file_key: &[u8; 32],
    file_id: &str,
    generation: u32,
    expect: &Expect,
    dst: &mut impl std::io::Write,
    on_progress: impl FnMut(u64),
) -> Result<Opened> {
    let opened = crate::transfer::read_object(
        |range| client.get_range(route, range),
        file_key,
        file_id,
        generation,
        expect,
        dst,
        on_progress,
    )?;
    crate::drive_signer::check(client, &opened.manifest, file_id, &opened.revision_id);
    Ok(opened)
}

/// [`read`] into memory.
pub fn read_to_vec(
    client: &Client,
    route: &crate::api::versions::ContentRoute<'_>,
    file_key: &[u8; 32],
    file_id: &str,
    generation: u32,
    expect: &Expect,
) -> Result<(Vec<u8>, Opened)> {
    let mut out = Vec::new();
    let opened = read(
        client,
        route,
        file_key,
        file_id,
        generation,
        expect,
        &mut out,
        |_| {},
    )?;
    Ok((out, opened))
}

/// What the file's current content must be: what its metadata commits to.
pub fn current(metadata: &FileMetadata) -> Expect {
    Expect::Current {
        content: metadata.content.clone(),
        size: metadata.size,
    }
}

/// Reads the file's current content into memory, sealed at its
/// `contentKeyGeneration`; with the version the server named.
pub fn read_current(
    client: &Client,
    file: &File,
    file_key: &[u8; 32],
) -> Result<(Vec<u8>, Opened)> {
    let metadata =
        crate::file_crypto::open_metadata(file, file_key).context("decrypt file metadata")?;
    let (key, generation) = crate::file_crypto::content_key(file, file_key)?;
    read_to_vec(
        client,
        &crate::api::versions::ContentRoute::Current(&file.id),
        &key,
        &file.id,
        generation,
        &current(&metadata),
    )
}

/// Reads a listed version into memory, against its sealed record.
pub fn read_version(
    client: &Client,
    file: &File,
    file_key: &[u8; 32],
    version: &crate::api::versions::VersionRow,
) -> Result<Vec<u8>> {
    let key = crate::file_crypto::key_at(file, file_key, version.key_generation)?;
    Ok(read_to_vec(
        client,
        &crate::api::versions::ContentRoute::Version(&file.id, &version.id),
        &key,
        &file.id,
        version.key_generation,
        &Expect::Revision {
            revision_id: version.id.clone(),
            envelope: version.revision_content_envelope.clone(),
        },
    )?
    .0)
}

/// Reads the original upload into memory: the revision the file's metadata
/// names (`originalRevisionId`), with the record served with it.
pub fn read_original(client: &Client, file: &File, file_key: &[u8; 32]) -> Result<Vec<u8>> {
    let metadata =
        crate::file_crypto::open_metadata(file, file_key).context("decrypt file metadata")?;
    let original = metadata
        .original_revision_id
        .context("the file's metadata names no original upload")?;
    let generation = file.original_key_generation;
    let key = crate::file_crypto::key_at(file, file_key, generation)?;
    Ok(read_to_vec(
        client,
        &crate::api::versions::ContentRoute::Original(&file.id),
        &key,
        &file.id,
        generation,
        &Expect::Revision {
            revision_id: original,
            envelope: None,
        },
    )?
    .0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn a_clash_number_is_replaced_not_added_to() {
        assert_eq!(split_name("report.pdf"), ("report".into(), ".pdf".into()));
        assert_eq!(
            split_name("report (2).pdf"),
            ("report".into(), ".pdf".into())
        );
        assert_eq!(split_name("notes"), ("notes".into(), "".into()));
        assert_eq!(split_name(".bashrc"), (".bashrc".into(), "".into()));
        assert_eq!(split_name("a (x).txt"), ("a (x)".into(), ".txt".into()));
    }

    const FILE: &str = "11111111-1111-4111-8111-111111111111";
    const REVISION: &str = "22222222-2222-4222-8222-222222222222";
    const FOLDER: &str = "33333333-3333-4333-8333-333333333333";

    /// A server that answers each commit with the next of `answers` (`None`:
    /// accepted) and keeps what was sent.
    struct Fake {
        answers: RefCell<Vec<Option<&'static str>>>,
        sent: RefCell<Vec<CommitRevision>>,
        row: File,
    }

    impl Commits for Fake {
        fn commit(&self, _: &str, _: &str, body: &CommitRevision) -> Result<()> {
            self.sent.borrow_mut().push(body.clone());
            match self.answers.borrow_mut().remove(0) {
                None => Ok(()),
                Some(code) => Err(anyhow::Error::new(ApiError::from_parts(
                    409,
                    "",
                    format!(r#"{{"error":"no","code":"{code}"}}"#),
                ))),
            }
        }
        fn file_row(&self, _: &str, _: &str) -> Result<File> {
            Ok(self.row.clone())
        }
    }

    fn draft() -> Draft {
        Draft {
            name: "a.txt".into(),
            mime_type: "text/plain".into(),
            size: 3,
            sha256: None,
            media: None,
            original_revision_id: None,
            state_revision_id: None,
            v: kutup_crypto::file_metadata::FILE_METADATA_VERSION,
            min: None,
            extra: Default::default(),
        }
    }

    fn row(key: &[u8; 32], metadata_revision: u64, name: &str) -> File {
        let content = ContentCommitmentV1::new([7; 16], [8; 32]);
        let metadata = Draft {
            name: name.into(),
            original_revision_id: Some("77777777-7777-4777-8777-777777777777".into()),
            ..draft()
        }
        .with_content(&content);
        File {
            id: FILE.into(),
            collection_id: FOLDER.into(),
            metadata_envelope: crate::file_crypto::seal_metadata(
                &metadata,
                key,
                FILE,
                1,
                metadata_revision,
            )
            .unwrap(),
            file_key_envelope: String::new(),
            key_epoch: 1,
            key_generation: 1,
            metadata_revision,
            encrypted_size_bytes: 0,
            created_at: String::new(),
            content_key_generation: 1,
            original_key_generation: 1,
            key_history: Vec::new(),
            name_hash: None,
            content_hash: None,
        }
    }

    fn opened(key: &[u8; 32], body: &CommitRevision) -> FileMetadata {
        let file = File {
            metadata_envelope: body.metadata_envelope.clone(),
            metadata_revision: body.metadata_revision,
            ..row(key, 1, "x")
        };
        crate::file_crypto::open_metadata(&file, key).unwrap()
    }

    #[test]
    fn a_new_file_names_its_original_and_moves_to_a_free_name() {
        let key = [5u8; 32];
        let content = ContentCommitmentV1::new(
            *uuid::Uuid::parse_str(REVISION).unwrap().as_bytes(),
            [1; 32],
        );
        let fake = Fake {
            answers: RefCell::new(vec![Some("name_taken"), Some("name_taken"), None]),
            sent: RefCell::new(Vec::new()),
            row: row(&key, 1, "a.txt"),
        };
        let free = |taken: &str| Ok((format!("{taken}+"), format!("hash-{taken}")));
        let name = commit_upload(
            &fake,
            &CommitUpload {
                file_id: FILE,
                revision_id: REVISION,
                file_key: &key,
                key_generation: 1,
                content: &content,
                draft: draft(),
                base: Base::NewFile,
                free_name: Some(&free),
            },
        )
        .unwrap();
        assert_eq!(name, "a.txt++");
        let sent = fake.sent.borrow();
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[0].name_hash, None);
        assert_eq!(sent[2].name_hash.as_deref(), Some("hash-a.txt+"));
        let metadata = opened(&key, &sent[2]);
        assert_eq!(metadata.name, "a.txt++");
        assert_eq!(metadata.original_revision_id.as_deref(), Some(REVISION));
        assert_eq!(metadata.content, content);
        assert!(sent.iter().all(|body| body.metadata_revision == 1));
    }

    #[test]
    fn a_version_reseals_once_on_top_of_a_rename_and_already_committed_is_success() {
        let key = [5u8; 32];
        let content = ContentCommitmentV1::new(
            *uuid::Uuid::parse_str(REVISION).unwrap().as_bytes(),
            [1; 32],
        );
        let commit = |answers: Vec<Option<&'static str>>| {
            let fake = Fake {
                answers: RefCell::new(answers),
                sent: RefCell::new(Vec::new()),
                row: row(&key, 4, "renamed.txt"),
            };
            let result = commit_upload(
                &fake,
                &CommitUpload {
                    file_id: FILE,
                    revision_id: REVISION,
                    file_key: &key,
                    key_generation: 1,
                    content: &content,
                    draft: draft(),
                    base: Base::Version {
                        metadata_revision: 2,
                        collection_id: FOLDER.into(),
                    },
                    free_name: None,
                },
            );
            (result, fake.sent.into_inner())
        };
        let (result, sent) = commit(vec![Some("revision_conflict"), None]);
        assert_eq!(result.unwrap(), "renamed.txt");
        assert_eq!(sent[0].metadata_revision, 3);
        assert_eq!(sent[1].metadata_revision, 5);
        let metadata = opened(&key, &sent[1]);
        assert_eq!(metadata.name, "renamed.txt");
        assert_eq!(
            metadata.original_revision_id.as_deref(),
            Some("77777777-7777-4777-8777-777777777777")
        );
        // Once only.
        let (result, sent) = commit(vec![Some("revision_conflict"), Some("revision_conflict")]);
        assert!(result.is_err());
        assert_eq!(sent.len(), 2);
        // An interrupted commit that took effect.
        let (result, _) = commit(vec![Some("alreadyCommitted")]);
        assert!(result.is_ok());
        // A lost object is the caller's to settle.
        let (result, _) = commit(vec![Some("objectMissing")]);
        assert_eq!(conflict_code(&result.unwrap_err()), Some("objectMissing"));
    }
}
