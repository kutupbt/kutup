//! Live e2e for the commit of an uploaded revision
//! (docs/plans/drive-block-format.md §10 slice 3, "The commit, as
//! Proton's"): a block-format upload lands stored, checked and reserved, but
//! not current; `POST /api/v1/drive/files/{id}/revisions/{revisionId}/commit` brings
//! the metadata committing to it and makes it current in one transaction. A
//! new file is listed nowhere before its first commit.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test drive_commit_live -- --nocapture

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::blocks::SignerIdentity;
use kutup_crypto::drive_blocks::{self, DriveBlobContextV2};
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1};
use kutup_crypto::file_metadata::{encode, ContentCommitmentV1, FileMetadata};
use reqwest::blocking::{multipart, Client, Response};
use reqwest::StatusCode;
use serde_json::Value;

mod common;
use common::*;

/// A block-format object of `plain` for `revision` of `file` (generation 1),
/// and its manifest's digest.
fn sealed(user: &User, file: &Sealed, revision: &str, plain: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let identity = SignerIdentity {
        account_id: *uuid::Uuid::parse_str(&user.id).unwrap().as_bytes(),
        incarnation_id: hex::decode(user.identity.incarnation_id())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let object = drive_blocks::seal_file(
        plain,
        &file.key,
        DriveBlobContextV2::new(&file.id, revision, 1).unwrap(),
        user.identity.drive_signing_key(),
        identity,
    )
    .unwrap();
    (object.bytes, object.manifest_sha256)
}

/// `FileMetadata` committing to `revision`, sealed at `metadata_revision`.
fn metadata_v2(
    file: &Sealed,
    revision: &str,
    manifest: [u8; 32],
    size: u64,
    metadata_revision: u64,
) -> String {
    let plain = encode(&FileMetadata::new(
        "a.txt",
        "text/plain",
        size,
        ContentCommitmentV1::new(
            *uuid::Uuid::parse_str(revision).unwrap().as_bytes(),
            manifest,
        ),
    ))
    .unwrap();
    drive_envelope::seal_b64(
        &plain,
        &file.key,
        DriveEnvelopeContextV1::file_metadata(&file.id, 1, metadata_revision).unwrap(),
    )
    .unwrap()
}

fn tus_meta(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k} {}", b64(v.as_bytes())))
        .collect::<Vec<_>>()
        .join(",")
}

/// Opens a tus upload and sends `bytes` in one part; the upload's location.
fn tus_upload(c: &Client, base: &str, token: &str, meta: String, bytes: &[u8]) -> String {
    let created = bearer(c.post(format!("{base}/api/v1/drive/uploads")), token)
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Length", bytes.len().to_string())
        .header("Upload-Metadata", meta)
        .send()
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let location = created.headers()["location"].to_str().unwrap().to_owned();
    let r = bearer(c.patch(format!("{base}{location}")), token)
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Offset", "0")
        .header("Content-Type", "application/offset+octet-stream")
        .body(bytes.to_vec())
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    location
}

/// A new file by tus, in the block format: no metadata yet.
fn upload_new(
    c: &Client,
    base: &str,
    token: &str,
    folder: &Folder,
    file: &Sealed,
    revision: &str,
    bytes: &[u8],
) -> String {
    let name_hash = test_name_hash(&file.id);
    tus_upload(
        c,
        base,
        token,
        tus_meta(&[
            ("fileId", &file.id),
            ("collectionId", &folder.id),
            ("fileKeyEnvelope", &file.file_key_envelope),
            ("nameHash", &name_hash),
            ("revisionId", revision),
        ]),
        bytes,
    )
}

fn listed(c: &Client, base: &str, token: &str, folder: &Folder, file_id: &str) -> bool {
    let in_folder: Value = bearer(
        c.get(format!(
            "{base}/api/v1/drive/collections/{}/files",
            folder.id
        )),
        token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let everywhere: Value = bearer(c.get(format!("{base}/api/v1/drive/files")), token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let has = |rows: &Value| {
        rows.as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == file_id)
    };
    assert_eq!(has(&in_folder), has(&everywhere));
    has(&in_folder)
}

fn code(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    (
        status,
        response.json::<Value>().unwrap_or(Value::Null)["code"].clone(),
    )
}

fn live() -> Option<String> {
    match std::env::var("KUTUP_LIVE_SERVER") {
        Ok(base) => Some(base.trim_end_matches('/').to_string()),
        Err(_) => {
            eprintln!("KUTUP_LIVE_SERVER not set; skipping");
            None
        }
    }
}

#[test]
fn an_uploaded_file_appears_only_once_committed() {
    let Some(base) = live() else { return };
    let c = client();
    let owner = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    let file = seal_file(&folder, &uuid(), b"unused");
    let revision = uuid();
    let plain = b"committed content".repeat(4000);
    let (bytes, manifest) = sealed(&owner, &file, &revision, &plain);
    let before = used(&c, &base, &owner.token);

    upload_new(&c, &base, &owner.token, &folder, &file, &revision, &bytes);
    // Uploaded, not current: listed nowhere, not readable, not charged yet
    // (only reserved).
    assert!(!listed(&c, &base, &owner.token, &folder, &file.id));
    assert_eq!(
        download(&c, &base, &owner.token, &file.id).0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(used(&c, &base, &owner.token), before);

    // The metadata of a new file is revision 1.
    let wrong = metadata_v2(&file, &revision, manifest, plain.len() as u64, 2);
    assert_eq!(
        code(commit(
            &c,
            &base,
            &owner.token,
            &file.id,
            &revision,
            &wrong,
            2,
            &revision_content_at(&file, &revision)
        )),
        (StatusCode::CONFLICT, Value::from("revisionConflict"))
    );
    assert!(!listed(&c, &base, &owner.token, &folder, &file.id));

    let metadata = metadata_v2(&file, &revision, manifest, plain.len() as u64, 1);
    let r = commit(
        &c,
        &base,
        &owner.token,
        &file.id,
        &revision,
        &metadata,
        1,
        &revision_content_at(&file, &revision),
    );
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().unwrap();
    assert_eq!(body["kind"], "file");
    assert_eq!(body["revisionId"], revision.as_str());
    assert!(listed(&c, &base, &owner.token, &folder, &file.id));
    assert_eq!(
        download(&c, &base, &owner.token, &file.id),
        (StatusCode::OK, bytes.clone())
    );
    assert_eq!(used(&c, &base, &owner.token), before + bytes.len() as i64);

    // Committed once: a second commit changes nothing.
    assert_eq!(
        code(commit(
            &c,
            &base,
            &owner.token,
            &file.id,
            &revision,
            &metadata,
            1,
            &revision_content_at(&file, &revision)
        )),
        (StatusCode::CONFLICT, Value::from("alreadyCommitted"))
    );
    assert_eq!(used(&c, &base, &owner.token), before + bytes.len() as i64);

    purge_accounts(&c, &base, &[&owner]);
}

#[test]
fn a_commit_takes_only_its_own_files_revision() {
    let Some(base) = live() else { return };
    let c = client();
    let owner = register(&c, &base);
    let stranger = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    let first = seal_file(&folder, &uuid(), b"unused");
    let second = seal_file(&folder, &uuid(), b"unused");
    let first_revision = uuid();
    let second_revision = uuid();
    let (first_bytes, first_manifest) = sealed(&owner, &first, &first_revision, b"one");
    let (second_bytes, _) = sealed(&owner, &second, &second_revision, b"two");
    upload_new(
        &c,
        &base,
        &owner.token,
        &folder,
        &first,
        &first_revision,
        &first_bytes,
    );
    let second_upload = upload_new(
        &c,
        &base,
        &owner.token,
        &folder,
        &second,
        &second_revision,
        &second_bytes,
    );

    // Another file's revision under this file, or a revision never uploaded.
    let metadata = metadata_v2(&first, &first_revision, first_manifest, 3, 1);
    for (file_id, revision) in [
        (&first.id, &second_revision),
        (&second.id, &first_revision),
        (&first.id, &uuid()),
    ] {
        assert_eq!(
            commit(
                &c,
                &base,
                &owner.token,
                file_id,
                revision,
                &metadata,
                1,
                &revision_content_at(&first, revision)
            )
            .status(),
            StatusCode::NOT_FOUND
        );
    }
    // Someone else's upload.
    assert_eq!(
        commit(
            &c,
            &base,
            &stranger.token,
            &first.id,
            &first_revision,
            &metadata,
            1,
            &revision_content_at(&first, &first_revision)
        )
        .status(),
        StatusCode::NOT_FOUND
    );
    // An envelope sealed for another file.
    let other = metadata_v2(&second, &first_revision, first_manifest, 3, 1);
    assert_eq!(
        commit(
            &c,
            &base,
            &owner.token,
            &first.id,
            &first_revision,
            &other,
            1,
            &revision_content_at(&first, &first_revision)
        )
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(!listed(&c, &base, &owner.token, &folder, &first.id));
    assert_eq!(
        commit(
            &c,
            &base,
            &owner.token,
            &first.id,
            &first_revision,
            &metadata,
            1,
            &revision_content_at(&first, &first_revision)
        )
        .status(),
        StatusCode::OK
    );
    assert!(!listed(&c, &base, &owner.token, &folder, &second.id));

    // A cancelled upload is gone with its object: nothing to commit.
    let r = bearer(c.delete(format!("{base}{second_upload}")), &owner.token)
        .header("Tus-Resumable", "1.0.0")
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let metadata = metadata_v2(&second, &second_revision, [0; 32], 3, 1);
    assert_eq!(
        commit(
            &c,
            &base,
            &owner.token,
            &second.id,
            &second_revision,
            &metadata,
            1,
            &revision_content_at(&second, &second_revision)
        )
        .status(),
        StatusCode::NOT_FOUND
    );

    purge_accounts(&c, &base, &[&owner, &stranger]);
}

#[test]
fn a_version_commit_keeps_the_old_content_in_history() {
    let Some(base) = live() else { return };
    let c = client();
    let owner = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    let file = seal_file(&folder, &uuid(), b"unused");

    // A small new file: the multipart upload commits inline, naming
    // metadata revision 1.
    let original = uuid();
    let (original_bytes, original_manifest) = sealed(&owner, &file, &original, b"first");
    let form = |revision: Option<&str>| {
        let mut form = multipart::Form::new()
            .text("fileId", file.id.clone())
            .text("collectionId", folder.id.clone())
            .text("fileKeyEnvelope", file.file_key_envelope.clone())
            .text(
                "metadataEnvelope",
                metadata_v2(&file, &original, original_manifest, 5, 1),
            )
            .text("nameHash", test_name_hash(&file.id))
            .text("revisionId", original.clone())
            .text(
                "revisionContentEnvelope",
                revision_content_of(&file, &original, original_manifest, 5, 1),
            );
        if let Some(revision) = revision {
            form = form.text("metadataRevision", revision.to_owned());
        }
        form.part(
            "file",
            multipart::Part::bytes(original_bytes.clone()).file_name("encrypted"),
        )
    };
    let send = |form: multipart::Form| {
        bearer(c.post(format!("{base}/api/v1/drive/files")), &owner.token)
            .multipart(form)
            .send()
            .unwrap()
    };
    assert_eq!(send(form(None)).status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        code(send(form(Some("2")))),
        (StatusCode::CONFLICT, Value::from("revisionConflict"))
    );
    assert_eq!(send(form(Some("1"))).status(), StatusCode::CREATED);

    // A new version by tus: uploaded, the original still current.
    let version = uuid();
    let (next, next_manifest) = sealed(&owner, &file, &version, b"second, longer");
    tus_upload(
        &c,
        &base,
        &owner.token,
        tus_meta(&[("versionOf", &file.id), ("revisionId", &version)]),
        &next,
    );
    assert_eq!(
        download(&c, &base, &owner.token, &file.id),
        (StatusCode::OK, original_bytes.clone())
    );
    // The metadata must be the file's next revision, exactly.
    for stale in [1, 3] {
        let metadata = metadata_v2(&file, &version, next_manifest, 14, stale);
        assert_eq!(
            code(commit(
                &c,
                &base,
                &owner.token,
                &file.id,
                &version,
                &metadata,
                stale as i64,
                &revision_content_at(&file, &version)
            )),
            (StatusCode::CONFLICT, Value::from("revisionConflict"))
        );
    }
    let metadata = metadata_v2(&file, &version, next_manifest, 14, 2);
    // What the version is, sealed for it: one sealed for another revision,
    // or none, is refused.
    let content = revision_content_of(&file, &version, next_manifest, 14, 1);
    assert_eq!(
        commit(
            &c,
            &base,
            &owner.token,
            &file.id,
            &version,
            &metadata,
            2,
            &revision_content_of(&file, &original, next_manifest, 14, 1)
        )
        .status(),
        StatusCode::BAD_REQUEST
    );
    let without = bearer(
        c.post(format!(
            "{base}/api/v1/drive/files/{}/revisions/{version}/commit",
            file.id
        )),
        &owner.token,
    )
    .json(&serde_json::json!({ "metadataEnvelope": metadata, "metadataRevision": 2 }))
    .send()
    .unwrap();
    assert!(without.status().is_client_error());
    let r = commit(
        &c,
        &base,
        &owner.token,
        &file.id,
        &version,
        &metadata,
        2,
        &content,
    );
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.json::<Value>().unwrap()["kind"], "version");
    assert_eq!(
        download(&c, &base, &owner.token, &file.id),
        (StatusCode::OK, next.clone())
    );
    // The content it replaced is in the history: the original, the new
    // version's parent.
    let versions: Value = bearer(
        c.get(format!("{base}/api/v1/drive/files/{}/versions", file.id)),
        &owner.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let rows = versions.as_array().unwrap();
    assert_eq!(rows.len(), 1, "{versions}");
    assert_eq!(rows[0]["id"], version.as_str());
    assert!(rows[0]["parentVersionId"].is_null());
    // Each revision carries what it is, and it opens to its digest and size.
    assert_eq!(rows[0]["revisionContentEnvelope"], content.as_str());
    let opened = kutup_crypto::revision_content::open_revision_content(
        &STANDARD.decode(&content).unwrap(),
        &file.key,
        &file.id,
        &version,
        1,
    )
    .unwrap();
    assert_eq!(
        (opened.size, opened.commitment()),
        (
            14,
            ContentCommitmentV1::new(
                *uuid::Uuid::parse_str(&version).unwrap().as_bytes(),
                next_manifest
            )
        )
    );
    let original_now = bearer(
        c.get(format!("{base}/api/v1/drive/files/{}/original", file.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert_eq!(original_now.status(), StatusCode::OK);
    assert_eq!(
        original_now.headers()["x-kutup-revision"].to_str().unwrap(),
        original
    );
    let original_content = original_now.headers()["x-kutup-revision-content"]
        .to_str()
        .unwrap()
        .to_owned();
    let opened = kutup_crypto::revision_content::open_revision_content(
        &STANDARD.decode(&original_content).unwrap(),
        &file.key,
        &file.id,
        &original,
        1,
    )
    .unwrap();
    assert_eq!(
        (opened.revision_id.as_str(), opened.size),
        (original.as_str(), 5)
    );
    assert_eq!(original_now.bytes().unwrap().to_vec(), original_bytes);

    // Committed once only.
    assert_eq!(
        code(commit(
            &c,
            &base,
            &owner.token,
            &file.id,
            &version,
            &metadata,
            2,
            &revision_content_at(&file, &version)
        )),
        (StatusCode::CONFLICT, Value::from("alreadyCommitted"))
    );

    purge_accounts(&c, &base, &[&owner]);
}
