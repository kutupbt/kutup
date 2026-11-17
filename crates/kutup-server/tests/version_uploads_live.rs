//! Live e2e for new versions over tus (docs/plans/drive-unique-names.md,
//! "Replace"): resumable at any size, as Proton Drive's revisions; checked
//! when the upload starts, when it lands as an uploaded revision and at its
//! commit (docs/plans/drive-block-format.md §10 slice 3), where the content,
//! the next metadata revision and the content hash are stored together. One
//! open version upload per file.
//!
//! Gated on `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_DATABASE_URL` for the
//! table's own check):
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test version_uploads_live -- --nocapture

use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1};
use reqwest::blocking::{Client, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

const PART: usize = 5 * 1024 * 1024;

fn metadata(file: &Sealed, revision: u64, size: usize) -> String {
    drive_envelope::seal_b64(
        format!(r#"{{"name":"a.txt","mimeType":"text/plain","size":{size}}}"#).as_bytes(),
        &file.key,
        DriveEnvelopeContextV1::file_metadata(&file.id, 1, revision).unwrap(),
    )
    .unwrap()
}

fn create_version(
    c: &Client,
    base: &str,
    token: &str,
    file_id: &str,
    length: usize,
    fields: &[(&str, &str)],
) -> Response {
    let meta = std::iter::once(("versionOf", file_id))
        .chain(fields.iter().copied())
        .map(|(k, v)| format!("{k} {}", b64(v.as_bytes())))
        .collect::<Vec<_>>()
        .join(",");
    bearer(c.post(format!("{base}/api/uploads")), token)
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Length", length.to_string())
        .header("Upload-Metadata", meta)
        .send()
        .unwrap()
}

fn patch(
    c: &Client,
    base: &str,
    token: &str,
    location: &str,
    offset: usize,
    body: &[u8],
) -> Response {
    bearer(c.patch(format!("{base}{location}")), token)
        .header("Tus-Resumable", "1.0.0")
        .header("Content-Type", "application/offset+octet-stream")
        .header("Upload-Offset", offset.to_string())
        .body(body.to_vec())
        .send()
        .unwrap()
}

fn location(r: &Response) -> String {
    r.headers()["Location"].to_str().unwrap().to_owned()
}

fn code(r: Response) -> String {
    let body: Value = r.json().unwrap();
    body["code"].as_str().unwrap_or_default().to_owned()
}

fn listed(c: &Client, base: &str, token: &str, folder: &Folder, id: &str) -> Value {
    let list: Value = bearer(
        c.get(format!("{base}/api/collections/{}/files", folder.id)),
        token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let rows = list
        .get("files")
        .unwrap_or(&list)
        .as_array()
        .unwrap()
        .clone();
    rows.into_iter().find(|row| row["id"] == id).unwrap()
}

#[test]
fn a_version_uploads_resumably_and_lands_with_its_metadata() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER unset; skipping");
        return;
    };
    let c = crate::common::client();
    let owner = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    let file = seal_file(&folder, &uuid(), b"first");
    assert!(upload(&c, &base, &owner.token, &folder, &file)
        .status()
        .is_success());
    let before = used(&c, &base, &owner.token);

    let plain = vec![7u8; PART + 1000];
    let version = Version::seal(&file.id, &file.key, 1, &plain);
    let blob = version.blob.clone();
    let hash = "ab".repeat(32);
    let fields = [
        ("revisionId", version.revision.as_str()),
        ("contentHash", hash.as_str()),
        ("basedOn", "original"),
    ];

    // Someone who cannot write the file is refused.
    let stranger = register(&c, &base);
    let r = create_version(&c, &base, &stranger.token, &file.id, blob.len(), &fields);
    assert!(
        matches!(r.status(), StatusCode::FORBIDDEN | StatusCode::NOT_FOUND),
        "{}",
        r.status()
    );
    // Checked when it starts: a stale basis, too large.
    let r = create_version(
        &c,
        &base,
        &owner.token,
        &file.id,
        blob.len(),
        &[
            ("revisionId", version.revision.as_str()),
            ("basedOn", "00000000-0000-4000-8000-000000000000"),
        ],
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(code(r), "version_conflict");
    let r = create_version(&c, &base, &owner.token, &file.id, 1 << 50, &fields);
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // A new file's fields are not a version's, its metadata comes with the
    // commit, and the revision is named.
    let next = metadata(&file, 2, plain.len());
    for refused in [
        vec![
            ("revisionId", version.revision.as_str()),
            ("nameHash", hash.as_str()),
        ],
        vec![
            ("revisionId", version.revision.as_str()),
            ("metadataEnvelope", next.as_str()),
            ("metadataRevision", "2"),
        ],
        vec![("contentHash", hash.as_str())],
    ] {
        let r = create_version(&c, &base, &owner.token, &file.id, blob.len(), &refused);
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{refused:?}");
    }

    let r = create_version(&c, &base, &owner.token, &file.id, blob.len(), &fields);
    assert_eq!(r.status(), StatusCode::CREATED);
    let at = location(&r);
    let created: Value = r.json().unwrap();
    let version_id = created["versionId"].as_str().unwrap().to_owned();
    // The version's id is the revision the client chose, and the upload's:
    // clients address it by `versionId`.
    assert_eq!(version_id, version.revision);
    assert_eq!(at, format!("/api/uploads/{version_id}"));
    // One open version upload per file; the caller is told which is theirs.
    let r = create_version(&c, &base, &owner.token, &file.id, blob.len(), &fields);
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let body: Value = r.json().unwrap();
    assert_eq!(body["code"], "versionUploading");
    assert_eq!(body["uploadId"], at.rsplit('/').next().unwrap());
    assert!(body["idleSeconds"].as_i64().unwrap() < 60, "{body}");

    // A blob sealed for another file is refused at its first byte.
    let other = block_blob(&uuid(), &file.key, &version.revision, 1, &plain);
    assert_eq!(
        patch(&c, &base, &owner.token, &at, 0, &other[..PART]).status(),
        StatusCode::BAD_REQUEST
    );
    // Resumed: a part, a wrong offset, the offset asked, the rest.
    assert_eq!(
        patch(&c, &base, &owner.token, &at, 0, &blob[..PART]).status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        patch(&c, &base, &owner.token, &at, 0, &blob[..PART]).status(),
        StatusCode::CONFLICT
    );
    let head = bearer(c.head(format!("{base}{at}")), &owner.token)
        .header("Tus-Resumable", "1.0.0")
        .send()
        .unwrap();
    let offset: usize = head.headers()["Upload-Offset"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(offset, PART);
    let r = patch(&c, &base, &owner.token, &at, offset, &blob[offset..]);
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(r.headers()["X-Kutup-Version-Id"], version_id.as_str());

    // Uploaded, not yet current: the file still serves its first upload.
    let (status, body) = download(&c, &base, &owner.token, &file.id);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, file.blob);
    // The commit's metadata must be the next revision.
    let r = commit(
        &c,
        &base,
        &owner.token,
        &file.id,
        &version_id,
        &metadata(&file, 3, plain.len()),
        3,
        &version.revision_content(),
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(code(r), "revision_conflict");
    let r = commit(
        &c,
        &base,
        &owner.token,
        &file.id,
        &version_id,
        &next,
        2,
        &version.revision_content(),
    );
    assert!(r.status().is_success(), "commit: {}", r.status());

    // Landed together: the content, its metadata, its content hash, the charge.
    let (status, body) = download(&c, &base, &owner.token, &file.id);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, blob);
    let row = listed(&c, &base, &owner.token, &folder, &file.id);
    assert_eq!(row["metadataRevision"], 2, "{row}");
    assert_eq!(row["contentHash"], hash.as_str(), "{row}");
    assert_eq!(used(&c, &base, &owner.token), before + blob.len() as i64);
    let versions: Value = bearer(
        c.get(format!("{base}/api/files/{}/versions", file.id)),
        &owner.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert!(versions.to_string().contains(&version_id), "{versions}");

    // Checked again at the commit: a rename meanwhile takes revision 3, so
    // the commit naming 3 is refused, and its uploader cancels it.
    let small = Version::seal(&file.id, &file.key, 1, b"four");
    let r = create_version(
        &c,
        &base,
        &owner.token,
        &file.id,
        small.blob.len(),
        &[
            ("revisionId", small.revision.as_str()),
            ("basedOn", version_id.as_str()),
        ],
    );
    assert_eq!(r.status(), StatusCode::CREATED);
    let late = location(&r);
    assert_eq!(
        patch(&c, &base, &owner.token, &late, 0, &small.blob).status(),
        StatusCode::NO_CONTENT
    );
    let renamed = metadata(&file, 3, plain.len());
    let r = bearer(c.put(format!("{base}/api/files/{}", file.id)), &owner.token)
        .json(&json!({ "metadataEnvelope": renamed, "metadataRevision": 3 }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    let r = commit(
        &c,
        &base,
        &owner.token,
        &file.id,
        &small.revision,
        &metadata(&file, 3, 4),
        3,
        &small.revision_content(),
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(code(r), "revision_conflict");
    let r = bearer(c.delete(format!("{base}{late}")), &owner.token)
        .header("Tus-Resumable", "1.0.0")
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(used(&c, &base, &owner.token), before + blob.len() as i64);
    purge_accounts(&c, &base, &[&owner, &stranger]);
}

/// The table refuses a row that mixes a new file's fields with a version's.
#[test]
fn upload_rows_are_a_file_or_a_version() {
    let (Ok(_), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&database_url))
        .unwrap();
    let insert = |kind: &str,
                  name_hash: Option<&str>,
                  key_envelope: Option<&str>,
                  generation: Option<i32>| {
        runtime.block_on(
            sqlx::query(
                "INSERT INTO drive_uploads (account_id, collection_id, file_id, total_bytes,
                    file_key_envelope, key_epoch, storage_path, s3_upload_id,
                    name_hash, kind, key_generation)
                 VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 1, $2, 1,
                    gen_random_uuid()::text, 's', $1, $3, $4)",
            )
            .bind(name_hash)
            .bind(key_envelope)
            .bind(kind)
            .bind(generation)
            .execute(&pool),
        )
    };
    let hash = "cd".repeat(32);
    for (kind, name_hash, key_envelope, generation) in [
        ("version", Some(hash.as_str()), None, Some(1)),
        ("version", None, Some("k"), Some(1)),
        ("version", None, None, None),
        ("file", None, Some("k"), None),
        ("file", Some(hash.as_str()), None, None),
        ("file", Some(hash.as_str()), Some("k"), Some(1)),
        ("draft", Some(hash.as_str()), Some("k"), None),
    ] {
        let error = insert(kind, name_hash, key_envelope, generation).unwrap_err();
        assert!(
            error.to_string().contains("check constraint"),
            "{kind} {name_hash:?} {key_envelope:?} {generation:?}: {error}"
        );
    }
}

/// A Replace stands at the collaboration log's head: an office document
/// opened afterwards replays none of the edits made to what it replaced.
#[test]
fn a_version_over_tus_stands_at_the_log_head() {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER / KUTUP_LIVE_DATABASE_URL not set; skipping");
        return;
    };
    let c = crate::common::client();
    let owner = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    let file = seal_file(&folder, &uuid(), b"report");
    assert!(upload(&c, &base, &owner.token, &folder, &file)
        .status()
        .is_success());
    // Edits were made in the editor up to position 7.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pool = runtime
        .block_on(sqlx::PgPool::connect(&database_url))
        .unwrap();
    runtime
        .block_on(
            sqlx::query("UPDATE drive_files SET collab_log_floor = 7 WHERE id = $1::uuid")
                .bind(&file.id)
                .execute(&pool),
        )
        .unwrap();

    let version = Version::seal(&file.id, &file.key, 1, b"replaced");
    let r = create_version(
        &c,
        &base,
        &owner.token,
        &file.id,
        version.blob.len(),
        &[("revisionId", version.revision.as_str())],
    );
    assert_eq!(r.status(), StatusCode::CREATED);
    let at = location(&r);
    assert_eq!(
        patch(&c, &base, &owner.token, &at, 0, &version.blob).status(),
        StatusCode::NO_CONTENT
    );
    let r = commit(
        &c,
        &base,
        &owner.token,
        &file.id,
        &version.revision,
        &metadata(&file, 2, 8),
        2,
        &version.revision_content(),
    );
    assert!(r.status().is_success(), "commit: {}", r.status());
    let versions: Value = bearer(
        c.get(format!("{base}/api/files/{}/versions", file.id)),
        &owner.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let rows = versions
        .get("versions")
        .unwrap_or(&versions)
        .as_array()
        .unwrap()
        .clone();
    assert!(rows.iter().any(|v| v["seqAtSnapshot"] == 7), "{versions}");
    purge_accounts(&c, &base, &[&owner]);
}

/// Other writers: a share editor may upload a new version; a read-only
/// recipient may not; someone else's open upload is named only to its
/// uploader and the folder's owner, who may cancel it; a writer whose access
/// is taken away mid-upload loses the upload.
#[test]
fn other_writers_and_the_owner() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER unset; skipping");
        return;
    };
    let c = crate::common::client();
    let owner = register(&c, &base);
    let editor = register(&c, &base);
    let other_editor = register(&c, &base);
    let viewer = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    share(&c, &base, &owner, &folder, &editor, true);
    share(&c, &base, &owner, &folder, &other_editor, true);
    share(&c, &base, &owner, &folder, &viewer, false);
    let file = seal_file(&folder, &uuid(), b"shared");
    assert!(upload(&c, &base, &owner.token, &folder, &file)
        .status()
        .is_success());

    // One revision throughout: each upload of it is cancelled or lost
    // before the next starts, so its id is free again.
    let version = Version::seal(&file.id, &file.key, 1, &vec![3u8; PART + 10]);
    let blob = version.blob.clone();
    let fields = [("revisionId", version.revision.as_str())];

    // A read-only recipient cannot start one.
    let r = create_version(&c, &base, &viewer.token, &file.id, blob.len(), &fields);
    assert!(
        matches!(r.status(), StatusCode::FORBIDDEN | StatusCode::NOT_FOUND),
        "{}",
        r.status()
    );

    // An editor can.
    let r = create_version(&c, &base, &editor.token, &file.id, blob.len(), &fields);
    assert_eq!(r.status(), StatusCode::CREATED);
    let first = location(&r);
    let first_id = first.rsplit('/').next().unwrap().to_owned();
    assert_eq!(
        patch(&c, &base, &editor.token, &first, 0, &blob[..PART]).status(),
        StatusCode::NO_CONTENT
    );

    // Another editor is told only that one is open.
    let r = create_version(
        &c,
        &base,
        &other_editor.token,
        &file.id,
        blob.len(),
        &fields,
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let body: Value = r.json().unwrap();
    assert_eq!(body["code"], "versionUploading");
    assert!(body.get("uploadId").is_none(), "{body}");
    // The folder's owner is told which, and may cancel it.
    let r = create_version(&c, &base, &owner.token, &file.id, blob.len(), &fields);
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let body: Value = r.json().unwrap();
    assert_eq!(body["uploadId"], first_id.as_str());
    assert_eq!(body["yours"], false);
    // Another editor may not cancel it.
    let r = bearer(c.delete(format!("{base}{first}")), &other_editor.token)
        .header("Tus-Resumable", "1.0.0")
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = bearer(c.delete(format!("{base}{first}")), &owner.token)
        .header("Tus-Resumable", "1.0.0")
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        patch(&c, &base, &editor.token, &first, PART, &blob[PART..]).status(),
        StatusCode::NOT_FOUND
    );

    // Access taken away mid-upload: the next part is refused and the upload goes.
    let r = create_version(&c, &base, &editor.token, &file.id, blob.len(), &fields);
    assert_eq!(r.status(), StatusCode::CREATED);
    let second = location(&r);
    assert_eq!(
        patch(&c, &base, &editor.token, &second, 0, &blob[..PART]).status(),
        StatusCode::NO_CONTENT
    );
    share(&c, &base, &owner, &folder, &editor, false);
    assert_eq!(
        patch(&c, &base, &editor.token, &second, PART, &blob[PART..]).status(),
        StatusCode::FORBIDDEN
    );
    let head = bearer(c.head(format!("{base}{second}")), &editor.token)
        .header("Tus-Resumable", "1.0.0")
        .send()
        .unwrap();
    assert_eq!(head.status(), StatusCode::NOT_FOUND);
    // The slot is free again.
    let r = create_version(&c, &base, &owner.token, &file.id, blob.len(), &fields);
    assert_eq!(r.status(), StatusCode::CREATED);
    let third = location(&r);
    let r = bearer(c.delete(format!("{base}{third}")), &owner.token)
        .header("Tus-Resumable", "1.0.0")
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    purge_accounts(&c, &base, &[&owner, &editor, &other_editor, &viewer]);
}
