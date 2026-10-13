//! Live e2e for new versions over tus (docs/plans/drive-unique-names.md,
//! "Replace"): resumable at any size, as Proton Drive's revisions; checked
//! when the upload starts and again when it lands, where the content, the
//! next metadata revision and the content hash are stored together. One open
//! version upload per file.
//!
//! Gated on `KUTUP_LIVE_SERVER` (and `KUTUP_LIVE_DATABASE_URL` for the
//! table's own check):
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test version_uploads_live -- --nocapture

use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};
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
    let c = Client::new();
    let owner = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    let file = seal_file(&folder, &uuid(), b"first");
    assert!(upload(&c, &base, &owner.token, &folder, &file)
        .status()
        .is_success());
    let before = used(&c, &base, &owner.token);

    let plain = vec![7u8; PART + 1000];
    let blob = drive_object::encrypt_file_blob(
        &plain,
        &file.key,
        DriveFileBlobContextV1::new(&file.id, 1).unwrap(),
    )
    .unwrap();
    let hash = "ab".repeat(32);
    let next = metadata(&file, 2, plain.len());
    let fields = [
        ("metadataEnvelope", next.as_str()),
        ("metadataRevision", "2"),
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
    // Checked when it starts: a stale revision, a stale basis, too large.
    let stale = metadata(&file, 3, plain.len());
    let r = create_version(
        &c,
        &base,
        &owner.token,
        &file.id,
        blob.len(),
        &[
            ("metadataEnvelope", stale.as_str()),
            ("metadataRevision", "3"),
        ],
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(code(r), "revision_conflict");
    let r = create_version(
        &c,
        &base,
        &owner.token,
        &file.id,
        blob.len(),
        &[
            ("metadataEnvelope", next.as_str()),
            ("metadataRevision", "2"),
            ("basedOn", "00000000-0000-4000-8000-000000000000"),
        ],
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(code(r), "version_conflict");
    let r = create_version(&c, &base, &owner.token, &file.id, 1 << 50, &fields);
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // A new file's fields are not a version's.
    let r = create_version(
        &c,
        &base,
        &owner.token,
        &file.id,
        blob.len(),
        &[
            ("metadataEnvelope", next.as_str()),
            ("metadataRevision", "2"),
            ("nameHash", hash.as_str()),
        ],
    );
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let r = create_version(&c, &base, &owner.token, &file.id, blob.len(), &fields);
    assert_eq!(r.status(), StatusCode::CREATED);
    let at = location(&r);
    let created: Value = r.json().unwrap();
    let version_id = created["versionId"].as_str().unwrap().to_owned();
    // One open version upload per file; the caller is told which is theirs.
    let r = create_version(&c, &base, &owner.token, &file.id, blob.len(), &fields);
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let body: Value = r.json().unwrap();
    assert_eq!(body["code"], "versionUploading");
    assert_eq!(body["uploadId"], at.rsplit('/').next().unwrap());
    assert!(body["idleSeconds"].as_i64().unwrap() < 60, "{body}");

    // A blob sealed for another file is refused at its first byte.
    let other = drive_object::encrypt_file_blob(
        &plain,
        &file.key,
        DriveFileBlobContextV1::new(&uuid(), 1).unwrap(),
    )
    .unwrap();
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

    // Checked again when it lands: a rename meanwhile takes revision 3, so
    // an upload started at 3 is refused at the end and discarded at once.
    let third = metadata(&file, 3, 4);
    let small = drive_object::encrypt_file_blob(
        b"four",
        &file.key,
        DriveFileBlobContextV1::new(&file.id, 1).unwrap(),
    )
    .unwrap();
    let r = create_version(
        &c,
        &base,
        &owner.token,
        &file.id,
        small.len(),
        &[
            ("metadataEnvelope", third.as_str()),
            ("metadataRevision", "3"),
            ("basedOn", version_id.as_str()),
        ],
    );
    assert_eq!(r.status(), StatusCode::CREATED);
    let late = location(&r);
    let renamed = metadata(&file, 3, plain.len());
    let r = bearer(c.put(format!("{base}/api/files/{}", file.id)), &owner.token)
        .json(&json!({ "metadataEnvelope": renamed, "metadataRevision": 3 }))
        .send()
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    let r = patch(&c, &base, &owner.token, &late, 0, &small);
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(code(r), "revision_conflict");
    let head = bearer(c.head(format!("{base}{late}")), &owner.token)
        .header("Tus-Resumable", "1.0.0")
        .send()
        .unwrap();
    assert_eq!(head.status(), StatusCode::NOT_FOUND);
    assert_eq!(used(&c, &base, &owner.token), before + blob.len() as i64);
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
                "INSERT INTO uploads (user_id, collection_id, file_id, total_bytes,
                    metadata_envelope, file_key_envelope, key_epoch, storage_path, s3_upload_id,
                    name_hash, kind, key_generation)
                 VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 1, 'm', $2, 1,
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
