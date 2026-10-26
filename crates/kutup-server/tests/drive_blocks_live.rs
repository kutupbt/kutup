//! Live e2e for the block format's server side
//! (docs/plans/drive-block-format.md §3, slice 2): a block-format blob names
//! its revision, which the request names too; the server checks the header
//! and the structure on every upload path, keys each revision apart, and
//! serves one `Range` at a time with the revision id as the ETag.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test drive_blocks_live -- --nocapture

use kutup_crypto::blocks::TRAILER_LEN;
use kutup_crypto::drive_blocks::{self, DriveBlobContextV2, DRIVE_BLOCKS_HEADER_BYTES};
use reqwest::blocking::{multipart, Client, Response};
use reqwest::StatusCode;
use serde_json::Value;

mod common;
use common::*;

/// `plain` sealed in the block format for revision `revision` of `file`
/// (generation `generation`), signed by `user`.
fn blob(user: &User, file: &Sealed, revision: &str, generation: u32, plain: &[u8]) -> Vec<u8> {
    let account = *uuid::Uuid::parse_str(&user.id).unwrap().as_bytes();
    drive_blocks::seal_file(
        plain,
        &file.key,
        DriveBlobContextV2::new(&file.id, revision, generation).unwrap(),
        user.identity.drive_signing_key(),
        account,
    )
    .unwrap()
    .bytes
}

fn form_upload(
    c: &Client,
    base: &str,
    user: &User,
    folder: &Folder,
    file: &Sealed,
    revision: &str,
    bytes: Vec<u8>,
) -> Response {
    let form = multipart::Form::new()
        .text("fileId", file.id.clone())
        .text("collectionId", folder.id.clone())
        .text("fileKeyEnvelope", file.file_key_envelope.clone())
        .text("metadataEnvelope", file.metadata_envelope.clone())
        .text("nameHash", test_name_hash(&file.id))
        .text("revisionId", revision.to_owned())
        .part("file", multipart::Part::bytes(bytes).file_name("encrypted"));
    bearer(c.post(format!("{base}/api/files/upload")), &user.token)
        .multipart(form)
        .send()
        .unwrap()
}

fn get(c: &Client, url: &str, token: &str, headers: &[(&str, &str)]) -> Response {
    let mut request = bearer(c.get(url), token);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.send().unwrap()
}

fn header(response: &Response, name: &str) -> String {
    response
        .headers()
        .get(name)
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default()
}

#[test]
fn block_blobs_are_checked_keyed_by_revision_and_read_by_range() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER not set; skipping");
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let owner = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);

    // The limits a client reads.
    let limits: Value = bearer(c.get(format!("{base}/api/drive/limits")), &owner.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    for field in [
        "uploadMaxBytes",
        "versionMaxBytes",
        "streamMaxBytes",
        "streamCacheBlocks",
        "streamReadaheadBlocks",
        "streamMaxConcurrent",
        "streamResponseMaxBytes",
        "streamBlobFallbackMaxBytes",
    ] {
        assert!(limits[field].as_i64().is_some(), "{field}: {limits}");
    }

    // --- Upload checks: the header names the request's revision, and the
    // trailer and length fit together. ---
    let file = seal_file(&folder, &uuid(), b"unused");
    let revision = uuid();
    let plain: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
    let good = blob(&owner, &file, &revision, 1, &plain);
    let total = good.len();
    let other_revision = blob(&owner, &file, &uuid(), 1, &plain);
    assert_eq!(
        form_upload(&c, &base, &owner, &folder, &file, &revision, other_revision).status(),
        StatusCode::BAD_REQUEST,
        "a header naming another revision"
    );
    let mut longer = good[..total - TRAILER_LEN].to_vec();
    longer.extend_from_slice(&vec![0; 5 * 1024 * 1024]);
    longer.extend_from_slice(&good[total - TRAILER_LEN..]);
    assert_eq!(
        form_upload(&c, &base, &owner, &folder, &file, &revision, longer).status(),
        StatusCode::BAD_REQUEST,
        "a length its trailer doesn't fit"
    );
    let mut broken = good.clone();
    broken[total - 1] ^= 1;
    assert_eq!(
        form_upload(&c, &base, &owner, &folder, &file, &revision, broken).status(),
        StatusCode::BAD_REQUEST,
        "a broken trailer"
    );
    assert_eq!(
        form_upload(
            &c,
            &base,
            &owner,
            &folder,
            &file,
            "not-a-uuid",
            good.clone()
        )
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        form_upload(&c, &base, &owner, &folder, &file, &revision, good.clone()).status(),
        StatusCode::CREATED
    );
    // A revision id names one content: another file can't take it.
    let second = seal_file(&folder, &uuid(), b"unused");
    let reused = blob(&owner, &second, &revision, 1, b"x");
    let r = form_upload(&c, &base, &owner, &folder, &second, &revision, reused);
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>().unwrap()["code"], "revisionTaken");

    // --- Ranged reads: the ETag is the revision id. ---
    let url = format!("{base}/api/files/{}/download", file.id);
    let etag = format!("\"{revision}\"");
    let whole = get(&c, &url, &owner.token, &[]);
    assert_eq!(whole.status(), StatusCode::OK);
    assert_eq!(header(&whole, "etag"), etag);
    assert_eq!(header(&whole, "accept-ranges"), "bytes");
    assert_eq!(whole.bytes().unwrap().to_vec(), good);
    let head = get(&c, &url, &owner.token, &[("Range", "bytes=0-47")]);
    assert_eq!(head.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        header(&head, "content-range"),
        format!("bytes 0-47/{total}")
    );
    assert_eq!(
        head.bytes().unwrap().to_vec(),
        good[..DRIVE_BLOCKS_HEADER_BYTES]
    );
    let trailer = get(&c, &url, &owner.token, &[("Range", "bytes=-12")]);
    assert_eq!(trailer.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        trailer.bytes().unwrap().to_vec(),
        good[total - TRAILER_LEN..]
    );
    let rest = get(&c, &url, &owner.token, &[("Range", "bytes=48-")]);
    assert_eq!(rest.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(rest.bytes().unwrap().to_vec(), good[48..]);
    // If-Range: a range of the same content only.
    let same = get(
        &c,
        &url,
        &owner.token,
        &[("Range", "bytes=0-9"), ("If-Range", &etag)],
    );
    assert_eq!(same.status(), StatusCode::PARTIAL_CONTENT);
    let changed = get(
        &c,
        &url,
        &owner.token,
        &[
            ("Range", "bytes=0-9"),
            ("If-Range", "\"00000000-0000-4000-8000-000000000000\""),
        ],
    );
    assert_eq!(changed.status(), StatusCode::OK);
    assert_eq!(changed.bytes().unwrap().len(), total);
    // Past the end, and several ranges (answered whole).
    let past = get(
        &c,
        &url,
        &owner.token,
        &[("Range", &format!("bytes={total}-"))],
    );
    assert_eq!(past.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(header(&past, "content-range"), format!("bytes */{total}"));
    let several = get(&c, &url, &owner.token, &[("Range", "bytes=0-1,5-6")]);
    assert_eq!(several.status(), StatusCode::OK);

    // --- A version is a revision: its own id, key and ETag. ---
    let version = uuid();
    let saved = blob(&owner, &file, &version, 1, b"the next content");
    let form = multipart::Form::new()
        .text("kind", "file")
        .text("seqAtSnapshot", "0")
        .text("docKeyId", "1")
        .text("revisionId", version.clone())
        .part(
            "file",
            multipart::Part::bytes(saved.clone()).file_name("version"),
        );
    let r = bearer(
        c.post(format!("{base}/api/files/{}/versions", file.id)),
        &owner.token,
    )
    .multipart(form)
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    assert_eq!(r.json::<Value>().unwrap()["id"], version.as_str());
    let now = get(&c, &url, &owner.token, &[]);
    assert_eq!(header(&now, "etag"), format!("\"{version}\""));
    assert_eq!(now.bytes().unwrap().to_vec(), saved);
    // The original's range by its old ETag now reads the new content whole.
    let stale = get(
        &c,
        &url,
        &owner.token,
        &[("Range", "bytes=0-9"), ("If-Range", &etag)],
    );
    assert_eq!(stale.status(), StatusCode::OK);
    let by_version = get(
        &c,
        &format!("{base}/api/files/{}/versions/{version}/download", file.id),
        &owner.token,
        &[("Range", "bytes=0-47")],
    );
    assert_eq!(by_version.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(by_version.bytes().unwrap().to_vec(), saved[..48]);

    // --- tus: the header on the first part, the structure at the end. ---
    for (broken_trailer, expect) in [
        (false, StatusCode::NO_CONTENT),
        (true, StatusCode::BAD_REQUEST),
    ] {
        let file = seal_file(&folder, &uuid(), b"unused");
        let revision = uuid();
        let mut bytes = blob(&owner, &file, &revision, 1, &plain);
        if broken_trailer {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        }
        let created = tus_create_blocks(
            &c,
            &base,
            &owner.token,
            &folder,
            &file,
            &revision,
            bytes.len() as i64,
        );
        assert_eq!(created.status(), StatusCode::CREATED);
        let location = header(&created, "location");
        let r = bearer(c.patch(format!("{base}{location}")), &owner.token)
            .header("Tus-Resumable", "1.0.0")
            .header("Upload-Offset", "0")
            .header("Content-Type", "application/offset+octet-stream")
            .body(bytes.clone())
            .send()
            .unwrap();
        assert_eq!(r.status(), expect, "broken trailer: {broken_trailer}");
        let (status, stored) = download(&c, &base, &owner.token, &file.id);
        if broken_trailer {
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "a refused upload leaves nothing"
            );
        } else {
            assert_eq!((status, stored), (StatusCode::OK, bytes));
        }
    }
    // A first part whose header names another revision.
    let file = seal_file(&folder, &uuid(), b"unused");
    let revision = uuid();
    let bytes = blob(&owner, &file, &uuid(), 1, &plain);
    let created = tus_create_blocks(
        &c,
        &base,
        &owner.token,
        &folder,
        &file,
        &revision,
        bytes.len() as i64,
    );
    let location = header(&created, "location");
    let r = bearer(c.patch(format!("{base}{location}")), &owner.token)
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Offset", "0")
        .header("Content-Type", "application/offset+octet-stream")
        .body(bytes)
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // A version upload's id is its revision's, which the client chose and
    // which becomes a public ETag: still, only its uploader (or the folder's
    // owner, to cancel) can touch the upload.
    let file = seal_file(&folder, &uuid(), b"unused");
    let first = uuid();
    assert_eq!(
        form_upload(
            &c,
            &base,
            &owner,
            &folder,
            &file,
            &first,
            blob(&owner, &file, &first, 1, b"x")
        )
        .status(),
        StatusCode::CREATED
    );
    let version = uuid();
    let next = blob(&owner, &file, &version, 1, &plain);
    let metadata = kutup_crypto::drive_envelope::seal_b64(
        br#"{"name":"a.txt","mimeType":"text/plain","size":70000}"#,
        &file.key,
        kutup_crypto::drive_envelope::DriveEnvelopeContextV1::file_metadata(&file.id, 1, 2)
            .unwrap(),
    )
    .unwrap();
    let meta = [
        ("versionOf", file.id.as_str()),
        ("metadataEnvelope", metadata.as_str()),
        ("metadataRevision", "2"),
        ("revisionId", version.as_str()),
    ]
    .iter()
    .map(|(k, v)| format!("{k} {}", b64(v.as_bytes())))
    .collect::<Vec<_>>()
    .join(",");
    let created = bearer(c.post(format!("{base}/api/uploads")), &owner.token)
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Length", next.len().to_string())
        .header("Upload-Metadata", meta)
        .send()
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(
        header(&created, "location"),
        format!("/api/uploads/{version}")
    );
    let stranger = register(&c, &base);
    let at = format!("{base}/api/uploads/{version}");
    let tus = |request: reqwest::blocking::RequestBuilder| {
        request
            .header("Tus-Resumable", "1.0.0")
            .send()
            .unwrap()
            .status()
    };
    assert_eq!(
        tus(bearer(c.head(&at), &stranger.token)),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        tus(bearer(c.patch(&at), &stranger.token)
            .header("Upload-Offset", "0")
            .header("Content-Type", "application/offset+octet-stream")
            .body(next.clone())),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        tus(bearer(c.delete(&at), &stranger.token)),
        StatusCode::NOT_FOUND
    );
    // Its uploader goes on with it.
    assert_eq!(
        tus(bearer(c.patch(&at), &owner.token)
            .header("Upload-Offset", "0")
            .header("Content-Type", "application/offset+octet-stream")
            .body(next.clone())),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        download(&c, &base, &owner.token, &file.id),
        (StatusCode::OK, next)
    );

    purge_accounts(&c, &base, &[&owner, &stranger]);
}

/// `tus_create` with the block format's `revisionId`.
fn tus_create_blocks(
    c: &Client,
    base: &str,
    token: &str,
    folder: &Folder,
    file: &Sealed,
    revision: &str,
    length: i64,
) -> Response {
    let name_hash = test_name_hash(&file.id);
    let meta = [
        ("fileId", file.id.as_str()),
        ("collectionId", folder.id.as_str()),
        ("metadataEnvelope", file.metadata_envelope.as_str()),
        ("fileKeyEnvelope", file.file_key_envelope.as_str()),
        ("nameHash", name_hash.as_str()),
        ("revisionId", revision),
    ]
    .iter()
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
