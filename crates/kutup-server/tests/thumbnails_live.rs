//! Live e2e for Drive thumbnails (`docs/plans/drive-thumbnails.md`).
//!
//! Builds an owned folder and a file the way a client does (Rust crypto),
//! then checks the thumbnail contract over HTTP: header validation without a
//! key (variant, file, content revision, epoch, size), replace-in-place with exact quota
//! accounting, ciphertext-only caching headers, the listing's thumbnail
//! fields and staleness against the latest version, access control, and
//! deletion releasing the bytes.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test thumbnails_live -- --nocapture

mod common;

use common::{register, sign_in, User};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::StatusCode;
use serde_json::{json, Value};

fn client() -> Client {
    crate::common::client_builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

fn bearer(req: RequestBuilder, token: &str) -> RequestBuilder {
    req.header("authorization", format!("Bearer {token}"))
}

use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::thumbnail::{self, Thumbnail, ThumbnailFormat, ThumbnailVariant};

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// A fresh OPAQUE sign-in of `a` (as the CLI): its access token.
fn token_of(c: &Client, base: &str, a: &User) -> String {
    sign_in(c, base, &a.username, &a.password)["accessToken"]
        .as_str()
        .unwrap()
        .to_string()
}

fn me(c: &Client, base: &str, token: &str) -> Value {
    bearer(c.get(format!("{base}/api/user/me")), token)
        .send()
        .unwrap()
        .json()
        .unwrap()
}

fn used(c: &Client, base: &str, token: &str) -> i64 {
    me(c, base, token)["storageUsedBytes"].as_i64().unwrap()
}

fn picture(fill: u8, len: usize) -> Thumbnail {
    let mut image = vec![0xFF, 0xD8, 0xFF, 0xE0];
    image.resize(len, fill);
    Thumbnail {
        format: ThumbnailFormat::Jpeg,
        width: 320,
        height: 200,
        image,
    }
}

/// Stores a thumbnail envelope bound to content revision `revision`.
#[allow(clippy::too_many_arguments)]
fn put_thumb(
    c: &Client,
    base: &str,
    token: &str,
    file_id: &str,
    variant: &str,
    body: Vec<u8>,
    revision: &str,
    source: Option<&str>,
) -> StatusCode {
    let mut url = format!("{base}/api/files/{file_id}/thumbnails/{variant}?revision={revision}");
    if let Some(s) = source {
        url.push_str(&format!("&source={s}"));
    }
    bearer(c.put(url), token)
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .unwrap()
        .status()
}

fn listed(c: &Client, base: &str, token: &str, collection_id: &str, file_id: &str) -> Value {
    let rows: Vec<Value> = bearer(
        c.get(format!("{base}/api/collections/{collection_id}/files")),
        token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    rows.into_iter()
        .find(|r| r["id"] == file_id)
        .expect("file listed")
}

#[test]
fn thumbnails_contract() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = client();
    let owner = register(&c, &base);
    let token = token_of(&c, &base, &owner);
    let user_id = me(&c, &base, &token)["id"].as_str().unwrap().to_string();
    let identity =
        kutup_crypto::identity::AccountIdentityKeysV1::derive(&owner.master_key).unwrap();

    // An owned folder, as createOwnedCollectionV1 makes it.
    let collection_id = uuid();
    let collection_key = [0x51u8; 32];
    let ctx = |purpose, object: &str, parent: &str| {
        DriveEnvelopeContextV1::new(purpose, 1, 1, object, parent).unwrap()
    };
    let created = bearer(c.post(format!("{base}/api/collections")), &token)
        .json(&json!({
            "id": collection_id,
            "ownerKeyEnvelope": drive_envelope::seal_b64(&collection_key, &owner.master_key, ctx(DriveEnvelopePurpose::CollectionKey, &collection_id, &user_id)).unwrap(),
            "nameEnvelope": drive_envelope::seal_b64(b"Thumbs", &collection_key, ctx(DriveEnvelopePurpose::CollectionName, &collection_id, &user_id)).unwrap(),
            "epochStatement": CollectionEpochStatementV1::create(&collection_id, &user_id, 1, None, &collection_key, identity.authority_signing_key()).unwrap().encode_b64(),
            "parentCollectionId": null,
            "nameHash": collection_id.replace('-', "").repeat(2),
        }))
        .send()
        .unwrap();
    assert!(
        created.status().is_success(),
        "create collection: {}",
        created.status()
    );

    // A file in it, as the upload path makes it.
    let file_id = uuid();
    let file_key = [0x61u8; 32];
    let revision = uuid();
    let blob = common::block_blob(&file_id, &file_key, &revision, 1, b"hello thumbnails");
    let form = reqwest::blocking::multipart::Form::new()
        .text("fileId", file_id.clone())
        .text("collectionId", collection_id.clone())
        .text("revisionId", revision.clone())
        .text("metadataRevision", "1")
        .text(
            "revisionContentEnvelope",
            common::sealed_revision_content(&file_id, &file_key, &revision, 1),
        )
        .text("nameHash", file_id.replace('-', "").repeat(2))
        .text(
            "fileKeyEnvelope",
            drive_envelope::seal_b64(
                &file_key,
                &collection_key,
                DriveEnvelopeContextV1::file_key(&file_id, &collection_id, 1, 1).unwrap(),
            )
            .unwrap(),
        )
        .text(
            "metadataEnvelope",
            drive_envelope::seal_b64(
                br#"{"name":"a.txt","mimeType":"text/plain","size":16}"#,
                &file_key,
                DriveEnvelopeContextV1::file_metadata(&file_id, 1, 1).unwrap(),
            )
            .unwrap(),
        )
        .part(
            "file",
            reqwest::blocking::multipart::Part::bytes(blob).file_name("encrypted"),
        );
    let uploaded = bearer(c.post(format!("{base}/api/files/upload")), &token)
        .multipart(form)
        .send()
        .unwrap();
    assert!(
        uploaded.status().is_success(),
        "upload: {}",
        uploaded.status()
    );

    let row = listed(&c, &base, &token, &collection_id, &file_id);
    assert_eq!(row["thumbnails"], json!({}), "no thumbnails yet");
    assert_eq!(row["thumbnailStale"], false);
    let baseline = used(&c, &base, &token);

    // Store one: charged exactly, served as the same bytes with immutable caching.
    let first = thumbnail::seal(
        &picture(1, 2000),
        ThumbnailVariant::Small,
        &file_key,
        &file_id,
        &revision,
        1,
    )
    .unwrap();
    assert_eq!(
        put_thumb(
            &c,
            &base,
            &token,
            &file_id,
            "sm",
            first.clone(),
            &revision,
            Some("original")
        ),
        StatusCode::NO_CONTENT
    );
    assert_eq!(used(&c, &base, &token), baseline + first.len() as i64);
    let got = bearer(
        c.get(format!("{base}/api/files/{file_id}/thumbnails/sm")),
        &token,
    )
    .send()
    .unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    assert!(got.headers()["cache-control"]
        .to_str()
        .unwrap()
        .contains("immutable"));
    let bytes = got.bytes().unwrap().to_vec();
    assert_eq!(bytes, first);
    assert_eq!(
        thumbnail::open(
            &bytes,
            ThumbnailVariant::Small,
            &file_key,
            &file_id,
            &revision,
            1
        )
        .unwrap(),
        picture(1, 2000)
    );
    let row = listed(&c, &base, &token, &collection_id, &file_id);
    assert!(row["thumbnails"]["sm"].is_string() && row["thumbnails"]["lg"].is_null());
    assert_eq!(row["thumbnailStale"], false);

    // Replace it with a larger one: the charge moves by the difference only.
    let second = thumbnail::seal(
        &picture(2, 9000),
        ThumbnailVariant::Small,
        &file_key,
        &file_id,
        &revision,
        1,
    )
    .unwrap();
    assert_ne!(first.len(), second.len(), "padding buckets differ");
    assert_eq!(
        put_thumb(
            &c,
            &base,
            &token,
            &file_id,
            "sm",
            second.clone(),
            &revision,
            None
        ),
        StatusCode::NO_CONTENT
    );
    assert_eq!(used(&c, &base, &token), baseline + second.len() as i64);

    // The server checks the public header, never the picture.
    let as_small = thumbnail::seal(
        &picture(3, 100),
        ThumbnailVariant::Small,
        &file_key,
        &file_id,
        &revision,
        1,
    )
    .unwrap();
    assert_eq!(
        put_thumb(&c, &base, &token, &file_id, "lg", as_small, &revision, None),
        StatusCode::BAD_REQUEST,
        "variant bound"
    );
    let other_file = thumbnail::seal(
        &picture(3, 100),
        ThumbnailVariant::Small,
        &file_key,
        &uuid(),
        &revision,
        1,
    )
    .unwrap();
    assert_eq!(
        put_thumb(&c, &base, &token, &file_id, "sm", other_file, &revision, None),
        StatusCode::BAD_REQUEST,
        "file bound"
    );
    let other_epoch = thumbnail::seal(
        &picture(3, 100),
        ThumbnailVariant::Small,
        &file_key,
        &file_id,
        &revision,
        2,
    )
    .unwrap();
    assert_eq!(
        put_thumb(
            &c,
            &base,
            &token,
            &file_id,
            "sm",
            other_epoch,
            &revision,
            None
        ),
        StatusCode::BAD_REQUEST,
        "epoch bound"
    );
    assert_eq!(
        put_thumb(
            &c,
            &base,
            &token,
            &file_id,
            "sm",
            second.clone(),
            &uuid(),
            None
        ),
        StatusCode::BAD_REQUEST,
        "revision bound"
    );
    // Sealed and named consistently, but not a revision of this file.
    let made_up = uuid();
    let made_up_revision = thumbnail::seal(
        &picture(3, 100),
        ThumbnailVariant::Small,
        &file_key,
        &file_id,
        &made_up,
        1,
    )
    .unwrap();
    assert_eq!(
        put_thumb(
            &c,
            &base,
            &token,
            &file_id,
            "sm",
            made_up_revision,
            &made_up,
            None
        ),
        StatusCode::BAD_REQUEST,
        "unknown revision"
    );
    let mut unnamed = bearer(
        c.put(format!("{base}/api/files/{file_id}/thumbnails/sm")),
        &token,
    )
    .header("content-type", "application/octet-stream")
    .body(second.clone())
    .send()
    .unwrap();
    assert_eq!(
        unnamed.status(),
        StatusCode::BAD_REQUEST,
        "no revision named: {}",
        unnamed.text().unwrap_or_default()
    );
    unnamed = bearer(
        c.put(format!(
            "{base}/api/files/{file_id}/thumbnails/sm?revision=x"
        )),
        &token,
    )
    .body(second.clone())
    .send()
    .unwrap();
    assert_eq!(
        unnamed.status(),
        StatusCode::BAD_REQUEST,
        "not a revision id"
    );
    assert_eq!(
        put_thumb(
            &c,
            &base,
            &token,
            &file_id,
            "sm",
            vec![0u8; 70 * 1024],
            &revision,
            None
        ),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        put_thumb(
            &c,
            &base,
            &token,
            &file_id,
            "xl",
            second.clone(),
            &revision,
            None
        ),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put_thumb(
            &c,
            &base,
            &token,
            &file_id,
            "sm",
            second.clone(),
            &revision,
            Some(&uuid())
        ),
        StatusCode::BAD_REQUEST,
        "foreign source"
    );
    assert_eq!(
        used(&c, &base, &token),
        baseline + second.len() as i64,
        "refusals charge nothing"
    );

    // A new version makes it stale; one drawn from that version (bound to
    // its revision) is current.
    let snap = common::Version::seal(&file_id, &file_key, 1, b"edited");
    let version: Value = common::save_version(&c, &base, &token, &snap, &common::WHOLE_FILE)
        .json()
        .unwrap();
    let version_id = version["id"].as_str().unwrap().to_string();
    assert_eq!(version_id, snap.revision);
    let redrawn = thumbnail::seal(
        &picture(2, 9000),
        ThumbnailVariant::Small,
        &file_key,
        &file_id,
        &version_id,
        1,
    )
    .unwrap();
    assert_eq!(
        listed(&c, &base, &token, &collection_id, &file_id)["thumbnailStale"],
        true,
        "stale after a version"
    );
    assert_eq!(
        put_thumb(
            &c,
            &base,
            &token,
            &file_id,
            "sm",
            redrawn.clone(),
            &version_id,
            Some(&version_id)
        ),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        listed(&c, &base, &token, &collection_id, &file_id)["thumbnailStale"],
        false,
        "current again"
    );

    // Someone without access can neither read nor write it.
    let stranger = register(&c, &base);
    let stranger_token = token_of(&c, &base, &stranger);
    assert_eq!(
        bearer(
            c.get(format!("{base}/api/files/{file_id}/thumbnails/sm")),
            &stranger_token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        put_thumb(
            &c,
            &base,
            &stranger_token,
            &file_id,
            "sm",
            second,
            &revision,
            None
        ),
        StatusCode::FORBIDDEN
    );

    // Deleting releases exactly what was charged, and it is gone.
    let with_version = used(&c, &base, &token);
    let second_len = thumbnail::seal(
        &picture(2, 9000),
        ThumbnailVariant::Small,
        &file_key,
        &file_id,
        &revision,
        1,
    )
    .unwrap()
    .len() as i64;
    assert_eq!(
        bearer(
            c.delete(format!("{base}/api/files/{file_id}/thumbnails")),
            &token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(used(&c, &base, &token), with_version - second_len);
    assert_eq!(
        bearer(
            c.get(format!("{base}/api/files/{file_id}/thumbnails/sm")),
            &token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        listed(&c, &base, &token, &collection_id, &file_id)["thumbnails"],
        json!({})
    );
    // Nothing left behind for the gate's checks.
    common::purge_accounts(&c, &base, &[&owner, &stranger]);
}
