//! Live e2e for Drive versions v2 (`docs/plans/drive-versions-v2.md`).
//!
//! One request stores a version, charged by its measured size; downloads
//! serve the latest whole-file version and name it; conditional saves
//! (`basedOn`); the retention setting.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test versions_live -- --nocapture

mod common;

use common::{register, sign_in, User};
use reqwest::blocking::{Client, RequestBuilder, Response};
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
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};

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

fn post_version(
    c: &Client,
    base: &str,
    token: &str,
    file_id: &str,
    kind: &str,
    blob: Vec<u8>,
    extra: &[(&str, &str)],
) -> Response {
    let mut form = reqwest::blocking::multipart::Form::new()
        .text("kind", kind.to_string())
        .text("seqAtSnapshot", "0")
        .text("docKeyId", "1");
    for (k, v) in extra {
        form = form.text(k.to_string(), v.to_string());
    }
    form = form.part(
        "file",
        reqwest::blocking::multipart::Part::bytes(blob).file_name("version"),
    );
    bearer(
        c.post(format!("{base}/api/files/{file_id}/versions")),
        token,
    )
    .multipart(form)
    .send()
    .unwrap()
}

#[test]
fn versions_v2_contract() {
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
    let blob = drive_object::encrypt_file_blob(
        b"hello thumbnails",
        &file_key,
        DriveFileBlobContextV1::new(&file_id, 1).unwrap(),
    )
    .unwrap();
    let form = reqwest::blocking::multipart::Form::new()
        .text("fileId", file_id.clone())
        .text("collectionId", collection_id.clone())
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

    let seal = |plain: &[u8]| {
        drive_object::encrypt_file_blob(
            plain,
            &file_key,
            DriveFileBlobContextV1::new(&file_id, 1).unwrap(),
        )
        .unwrap()
    };
    let download = |token: &str| -> Vec<u8> {
        bearer(c.get(format!("{base}/api/files/{file_id}/download")), token)
            .send()
            .unwrap()
            .bytes()
            .unwrap()
            .to_vec()
    };
    let current_version = |token: &str| -> String {
        let r = bearer(c.get(format!("{base}/api/files/{file_id}/download")), token)
            .send()
            .unwrap();
        r.headers()["x-kutup-version"].to_str().unwrap().to_owned()
    };
    let original = download(&token);
    assert_eq!(current_version(&token), "original");
    let baseline = used(&c, &base, &token);

    // Charged by what arrived; a client's size claim is ignored.
    let edited = seal(&vec![7u8; 50_000]);
    let r = post_version(
        &c,
        &base,
        &token,
        &file_id,
        "file",
        edited.clone(),
        &[("sizeBytes", "1"), ("label", "Draft")],
    );
    assert_eq!(r.status(), StatusCode::CREATED);
    let v: Value = r.json().unwrap();
    assert_eq!(v["kind"], "file");
    assert_eq!(v["label"], "Draft");
    assert_eq!(v["sizeBytes"], edited.len() as i64);
    assert!(v.get("s3VersionId").is_none());
    assert!(v["storagePath"]
        .as_str()
        .unwrap()
        .ends_with(v["id"].as_str().unwrap()));
    assert_eq!(used(&c, &base, &token), baseline + edited.len() as i64);
    // It replaced the original upload, and downloads now name it.
    assert_eq!(v["parentVersionId"], Value::Null);
    assert_eq!(current_version(&token), v["id"].as_str().unwrap());

    // The download is the file as it is now: the latest whole-file version…
    assert_eq!(download(&token), edited);
    // …which a note-state version does not replace.
    let r = post_version(&c, &base, &token, &file_id, "yjs", seal(b"yjs state"), &[]);
    assert_eq!(r.status(), StatusCode::CREATED);
    assert_eq!(download(&token), edited);
    assert_ne!(download(&token), original);

    // The version downloads as itself.
    let got = bearer(
        c.get(format!(
            "{base}/api/files/{file_id}/versions/{}/download",
            v["id"].as_str().unwrap()
        )),
        &token,
    )
    .send()
    .unwrap()
    .bytes()
    .unwrap()
    .to_vec();
    assert_eq!(got, edited);

    // Refused: an unknown kind, no body, a blob sealed for another file.
    assert_eq!(
        post_version(&c, &base, &token, &file_id, "zip", seal(b"x"), &[]).status(),
        StatusCode::BAD_REQUEST
    );
    let other = drive_object::encrypt_file_blob(
        b"x",
        &file_key,
        DriveFileBlobContextV1::new(&uuid(), 1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        post_version(&c, &base, &token, &file_id, "file", other, &[]).status(),
        StatusCode::BAD_REQUEST
    );
    let no_file = reqwest::blocking::multipart::Form::new().text("kind", "file");
    assert_eq!(
        bearer(
            c.post(format!("{base}/api/files/{file_id}/versions")),
            &token
        )
        .multipart(no_file)
        .send()
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );

    // Someone without access cannot add one.
    let stranger = register(&c, &base);
    let stranger_token = token_of(&c, &base, &stranger);
    assert_eq!(
        post_version(
            &c,
            &base,
            &stranger_token,
            &file_id,
            "file",
            seal(b"x"),
            &[]
        )
        .status(),
        StatusCode::FORBIDDEN
    );

    // Conditional saves (docs/plans/pass.md, "Saving without overwriting").
    let v_id = v["id"].as_str().unwrap().to_owned();
    let count = || -> usize {
        bearer(
            c.get(format!("{base}/api/files/{file_id}/versions")),
            &token,
        )
        .send()
        .unwrap()
        .json::<Vec<Value>>()
        .unwrap()
        .len()
    };
    let stored = count();
    // Made from the original, which is no longer current: refused, with the
    // version that is, and nothing stored or charged.
    let before = used(&c, &base, &token);
    let r = post_version(
        &c,
        &base,
        &token,
        &file_id,
        "file",
        seal(b"stale"),
        &[("basedOn", "original")],
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let body: Value = r.json().unwrap();
    assert_eq!(body["code"], "version_conflict");
    assert_eq!(body["current"], v_id.as_str());
    assert_eq!(count(), stored);
    assert_eq!(used(&c, &base, &token), before);
    // Made from the current one: stored, recording what it replaced.
    let next = seal(b"next");
    let r = post_version(
        &c,
        &base,
        &token,
        &file_id,
        "file",
        next.clone(),
        &[("basedOn", &v_id)],
    );
    assert_eq!(r.status(), StatusCode::CREATED);
    let w: Value = r.json().unwrap();
    let w_id = w["id"].as_str().unwrap().to_owned();
    assert_eq!(w["parentVersionId"], v_id.as_str());
    assert_eq!(download(&token), next);
    assert_eq!(current_version(&token), w_id);
    // The same base again is now stale.
    let r = post_version(
        &c,
        &base,
        &token,
        &file_id,
        "file",
        seal(b"lost"),
        &[("basedOn", &v_id)],
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.json::<Value>().unwrap()["current"], w_id.as_str());
    // Refused: a base that is no version id, a base on a note's state.
    for (kind, based_on) in [("file", "latest"), ("yjs", w_id.as_str())] {
        let r = post_version(
            &c,
            &base,
            &token,
            &file_id,
            kind,
            seal(b"x"),
            &[("basedOn", based_on)],
        );
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{kind} {based_on}");
    }
    // Two saves from one base at once: exactly one lands.
    let statuses: Vec<StatusCode> = std::thread::scope(|scope| {
        let saves: Vec<_> = (0..4)
            .map(|n| {
                let (c, base, token, file_id, w_id) = (&c, &base, &token, &file_id, &w_id);
                let blob = seal(format!("racer {n}").as_bytes());
                scope.spawn(move || {
                    post_version(c, base, token, file_id, "file", blob, &[("basedOn", w_id)])
                        .status()
                })
            })
            .collect();
        saves.into_iter().map(|s| s.join().unwrap()).collect()
    });
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::CREATED)
            .count(),
        1,
        "{statuses:?}"
    );
    assert!(statuses
        .iter()
        .all(|s| *s == StatusCode::CREATED || *s == StatusCode::CONFLICT));
    // A save without a base still lands, and records what it replaced.
    let winner = current_version(&token);
    let r = post_version(&c, &base, &token, &file_id, "file", seal(b"plain"), &[]);
    assert_eq!(r.status(), StatusCode::CREATED);
    assert_eq!(
        r.json::<Value>().unwrap()["parentVersionId"],
        winner.as_str()
    );

    // The retention setting.
    assert_eq!(me(&c, &base, &token)["versionRetentionDays"], 30);
    let set = |days: i32| {
        bearer(c.patch(format!("{base}/api/user/me")), &token)
            .json(&json!({ "versionRetentionDays": days }))
            .send()
            .unwrap()
            .status()
    };
    assert_eq!(set(90), StatusCode::OK);
    assert_eq!(me(&c, &base, &token)["versionRetentionDays"], 90);
    assert_eq!(set(45), StatusCode::BAD_REQUEST);
    assert_eq!(me(&c, &base, &token)["versionRetentionDays"], 90);
    // Nothing left behind for the gate's checks.
    common::purge_accounts(&c, &base, &[&owner, &stranger]);
}
