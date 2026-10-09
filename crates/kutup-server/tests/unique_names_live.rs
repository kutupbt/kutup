//! Live e2e for names unique in a folder (docs/plans/drive-unique-names.md).
//!
//! Clients send each name's hash under the folder's hash key; the server
//! keeps them apart among a folder's files and subfolders together, and
//! among an owner's top-level folders, without reading a name. A clash is
//! `409 name_taken` naming what holds the name, before any byte is stored.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test unique_names_live -- --nocapture

use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::drive_envelope;
use kutup_crypto::drive_names;
use rand::RngCore;
use reqwest::blocking::{multipart, Client, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

fn hash_key(folder: &Folder) -> [u8; 32] {
    drive_names::folder_hash_key(&folder.key, &folder.id).unwrap()
}

fn name(folder: &Folder, name: &str) -> String {
    drive_names::name_hash(&hash_key(folder), name).unwrap()
}

fn upload_named(
    c: &Client,
    base: &str,
    user: &User,
    folder: &Folder,
    file: &Sealed,
    hash: Option<&str>,
) -> Response {
    let mut form = multipart::Form::new()
        .text("fileId", file.id.clone())
        .text("collectionId", folder.id.clone())
        .text("fileKeyEnvelope", file.file_key_envelope.clone())
        .text("metadataEnvelope", file.metadata_envelope.clone());
    if let Some(hash) = hash {
        form = form.text("nameHash", hash.to_owned());
    }
    let form = form.part(
        "file",
        multipart::Part::bytes(file.blob.clone()).file_name("encrypted"),
    );
    bearer(c.post(format!("{base}/api/files/upload")), &user.token)
        .multipart(form)
        .send()
        .unwrap()
}

/// A folder named by `hash`, under `parent` or at the top level.
fn folder_named(
    c: &Client,
    base: &str,
    owner: &User,
    parent: Option<&Folder>,
    hash: &str,
) -> (StatusCode, Value, Folder) {
    let id = uuid();
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    use kutup_crypto::drive_envelope::DriveEnvelopePurpose;
    let r = bearer(c.post(format!("{base}/api/collections")), &owner.token)
        .json(&json!({
            "id": id,
            "ownerKeyEnvelope": drive_envelope::seal_b64(&key, &owner.master_key, ctx(DriveEnvelopePurpose::CollectionKey, &id, &owner.id)).unwrap(),
            "nameEnvelope": drive_envelope::seal_b64(b"Named", &key, ctx(DriveEnvelopePurpose::CollectionName, &id, &owner.id)).unwrap(),
            "epochStatement": CollectionEpochStatementV1::create(&id, &owner.id, 1, None, &key, owner.identity.authority_signing_key()).unwrap().encode_b64(),
            "parentCollectionId": parent.map(|p| p.id.clone()),
            "nameHash": hash,
        }))
        .send()
        .unwrap();
    let status = r.status();
    let body = r.json().unwrap_or(Value::Null);
    (status, body, Folder { id, key })
}

fn rows(c: &Client, base: &str, user: &User, folder: &Folder) -> Vec<Value> {
    bearer(
        c.get(format!("{base}/api/collections/{}/files", folder.id)),
        &user.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap()
}

fn row(c: &Client, base: &str, user: &User, folder: &Folder, id: &str) -> Value {
    rows(c, base, user, folder)
        .into_iter()
        .find(|r| r["id"] == id)
        .unwrap_or_else(|| panic!("{id} not listed"))
}

fn assert_taken(r: Response, kind: &str, holder: &str) -> Value {
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let body: Value = r.json().unwrap();
    assert_eq!(body["code"], "name_taken", "{body}");
    assert_eq!(body["holder"]["kind"], kind, "{body}");
    assert_eq!(body["holder"]["id"], holder, "{body}");
    body
}

#[test]
fn names_are_unique_in_a_folder() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER unset; skipping");
        return;
    };
    let c = Client::new();
    let owner = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    let report = name(&folder, "Report.pdf");
    assert_eq!(report, name(&folder, "report.PDF"));

    // The first upload takes the name; its content hash is recorded after.
    let first = seal_file(&folder, &uuid(), b"first");
    assert!(
        upload_named(&c, &base, &owner, &folder, &first, Some(&report))
            .status()
            .is_success()
    );
    let content =
        drive_names::content_hash(&hash_key(&folder), &drive_names::content_sha256(b"first"))
            .unwrap();
    let r = bearer(
        c.put(format!("{base}/api/files/{}/content-hash", first.id)),
        &owner.token,
    )
    .json(&json!({ "contentHash": content }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let listed = row(&c, &base, &owner, &folder, &first.id);
    assert_eq!(listed["nameHash"], report);
    assert_eq!(listed["contentHash"], content);

    // A second upload under the same name: refused before anything is
    // stored, naming the file and its content hash.
    let before = used(&c, &base, &owner.token);
    let second = seal_file(&folder, &uuid(), b"second");
    let body = assert_taken(
        upload_named(&c, &base, &owner, &folder, &second, Some(&report)),
        "file",
        &first.id,
    );
    assert_eq!(body["holder"]["contentHash"], content);
    assert_eq!(used(&c, &base, &owner.token), before);
    assert_taken(
        tus_create_named(&c, &base, &owner, &folder, &second, Some(&report)),
        "file",
        &first.id,
    );
    // A malformed hash is refused outright.
    assert_eq!(
        upload_named(&c, &base, &owner, &folder, &second, Some("ABC")).status(),
        StatusCode::BAD_REQUEST
    );

    // Files and subfolders share one set of names.
    let (status, body, _) = folder_named(&c, &base, &owner, Some(&folder), &report);
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["holder"]["id"], first.id);
    let docs = name(&folder, "Docs");
    let (status, _, sub) = folder_named(&c, &base, &owner, Some(&folder), &docs);
    assert!(status.is_success());
    assert_taken(
        upload_named(&c, &base, &owner, &folder, &second, Some(&docs)),
        "folder",
        &sub.id,
    );

    // The same name in another folder is another name.
    let other = create_folder(&c, &base, &owner);
    let elsewhere = seal_file(&other, &uuid(), b"second");
    assert!(upload_named(
        &c,
        &base,
        &owner,
        &other,
        &elsewhere,
        Some(&name(&other, "Report.pdf"))
    )
    .status()
    .is_success());

    // A tus upload checked free at creation is checked again when it ends.
    let late = seal_file(&folder, &uuid(), b"late");
    let late_name = name(&folder, "late.txt");
    let r = tus_create_named(&c, &base, &owner, &folder, &late, Some(&late_name));
    assert_eq!(r.status(), StatusCode::CREATED);
    let location = r.headers()["location"].to_str().unwrap().to_owned();
    let racer = seal_file(&folder, &uuid(), b"racer");
    assert!(
        upload_named(&c, &base, &owner, &folder, &racer, Some(&late_name))
            .status()
            .is_success()
    );
    let r = bearer(c.patch(format!("{base}{location}")), &owner.token)
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Offset", "0")
        .header("Content-Type", "application/offset+octet-stream")
        .body(late.blob.clone())
        .send()
        .unwrap();
    assert_taken(r, "file", &racer.id);
    assert!(!rows(&c, &base, &owner, &folder)
        .iter()
        .any(|r| r["id"] == late.id));

    // A rename onto a taken name is refused; onto a free one moves the name.
    let renamed = name(&folder, "racer-renamed.txt");
    assert_taken(
        rename_file(&c, &base, &owner, &racer, 2, &report),
        "file",
        &first.id,
    );
    assert_eq!(
        rename_file(&c, &base, &owner, &racer, 2, &renamed).status(),
        StatusCode::OK
    );
    assert_eq!(
        row(&c, &base, &owner, &folder, &racer.id)["nameHash"],
        renamed
    );
    let freed = seal_file(&folder, &uuid(), b"freed");
    assert!(
        upload_named(&c, &base, &owner, &folder, &freed, Some(&late_name))
            .status()
            .is_success()
    );
    // Renaming a folder onto a file's name is refused too.
    assert_taken(
        rename_folder(&c, &base, &owner, &sub, &report),
        "file",
        &first.id,
    );

    // A move into a folder where the name is taken is refused.
    let r = bearer(c.post(format!("{base}/api/files/{}/move", elsewhere.id)), &owner.token)
        .json(&json!({
            "fromCollectionId": other.id,
            "toCollectionId": folder.id,
            "toKeyEpoch": 1,
            "fileKeyEnvelope": drive_envelope::seal_b64(
                &elsewhere.key,
                &folder.key,
                kutup_crypto::drive_envelope::DriveEnvelopeContextV1::file_key(&elsewhere.id, &folder.id, 1, 1).unwrap(),
            ).unwrap(),
            "nameHash": report,
        }))
        .send()
        .unwrap();
    assert_taken(r, "file", &first.id);

    // A file in the trash holds no name; restored after the name was taken,
    // it comes back without its hash for the client to rename.
    let r = bearer(
        c.delete(format!("{base}/api/files/{}", first.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert!(r.status().is_success());
    assert!(
        upload_named(&c, &base, &owner, &folder, &second, Some(&report))
            .status()
            .is_success()
    );
    let r = bearer(
        c.post(format!("{base}/api/trash/{}/restore", first.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        row(&c, &base, &owner, &folder, &first.id)["nameHash"],
        Value::Null
    );
    assert_eq!(
        row(&c, &base, &owner, &folder, &second.id)["nameHash"],
        report
    );
    // Restored where its name is still free, it keeps it.
    let r = bearer(
        c.delete(format!("{base}/api/files/{}", freed.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert!(r.status().is_success());
    let r = bearer(
        c.post(format!("{base}/api/trash/{}/restore", freed.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        row(&c, &base, &owner, &folder, &freed.id)["nameHash"],
        late_name
    );

    // Filling in: items without a hash get one; the later of two with the
    // same name is reported, to be renamed.
    let old_a = seal_file(&folder, &uuid(), b"a");
    let old_b = seal_file(&folder, &uuid(), b"b");
    assert!(upload_named(&c, &base, &owner, &folder, &old_a, None)
        .status()
        .is_success());
    assert!(upload_named(&c, &base, &owner, &folder, &old_b, None)
        .status()
        .is_success());
    let notes = name(&folder, "notes.txt");
    let r = bearer(
        c.post(format!("{base}/api/collections/{}/name-hashes", folder.id)),
        &owner.token,
    )
    .json(&json!({ "files": [
        { "id": old_a.id, "nameHash": notes },
        { "id": old_b.id, "nameHash": notes },
        // Already hashed: left alone.
        { "id": second.id, "nameHash": notes },
    ]}))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().unwrap();
    assert_eq!(
        body["clashes"],
        json!([{ "id": old_b.id, "holderKind": "file", "holderId": old_a.id }])
    );
    assert_eq!(
        row(&c, &base, &owner, &folder, &old_a.id)["nameHash"],
        notes
    );
    assert_eq!(
        row(&c, &base, &owner, &folder, &second.id)["nameHash"],
        report
    );
    // Someone who cannot write the folder fills nothing in.
    let stranger = register(&c, &base);
    let r = bearer(
        c.post(format!("{base}/api/collections/{}/name-hashes", folder.id)),
        &stranger.token,
    )
    .json(&json!({ "files": [{ "id": old_b.id, "nameHash": name(&folder, "x") }] }))
    .send()
    .unwrap();
    assert!(r.status() == StatusCode::FORBIDDEN || r.status() == StatusCode::NOT_FOUND);
}

#[test]
fn top_level_folder_names_are_unique_per_owner() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        eprintln!("KUTUP_LIVE_SERVER unset; skipping");
        return;
    };
    let c = Client::new();
    let owner = register(&c, &base);
    let top = drive_names::top_level_hash_key(&owner.master_key).unwrap();
    let projects = drive_names::name_hash(&top, "Projects").unwrap();
    let (status, _, first) = folder_named(&c, &base, &owner, None, &projects);
    assert!(status.is_success());
    let (status, body, _) = folder_named(&c, &base, &owner, None, &projects);
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["holder"]["id"], first.id);
    // Another account's top level is its own.
    let other = register(&c, &base);
    let (status, _, _) = folder_named(&c, &base, &other, None, &projects);
    assert!(status.is_success());

    // A folder moved to the top level brings a name free there.
    let (_, _, holder) = folder_named(
        &c,
        &base,
        &owner,
        None,
        &drive_names::name_hash(&top, "Holder").unwrap(),
    );
    let (_, _, inner) = folder_named(
        &c,
        &base,
        &owner,
        Some(&holder),
        &drive_names::name_hash(
            &drive_names::folder_hash_key(&holder.key, &holder.id).unwrap(),
            "Projects",
        )
        .unwrap(),
    );
    let r = bearer(
        c.post(format!("{base}/api/collections/{}/move", inner.id)),
        &owner.token,
    )
    .json(&json!({ "parentCollectionId": null, "nameHash": projects }))
    .send()
    .unwrap();
    assert_taken(r, "folder", &first.id);
    let elsewhere = drive_names::name_hash(&top, "Projects (2)").unwrap();
    let r = bearer(
        c.post(format!("{base}/api/collections/{}/move", inner.id)),
        &owner.token,
    )
    .json(&json!({ "parentCollectionId": null, "nameHash": elsewhere }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    // A folder restored after its name was taken comes back without it.
    let r = bearer(
        c.delete(format!("{base}/api/collections/{}", first.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert!(r.status().is_success());
    let (status, _, _) = folder_named(&c, &base, &owner, None, &projects);
    assert!(status.is_success());
    let r = bearer(
        c.post(format!("{base}/api/trash/{}/restore", first.id)),
        &owner.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let restored: Value = bearer(
        c.get(format!("{base}/api/collections/{}", first.id)),
        &owner.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(restored["nameHash"], Value::Null, "{restored}");
}

fn tus_create_named(
    c: &Client,
    base: &str,
    user: &User,
    folder: &Folder,
    file: &Sealed,
    hash: Option<&str>,
) -> Response {
    let mut meta = vec![
        ("fileId", file.id.as_str()),
        ("collectionId", folder.id.as_str()),
        ("metadataEnvelope", file.metadata_envelope.as_str()),
        ("fileKeyEnvelope", file.file_key_envelope.as_str()),
    ];
    if let Some(hash) = hash {
        meta.push(("nameHash", hash));
    }
    let meta = meta
        .iter()
        .map(|(k, v)| format!("{k} {}", b64(v.as_bytes())))
        .collect::<Vec<_>>()
        .join(",");
    bearer(c.post(format!("{base}/api/uploads")), &user.token)
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Length", file.blob.len().to_string())
        .header("Upload-Metadata", meta)
        .send()
        .unwrap()
}

fn rename_file(
    c: &Client,
    base: &str,
    user: &User,
    file: &Sealed,
    revision: u64,
    hash: &str,
) -> Response {
    let envelope = drive_envelope::seal_b64(
        br#"{"name":"renamed.txt","mimeType":"text/plain","size":1}"#,
        &file.key,
        kutup_crypto::drive_envelope::DriveEnvelopeContextV1::file_metadata(&file.id, 1, revision)
            .unwrap(),
    )
    .unwrap();
    bearer(c.put(format!("{base}/api/files/{}", file.id)), &user.token)
        .json(&json!({ "metadataEnvelope": envelope, "metadataRevision": revision, "nameHash": hash }))
        .send()
        .unwrap()
}

fn rename_folder(c: &Client, base: &str, user: &User, folder: &Folder, hash: &str) -> Response {
    use kutup_crypto::drive_envelope::{DriveEnvelopeContextV1, DriveEnvelopePurpose};
    let envelope = drive_envelope::seal_b64(
        b"Renamed",
        &folder.key,
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::CollectionName,
            1,
            2,
            &folder.id,
            &user.id,
        )
        .unwrap(),
    )
    .unwrap();
    bearer(
        c.put(format!("{base}/api/collections/{}", folder.id)),
        &user.token,
    )
    .json(&json!({ "nameEnvelope": envelope, "nameRevision": 2, "nameHash": hash }))
    .send()
    .unwrap()
}
