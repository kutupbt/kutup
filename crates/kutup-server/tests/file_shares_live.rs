//! Live e2e for sharing a single file (docs/plans/drive-file-sharing.md).
//!
//! The owner shares one file (view or edit) without its folder: the
//! recipient lists it, opens its key, downloads it, and may save versions
//! only with edit access; nobody else reaches it; the folder stays closed;
//! removing someone moves the file to a new key, re-sealed for whoever stays,
//! and the removed person is refused from then on. When the folder moves
//! past the file's key, or someone else re-keys the file, its shares can
//! read but not edit until the owner re-seals them.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test file_shares_live -- --nocapture

use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::collection_keyring;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};
use kutup_crypto::file_keyring;
use kutup_crypto::named_share::FileShareEnvelopeV1;
use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

fn account(user: &User) -> String {
    format!("{}@{DOMAIN}", user.username)
}

fn file_share(owner: &User, file_id: &str, key: &[u8; 32], generation: u32, to: &User) -> String {
    FileShareEnvelopeV1::seal(
        key,
        file_id,
        generation,
        &account(owner),
        &owner.identity.incarnation_id(),
        owner.identity.drive_signing_key(),
        &account(to),
        &to.identity.incarnation_id(),
        &to.identity.drive_hpke_public_key(),
    )
    .unwrap()
    .encode_b64()
    .unwrap()
}

#[test]
fn file_share_contract() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::new();
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let carol = register(&c, &base);
    let dave = register(&c, &base);
    let folder = create_folder(&c, &base, &alice);
    let file = seal_file(&folder, &uuid(), b"just this one");
    assert!(upload(&c, &base, &alice.token, &folder, &file)
        .status()
        .is_success());

    let share = |to: &User, envelope: String, can_edit: bool, by: &User| {
        bearer(
            c.post(format!("{base}/api/files/{}/share", file.id)),
            &by.token,
        )
        .json(&json!({ "recipientUserId": to.id, "shareEnvelope": envelope, "canEdit": can_edit }))
        .send()
        .unwrap()
        .status()
    };
    // Bob may view, Carol may edit.
    assert_eq!(
        share(
            &bob,
            file_share(&alice, &file.id, &file.key, 1, &bob),
            false,
            &alice
        ),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        share(
            &carol,
            file_share(&alice, &file.id, &file.key, 1, &carol),
            true,
            &alice
        ),
        StatusCode::NO_CONTENT
    );
    // Only the owner shares, only with a matching envelope.
    assert_eq!(
        share(
            &dave,
            file_share(&alice, &file.id, &file.key, 1, &dave),
            false,
            &bob
        ),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        share(
            &dave,
            file_share(&alice, &file.id, &file.key, 2, &dave),
            false,
            &alice
        ),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        share(
            &dave,
            file_share(&alice, &file.id, &file.key, 1, &bob),
            false,
            &alice
        ),
        StatusCode::BAD_REQUEST
    );

    // Bob lists it and opens its key; the folder stays closed.
    let listed: Value = bearer(c.get(format!("{base}/api/shared-files")), &bob.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let entry = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["file"]["id"] == file.id.as_str())
        .expect("listed");
    assert_eq!(entry["canEdit"], false);
    assert_eq!(entry["ownerAccount"], account(&alice));
    let opened = FileShareEnvelopeV1::decode_b64(entry["shareEnvelope"].as_str().unwrap())
        .unwrap()
        .open(
            &file.id,
            1,
            &account(&alice),
            &alice.identity.incarnation_id(),
            &alice.identity.drive_signing_public_key(),
            &account(&bob),
            &bob.identity.incarnation_id(),
            bob.identity.drive_hpke_private_key(),
        )
        .unwrap();
    assert_eq!(opened, file.key);
    let (status, blob) = download(&c, &base, &bob.token, &file.id);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        drive_object::decrypt_file_blob(
            &blob,
            &opened,
            DriveFileBlobContextV1::new(&file.id, 1).unwrap()
        )
        .unwrap(),
        b"just this one"
    );
    let folder_files = bearer(
        c.get(format!("{base}/api/collections/{}/files", folder.id)),
        &bob.token,
    )
    .send()
    .unwrap();
    assert_eq!(
        folder_files.status(),
        StatusCode::FORBIDDEN,
        "the folder is not shared"
    );
    assert_ne!(
        download(&c, &base, &dave.token, &file.id).0,
        StatusCode::OK,
        "a stranger"
    );

    // Viewing is not editing.
    let version = || {
        drive_object::encrypt_file_blob(
            b"edited",
            &file.key,
            DriveFileBlobContextV1::new(&file.id, 1).unwrap(),
        )
        .unwrap()
    };
    assert_eq!(
        post_version(&c, &base, &bob.token, &file.id, version()).status(),
        StatusCode::FORBIDDEN
    );
    assert!(post_version(&c, &base, &carol.token, &file.id, version())
        .status()
        .is_success());

    // The owner sees who has it.
    let access: Value = bearer(
        c.get(format!("{base}/api/files/{}/access", file.id)),
        &alice.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(access["members"].as_array().unwrap().len(), 2);
    assert_eq!(
        bearer(
            c.get(format!("{base}/api/files/{}/access", file.id)),
            &bob.token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN
    );

    // Removing Bob: a new key, re-sealed for Carol only, in one request.
    let mut next_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut next_key);
    let rotate = |members: Value, removed: Value| {
        bearer(c.post(format!("{base}/api/files/{}/rotate", file.id)), &alice.token)
            .json(&json!({
                "fromGeneration": 1,
                "fileKeyEnvelope": drive_envelope::seal_b64(&next_key, &folder.key,
                    DriveEnvelopeContextV1::file_key(&file.id, &folder.id, 1, 2).unwrap()).unwrap(),
                "metadataEnvelope": drive_envelope::seal_b64(br#"{"name":"a.txt","mimeType":"text/plain","size":1}"#, &next_key,
                    DriveEnvelopeContextV1::file_metadata(&file.id, 2, 1).unwrap()).unwrap(),
                "previousKeyEnvelope": drive_envelope::seal_b64(&file.key, &next_key,
                    DriveEnvelopeContextV1::previous_file_key(&file.id, 2).unwrap()).unwrap(),
                "members": members,
                "removed": removed,
            }))
            .send()
            .unwrap()
    };
    // Leaving Carol out entirely would drop her silently: refused.
    assert_eq!(
        rotate(json!([]), json!([bob.id])).status(),
        StatusCode::CONFLICT
    );
    let rotated = rotate(
        json!([{ "userId": carol.id, "shareEnvelope": file_share(&alice, &file.id, &next_key, 2, &carol) }]),
        json!([bob.id]),
    );
    assert_eq!(rotated.status(), StatusCode::OK);
    let rotated: Value = rotated.json().unwrap();
    assert_eq!(rotated["keyGeneration"], 2);
    assert_eq!(rotated["members"].as_array().unwrap().len(), 1);

    assert_ne!(
        download(&c, &base, &bob.token, &file.id).0,
        StatusCode::OK,
        "Bob was removed"
    );
    let bob_listed: Value = bearer(c.get(format!("{base}/api/shared-files")), &bob.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(bob_listed
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["file"]["id"] != file.id.as_str()));
    let carol_listed: Value = bearer(c.get(format!("{base}/api/shared-files")), &carol.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let carol_entry = carol_listed
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["file"]["id"] == file.id.as_str())
        .unwrap();
    assert_eq!(carol_entry["keyGeneration"], 2);
    assert_eq!(
        download(&c, &base, &carol.token, &file.id).0,
        StatusCode::OK
    );

    // In the trash, a shared file is out of reach; restored, back.
    assert!(bearer(
        c.delete(format!("{base}/api/files/{}", file.id)),
        &alice.token
    )
    .send()
    .unwrap()
    .status()
    .is_success());
    assert_ne!(
        download(&c, &base, &carol.token, &file.id).0,
        StatusCode::OK
    );
    let trashed: Value = bearer(c.get(format!("{base}/api/shared-files")), &carol.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(trashed
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["file"]["id"] != file.id.as_str()));
}

fn get(c: &Client, url: String, token: &str) -> Value {
    bearer(c.get(url), token).send().unwrap().json().unwrap()
}

#[test]
fn stale_file_shares_wait_for_the_owner() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::new();
    let (alice, editor, leaver, carol) = (
        register(&c, &base),
        register(&c, &base),
        register(&c, &base),
        register(&c, &base),
    );
    let folder = create_folder(&c, &base, &alice);
    share(&c, &base, &alice, &folder, &editor, true);
    share(&c, &base, &alice, &folder, &leaver, false);
    let file = seal_file(&folder, &uuid(), b"stale");
    assert!(upload(&c, &base, &alice.token, &folder, &file)
        .status()
        .is_success());
    let status = bearer(
        c.post(format!("{base}/api/files/{}/share", file.id)),
        &alice.token,
    )
    .json(&json!({ "recipientUserId": carol.id,
                   "shareEnvelope": file_share(&alice, &file.id, &file.key, 1, &carol),
                   "canEdit": true }))
    .send()
    .unwrap()
    .status();
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Shared by me: the folder (two people) and the file by itself (one).
    let by_me = get(&c, format!("{base}/api/shared-by-me"), &alice.token);
    let by_me = by_me.as_array().unwrap();
    assert!(by_me.iter().any(|i| i["collectionId"] == folder.id.as_str()
        && i.get("fileId").is_none()
        && i["people"] == 2));
    assert!(by_me
        .iter()
        .any(|i| i["fileId"] == file.id.as_str() && i["people"] == 1));
    assert_eq!(
        get(&c, format!("{base}/api/shared-by-me"), &carol.token)
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // The owner sees the mark; a folder member does not.
    let listing = |token: &str| {
        get(
            &c,
            format!("{base}/api/collections/{}/files", folder.id),
            token,
        )
    };
    assert_eq!(listing(&alice.token)[0]["shared"], true);
    assert!(listing(&editor.token)[0].get("shared").is_none());
    let pending = |token: &str| get(&c, format!("{base}/api/file-shares/pending"), token);
    assert_eq!(pending(&alice.token).as_array().unwrap().len(), 0);
    let version = |key: &[u8; 32], generation: u32| {
        drive_object::encrypt_file_blob(
            b"v",
            key,
            DriveFileBlobContextV1::new(&file.id, generation).unwrap(),
        )
        .unwrap()
    };
    assert!(
        post_version(&c, &base, &carol.token, &file.id, version(&file.key, 1))
            .status()
            .is_success()
    );

    // The folder moves to a new key (the leaver removed); the file is behind.
    let access = get(
        &c,
        format!("{base}/api/collections/{}/access", folder.id),
        &alice.token,
    );
    let mut folder2 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut folder2);
    let statement = CollectionEpochStatementV1::create(
        &folder.id,
        &alice.id,
        2,
        access["epochStatementHash"].as_str(),
        &folder2,
        alice.identity.authority_signing_key(),
    )
    .unwrap();
    let editor_share = kutup_crypto::named_share::NamedShareEnvelopeV1::seal(
        &folder2,
        &folder.id,
        2,
        &account(&alice),
        &alice.identity.incarnation_id(),
        alice.identity.drive_signing_key(),
        &account(&editor),
        &editor.identity.incarnation_id(),
        &editor.identity.drive_hpke_public_key(),
    )
    .unwrap()
    .encode_b64()
    .unwrap();
    let ctx2 = |purpose, revision| {
        DriveEnvelopeContextV1::new(purpose, 2, revision, &folder.id, &alice.id).unwrap()
    };
    let r = bearer(
        c.post(format!("{base}/api/collections/{}/rotate", folder.id)),
        &alice.token,
    )
    .json(&json!({
        "fromEpoch": 1,
        "epochStatement": statement.encode_b64(),
        "ownerKeyEnvelope": drive_envelope::seal_b64(&folder2, &alice.master_key, ctx2(DriveEnvelopePurpose::CollectionKey, 1)).unwrap(),
        "previousKeyEnvelope": collection_keyring::seal_previous_key(&folder.key, &folder2, &folder.id, &alice.id, 2).unwrap(),
        "nameEnvelope": drive_envelope::seal_b64(b"Stale", &folder2, ctx2(DriveEnvelopePurpose::CollectionName, 2)).unwrap(),
        "members": [{ "userId": editor.id, "namedShareEnvelope": editor_share }],
        "publicLinks": [],
        "removed": { "members": [leaver.id] },
    }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "rotate: {:?}", r.text());

    let carol_entry = |token: &str| {
        get(&c, format!("{base}/api/shared-files"), token)
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["file"]["id"] == file.id.as_str())
            .cloned()
            .unwrap()
    };
    assert_eq!(carol_entry(&carol.token)["folderKeyCurrent"], false);
    assert_eq!(pending(&alice.token)[0]["fileId"], file.id.as_str());
    assert_eq!(pending(&carol.token).as_array().unwrap().len(), 0);
    // The leaver holds the key the file is still under: Carol may not write.
    assert_eq!(
        post_version(&c, &base, &carol.token, &file.id, version(&file.key, 1)).status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        download(&c, &base, &carol.token, &file.id).0,
        StatusCode::OK
    );

    // The folder's editor re-keys the file; they cannot seal for the owner.
    let mut key2 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key2);
    let r = bearer(c.post(format!("{base}/api/files/{}/rekey", file.id)), &editor.token)
        .json(&json!({
            "fromGeneration": 1,
            "fileKeyEnvelope": drive_envelope::seal_b64(&key2, &folder2,
                DriveEnvelopeContextV1::file_key(&file.id, &folder.id, 2, 2).unwrap()).unwrap(),
            "metadataEnvelope": drive_envelope::seal_b64(br#"{"name":"a.txt","mimeType":"text/plain","size":1}"#, &key2,
                DriveEnvelopeContextV1::file_metadata(&file.id, 2, 1).unwrap()).unwrap(),
            "previousKeyEnvelope": file_keyring::seal_previous_key(&file.key, &key2, &file.id, 2).unwrap(),
        }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "rekey: {:?}", r.text());
    let entry = carol_entry(&carol.token);
    assert_eq!(entry["folderKeyCurrent"], true);
    assert_eq!(entry["keyGeneration"], 1);
    assert_eq!(entry["file"]["keyGeneration"], 2);
    // Waiting, it can still be named: the metadata of generation 1, under the key Carol has.
    let at_share = &entry["metadataAtShare"];
    let revision = at_share["revision"].as_u64().unwrap();
    let named = drive_envelope::open_b64(
        at_share["envelope"].as_str().unwrap(),
        &file.key,
        DriveEnvelopeContextV1::file_metadata(&file.id, 1, revision).unwrap(),
    )
    .unwrap();
    assert!(!named.is_empty());
    assert_eq!(pending(&alice.token).as_array().unwrap().len(), 1);
    assert_eq!(
        post_version(&c, &base, &carol.token, &file.id, version(&key2, 2)).status(),
        StatusCode::FORBIDDEN
    );

    // The owner re-seals: Carol edits again, nothing is pending.
    let r = bearer(c.put(format!("{base}/api/files/{}/shares", file.id)), &alice.token)
        .json(&json!({ "members": [{ "userId": carol.id,
                                     "shareEnvelope": file_share(&alice, &file.id, &key2, 2, &carol) }] }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(pending(&alice.token).as_array().unwrap().len(), 0);
    assert_eq!(carol_entry(&carol.token)["keyGeneration"], 2);
    assert!(carol_entry(&carol.token).get("metadataAtShare").is_none());
    assert!(
        post_version(&c, &base, &carol.token, &file.id, version(&key2, 2))
            .status()
            .is_success()
    );
}

#[test]
fn editors_share_and_rename_when_allowed() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::new();
    let (alice, carol, dave, erin) = (
        register(&c, &base),
        register(&c, &base),
        register(&c, &base),
        register(&c, &base),
    );
    let folder = create_folder(&c, &base, &alice);
    let file = seal_file(&folder, &uuid(), b"edit me");
    assert!(upload(&c, &base, &alice.token, &folder, &file)
        .status()
        .is_success());
    let share = |by: &User, to: &User, can_edit: bool| {
        bearer(
            c.post(format!("{base}/api/files/{}/share", file.id)),
            &by.token,
        )
        .json(&json!({ "recipientUserId": to.id,
                       "shareEnvelope": file_share(by, &file.id, &file.key, 1, to),
                       "canEdit": can_edit }))
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(share(&alice, &carol, true), StatusCode::NO_CONTENT);
    assert_eq!(share(&alice, &erin, false), StatusCode::NO_CONTENT);

    // Off by default: an editor may not share on, nor see who has it.
    assert_eq!(share(&carol, &dave, false), StatusCode::FORBIDDEN);
    let access = |by: &User| {
        bearer(
            c.get(format!("{base}/api/files/{}/access", file.id)),
            &by.token,
        )
        .send()
        .unwrap()
    };
    assert_eq!(access(&carol).status(), StatusCode::FORBIDDEN);
    let allow = |value: bool, by: &User| {
        bearer(
            c.put(format!("{base}/api/files/{}/sharing", file.id)),
            &by.token,
        )
        .json(&json!({ "editorsCanShare": value }))
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(allow(true, &carol), StatusCode::FORBIDDEN, "only the owner");
    assert_eq!(allow(true, &alice), StatusCode::NO_CONTENT);

    // Now Carol adds Dave, signing it herself; she changes nobody.
    assert_eq!(share(&carol, &dave, false), StatusCode::NO_CONTENT);
    assert_eq!(
        share(&carol, &erin, true),
        StatusCode::CONFLICT,
        "Erin has it"
    );
    assert_eq!(
        share(&carol, &alice, false),
        StatusCode::CONFLICT,
        "the owner"
    );
    assert_eq!(
        share(&erin, &dave, false),
        StatusCode::FORBIDDEN,
        "a viewer"
    );
    let seen: Value = access(&carol).json().unwrap();
    assert_eq!(seen["members"].as_array().unwrap().len(), 3);
    assert_eq!(seen["editorsCanShare"], true);

    let listed = get(&c, format!("{base}/api/shared-files"), &dave.token);
    let entry = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["file"]["id"] == file.id.as_str())
        .unwrap();
    assert_eq!(entry["sharerAccount"], account(&carol));
    assert_eq!(entry["ownerAccount"], account(&alice));
    let opened = FileShareEnvelopeV1::decode_b64(entry["shareEnvelope"].as_str().unwrap())
        .unwrap()
        .open(
            &file.id,
            1,
            &account(&carol),
            &carol.identity.incarnation_id(),
            &carol.identity.drive_signing_public_key(),
            &account(&dave),
            &dave.identity.incarnation_id(),
            dave.identity.drive_hpke_private_key(),
        )
        .unwrap();
    assert_eq!(opened, file.key);

    // Editors rename; viewers do not.
    let rename = |by: &User, revision: u64| {
        bearer(c.put(format!("{base}/api/files/{}", file.id)), &by.token)
            .json(&json!({
                "metadataEnvelope": drive_envelope::seal_b64(br#"{"name":"renamed.txt","mimeType":"text/plain","size":1}"#, &file.key,
                    DriveEnvelopeContextV1::file_metadata(&file.id, 1, revision).unwrap()).unwrap(),
                "metadataRevision": revision,
            }))
            .send()
            .unwrap()
            .status()
    };
    assert!(rename(&carol, 2).is_success());
    assert_eq!(rename(&erin, 3), StatusCode::FORBIDDEN);

    // Only the owner removes (it takes the folder's key); what the owner
    // re-seals is theirs.
    let rotate = |by: &User| {
        let mut next = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut next);
        let members: Vec<Value> = [&carol, &erin]
            .iter()
            .map(|m| json!({ "userId": m.id, "shareEnvelope": file_share(&alice, &file.id, &next, 2, m) }))
            .collect();
        bearer(c.post(format!("{base}/api/files/{}/rotate", file.id)), &by.token)
            .json(&json!({
                "fromGeneration": 1,
                "fileKeyEnvelope": drive_envelope::seal_b64(&next, &folder.key,
                    DriveEnvelopeContextV1::file_key(&file.id, &folder.id, 1, 2).unwrap()).unwrap(),
                "metadataEnvelope": drive_envelope::seal_b64(br#"{"name":"a.txt","mimeType":"text/plain","size":1}"#, &next,
                    DriveEnvelopeContextV1::file_metadata(&file.id, 2, 2).unwrap()).unwrap(),
                "previousKeyEnvelope": file_keyring::seal_previous_key(&file.key, &next, &file.id, 2).unwrap(),
                "members": members,
                "removed": [dave.id],
            }))
            .send()
            .unwrap()
            .status()
    };
    assert_eq!(rotate(&carol), StatusCode::FORBIDDEN);
    assert_eq!(rotate(&alice), StatusCode::OK);
    let carol_entry = get(&c, format!("{base}/api/shared-files"), &carol.token);
    let carol_entry = carol_entry
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["file"]["id"] == file.id.as_str())
        .unwrap()
        .clone();
    assert_eq!(carol_entry["sharerAccount"], account(&alice));
}

#[test]
fn a_public_link_to_one_file() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::new();
    let (alice, bob) = (register(&c, &base), register(&c, &base));
    let folder = create_folder(&c, &base, &alice);
    let file = seal_file(&folder, &uuid(), b"just this file");
    let neighbour = seal_file(&folder, &uuid(), b"not linked");
    for f in [&file, &neighbour] {
        assert!(upload(&c, &base, &alice.token, &folder, f)
            .status()
            .is_success());
    }
    let wrap = |key: &[u8; 32], link_key: &[u8; 32], generation: u32| {
        drive_envelope::seal_b64(
            key,
            link_key,
            DriveEnvelopeContextV1::public_link_file_key(&file.id, &alice.id, generation).unwrap(),
        )
        .unwrap()
    };
    let make_link = |link_key: &[u8; 32]| -> Value {
        let id = uuid();
        let r = bearer(c.post(format!("{base}/api/share")), &alice.token)
            .json(&json!({
                "shareType": "file",
                "targetId": file.id,
                "collectionKeyEnvelope": wrap(&file.key, link_key, 1),
                "id": id,
                "ownerLinkKeyEnvelope": owner_link_key(link_key, &alice, &id),
            }))
            .send()
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED, "{:?}", r.text());
        r.json().unwrap()
    };
    let link_key = [0x21u8; 32];
    let link = make_link(&link_key);
    let token = link["token"].as_str().unwrap().to_string();

    // Anyone with the link: the file's record, its key, its content.
    let public: Value = c
        .get(format!("{base}/api/share/{token}"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(public["shareType"], "file");
    assert_eq!(public["file"]["id"], file.id.as_str());
    let key = drive_envelope::open_b64(
        public["collectionKeyEnvelope"].as_str().unwrap(),
        &link_key,
        DriveEnvelopeContextV1::public_link_file_key(&file.id, &alice.id, 1).unwrap(),
    )
    .unwrap();
    assert_eq!(key, file.key);
    let blob = c
        .get(format!("{base}/api/share/{token}/download/{}", file.id))
        .send()
        .unwrap();
    assert_eq!(blob.status(), StatusCode::OK);
    assert_eq!(
        drive_object::decrypt_file_blob(
            &blob.bytes().unwrap(),
            &file.key,
            DriveFileBlobContextV1::new(&file.id, 1).unwrap()
        )
        .unwrap(),
        b"just this file"
    );
    // No saved editing state yet: the upload is the file.
    assert_eq!(
        c.get(format!("{base}/api/share/{token}/state/{}", file.id))
            .send()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        c.get(format!("{base}/api/share/{token}/state/{}", neighbour.id))
            .send()
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    // Nothing else in the folder.
    assert_eq!(
        c.get(format!(
            "{base}/api/share/{token}/download/{}",
            neighbour.id
        ))
        .send()
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_ne!(
        c.get(format!("{base}/api/share/{token}/files"))
            .send()
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_ne!(
        c.get(format!("{base}/api/share/{token}/epochs"))
            .send()
            .unwrap()
            .status(),
        StatusCode::OK
    );
    // A wrap for the wrong generation is refused; only the owner links.
    let r = bearer(c.post(format!("{base}/api/share")), &bob.token)
        .json(&json!({ "shareType": "file", "targetId": file.id, "collectionKeyEnvelope": wrap(&file.key, &link_key, 1),
                       "id": uuid(), "ownerLinkKeyEnvelope": owner_link_key(&link_key, &bob, &uuid()) }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // The owner sees it; so does Shared by me.
    let access = get(
        &c,
        format!("{base}/api/files/{}/access", file.id),
        &alice.token,
    );
    assert_eq!(access["publicLinks"].as_array().unwrap().len(), 1);
    let by_me = get(&c, format!("{base}/api/shared-by-me"), &alice.token);
    assert!(by_me
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["fileId"] == file.id.as_str() && i["links"] == 1));

    // Removing Bob keeps the link, re-wrapped for the new key.
    let status = bearer(c.post(format!("{base}/api/files/{}/share", file.id)), &alice.token)
        .json(&json!({ "recipientUserId": bob.id, "shareEnvelope": file_share(&alice, &file.id, &file.key, 1, &bob), "canEdit": false }))
        .send()
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::NO_CONTENT);
    let mut next = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut next);
    let link_id = link["id"].as_str().unwrap();
    let rotate = |from: u32,
                  key: &[u8; 32],
                  to: &[u8; 32],
                  removed: Value,
                  links: Value,
                  removed_links: Value| {
        bearer(c.post(format!("{base}/api/files/{}/rotate", file.id)), &alice.token)
            .json(&json!({
                "fromGeneration": from,
                "fileKeyEnvelope": drive_envelope::seal_b64(to, &folder.key,
                    DriveEnvelopeContextV1::file_key(&file.id, &folder.id, 1, from + 1).unwrap()).unwrap(),
                "metadataEnvelope": drive_envelope::seal_b64(br#"{"name":"a.txt","mimeType":"text/plain","size":1}"#, to,
                    DriveEnvelopeContextV1::file_metadata(&file.id, from + 1, 1).unwrap()).unwrap(),
                "previousKeyEnvelope": file_keyring::seal_previous_key(key, to, &file.id, from + 1).unwrap(),
                "members": [],
                "removed": removed,
                "publicLinks": links,
                "removedLinks": removed_links,
            }))
            .send()
            .unwrap()
            .status()
    };
    // Leaving the link out entirely is refused.
    assert_eq!(
        rotate(1, &file.key, &next, json!([bob.id]), json!([]), json!([])),
        StatusCode::CONFLICT
    );
    assert_eq!(
        rotate(
            1,
            &file.key,
            &next,
            json!([bob.id]),
            json!([{ "id": link_id, "keyEnvelope": wrap(&next, &link_key, 2) }]),
            json!([])
        ),
        StatusCode::OK
    );
    let public: Value = c
        .get(format!("{base}/api/share/{token}"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(public["collectionKeyEpoch"], 2);
    let reopened = drive_envelope::open_b64(
        public["collectionKeyEnvelope"].as_str().unwrap(),
        &link_key,
        DriveEnvelopeContextV1::public_link_file_key(&file.id, &alice.id, 2).unwrap(),
    )
    .unwrap();
    assert_eq!(reopened, next);

    // Removing the link: a new key, and the link is gone.
    let mut third = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut third);
    assert_eq!(
        rotate(2, &next, &third, json!([]), json!([]), json!([link_id])),
        StatusCode::OK
    );
    assert_eq!(
        c.get(format!("{base}/api/share/{token}"))
            .send()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    // A link to a file in the trash goes dark.
    let second_key = [0x31u8; 32];
    let id = uuid();
    let r = bearer(c.post(format!("{base}/api/share")), &alice.token)
        .json(&json!({ "shareType": "file", "targetId": file.id,
                       "collectionKeyEnvelope": drive_envelope::seal_b64(&third, &second_key,
                           DriveEnvelopeContextV1::public_link_file_key(&file.id, &alice.id, 3).unwrap()).unwrap(),
                       "id": id, "ownerLinkKeyEnvelope": owner_link_key(&second_key, &alice, &id) }))
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let token2 = r.json::<Value>().unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(bearer(
        c.delete(format!("{base}/api/files/{}", file.id)),
        &alice.token
    )
    .send()
    .unwrap()
    .status()
    .is_success());
    assert_eq!(
        c.get(format!("{base}/api/share/{token2}"))
            .send()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}
