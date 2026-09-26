//! Live e2e for sharing a single file (docs/plans/drive-file-sharing.md).
//!
//! The owner shares one file (view or edit) without its folder: the
//! recipient lists it, opens its key, downloads it, and may save versions
//! only with edit access; nobody else reaches it; the folder stays closed;
//! removing someone moves the file to a new key, re-sealed for whoever stays,
//! and the removed person is refused from then on.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test file_shares_live -- --nocapture

use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};
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
