//! Live e2e for moving files and folders (docs/plans/drive-move.md).
//!
//! A file moves by re-sealing only its key for the destination: its content,
//! metadata and versions open there unchanged. Moves stay within one owner's
//! folders and need edit rights on both ends; a file its folder has rotated
//! past is re-keyed first, and its key history travels with it. A folder
//! moves under another of its owner's folders, never into itself.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test drive_move_live -- --nocapture

use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::collection_keyring;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};
use kutup_crypto::file_keyring::{self, FileKeyLinkV1};
use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

fn rows(c: &Client, base: &str, token: &str, folder: &Folder) -> Vec<Value> {
    bearer(
        c.get(format!("{base}/api/collections/{}/files", folder.id)),
        token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap()
}

/// The file's current key, sealed for `to` at `epoch` with `generation`.
fn wrap(key: &[u8; 32], file_id: &str, to: &Folder, epoch: u32, generation: u32) -> String {
    drive_envelope::seal_b64(
        key,
        &to.key,
        DriveEnvelopeContextV1::file_key(file_id, &to.id, epoch, generation).unwrap(),
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn move_file(
    c: &Client,
    base: &str,
    token: &str,
    file_id: &str,
    from: &Folder,
    to: &Folder,
    epoch: i32,
    envelope: &str,
) -> reqwest::blocking::Response {
    bearer(c.post(format!("{base}/api/files/{file_id}/move")), token)
        .json(&json!({
            "fromCollectionId": from.id,
            "toCollectionId": to.id,
            "toKeyEpoch": epoch,
            "fileKeyEnvelope": envelope,
        }))
        .send()
        .unwrap()
}

fn move_folder(
    c: &Client,
    base: &str,
    token: &str,
    folder: &Folder,
    parent: Option<&Folder>,
) -> StatusCode {
    bearer(
        c.post(format!("{base}/api/collections/{}/move", folder.id)),
        token,
    )
    .json(&json!({ "parentCollectionId": parent.map(|p| p.id.clone()) }))
    .send()
    .unwrap()
    .status()
}

#[test]
fn drive_move_contract() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let owner = register(&c, &base);
    let editor = register(&c, &base);
    let viewer = register(&c, &base);
    let stranger = register(&c, &base);
    let a = create_folder(&c, &base, &owner);
    let b = create_folder(&c, &base, &owner);
    let elsewhere = create_folder(&c, &base, &stranger);
    share(&c, &base, &owner, &a, &editor, true);
    share(&c, &base, &owner, &b, &editor, true);
    share(&c, &base, &owner, &a, &viewer, true);
    share(&c, &base, &owner, &b, &viewer, false);

    // --- A file moves by re-wrapping its key; everything else is untouched.
    let file = seal_file(&a, &uuid(), b"moves without re-encryption");
    assert_eq!(
        upload(&c, &base, &owner.token, &a, &file).status(),
        StatusCode::CREATED
    );
    let before = download(&c, &base, &owner.token, &file.id).1;
    let used_before = used(&c, &base, &owner.token);

    // Refused: an envelope sealed for another folder, or for the source.
    let r = move_file(
        &c,
        &base,
        &owner.token,
        &file.id,
        &a,
        &b,
        1,
        &wrap(&file.key, &file.id, &a, 1, 1),
    );
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // Refused: the wrong generation.
    let r = move_file(
        &c,
        &base,
        &owner.token,
        &file.id,
        &a,
        &b,
        1,
        &wrap(&file.key, &file.id, &b, 1, 2),
    );
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // Refused: the client saw the file elsewhere.
    let r = move_file(
        &c,
        &base,
        &owner.token,
        &file.id,
        &elsewhere,
        &b,
        1,
        &wrap(&file.key, &file.id, &b, 1, 1),
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    // Refused: into the folder it is in.
    let r = move_file(
        &c,
        &base,
        &owner.token,
        &file.id,
        &a,
        &a,
        1,
        &wrap(&file.key, &file.id, &a, 1, 1),
    );
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // Refused: a viewer of the destination, and a stranger.
    let into_b = wrap(&file.key, &file.id, &b, 1, 1);
    assert_eq!(
        move_file(&c, &base, &viewer.token, &file.id, &a, &b, 1, &into_b).status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        move_file(&c, &base, &stranger.token, &file.id, &a, &b, 1, &into_b).status(),
        StatusCode::FORBIDDEN
    );
    // Refused: another owner's folder (the stranger's own folder, even
    // with edit rights there, is not the file owner's).
    share(&c, &base, &stranger, &elsewhere, &owner, true);
    let r = move_file(
        &c,
        &base,
        &owner.token,
        &file.id,
        &a,
        &elsewhere,
        1,
        &wrap(&file.key, &file.id, &elsewhere, 1, 1),
    );
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // Accepted: an editor of both folders moves it.
    let r = move_file(&c, &base, &editor.token, &file.id, &a, &b, 1, &into_b);
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.json::<Value>().unwrap()["collectionId"], b.id.as_str());
    assert!(rows(&c, &base, &owner.token, &a).is_empty());
    let moved = rows(&c, &base, &owner.token, &b);
    assert_eq!(moved.len(), 1);
    assert_eq!(moved[0]["id"], file.id.as_str());
    assert_eq!(moved[0]["keyGeneration"], 1);
    // The destination's key opens it; the metadata and content are the same bytes.
    let key = drive_envelope::open_b64(
        moved[0]["fileKeyEnvelope"].as_str().unwrap(),
        &b.key,
        DriveEnvelopeContextV1::file_key(&file.id, &b.id, 1, 1).unwrap(),
    )
    .unwrap();
    assert_eq!(key.as_slice(), file.key.as_slice());
    assert_eq!(
        moved[0]["metadataEnvelope"],
        file.metadata_envelope.as_str()
    );
    let after = download(&c, &base, &owner.token, &file.id).1;
    assert_eq!(after, before);
    assert_eq!(
        drive_object::decrypt_file_blob(
            &after,
            &key,
            DriveFileBlobContextV1::new(&file.id, 1).unwrap()
        )
        .unwrap(),
        b"moves without re-encryption"
    );
    assert_eq!(used(&c, &base, &owner.token), used_before, "a move is free");
    // A viewer who can now only read the file there cannot move it back.
    assert_eq!(
        move_file(
            &c,
            &base,
            &viewer.token,
            &file.id,
            &b,
            &a,
            1,
            &wrap(&file.key, &file.id, &a, 1, 1)
        )
        .status(),
        StatusCode::FORBIDDEN
    );

    // --- A file behind its folder is re-keyed before it moves, and its
    // history goes with it.
    let second = seal_file(&a, &uuid(), b"sealed under generation 1");
    assert_eq!(
        upload(&c, &base, &owner.token, &a, &second).status(),
        StatusCode::CREATED
    );
    // Rotate A, removing the viewer.
    let access: Value = bearer(
        c.get(format!("{base}/api/collections/{}/access", a.id)),
        &owner.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let mut a2 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut a2);
    let statement = CollectionEpochStatementV1::create(
        &a.id,
        &owner.id,
        2,
        access["epochStatementHash"].as_str(),
        &a2,
        owner.identity.authority_signing_key(),
    )
    .unwrap();
    let editor_share = kutup_crypto::named_share::NamedShareEnvelopeV1::seal(
        &a2,
        &a.id,
        2,
        &format!("{}@{DOMAIN}", owner.username),
        &owner.identity.incarnation_id(),
        owner.identity.drive_signing_key(),
        &format!("{}@{DOMAIN}", editor.username),
        &editor.identity.incarnation_id(),
        &editor.identity.drive_hpke_public_key(),
    )
    .unwrap()
    .encode_b64()
    .unwrap();
    let ctx2 = |purpose, revision| {
        DriveEnvelopeContextV1::new(purpose, 2, revision, &a.id, &owner.id).unwrap()
    };
    let r = bearer(
        c.post(format!("{base}/api/collections/{}/rotate", a.id)),
        &owner.token,
    )
    .json(&json!({
        "fromEpoch": 1,
        "epochStatement": statement.encode_b64(),
        "ownerKeyEnvelope": drive_envelope::seal_b64(&a2, &owner.master_key, ctx2(DriveEnvelopePurpose::CollectionKey, 1)).unwrap(),
        "previousKeyEnvelope": collection_keyring::seal_previous_key(&a.key, &a2, &a.id, &owner.id, 2).unwrap(),
        "nameEnvelope": drive_envelope::seal_b64(b"Integrity", &a2, ctx2(DriveEnvelopePurpose::CollectionName, 2)).unwrap(),
        "members": [{ "userId": editor.id, "namedShareEnvelope": editor_share }],
        "publicLinks": [],
        "removed": { "members": [viewer.id] },
    }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "rotate: {:?}", r.text());

    // Refused while behind: the removed viewer holds this key.
    let r = move_file(
        &c,
        &base,
        &owner.token,
        &second.id,
        &a,
        &b,
        1,
        &wrap(&second.key, &second.id, &b, 1, 1),
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert!(r.text().unwrap().contains("re-key"));

    // Re-key: generation 2 at epoch 2, sealing generation 1.
    let mut second_key2 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut second_key2);
    let r = bearer(
        c.post(format!("{base}/api/files/{}/rekey", second.id)),
        &owner.token,
    )
    .json(&json!({
        "fromGeneration": 1,
        "fileKeyEnvelope": drive_envelope::seal_b64(&second_key2, &a2,
            DriveEnvelopeContextV1::file_key(&second.id, &a.id, 2, 2).unwrap()).unwrap(),
        "metadataEnvelope": drive_envelope::seal_b64(br#"{"name":"a.txt","mimeType":"text/plain","size":1}"#, &second_key2,
            DriveEnvelopeContextV1::file_metadata(&second.id, 2, 1).unwrap()).unwrap(),
        "previousKeyEnvelope": file_keyring::seal_previous_key(&second.key, &second_key2, &second.id, 2).unwrap(),
    }))
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // A wrap at the destination's old epoch is stale; at its current one it moves.
    let r = move_file(
        &c,
        &base,
        &owner.token,
        &second.id,
        &a,
        &b,
        2,
        &wrap(&second_key2, &second.id, &b, 1, 2),
    );
    assert_eq!(r.status(), StatusCode::CONFLICT, "b is still at epoch 1");
    let r = move_file(
        &c,
        &base,
        &owner.token,
        &second.id,
        &a,
        &b,
        1,
        &wrap(&second_key2, &second.id, &b, 1, 2),
    );
    assert_eq!(r.status(), StatusCode::OK);

    // In B, the chain still reaches generation 1, which opens the upload.
    let row = rows(&c, &base, &owner.token, &b)
        .into_iter()
        .find(|r| r["id"] == second.id.as_str())
        .unwrap();
    assert_eq!(row["keyEpoch"], 1);
    assert_eq!(row["keyGeneration"], 2);
    assert_eq!(row["contentKeyGeneration"], 1);
    let current = drive_envelope::open_b64(
        row["fileKeyEnvelope"].as_str().unwrap(),
        &b.key,
        DriveEnvelopeContextV1::file_key(&second.id, &b.id, 1, 2).unwrap(),
    )
    .unwrap();
    let chain: Vec<FileKeyLinkV1> = row["keyHistory"]
        .as_array()
        .unwrap()
        .iter()
        .map(|link| FileKeyLinkV1 {
            generation: link["generation"].as_u64().unwrap() as u32,
            previous_key_envelope: link["previousKeyEnvelope"].as_str().unwrap().to_string(),
        })
        .collect();
    let first = file_keyring::key_at(&current, &second.id, 2, &chain, 1).unwrap();
    assert_eq!(
        drive_object::decrypt_file_blob(
            &download(&c, &base, &owner.token, &second.id).1,
            &first,
            DriveFileBlobContextV1::new(&second.id, 1).unwrap()
        )
        .unwrap(),
        b"sealed under generation 1"
    );

    // --- Folders.
    let parent = create_folder(&c, &base, &owner);
    let child = create_folder_in(&c, &base, &owner, Some(&parent.id));
    let grandchild = create_folder_in(&c, &base, &owner, Some(&child.id));
    assert_eq!(
        move_folder(&c, &base, &owner.token, &parent, Some(&parent)),
        StatusCode::BAD_REQUEST,
        "into itself"
    );
    assert_eq!(
        move_folder(&c, &base, &owner.token, &parent, Some(&grandchild)),
        StatusCode::BAD_REQUEST,
        "into a folder inside it"
    );
    assert_eq!(
        move_folder(&c, &base, &owner.token, &child, Some(&elsewhere)),
        StatusCode::BAD_REQUEST,
        "under another owner's folder"
    );
    assert_eq!(
        move_folder(&c, &base, &editor.token, &a, Some(&b)),
        StatusCode::NOT_FOUND,
        "only the owner moves a folder"
    );
    assert_eq!(
        move_folder(&c, &base, &owner.token, &grandchild, None),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        move_folder(&c, &base, &owner.token, &parent, Some(&grandchild)),
        StatusCode::NO_CONTENT,
        "no longer below it"
    );
    let folders: Vec<Value> = bearer(c.get(format!("{base}/api/collections")), &owner.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let parent_of =
        |id: &str| folders.iter().find(|f| f["id"] == id).unwrap()["parentCollectionId"].clone();
    assert_eq!(parent_of(&grandchild.id), Value::Null);
    assert_eq!(parent_of(&parent.id), grandchild.id.as_str());
    assert_eq!(parent_of(&child.id), parent.id.as_str());
}
