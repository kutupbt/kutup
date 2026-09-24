//! Live e2e for share revocation and folder-key rotation
//! (docs/plans/drive-share-revocation.md).
//!
//! Removing a member rotates the folder key in one request that must name
//! everyone who stays; the removed member loses access; the history unlocks
//! every older key from the current one and not from an older one; a file
//! behind the folder takes no new content until it is re-keyed; a kept
//! public link follows the key.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test share_revocation_live -- --nocapture

use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::collection_keyring::{self, EpochLinkV1};
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};
use kutup_crypto::named_share::NamedShareEnvelopeV1;
use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

fn ctx_at(
    purpose: DriveEnvelopePurpose,
    epoch: u32,
    revision: u64,
    object: &str,
    parent: &str,
) -> DriveEnvelopeContextV1 {
    DriveEnvelopeContextV1::new(purpose, epoch, revision, object, parent).unwrap()
}

fn named_share(owner: &User, folder_id: &str, key: &[u8; 32], epoch: u32, to: &User) -> String {
    NamedShareEnvelopeV1::seal(
        key,
        folder_id,
        epoch,
        &format!("{}@{DOMAIN}", owner.username),
        &owner.identity.incarnation_id(),
        owner.identity.drive_signing_key(),
        &format!("{}@{DOMAIN}", to.username),
        &to.identity.incarnation_id(),
        &to.identity.drive_hpke_public_key(),
    )
    .unwrap()
    .encode_b64()
    .unwrap()
}

#[test]
fn share_revocation_contract() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let owner = register(&c, &base);
    let alice = register(&c, &base);
    let bob = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    share(&c, &base, &owner, &folder, &alice, true);
    share(&c, &base, &owner, &folder, &bob, false);

    let file = seal_file(&folder, &uuid(), b"written at epoch 1");
    assert_eq!(
        upload(&c, &base, &owner.token, &folder, &file).status(),
        StatusCode::CREATED
    );

    // A public link, with the owner's copy of its key.
    let mut link_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut link_key);
    let link_id = uuid();
    let link = bearer(c.post(format!("{base}/api/share")), &owner.token)
        .json(&json!({
            "id": link_id,
            "shareType": "collection",
            "targetId": folder.id,
            "collectionKeyEnvelope": drive_envelope::seal_b64(&folder.key, &link_key,
                ctx_at(DriveEnvelopePurpose::PublicLinkCollectionKey, 1, 1, &folder.id, &owner.id)).unwrap(),
            "ownerLinkKeyEnvelope": owner_link_key(&link_key, &owner, &link_id),
        }))
        .send()
        .unwrap();
    assert_eq!(link.status(), StatusCode::CREATED);
    let token = link.json::<Value>().unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    // Who has access, as the owner sees it.
    let access: Value = bearer(
        c.get(format!("{base}/api/collections/{}/access", folder.id)),
        &owner.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(access["keyEpoch"], 1);
    assert_eq!(access["members"].as_array().unwrap().len(), 2);
    assert_eq!(access["publicLinks"].as_array().unwrap().len(), 1);
    assert_eq!(
        bearer(
            c.get(format!("{base}/api/collections/{}/access", folder.id)),
            &alice.token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::NOT_FOUND,
        "only the owner lists access"
    );
    let current_hash = access["epochStatementHash"].as_str().unwrap().to_string();

    // The rotation that removes Bob.
    let mut key2 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key2);
    let statement = CollectionEpochStatementV1::create(
        &folder.id,
        &owner.id,
        2,
        Some(&current_hash),
        &key2,
        owner.identity.authority_signing_key(),
    )
    .unwrap();
    let body = |members: Value, removed_members: Value| {
        json!({
            "fromEpoch": 1,
            "epochStatement": statement.encode_b64(),
            "ownerKeyEnvelope": drive_envelope::seal_b64(&key2, &owner.master_key,
                ctx_at(DriveEnvelopePurpose::CollectionKey, 2, 1, &folder.id, &owner.id)).unwrap(),
            "previousKeyEnvelope": collection_keyring::seal_previous_key(&folder.key, &key2, &folder.id, &owner.id, 2).unwrap(),
            "nameEnvelope": drive_envelope::seal_b64(b"Integrity", &key2,
                ctx_at(DriveEnvelopePurpose::CollectionName, 2, 2, &folder.id, &owner.id)).unwrap(),
            "members": members,
            "publicLinks": [{
                "id": link_id,
                "collectionKeyEnvelope": drive_envelope::seal_b64(&key2, &link_key,
                    ctx_at(DriveEnvelopePurpose::PublicLinkCollectionKey, 2, 1, &folder.id, &owner.id)).unwrap(),
            }],
            "removed": { "members": removed_members },
        })
    };
    let rotate = |body: Value, token: &str| {
        bearer(
            c.post(format!("{base}/api/collections/{}/rotate", folder.id)),
            token,
        )
        .json(&body)
        .send()
        .unwrap()
        .status()
    };
    let alice_kept = json!([{ "userId": alice.id, "namedShareEnvelope": named_share(&owner, &folder.id, &key2, 2, &alice) }]);
    // Refused: Bob neither kept nor removed (he would be dropped silently).
    assert_eq!(
        rotate(body(alice_kept.clone(), json!([])), &owner.token),
        StatusCode::CONFLICT
    );
    // Refused: not the owner.
    assert_eq!(
        rotate(body(alice_kept.clone(), json!([bob.id])), &alice.token),
        StatusCode::NOT_FOUND
    );
    // Refused: a kept member's share sealed at the wrong epoch.
    let stale_share = json!([{ "userId": alice.id, "namedShareEnvelope": named_share(&owner, &folder.id, &key2, 1, &alice) }]);
    assert_eq!(
        rotate(body(stale_share, json!([bob.id])), &owner.token),
        StatusCode::BAD_REQUEST
    );
    // Accepted.
    assert_eq!(
        rotate(body(alice_kept.clone(), json!([bob.id])), &owner.token),
        StatusCode::OK
    );
    // Replayed: the folder moved on.
    assert_eq!(
        rotate(body(alice_kept, json!([bob.id])), &owner.token),
        StatusCode::CONFLICT
    );

    // Bob is out; Alice is in, at epoch 2.
    assert_eq!(
        bearer(
            c.get(format!("{base}/api/collections/{}/files", folder.id)),
            &bob.token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        download(&c, &base, &bob.token, &file.id).0,
        StatusCode::FORBIDDEN
    );
    let alice_rows: Vec<Value> = bearer(c.get(format!("{base}/api/collections")), &alice.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let alice_row = alice_rows
        .iter()
        .find(|r| r["id"] == folder.id.as_str())
        .unwrap();
    assert_eq!(alice_row["keyEpoch"], 2);
    let opened =
        NamedShareEnvelopeV1::decode_b64(alice_row["namedShareEnvelope"].as_str().unwrap())
            .unwrap()
            .open(
                &folder.id,
                2,
                &format!("{}@{DOMAIN}", owner.username),
                &owner.identity.incarnation_id(),
                &owner.identity.drive_signing_public_key(),
                &format!("{}@{DOMAIN}", alice.username),
                &alice.identity.incarnation_id(),
                alice.identity.drive_hpke_private_key(),
            )
            .unwrap();
    assert_eq!(opened.as_slice(), key2.as_slice());

    // The history: the current key unlocks both; an old one unlocks nothing.
    let chain: Vec<Value> = bearer(
        c.get(format!("{base}/api/collections/{}/epochs", folder.id)),
        &alice.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let links: Vec<EpochLinkV1> = chain
        .iter()
        .map(|l| EpochLinkV1 {
            epoch: l["epoch"].as_u64().unwrap() as u32,
            statement: l["epochStatement"].as_str().unwrap().to_string(),
            previous_key_envelope: l["previousKeyEnvelope"].as_str().map(str::to_string),
        })
        .collect();
    let authority = owner.identity.authority_public_key();
    let keys =
        collection_keyring::unlock(&key2, &folder.id, &owner.id, &authority, &links).unwrap();
    assert_eq!(keys[0].as_slice(), folder.key.as_slice());
    assert_eq!(keys[1].as_slice(), key2.as_slice());
    assert!(
        collection_keyring::unlock(&folder.key, &folder.id, &owner.id, &authority, &links).is_err()
    );
    assert_eq!(
        bearer(
            c.get(format!("{base}/api/collections/{}/epochs", folder.id)),
            &bob.token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN,
        "a removed member gets no history"
    );

    // The file is still at epoch 1: no new content under the old key.
    let old_blob = |plain: &[u8]| {
        drive_object::encrypt_file_blob(
            plain,
            &file.key,
            DriveFileBlobContextV1::new(&file.id, &folder.id, 1).unwrap(),
        )
        .unwrap()
    };
    let r = post_version(
        &c,
        &base,
        &alice.token,
        &file.id,
        old_blob(b"edit under the old key"),
    );
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert!(r.text().unwrap().contains("re-key"));
    // New uploads with epoch-1 envelopes: the folder key changed.
    let stale = seal_file(&folder, &uuid(), b"stale");
    assert_eq!(
        upload(&c, &base, &alice.token, &folder, &stale).status(),
        StatusCode::CONFLICT
    );

    // Re-key the file to epoch 2.
    let mut file_key2 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut file_key2);
    let rekey = |from: i32| {
        bearer(c.post(format!("{base}/api/files/{}/rekey", file.id)), &alice.token)
            .json(&json!({
                "fromEpoch": from,
                "fileKeyEnvelope": drive_envelope::seal_b64(&file_key2, &key2,
                    ctx_at(DriveEnvelopePurpose::FileKey, 2, 1, &file.id, &folder.id)).unwrap(),
                "metadataEnvelope": drive_envelope::seal_b64(br#"{"name":"a.txt","mimeType":"text/plain","size":1}"#, &file_key2,
                    ctx_at(DriveEnvelopePurpose::FileMetadata, 2, 1, &file.id, &folder.id)).unwrap(),
            }))
            .send()
            .unwrap()
            .status()
    };
    assert_eq!(
        bearer(
            c.post(format!("{base}/api/files/{}/rekey", file.id)),
            &bob.token
        )
        .json(&json!({ "fromEpoch": 1, "fileKeyEnvelope": "", "metadataEnvelope": "" }))
        .send()
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(rekey(1), StatusCode::OK);
    assert_eq!(rekey(1), StatusCode::CONFLICT, "already moved");
    let rows: Vec<Value> = bearer(
        c.get(format!("{base}/api/collections/{}/files", folder.id)),
        &alice.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    let row = rows.iter().find(|r| r["id"] == file.id.as_str()).unwrap();
    assert_eq!(row["keyEpoch"], 2);
    assert_eq!(row["originalKeyEpoch"], 1);
    assert_eq!(row["contentKeyEpoch"], 1);
    let history = row["keyHistory"].as_array().unwrap();
    assert_eq!(history.len(), 1);
    // The upload still opens: the old file key through the history, under the old folder key.
    let old_key = drive_envelope::open_b64(
        history[0]["fileKeyEnvelope"].as_str().unwrap(),
        &keys[0],
        ctx_at(DriveEnvelopePurpose::FileKey, 1, 1, &file.id, &folder.id),
    )
    .unwrap();
    let (_, served) = download(&c, &base, &alice.token, &file.id);
    assert_eq!(
        drive_object::decrypt_file_blob(
            &served,
            &old_key,
            DriveFileBlobContextV1::new(&file.id, &folder.id, 1).unwrap()
        )
        .unwrap(),
        b"written at epoch 1"
    );

    // New content now goes under the new key.
    let new_blob = drive_object::encrypt_file_blob(
        b"written at epoch 2",
        &file_key2,
        DriveFileBlobContextV1::new(&file.id, &folder.id, 2).unwrap(),
    )
    .unwrap();
    let r = post_version(&c, &base, &alice.token, &file.id, new_blob.clone());
    assert_eq!(r.status(), StatusCode::CREATED);
    assert_eq!(r.json::<Value>().unwrap()["keyEpoch"], 2);
    let rows: Vec<Value> = bearer(
        c.get(format!("{base}/api/collections/{}/files", folder.id)),
        &alice.token,
    )
    .send()
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(
        rows.iter().find(|r| r["id"] == file.id.as_str()).unwrap()["contentKeyEpoch"],
        2
    );
    assert_eq!(download(&c, &base, &alice.token, &file.id).1, new_blob);

    // The kept public link follows the key, and serves its history.
    let public: Value = c
        .get(format!("{base}/api/share/{token}"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(public["collectionKeyEpoch"], 2);
    let via_link = drive_envelope::open_b64(
        public["collectionKeyEnvelope"].as_str().unwrap(),
        &link_key,
        ctx_at(
            DriveEnvelopePurpose::PublicLinkCollectionKey,
            2,
            1,
            &folder.id,
            &owner.id,
        ),
    )
    .unwrap();
    assert_eq!(via_link.as_slice(), key2.as_slice());
    let public_chain: Vec<Value> = c
        .get(format!("{base}/api/share/{token}/epochs"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(public_chain.len(), 2);
}
