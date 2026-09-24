//! Live e2e for the Drive write-rights and accounting fixes
//! (docs/drive-security-threat-model.md, "Write rights and accounting").
//!
//! A view-only recipient reads but changes nothing; a client-chosen file id
//! cannot overwrite a stored file; open tus uploads count against every
//! writer; concurrent purges release a file's bytes once; an asset re-PUT
//! changes nothing; public-link expiry and request bodies are bounded.
//!
//! Gated on `KUTUP_LIVE_SERVER`:
//!   KUTUP_LIVE_SERVER=http://localhost:3000 \
//!     cargo test -p kutup-server --test drive_integrity_live -- --nocapture

use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

mod common;
use common::*;

#[test]
fn drive_integrity_contract() {
    let Ok(base) = std::env::var("KUTUP_LIVE_SERVER") else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let owner = register(&c, &base);
    let viewer = register(&c, &base);
    let editor = register(&c, &base);
    let folder = create_folder(&c, &base, &owner);
    share(&c, &base, &owner, &folder, &viewer, false);
    share(&c, &base, &owner, &folder, &editor, true);

    let file = seal_file(&folder, &uuid(), b"the original");
    assert_eq!(
        upload(&c, &base, &owner.token, &folder, &file).status(),
        StatusCode::CREATED
    );
    let reseal = |plain: &[u8]| {
        drive_object::encrypt_file_blob(
            plain,
            &file.key,
            DriveFileBlobContextV1::new(&file.id, &folder.id, 1).unwrap(),
        )
        .unwrap()
    };

    // --- A view-only recipient reads, and changes nothing. ---
    assert_eq!(
        download(&c, &base, &viewer.token, &file.id).0,
        StatusCode::OK
    );
    assert_eq!(
        bearer(
            c.get(format!("{base}/api/files/{}/versions", file.id)),
            &viewer.token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        post_version(&c, &base, &viewer.token, &file.id, reseal(b"vandal")).status(),
        StatusCode::FORBIDDEN,
        "a viewer saves no version"
    );
    assert_eq!(
        put_asset(&c, &base, &viewer.token, &folder, &file, "img-1", b"x").status(),
        StatusCode::FORBIDDEN,
        "a viewer stores no asset"
    );
    assert_eq!(
        bearer(
            c.put(format!("{base}/api/files/{}/thumbnails/sm", file.id)),
            &viewer.token
        )
        .body(vec![0u8; 64])
        .send()
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN,
        "a viewer sets no thumbnail"
    );
    assert_eq!(
        bearer(
            c.delete(format!("{base}/api/files/{}/thumbnails", file.id)),
            &viewer.token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        bearer(
            c.post(format!("{base}/api/files/{}/claim-seed", file.id)),
            &viewer.token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN
    );

    // An editor may, charged to themselves.
    let editor_before = used(&c, &base, &editor.token);
    let edit = reseal(b"edited by the editor");
    let r = post_version(&c, &base, &editor.token, &file.id, edit.clone());
    assert_eq!(r.status(), StatusCode::CREATED);
    let version: Value = r.json().unwrap();
    assert_eq!(
        used(&c, &base, &editor.token),
        editor_before + edit.len() as i64
    );
    // Naming it is an editor's call too.
    let vid = version["id"].as_str().unwrap();
    let patch = |token: &str, label: &str| {
        bearer(
            c.patch(format!("{base}/api/files/{}/versions/{vid}", file.id)),
            token,
        )
        .json(&json!({ "label": label }))
        .send()
        .unwrap()
        .status()
    };
    assert_eq!(patch(&viewer.token, "mine"), StatusCode::FORBIDDEN);
    assert_eq!(patch(&editor.token, "Draft"), StatusCode::OK);
    assert_eq!(
        patch(&editor.token, &"x".repeat(201)),
        StatusCode::BAD_REQUEST
    );

    // --- A reused file id is refused, and the stored file is untouched. ---
    let clash = seal_file(&folder, &file.id, b"overwrite attempt");
    let r = upload(&c, &base, &owner.token, &folder, &clash);
    assert_eq!(r.status(), StatusCode::CONFLICT, "same id, second upload");
    assert_eq!(
        download(&c, &base, &owner.token, &file.id).1,
        edit,
        "the file still serves its content"
    );
    let r = tus_create(
        &c,
        &base,
        &owner.token,
        &folder,
        &clash,
        clash.blob.len() as i64,
    );
    assert_eq!(r.status(), StatusCode::CONFLICT, "same id, tus");

    // --- Open tus uploads count against every writer. ---
    let quota = me(&c, &base, &owner.token)["storageQuotaBytes"]
        .as_i64()
        .unwrap();
    let room = quota - used(&c, &base, &owner.token);
    let reserving = seal_file(&folder, &uuid(), b"reserved");
    let r = tus_create(&c, &base, &owner.token, &folder, &reserving, room - 1024);
    assert_eq!(r.status(), StatusCode::CREATED, "reserve nearly all");
    let location = r.headers()["location"].to_str().unwrap().to_string();
    let small = seal_file(&folder, &uuid(), &[1u8; 4096]);
    assert_eq!(
        upload(&c, &base, &owner.token, &folder, &small).status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "the reservation is not free space"
    );
    assert_eq!(
        post_version(&c, &base, &owner.token, &file.id, reseal(&[2u8; 4096])).status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "versions respect it too"
    );
    let r = bearer(c.delete(format!("{base}{location}")), &owner.token)
        .header("Tus-Resumable", "1.0.0")
        .send()
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        upload(&c, &base, &owner.token, &folder, &small).status(),
        StatusCode::CREATED,
        "cancelled, the room is back"
    );

    // --- Concurrent purges release a file's bytes once. ---
    let doomed = seal_file(&folder, &uuid(), &[3u8; 20_000]);
    assert_eq!(
        upload(&c, &base, &owner.token, &folder, &doomed).status(),
        StatusCode::CREATED
    );
    let before = used(&c, &base, &owner.token);
    assert_eq!(
        bearer(
            c.delete(format!("{base}/api/files/{}", doomed.id)),
            &owner.token
        )
        .send()
        .unwrap()
        .status(),
        StatusCode::NO_CONTENT
    );
    std::thread::scope(|scope| {
        for _ in 0..6 {
            scope.spawn(|| {
                bearer(
                    c.delete(format!("{base}/api/trash/{}", doomed.id)),
                    &owner.token,
                )
                .send()
                .unwrap()
                .status()
            });
        }
    });
    assert_eq!(
        used(&c, &base, &owner.token),
        before - doomed.blob.len() as i64,
        "released exactly once"
    );

    // --- An asset re-PUT changes nothing. ---
    let before = used(&c, &base, &owner.token);
    let r = put_asset(&c, &base, &owner.token, &folder, &file, "img-1", b"small");
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let charged = used(&c, &base, &owner.token) - before;
    assert!(charged > 0);
    let r = put_asset(
        &c,
        &base,
        &editor.token,
        &folder,
        &file,
        "img-1",
        &[9u8; 200_000],
    );
    assert_eq!(r.status(), StatusCode::NO_CONTENT, "idempotent");
    assert_eq!(used(&c, &base, &owner.token) - before, charged);
    let stored = bearer(
        c.get(format!("{base}/api/files/{}/assets/img-1", file.id)),
        &owner.token,
    )
    .send()
    .unwrap()
    .bytes()
    .unwrap();
    assert_eq!(stored.len() as i64, charged, "the first bytes stay");

    // --- Public-link expiry is bounded (no overflow panic). ---
    let link_envelope = drive_envelope::seal_b64(
        &folder.key,
        &[7u8; 32],
        DriveEnvelopeContextV1::new(
            DriveEnvelopePurpose::PublicLinkCollectionKey,
            1,
            1,
            &folder.id,
            &owner.id,
        )
        .unwrap(),
    )
    .unwrap();
    let link = |hours: i64| {
        let id = uuid();
        bearer(c.post(format!("{base}/api/share")), &owner.token)
            .json(&json!({
                "id": id,
                "shareType": "collection",
                "targetId": folder.id,
                "collectionKeyEnvelope": link_envelope,
                "ownerLinkKeyEnvelope": owner_link_key(&[7u8; 32], &owner, &id),
                "expiresInHours": hours,
            }))
            .send()
            .unwrap()
            .status()
    };
    assert_eq!(link(i64::MAX / 2), StatusCode::BAD_REQUEST);
    assert_eq!(link(0), StatusCode::BAD_REQUEST);
    assert_eq!(link(24), StatusCode::CREATED);

    // --- Request bodies are bounded by default. ---
    let r = bearer(c.patch(format!("{base}/api/user/me")), &owner.token)
        .header("content-type", "application/json")
        .body(format!(
            "{{\"username\":\"{}\"}}",
            "a".repeat(5 * 1024 * 1024)
        ))
        .send()
        .unwrap();
    let status = r.status();
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        r.text().unwrap_or_default()
    );
}

/// Deleting an account removes what it holds and hands what it added to
/// other people's folders to their owners — charges included — instead of
/// failing (a version it authored) or deleting others' data. Needs the
/// database too, to make an admin: `KUTUP_LIVE_DATABASE_URL`.
#[test]
fn admin_delete_user_hands_contributions_over() {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        return;
    };
    let base = base.trim_end_matches('/').to_string();
    let c = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let admin = register(&c, &base);
    let owner = register(&c, &base);
    let leaver = register(&c, &base);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::query("UPDATE users SET is_admin = true WHERE id = $1::uuid")
            .bind(&admin.id)
            .execute(&pool)
            .await
            .unwrap();
    });

    // The leaver edits the owner's file and adds one of their own there,
    // and keeps a folder of their own.
    let folder = create_folder(&c, &base, &owner);
    share(&c, &base, &owner, &folder, &leaver, true);
    let file = seal_file(&folder, &uuid(), b"owner's file");
    assert_eq!(
        upload(&c, &base, &owner.token, &folder, &file).status(),
        StatusCode::CREATED
    );
    let edit = drive_object::encrypt_file_blob(
        &[5u8; 30_000],
        &file.key,
        DriveFileBlobContextV1::new(&file.id, &folder.id, 1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        post_version(&c, &base, &leaver.token, &file.id, edit.clone()).status(),
        StatusCode::CREATED
    );
    let added = seal_file(&folder, &uuid(), &[6u8; 10_000]);
    assert_eq!(
        upload(&c, &base, &leaver.token, &folder, &added).status(),
        StatusCode::CREATED
    );
    let own_folder = create_folder(&c, &base, &leaver);
    let own = seal_file(&own_folder, &uuid(), b"leaver's own");
    assert_eq!(
        upload(&c, &base, &leaver.token, &own_folder, &own).status(),
        StatusCode::CREATED
    );
    let owner_before = used(&c, &base, &owner.token);

    let r = bearer(
        c.delete(format!("{base}/api/admin/users/{}", leaver.id)),
        &admin.token,
    )
    .send()
    .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT, "delete the account");

    // The owner keeps the edited file and the added one, and now pays for both.
    assert_eq!(download(&c, &base, &owner.token, &file.id).1, edit);
    assert_eq!(
        download(&c, &base, &owner.token, &added.id).1,
        added.blob,
        "what they added stays"
    );
    assert_eq!(
        used(&c, &base, &owner.token),
        owner_before + edit.len() as i64 + added.blob.len() as i64
    );
    // Their own folder and file are gone.
    runtime.block_on(async {
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        let left: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM files WHERE id = $1::uuid OR collection_id = $2::uuid",
        )
        .bind(&own.id)
        .bind(&own_folder.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(left, 0);
    });
}
