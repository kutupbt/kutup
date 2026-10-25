//! One device list per account (docs/plans/one-device-list.md, slice 1),
//! against a live server and its database: the manifest's entries of every
//! kind against the account's `devices` rows. Editor rows are made by SQL
//! (slice 2 brings their registration).
//!
//!   KUTUP_LIVE_SERVER=http://localhost:39083 \
//!   KUTUP_LIVE_DATABASE_URL=postgres://… \
//!     cargo test -p kutup-server --test account_devices_live -- --test-threads 1
//!
//! One thread: the cap test changes a site setting.

mod common;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use common::chat_identity::{token_sid, ChatAccount, ChatDevice};
use kutup_chat_proto::{
    AccountManifestDeviceV3, AccountManifestV3, DeviceKind, DeviceRegistrationV1, DEVICE_HEADER,
};
use kutup_crypto::primitives::{Hasher, SigningKey, Suite};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::runtime::Runtime;
use uuid::Uuid;

struct Live {
    base: String,
    c: Client,
    runtime: Runtime,
    pool: PgPool,
}

fn live() -> Option<Live> {
    let (Ok(base), Ok(database_url)) = (
        std::env::var("KUTUP_LIVE_SERVER"),
        std::env::var("KUTUP_LIVE_DATABASE_URL"),
    ) else {
        eprintln!("KUTUP_LIVE_SERVER or KUTUP_LIVE_DATABASE_URL not set; skipping");
        return None;
    };
    let runtime = Runtime::new().unwrap();
    let pool = runtime.block_on(PgPool::connect(&database_url)).unwrap();
    Some(Live {
        base: base.trim_end_matches('/').to_string(),
        c: common::client(),
        runtime,
        pool,
    })
}

impl Live {
    fn account(&self) -> ChatAccount {
        let user = common::register(&self.c, &self.base);
        let token = user.token.clone();
        ChatAccount::of(&user, &token)
    }

    fn sql(&self, query: &str, user_id: Uuid) {
        self.runtime
            .block_on(sqlx::query(query).bind(user_id).execute(&self.pool))
            .unwrap();
    }

    /// An editor row of `account` as `device_id`, under its token's sign-in:
    /// its manifest entry and the credential that opens it.
    fn editor(&self, account: &ChatAccount, device_id: u32) -> (AccountManifestDeviceV3, [u8; 32]) {
        let user_id = Uuid::parse_str(&account.account.account_id).unwrap();
        let credential = [device_id as u8; 32];
        let salt = [7u8; 16];
        let mut hasher = Hasher::new(Suite::V1);
        hasher.update(b"kutup/chat-device-credential/v1\0");
        hasher.update(salt);
        hasher.update(credential);
        let hash: [u8; 32] = hasher.finish().into();
        let frame_key = SigningKey::from_seed(Suite::V1, &[device_id as u8 + 100; 32])
            .verifying_key()
            .to_array::<32>();
        self.runtime
            .block_on(
                sqlx::query(
                    "INSERT INTO devices (user_id, device_id, kind, session_id, frame_key,
                         credential_salt, credential_hash, name)
                     VALUES ($1, $2, 'editor', $3, $4, $5, $6, 'live-test-editor')",
                )
                .bind(user_id)
                .bind(device_id as i32)
                .bind(token_sid(&account.token))
                .bind(&frame_key[..])
                .bind(&salt[..])
                .bind(&hash[..])
                .execute(&self.pool),
            )
            .unwrap();
        let entry = AccountManifestDeviceV3 {
            device_id,
            kind: DeviceKind::Editor,
            chat: None,
            frame_key: Some(STANDARD.encode(frame_key)),
            session: account.session.clone(),
        };
        (entry, credential)
    }
}

fn code(response: reqwest::blocking::Response) -> (StatusCode, Value) {
    let status = response.status();
    (status, response.json().unwrap_or_default())
}

/// The account's next manifest listing its Chat devices and `others`.
fn manifest_with(account: &ChatAccount, others: &[AccountManifestDeviceV3]) -> AccountManifestV3 {
    let chat: Vec<&ChatDevice> = account.devices.iter().collect();
    let mut manifest = account.next_manifest(&chat);
    manifest.devices.extend(others.iter().cloned());
    manifest.devices.sort_by_key(|device| device.device_id);
    account.sign(&mut manifest);
    manifest
}

/// Publishes `manifest` as `by`'s credential header value.
fn publish(
    live: &Live,
    account: &mut ChatAccount,
    by: &str,
    manifest: &AccountManifestV3,
) -> (StatusCode, Value) {
    let answer = code(
        live.c
            .post(format!("{}/api/chat/manifest", live.base))
            .bearer_auth(&account.token)
            .header(DEVICE_HEADER, by)
            .json(manifest)
            .send()
            .unwrap(),
    );
    if answer.0 == StatusCode::OK {
        account.head = Some(manifest.clone());
    }
    answer
}

fn header(device_id: u32, credential: &[u8; 32]) -> String {
    format!("{device_id}.{}", URL_SAFE_NO_PAD.encode(credential))
}

/// An editor's credential opens no Chat route; it lists itself in the
/// account's manifest as any device may.
#[test]
fn an_editor_credential_opens_no_chat_route() {
    let Some(live) = live() else { return };
    let mut ada = live.account();
    let first = ada.reregister(&live.c, &live.base);
    let (editor, credential) = live.editor(&ada, 2);
    let as_editor = header(2, &credential);
    for (method, path) in [
        ("POST", "/api/chat/keys/check"),
        ("POST", "/api/chat/link-tokens"),
        ("POST", "/api/chat/ws-ticket?deviceId=2"),
        ("GET", "/api/chat/messages?deviceId=2"),
    ] {
        let request = match method {
            "POST" => live.c.post(format!("{}{path}", live.base)),
            _ => live.c.get(format!("{}{path}", live.base)),
        };
        let (status, answer) = code(
            request
                .bearer_auth(&ada.token)
                .header(DEVICE_HEADER, &as_editor)
                .json(&json!({ "digest": hex::encode([0u8; 32]) }))
                .send()
                .unwrap(),
        );
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}: {answer}");
        assert_eq!(answer["code"], "deviceCredential", "{path}");
    }
    // The manifest is the account's, not Chat's: the editor lists itself.
    let manifest = manifest_with(&ada, std::slice::from_ref(&editor));
    let (status, answer) = publish(&live, &mut ada, &as_editor, &manifest);
    assert_eq!(status, StatusCode::OK, "{answer}");
    // The Chat device still works.
    let next = manifest_with(&ada, &[editor]);
    let (status, answer) = publish(&live, &mut ada, &first.header(), &next);
    assert_eq!(status, StatusCode::OK, "{answer}");
}

/// Every listed entry is its row: kind, sign-in and frame key.
#[test]
fn a_published_entry_is_its_row() {
    let Some(live) = live() else { return };
    let mut ada = live.account();
    let first = ada.reregister(&live.c, &live.base);
    let (editor, _) = live.editor(&ada, 2);
    let mut other_kind = editor.clone();
    other_kind.kind = DeviceKind::Cli;
    let mut other_session = editor.clone();
    other_session.session = "00".repeat(32);
    let mut other_frame_key = editor.clone();
    other_frame_key.frame_key = Some(
        STANDARD.encode(
            SigningKey::from_seed(Suite::V1, &[9; 32])
                .verifying_key()
                .to_array::<32>(),
        ),
    );
    for entry in [other_kind, other_session, other_frame_key] {
        let manifest = manifest_with(&ada, std::slice::from_ref(&entry));
        let (status, answer) = publish(&live, &mut ada, &first.header(), &manifest);
        assert_eq!(status, StatusCode::CONFLICT, "{entry:?}: {answer}");
        assert_eq!(answer["code"], "devicesMismatch");
    }
    let manifest = manifest_with(&ada, &[editor]);
    let (status, answer) = publish(&live, &mut ada, &first.header(), &manifest);
    assert_eq!(status, StatusCode::OK, "{answer}");
}

/// A re-registration (the recovery when every Chat device is lost) keeps the
/// account's other devices, an idled-out one too; it may leave some out,
/// never change or add one, and lists this device under its own sign-in.
#[test]
fn a_reregistration_carries_the_other_devices_over() {
    let Some(live) = live() else { return };
    let mut ada = live.account();
    let first = ada.reregister(&live.c, &live.base);
    let (editor, _) = live.editor(&ada, 2);
    let manifest = manifest_with(&ada, std::slice::from_ref(&editor));
    let (status, answer) = publish(&live, &mut ada, &first.header(), &manifest);
    assert_eq!(status, StatusCode::OK, "{answer}");
    let user_id = Uuid::parse_str(&ada.account.account_id).unwrap();
    live.sql(
        "UPDATE devices SET expired_at = now() WHERE user_id = $1 AND device_id = 2",
        user_id,
    );

    let reregistration =
        |ada: &ChatAccount, others: &[AccountManifestDeviceV3], session: Option<String>| {
            let device = ChatDevice {
                id: 1,
                registration_id: 4321,
                credential: [0x44; 32],
            };
            let mut manifest = ada.next_manifest(&[&device]);
            if let Some(session) = session {
                manifest.devices[0].session = session;
            }
            manifest.devices.extend(others.iter().cloned());
            manifest.devices.sort_by_key(|device| device.device_id);
            ada.sign(&mut manifest);
            let body = ada.registration(
                device.registration_id,
                &device.credential,
                DeviceRegistrationV1::Reregistration {
                    manifest: Box::new(manifest.clone()),
                },
            );
            (
                code(ada.post_registration(&live.c, &live.base, &body)),
                manifest,
            )
        };

    // Another sign-in named for this device.
    let ((status, answer), _) =
        reregistration(&ada, std::slice::from_ref(&editor), Some("00".repeat(32)));
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "devicesMismatch");
    // A changed entry, or one the head doesn't list.
    let mut changed = editor.clone();
    changed.frame_key = Some(
        STANDARD.encode(
            SigningKey::from_seed(Suite::V1, &[9; 32])
                .verifying_key()
                .to_array::<32>(),
        ),
    );
    let mut added = editor.clone();
    added.device_id = 3;
    for others in [vec![changed], vec![editor.clone(), added]] {
        let ((status, answer), _) = reregistration(&ada, &others, None);
        assert_eq!(status, StatusCode::CONFLICT, "{answer}");
        assert_eq!(answer["code"], "devicesMismatch");
    }
    // The head's editor carried over, though its row idled out.
    let ((status, answer), manifest) = reregistration(&ada, std::slice::from_ref(&editor), None);
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["deviceId"], 1);
    ada.head = Some(manifest);
    // And a later one may leave it out.
    let ((status, answer), _) = reregistration(&ada, &[], None);
    assert_eq!(status, StatusCode::OK, "{answer}");
}

/// The account's cap over every kind: at link time, and on a manifest that
/// grows past it; one that removes devices still publishes after the cap
/// fell below the account's count.
#[test]
fn the_device_cap_counts_every_kind() {
    let Some(live) = live() else { return };
    let mut ada = live.account();
    let first = ada.reregister(&live.c, &live.base);
    let (editor, _) = live.editor(&ada, 2);
    let (cli, _) = live.editor(&ada, 3);
    let manifest = manifest_with(&ada, &[editor.clone(), cli.clone()]);
    let (status, answer) = publish(&live, &mut ada, &first.header(), &manifest);
    assert_eq!(status, StatusCode::OK, "{answer}");

    let set_cap = |value: Option<i64>| {
        let query = match value {
            Some(value) => format!(
                "INSERT INTO site_settings (key, value) VALUES ('devices_per_account', '{value}')
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            None => "DELETE FROM site_settings WHERE key = 'devices_per_account'".into(),
        };
        live.runtime
            .block_on(sqlx::query(&query).execute(&live.pool))
            .unwrap();
    };
    set_cap(Some(3));
    // Three of three: a link is refused.
    let token = ada.link_token(&live.c, &live.base, &first);
    let body = ada.registration(
        777,
        &[0x77; 32],
        DeviceRegistrationV1::Link { link_token: token },
    );
    let (status, answer) = code(ada.post_registration(&live.c, &live.base, &body));
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "deviceLimit");
    // A fourth entry: refused at publication.
    let (fourth, _) = live.editor(&ada, 4);
    let grown = manifest_with(&ada, &[editor.clone(), cli.clone(), fourth]);
    let (status, answer) = publish(&live, &mut ada, &first.header(), &grown);
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "deviceLimit");
    // The cap falls below the account's count: removing one still publishes.
    set_cap(Some(1));
    let fewer = manifest_with(&ada, std::slice::from_ref(&editor));
    let (status, answer) = publish(&live, &mut ada, &first.header(), &fewer);
    set_cap(None);
    assert_eq!(status, StatusCode::OK, "{answer}");
}
