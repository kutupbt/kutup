use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kutup_chat_proto::{AccountManifestPublicationV2, AccountManifestV2};
use kutup_client_ffi::{
    open_native_chat_client, ChatHttpClient, ChatHttpMethod, ChatHttpRequest, ChatHttpResponse,
    KutupChatError,
};

struct MockHttp {
    registrations: AtomicUsize,
    registration: Mutex<Option<serde_json::Value>>,
    manifest: Mutex<Option<String>>,
    /// Device-bound calls that carried the device's credential header.
    authenticated: AtomicUsize,
}

impl MockHttp {
    fn new() -> Self {
        Self {
            registrations: AtomicUsize::new(0),
            registration: Mutex::new(None),
            manifest: Mutex::new(None),
            authenticated: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ChatHttpClient for MockHttp {
    async fn execute(&self, request: ChatHttpRequest) -> Result<ChatHttpResponse, KutupChatError> {
        match (request.method, request.path.as_str()) {
            // The account's first device re-registers: the server takes its
            // manifest as the head and answers device 1.
            (ChatHttpMethod::Post, "/chat/device") => {
                assert!(request.chat_device.is_none(), "a registration has no credential header");
                self.registrations.fetch_add(1, Ordering::Relaxed);
                let body = request.body_json.expect("registration body");
                let value: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(value["suite"], 1);
                assert_eq!(value["registration"]["type"], "reregistration");
                let manifest = value["registration"]["manifest"].clone();
                assert_eq!(manifest["identityKey"], value["identityKey"]);
                *self.manifest.lock().unwrap() = Some(manifest.to_string());
                *self.registration.lock().unwrap() = Some(value);
                Ok(ChatHttpResponse {
                    status: 201,
                    body_json: r#"{"deviceId":1}"#.into(),
                })
            }
            (ChatHttpMethod::Get, "/chat/accounts/00000000-0000-4000-8000-2bd806c97f0e/manifest?server=chat.test") => {
                let manifest = self.manifest.lock().unwrap().clone();
                Ok(match manifest {
                    Some(body_json) => ChatHttpResponse {
                        status: 200,
                        body_json,
                    },
                    None => ChatHttpResponse {
                        status: 404,
                        body_json: String::new(),
                    },
                })
            }
            (ChatHttpMethod::Post, "/chat/manifest") => {
                let registration = self.registration.lock().unwrap().clone().unwrap();
                let credential = registration["credential"].as_str().unwrap();
                assert_eq!(
                    request.chat_device.as_deref(),
                    Some(format!("1.{credential}").as_str()),
                    "a manifest publication carries the device credential"
                );
                self.authenticated.fetch_add(1, Ordering::Relaxed);
                let body_json = request.body_json.expect("manifest body");
                *self.manifest.lock().unwrap() = Some(body_json.clone());
                let manifest: AccountManifestV2 = serde_json::from_str(&body_json).unwrap();
                let response = AccountManifestPublicationV2 { manifest };
                Ok(ChatHttpResponse {
                    status: 200,
                    body_json: serde_json::to_string(&response).unwrap(),
                })
            }
            (ChatHttpMethod::Get, "/chat/accounts/00000000-0000-4000-8000-2bd806c97f0e/keys?syncDeviceId=1&server=chat.test") => {
                let registration = self.registration.lock().unwrap().clone().unwrap();
                let manifest: AccountManifestV2 = serde_json::from_str(
                    self.manifest
                        .lock()
                        .unwrap()
                        .as_deref()
                        .expect("published manifest"),
                )
                .unwrap();
                Ok(ChatHttpResponse {
                    status: 200,
                    body_json: serde_json::json!({
                        "account": { "server": "chat.test", "accountId": "00000000-0000-4000-8000-2bd806c97f0e" },
                        "identityKey": registration["identityKey"],
                        "devices": [{
                            "deviceId": 1,
                            "registrationId": registration["registrationId"],
                            "suite": registration["suite"],
                            "signedPreKey": registration["signedPreKey"],
                            "kyberPreKey": registration["lastResortKyberPreKey"]
                        }],
                        "manifest": manifest
                    })
                    .to_string(),
                })
            }
            _ => Err(KutupChatError::Transport {
                message: format!("unexpected request: {:?} {}", request.method, request.path),
            }),
        }
    }
}

const ALICE: &str = "aci:00000000-0000-4000-8000-2bd806c97f0e@chat.test";

#[test]
fn encrypted_install_registers_once_and_reopens() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("chat.sqlite");
    let database = database.to_string_lossy().into_owned();
    let http = Arc::new(MockHttp::new());

    let first = futures_executor::block_on(open_native_chat_client(
        database.clone(),
        vec![3; 32],
        ALICE.into(),
        vec![9; 32],
        "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b".into(),
        http.clone(),
    ))
    .unwrap();
    assert_eq!(first.device_id(), 1);
    assert_eq!(first.user(), ALICE);
    assert_eq!(
        futures_executor::block_on(first.pending_send_count()).unwrap(),
        0
    );
    assert!(futures_executor::block_on(first.history())
        .unwrap()
        .is_empty());

    let note = futures_executor::block_on(first.send_text(
        "native-note-1".into(),
        ALICE.into(),
        "2026-07-16T12:00:00Z".into(),
        "remember on mobile".into(),
    ))
    .unwrap();
    assert!(note.delivered);
    assert_eq!(note.attempts, 0);
    let history = futures_executor::block_on(first.history()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].conversation, ALICE);
    assert_eq!(history[0].sender, ALICE);
    assert_eq!(
        history[0].content.text.as_deref(),
        Some("remember on mobile")
    );

    drop(first);
    let wrong_key = futures_executor::block_on(open_native_chat_client(
        database.clone(),
        vec![4; 32],
        ALICE.into(),
        vec![9; 32],
        "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b".into(),
        http.clone(),
    ));
    assert!(matches!(wrong_key, Err(KutupChatError::Storage { .. })));

    let second = futures_executor::block_on(open_native_chat_client(
        database,
        vec![3; 32],
        ALICE.into(),
        vec![9; 32],
        "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b".into(),
        http.clone(),
    ))
    .unwrap();
    assert_eq!(second.device_id(), 1);
    assert_eq!(http.registrations.load(Ordering::Relaxed), 1);
    assert!(http.authenticated.load(Ordering::Relaxed) >= 1);
    futures_executor::block_on(second.shutdown()).unwrap();
    assert!(matches!(
        futures_executor::block_on(second.history()),
        Err(KutupChatError::Closed)
    ));
}
