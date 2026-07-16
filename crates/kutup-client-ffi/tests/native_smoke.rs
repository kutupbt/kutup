use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kutup_client_ffi::{
    open_native_chat_client, ChatHttpClient, ChatHttpMethod, ChatHttpRequest, ChatHttpResponse,
    KutupChatError,
};

struct MockHttp {
    registrations: AtomicUsize,
    registration: Mutex<Option<serde_json::Value>>,
    manifest: Mutex<Option<String>>,
}

impl MockHttp {
    fn new() -> Self {
        Self {
            registrations: AtomicUsize::new(0),
            registration: Mutex::new(None),
            manifest: Mutex::new(None),
        }
    }
}

#[async_trait]
impl ChatHttpClient for MockHttp {
    async fn execute(&self, request: ChatHttpRequest) -> Result<ChatHttpResponse, KutupChatError> {
        match (request.method, request.path.as_str()) {
            (ChatHttpMethod::Post, "/chat/device") => {
                self.registrations.fetch_add(1, Ordering::Relaxed);
                let body = request.body_json.expect("registration body");
                let value: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(value["suite"], 1);
                *self.registration.lock().unwrap() = Some(value);
                Ok(ChatHttpResponse {
                    status: 201,
                    body_json: r#"{"deviceId":7}"#.into(),
                })
            }
            (ChatHttpMethod::Get, "/chat/users/alice/manifest") => {
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
                let body_json = request.body_json.expect("manifest body");
                *self.manifest.lock().unwrap() = Some(body_json.clone());
                Ok(ChatHttpResponse {
                    status: 200,
                    body_json,
                })
            }
            (ChatHttpMethod::Get, "/chat/users/alice/keys?syncDeviceId=7") => {
                let registration = self.registration.lock().unwrap().clone().unwrap();
                let manifest: serde_json::Value = serde_json::from_str(
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
                        "username": "alice",
                        "devices": [{
                            "deviceId": 7,
                            "registrationId": registration["registrationId"],
                            "suite": registration["suite"],
                            "identityKey": registration["identityKey"],
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

#[test]
fn encrypted_install_registers_once_and_reopens() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("chat.sqlite");
    let database = database.to_string_lossy().into_owned();
    let http = Arc::new(MockHttp::new());

    let first = futures_executor::block_on(open_native_chat_client(
        database.clone(),
        vec![3; 32],
        "alice".into(),
        vec![9; 32],
        http.clone(),
    ))
    .unwrap();
    assert_eq!(first.device_id(), 7);
    assert_eq!(first.user(), "alice");
    assert_eq!(
        futures_executor::block_on(first.pending_send_count()).unwrap(),
        0
    );
    assert!(futures_executor::block_on(first.history())
        .unwrap()
        .is_empty());

    let note = futures_executor::block_on(first.send_text(
        "native-note-1".into(),
        "alice".into(),
        "2026-07-16T12:00:00Z".into(),
        "remember on mobile".into(),
    ))
    .unwrap();
    assert!(note.delivered);
    assert_eq!(note.attempts, 0);
    let history = futures_executor::block_on(first.history()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].peer, "alice");
    assert_eq!(
        history[0].content.text.as_deref(),
        Some("remember on mobile")
    );

    drop(first);
    let wrong_key = futures_executor::block_on(open_native_chat_client(
        database.clone(),
        vec![4; 32],
        "alice".into(),
        vec![9; 32],
        http.clone(),
    ));
    assert!(matches!(wrong_key, Err(KutupChatError::Storage { .. })));

    let second = futures_executor::block_on(open_native_chat_client(
        database,
        vec![3; 32],
        "alice".into(),
        vec![9; 32],
        http.clone(),
    ))
    .unwrap();
    assert_eq!(second.device_id(), 7);
    assert_eq!(http.registrations.load(Ordering::Relaxed), 1);
    futures_executor::block_on(second.shutdown()).unwrap();
    assert!(matches!(
        futures_executor::block_on(second.history()),
        Err(KutupChatError::Closed)
    ));
}
