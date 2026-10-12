use std::sync::Mutex;
use std::time::Duration;

use kutup_pass::edit::{apply, new_vault, EntryInput, Op};
use kutup_pass::ssh::ssh_keys;
use kutup_pass::view::{self, FieldView};
use ssh_key::{Algorithm, LineEnding, PrivateKey};

use super::approval::{decide, prompt_text, Approver, Decision, SignRequest};
use super::proto::{self, Purpose, Request};
use super::{handle, Connection, LoadedKey, Policy, State};

struct Answer(Decision, Mutex<usize>);

impl Approver for Answer {
    fn ask(&self, _: &SignRequest) -> Decision {
        *self.1.lock().unwrap() += 1;
        self.0
    }
}

fn keys() -> (Vec<LoadedKey>, PrivateKey) {
    let now = chrono::DateTime::from_timestamp(1_791_000_000, 0)
        .unwrap()
        .naive_utc();
    let mut db = new_vault("Keys", now).unwrap();
    let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).unwrap();
    let root = view::view(&db).root_group_id;
    let id = apply(
        &mut db,
        &Op::CreateEntry {
            group_id: root,
            entry: EntryInput {
                fields: vec![FieldView {
                    key: "Title".into(),
                    value: "Sunucu".into(),
                    protected: false,
                }],
                ..EntryInput::default()
            },
        },
        now,
    )
    .unwrap()
    .id
    .unwrap();
    use base64::Engine as _;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let settings = "<EntrySettings><AllowUseOfSshKey>true</AllowUseOfSshKey><Location><SelectedType>attachment</SelectedType><AttachmentName>id</AttachmentName></Location></EntrySettings>";
    apply(
        &mut db,
        &Op::AddAttachment {
            entry_id: id.clone(),
            name: "id".into(),
            data: b64(key.to_openssh(LineEnding::LF).unwrap().as_bytes()),
        },
        now,
    )
    .unwrap();
    apply(
        &mut db,
        &Op::AddAttachment {
            entry_id: id,
            name: "KeeAgent.settings".into(),
            data: b64(settings.as_bytes()),
        },
        now,
    )
    .unwrap();
    let loaded = ssh_keys(&db)
        .0
        .into_iter()
        .map(|entry| LoadedKey {
            vault: "Keys.kdbx".into(),
            entry,
        })
        .collect();
    (loaded, key)
}

fn sign_request(key: &PrivateKey) -> Request {
    Request::Sign {
        key: key.public_key().to_bytes().unwrap(),
        data: b"data".to_vec(),
        flags: 0,
    }
}

fn policy(no_confirm: bool) -> Policy {
    Policy {
        no_confirm,
        idle: Duration::from_secs(900),
    }
}

#[test]
fn lists_keys_and_signs_only_when_allowed() {
    let (loaded, key) = keys();
    let state = Mutex::new(State::new(loaded));
    let mut connection = Connection::default();
    let quiet = |_: String| {};
    let listed = handle(
        Request::Identities,
        &mut connection,
        &state,
        &policy(false),
        &Answer(Decision::Deny, Mutex::new(0)),
        &quiet,
    );
    assert_eq!(listed[0], proto::IDENTITIES_ANSWER);
    assert_eq!(&listed[1..5], &1u32.to_be_bytes());

    let deny = Answer(Decision::Deny, Mutex::new(0));
    assert_eq!(
        handle(
            sign_request(&key),
            &mut connection,
            &state,
            &policy(false),
            &deny,
            &quiet
        ),
        vec![proto::FAILURE]
    );
    assert_eq!(*deny.1.lock().unwrap(), 1);

    let once = Answer(Decision::Once, Mutex::new(0));
    let signed = handle(
        sign_request(&key),
        &mut connection,
        &state,
        &policy(false),
        &once,
        &quiet,
    );
    assert_eq!(signed[0], proto::SIGN_RESPONSE);

    // Unknown keys fail without asking.
    let other = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).unwrap();
    let ask = Answer(Decision::Once, Mutex::new(0));
    assert_eq!(
        handle(
            sign_request(&other),
            &mut connection,
            &state,
            &policy(false),
            &ask,
            &quiet
        ),
        vec![proto::FAILURE]
    );
    assert_eq!(*ask.1.lock().unwrap(), 0);
}

#[test]
fn no_confirm_still_asks_for_forwarded_requests_and_host_approvals_last_until_lock() {
    let (loaded, key) = keys();
    let state = Mutex::new(State::new(loaded));
    let quiet = |_: String| {};
    let ask = Answer(Decision::Host, Mutex::new(0));
    let mut local = Connection::default();
    assert_eq!(
        handle(
            sign_request(&key),
            &mut local,
            &state,
            &policy(true),
            &ask,
            &quiet
        )[0],
        proto::SIGN_RESPONSE
    );
    assert_eq!(*ask.1.lock().unwrap(), 0, "no_confirm: not asked");
    let mut forwarded = Connection {
        forwarded: true,
        host: Some("SHA256:host".into()),
        ..Connection::default()
    };
    assert_eq!(
        handle(
            sign_request(&key),
            &mut forwarded,
            &state,
            &policy(true),
            &ask,
            &quiet
        )[0],
        proto::SIGN_RESPONSE
    );
    assert_eq!(*ask.1.lock().unwrap(), 1, "forwarded: asked");
    // Remembered for that host: not asked again, until the agent locks.
    handle(
        sign_request(&key),
        &mut forwarded,
        &state,
        &policy(true),
        &ask,
        &quiet,
    );
    assert_eq!(*ask.1.lock().unwrap(), 1);
    state.lock().unwrap().lock();
    handle(
        sign_request(&key),
        &mut forwarded,
        &state,
        &policy(true),
        &ask,
        &quiet,
    );
    assert_eq!(*ask.1.lock().unwrap(), 2);
    // Idle: forgotten.
    assert!(state.lock().unwrap().lock_if_idle(Duration::ZERO));
}

#[test]
fn a_session_bind_with_a_bad_signature_is_refused() {
    let host = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).unwrap();
    let state = Mutex::new(State::new(Vec::new()));
    let quiet = |_: String| {};
    let mut connection = Connection::default();
    let signature = kutup_pass::ssh::sign(&host, b"session", 0).unwrap();
    let good = Request::SessionBind {
        host_key: host.public_key().to_bytes().unwrap(),
        session_id: b"session".to_vec(),
        signature: signature.clone(),
        forwarding: true,
    };
    assert_eq!(
        handle(
            good,
            &mut connection,
            &state,
            &policy(false),
            &Answer(Decision::Deny, Mutex::new(0)),
            &quiet
        ),
        vec![proto::SUCCESS]
    );
    assert!(connection.forwarded && connection.host.is_some());
    let mut fresh = Connection::default();
    let bad = Request::SessionBind {
        host_key: host.public_key().to_bytes().unwrap(),
        session_id: b"other".to_vec(),
        signature,
        forwarding: false,
    };
    assert_eq!(
        handle(
            bad,
            &mut fresh,
            &state,
            &policy(false),
            &Answer(Decision::Deny, Mutex::new(0)),
            &quiet
        ),
        vec![proto::FAILURE]
    );
    assert!(fresh.host.is_none());
}

#[test]
fn the_prompt_says_what_is_asked() {
    let purpose = Purpose::Login {
        user: "ayse".into(),
    };
    let connection = Connection {
        host: Some("SHA256:abc".into()),
        host_names: vec!["github.com".into()],
        forwarded: true,
        process: Some("ssh github.com (pid 7)".into()),
    };
    let text = prompt_text(&SignRequest {
        key_title: "Sunucu".into(),
        key_fingerprint: "SHA256:key".into(),
        vault: "Keys.kdbx".into(),
        purpose: &purpose,
        connection: &connection,
    });
    assert!(text.contains("FORWARDED"));
    assert!(text.contains("ssh github.com (pid 7)"));
    assert!(text.contains("login as ayse to github.com"));
    assert!(text.contains("[h]ost"));
    assert_eq!(decide("h", true), Decision::Host);
    assert_eq!(decide("h", false), Decision::Deny);
    assert_eq!(decide("o\n", false), Decision::Once);
    assert_eq!(decide("", true), Decision::Deny);
}
