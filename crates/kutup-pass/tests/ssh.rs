//! SSH keys in vault entries, in KeePassXC's KeeAgent form
//! (docs/plans/pass.md, K3b). Keys are made at test time; none is checked in.

use base64::Engine as _;
use chrono::NaiveDate;
use kutup_pass::edit::{apply, new_vault, EntryInput, Op};
use kutup_pass::keepass::Database;
use kutup_pass::ssh::{
    sign, ssh_keys, KeeAgentSettings, KeyLocation, SshError, RSA_SHA2_256, RSA_SHA2_512,
};
use kutup_pass::view::{self, FieldView};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey};

fn now() -> chrono::NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 10, 12)
        .unwrap()
        .and_hms_opt(9, 0, 0)
        .unwrap()
}

/// KeePassXC's KeeAgent.settings for a key attached as `key`.
fn settings_xml(attachment: &str, allow: bool) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<EntrySettings xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <AllowUseOfSshKey>{allow}</AllowUseOfSshKey>
  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
  <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>
  <UseConfirmConstraintWhenAdding>true</UseConfirmConstraintWhenAdding>
  <UseLifetimeConstraintWhenAdding>false</UseLifetimeConstraintWhenAdding>
  <LifetimeConstraintDuration>600</LifetimeConstraintDuration>
  <Location>
    <SelectedType>attachment</SelectedType>
    <AttachmentName>{attachment}</AttachmentName>
    <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>
    <FileName/>
  </Location>
</EntrySettings>
"#
    )
}

fn add_key_entry(db: &mut Database, title: &str, passphrase: &str, key_pem: &str, settings: &str) {
    let root = view::view(db).root_group_id;
    let id = apply(
        db,
        &Op::CreateEntry {
            group_id: root,
            entry: EntryInput {
                fields: vec![
                    FieldView {
                        key: "Title".into(),
                        value: title.into(),
                        protected: false,
                    },
                    FieldView {
                        key: "Password".into(),
                        value: passphrase.into(),
                        protected: true,
                    },
                ],
                ..EntryInput::default()
            },
        },
        now(),
    )
    .unwrap()
    .id
    .unwrap();
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    for (name, data) in [
        ("id_key", key_pem.as_bytes()),
        ("KeeAgent.settings", settings.as_bytes()),
    ] {
        apply(
            db,
            &Op::AddAttachment {
                entry_id: id.clone(),
                name: name.into(),
                data: b64(data),
            },
            now(),
        )
        .unwrap();
    }
}

fn random(algorithm: Algorithm) -> PrivateKey {
    PrivateKey::random(&mut rand_core::OsRng, algorithm).unwrap()
}

#[test]
fn keeagent_settings_read_as_keepassxc_writes_them() {
    let settings = KeeAgentSettings::parse(settings_xml("id_ed25519", true).as_bytes()).unwrap();
    assert!(
        settings.allow_use && settings.add_at_open && settings.confirm && !settings.use_lifetime
    );
    assert_eq!(settings.lifetime_secs, 600);
    assert_eq!(
        settings.location,
        Some(KeyLocation::Attachment("id_ed25519".into()))
    );
    // KeeAgent's own files are UTF-16 with a BOM; names may hold entities.
    let xml = settings_xml("a&amp;b", true);
    let mut utf16 = vec![0xFF, 0xFE];
    utf16.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    assert_eq!(
        KeeAgentSettings::parse(&utf16).unwrap().location,
        Some(KeyLocation::Attachment("a&b".into()))
    );
    assert_eq!(
        KeeAgentSettings::parse(b"<Other/>"),
        Err(SshError::Settings)
    );
    assert_eq!(
        KeeAgentSettings::parse(b"not xml <"),
        Err(SshError::Settings)
    );
}

#[test]
fn an_encrypted_key_is_listed_locked_and_signs_with_the_entry_password() {
    let mut db = new_vault("Keys", now()).unwrap();
    let mut key = random(Algorithm::Ed25519);
    key.set_comment("ayse@laptop");
    let encrypted = key
        .encrypt(&mut rand_core::OsRng, "anahtar-parola")
        .unwrap();
    add_key_entry(
        &mut db,
        "Sunucu",
        "anahtar-parola",
        &encrypted.to_openssh(LineEnding::LF).unwrap(),
        &settings_xml("id_key", true),
    );
    let (keys, skipped) = ssh_keys(&db);
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(keys.len(), 1);
    let entry = &keys[0];
    // The public half without the passphrase.
    assert_eq!(
        entry.fingerprint(),
        key.public_key().fingerprint(HashAlg::Sha256).to_string()
    );
    // An encrypted key's comment is inside the encrypted part: while locked
    // the entry's title stands for it.
    assert_eq!(entry.comment(), "Sunucu");
    assert_eq!(entry.public_blob(), key.public_key().to_bytes().unwrap());
    // Signing decrypts with the entry's password, and verifies.
    let private = entry.private_key().unwrap();
    assert_eq!(private.comment(), "ayse@laptop");
    let blob = sign(&private, b"session data", 0).unwrap();
    let signature = decode_signature(&blob);
    use signature::Verifier as _;
    key.public_key()
        .key_data()
        .verify(b"session data", &signature)
        .unwrap();
}

#[test]
fn a_wrong_password_unusable_entries_and_the_recycle_bin() {
    let mut db = new_vault("Keys", now()).unwrap();
    let key = random(Algorithm::Ed25519)
        .encrypt(&mut rand_core::OsRng, "right")
        .unwrap();
    let pem = key.to_openssh(LineEnding::LF).unwrap();
    add_key_entry(
        &mut db,
        "Wrong",
        "wrong",
        &pem,
        &settings_xml("id_key", true),
    );
    add_key_entry(
        &mut db,
        "Off",
        "right",
        &pem,
        &settings_xml("id_key", false),
    );
    add_key_entry(
        &mut db,
        "Missing",
        "right",
        &pem,
        &settings_xml("other", true),
    );
    add_key_entry(
        &mut db,
        "Junk",
        "",
        "not a key",
        &settings_xml("id_key", true),
    );
    let (keys, skipped) = ssh_keys(&db);
    assert_eq!(keys.len(), 1, "only Wrong is listed: its public half reads");
    assert_eq!(keys[0].title, "Wrong");
    assert_eq!(
        keys[0].private_key().unwrap_err(),
        SshError::WrongPassphrase
    );
    let reasons: Vec<(String, SshError)> =
        skipped.into_iter().map(|s| (s.title, s.reason)).collect();
    assert!(reasons.contains(&("Missing".into(), SshError::MissingKey("other".into()))));
    assert!(reasons.contains(&("Junk".into(), SshError::Unreadable)));
    // Deleted (in the recycle bin): not listed.
    let id = view::view(&db)
        .entries
        .iter()
        .find(|e| e.fields[0].value == "Wrong")
        .unwrap()
        .id
        .clone();
    apply(&mut db, &Op::DeleteEntry { id }, now()).unwrap();
    assert!(ssh_keys(&db).0.is_empty());
}

#[test]
fn ecdsa_signs() {
    let mut db = new_vault("Keys", now()).unwrap();
    let key = random(Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    });
    add_key_entry(
        &mut db,
        "Ecdsa",
        "",
        &key.to_openssh(LineEnding::LF).unwrap(),
        &settings_xml("id_key", true),
    );
    let (keys, _) = ssh_keys(&db);
    let blob = sign(&keys[0].private_key().unwrap(), b"data", 0).unwrap();
    use signature::Verifier as _;
    key.public_key()
        .key_data()
        .verify(b"data", &decode_signature(&blob))
        .unwrap();
}

#[test]
fn rsa_signs_with_the_hash_asked_and_refuses_sha1() {
    // Made by ssh-keygen when it is here (RSA key generation is slow in a
    // debug build); skipped otherwise.
    let dir = std::env::temp_dir().join(format!("kutup-ssh-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("k_rsa");
    let made = std::process::Command::new("ssh-keygen")
        .args([
            "-q", "-t", "rsa", "-b", "2048", "-N", "", "-C", "deploy", "-f",
        ])
        .arg(&path)
        .status();
    if !matches!(made, Ok(status) if status.success()) {
        eprintln!("skipped: no ssh-keygen");
        return;
    }
    let pem = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let mut db = new_vault("Keys", now()).unwrap();
    add_key_entry(&mut db, "Deploy", "", &pem, &settings_xml("id_key", true));
    let (keys, _) = ssh_keys(&db);
    let private = keys[0].private_key().unwrap();
    use signature::Verifier as _;
    for (flags, name) in [
        (RSA_SHA2_256, "rsa-sha2-256"),
        (RSA_SHA2_512, "rsa-sha2-512"),
    ] {
        let blob = sign(&private, b"data", flags).unwrap();
        let signature = decode_signature(&blob);
        assert_eq!(signature.algorithm().as_str(), name);
        private
            .public_key()
            .key_data()
            .verify(b"data", &signature)
            .unwrap();
    }
    assert!(matches!(
        sign(&private, b"data", 0),
        Err(SshError::Unsupported(_))
    ));
}

/// The agent's signature blob back into a signature.
fn decode_signature(blob: &[u8]) -> ssh_key::Signature {
    let take = |at: &mut usize| -> Vec<u8> {
        let len = u32::from_be_bytes(blob[*at..*at + 4].try_into().unwrap()) as usize;
        let value = blob[*at + 4..*at + 4 + len].to_vec();
        *at += 4 + len;
        value
    };
    let mut at = 0;
    let algorithm = String::from_utf8(take(&mut at)).unwrap();
    let data = take(&mut at);
    assert_eq!(at, blob.len());
    ssh_key::Signature::new(Algorithm::new(&algorithm).unwrap(), data).unwrap()
}

#[test]
fn session_bind_and_identity_blobs() {
    use kutup_pass::ssh::{agent_identity_blob, blob_fingerprint, verify_session_bind};
    // A host key signs the session id (as sshd does for session-bind).
    let host = random(Algorithm::Ed25519);
    let host_blob = host.public_key().to_bytes().unwrap();
    let session_id = b"0123456789abcdef0123456789abcdef";
    let signature = sign(&host, session_id, 0).unwrap();
    let fingerprint = host.public_key().fingerprint(HashAlg::Sha256).to_string();
    assert_eq!(
        verify_session_bind(&host_blob, session_id, &signature),
        Some(fingerprint.clone())
    );
    assert_eq!(
        verify_session_bind(&host_blob, b"another session", &signature),
        None
    );
    assert_eq!(blob_fingerprint(&host_blob), Some(fingerprint));
    assert_eq!(blob_fingerprint(b"junk"), None);
    // The add-identity body starts with the key type and ends with the comment.
    let blob = agent_identity_blob(&host, "pushed").unwrap();
    assert_eq!(&blob[4..15], b"ssh-ed25519");
    assert!(blob.ends_with(b"\0\0\0\x06pushed"));
}
