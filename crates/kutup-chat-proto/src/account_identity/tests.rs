use super::*;
use crate::{AccountIdentitySuiteId, EnvelopeType};
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use sha2::{Digest, Sha256};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn identity(byte: u8) -> String {
    let mut key = [byte; 33];
    key[0] = DJB_KEY_TYPE;
    b64(&key)
}

fn authority() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7; 32])
}

fn session(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn device(device_id: u32, registration_id: u32) -> AccountManifestDeviceV3 {
    AccountManifestDeviceV3::chat(
        device_id,
        DirectChatSuiteId::PqxdhTripleRatchetV1,
        registration_id,
        session(0x51),
    )
}

fn frame_key(byte: u8) -> String {
    b64(&ed25519_dalek::SigningKey::from_bytes(&[byte; 32])
        .verifying_key()
        .to_bytes())
}

fn editor(device_id: u32) -> AccountManifestDeviceV3 {
    AccountManifestDeviceV3 {
        device_id,
        kind: DeviceKind::Editor,
        chat: None,
        frame_key: Some(frame_key(device_id as u8)),
        session: session(0x51),
    }
}

/// Signs the manifest; one with no signing bytes (a bad device) is left
/// unsigned, and can't verify either way.
fn sign(manifest: &mut AccountManifestV3) {
    if let Ok(bytes) = manifest.signing_bytes() {
        manifest.signature = b64(&authority().sign(&bytes).to_bytes());
    }
}

fn manifest(devices: Vec<AccountManifestDeviceV3>) -> AccountManifestV3 {
    let public = authority().verifying_key().to_bytes();
    let mut incarnation = Sha256::new();
    incarnation.update(b"kutup/account-incarnation/v1\0");
    incarnation.update(public);
    let drive_signing = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let mut manifest = AccountManifestV3 {
        manifest_version: ACCOUNT_MANIFEST_V3_VERSION,
        account: AccountRef::new("example.test", "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b").unwrap(),
        incarnation_id: hex::encode(incarnation.finalize()),
        sequence: 1,
        previous_hash: None,
        identity_key: Some(identity(3)),
        identity_binding: Some(b64(&[0x5b; 64])),
        drive: AccountManifestDriveKeysV1 {
            suite: AccountIdentitySuiteId::XWingEd25519V2,
            hpke_public_key: b64(&[9; 1216]),
            share_signing_public_key: b64(&drive_signing.verifying_key().to_bytes()),
        },
        devices,
        issued_at: "2026-10-22T12:00:00Z".into(),
        authority_key_id: hex::encode(Sha256::digest(public)),
        self_authority_key: b64(&public),
        signature: String::new(),
    };
    sign(&mut manifest);
    manifest
}

fn two_devices() -> AccountManifestV3 {
    manifest(vec![device(1, 10), device(2, 20)])
}

#[test]
fn manifest_v3_verifies_and_binds_every_field() {
    let good = two_devices();
    good.verify().unwrap();
    assert_eq!(good.chat_device(2).unwrap().registration_id, 20);
    assert!(good.device(3).is_none());

    // Every vouched-for field is under the signature.
    let mut other_identity = good.clone();
    other_identity.identity_key = Some(identity(4));
    assert!(other_identity.verify().is_err());
    let mut other_registration = good.clone();
    other_registration.devices[1]
        .chat
        .as_mut()
        .unwrap()
        .registration_id = 21;
    assert!(other_registration.verify().is_err());
    let mixed = manifest(vec![device(1, 10), editor(2)]);
    mixed.verify().unwrap();
    let mut other_frame_key = mixed.clone();
    other_frame_key.devices[1].frame_key = Some(frame_key(9));
    assert!(other_frame_key.verify().is_err());
    let mut other_session = mixed.clone();
    other_session.devices[1].session = session(0x52);
    assert!(other_session.verify().is_err());
    let mut other_kind = mixed.clone();
    other_kind.devices[1].kind = DeviceKind::Cli;
    assert!(other_kind.verify().is_err());
    let mut other_sequence = good.clone();
    other_sequence.sequence = 2;
    other_sequence.previous_hash = Some(good.manifest_hash().unwrap());
    assert!(other_sequence.verify().is_err());
}

#[test]
fn manifest_v3_refuses_bad_shapes_even_when_signed() {
    let mut v1 = two_devices();
    v1.manifest_version = 1;
    sign(&mut v1);
    assert!(v1.verify().is_err());

    // An unordered device list has no signing bytes, so it can't verify.
    let mut unordered = two_devices();
    unordered.devices.reverse();
    assert!(unordered.signing_bytes().is_err());
    assert!(unordered.verify().is_err());

    for (device_id, registration_id) in [(0, 1), (128, 1), (1, 0), (1, 0x4000)] {
        let bad = manifest(vec![device(device_id, registration_id)]);
        assert!(bad.verify().is_err(), "{device_id}/{registration_id}");
    }

    let mut not_curve = two_devices();
    not_curve.identity_key = Some(b64(&[3; 33]));
    assert!(not_curve.signing_bytes().is_err());

    let mut no_link = two_devices();
    no_link.sequence = 2;
    sign(&mut no_link);
    assert!(no_link.verify().is_err());

    let empty = manifest(Vec::new());
    assert!(empty.verify().is_err());

    // Up to 127 entries, of any kind; none need take Chat.
    manifest(vec![editor(1)]).verify().unwrap();
    manifest((1..=127).map(editor).collect()).verify().unwrap();
}

#[test]
fn each_kind_carries_its_keys() {
    let cli = |chat: Option<ChatDeviceKeysV3>, frame: Option<String>| AccountManifestDeviceV3 {
        device_id: 1,
        kind: DeviceKind::Cli,
        chat,
        frame_key: frame,
        session: session(0x51),
    };
    let keys = Some(ChatDeviceKeysV3 {
        direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
        registration_id: 10,
    });
    // A Chat device with a frame key too, and a CLI that takes Chat.
    let mut chat = device(1, 10);
    chat.frame_key = Some(frame_key(1));
    for good in [
        chat,
        cli(keys, Some(frame_key(1))),
        cli(None, Some(frame_key(1))),
    ] {
        good.validate().unwrap();
        manifest(vec![good]).verify().unwrap();
    }
    let mut no_chat = device(1, 10);
    no_chat.chat = None;
    let mut editor_with_chat = editor(1);
    editor_with_chat.chat = keys;
    let mut no_frame = editor(1);
    no_frame.frame_key = None;
    let mut not_ed25519 = editor(1);
    // The identity point: small order.
    let mut identity_point = [0; 32];
    identity_point[0] = 1;
    not_ed25519.frame_key = Some(b64(&identity_point));
    let mut short_session = editor(1);
    short_session.session = hex::encode([1; 31]);
    for bad in [
        no_chat,
        editor_with_chat,
        no_frame,
        not_ed25519,
        short_session,
        cli(keys, None),
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
        assert!(manifest(vec![bad]).signing_bytes().is_err());
    }
    // The kinds' names, on the wire and in the server's column.
    for kind in [DeviceKind::Chat, DeviceKind::Editor, DeviceKind::Cli] {
        let json = serde_json::to_value(kind).unwrap();
        assert_eq!(json, kind.as_str());
        assert_eq!(DeviceKind::parse(kind.as_str()).unwrap(), kind);
    }
    assert!(DeviceKind::parse("mls").is_err());
}

/// An account that never used Chat has a manifest too: its editing devices
/// and no identity. A Chat device needs the identity listed.
#[test]
fn a_manifest_without_a_chat_identity_lists_no_chat_device() {
    let without = |devices| {
        let mut manifest = manifest(devices);
        manifest.identity_key = None;
        manifest.identity_binding = None;
        sign(&mut manifest);
        manifest
    };
    let editors = without(vec![editor(1), editor(2)]);
    editors.verify().unwrap();
    assert!(editors.chat_identity_key().is_err());
    assert!(editors.identity_binding_bytes().is_err());
    let json = serde_json::to_value(&editors).unwrap();
    assert!(json.get("identityKey").is_none());
    assert!(without(vec![editor(1), device(2, 20)]).verify().is_err());
    // Both or neither.
    let mut half = manifest(vec![editor(1)]);
    half.identity_binding = None;
    assert!(half.signing_bytes().is_err());
    // The identity is signed in: dropping it breaks the signature.
    let mut dropped = manifest(vec![editor(1)]);
    dropped.identity_key = None;
    dropped.identity_binding = None;
    assert!(dropped.verify().is_err());
}

/// An editor's first manifest for an account: its keys, no identity, and a
/// successor that adds a device.
#[test]
fn an_accounts_first_manifest_and_its_successor() {
    let keys = kutup_crypto::identity::AccountIdentityKeysV1::derive(&[5; 32]).unwrap();
    let account = AccountRef::new("example.test", "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b").unwrap();
    let mut first =
        AccountManifestV3::first(account, &keys, vec![editor(2)], "2026-10-26T00:00:00Z");
    first.sign(keys.authority_signing_key()).unwrap();
    first.verify_successor(None).unwrap();
    assert_eq!(first.incarnation_id, keys.incarnation_id());
    let mut next = first
        .successor(vec![editor(2), editor(1)], "2026-10-26T00:01:00Z")
        .unwrap();
    assert_eq!(next.devices[0].device_id, 1, "ordered");
    next.sign(keys.authority_signing_key()).unwrap();
    next.verify_successor(Some(&first)).unwrap();
    // Another account's authority can't sign it.
    let other = kutup_crypto::identity::AccountIdentityKeysV1::derive(&[6; 32]).unwrap();
    assert!(next.clone().sign(other.authority_signing_key()).is_err());
}

#[test]
fn the_device_session_hash_is_pinned() {
    assert_eq!(
        device_session_hash(&[7; 16]),
        hex::encode(Sha256::digest(
            [b"kutup/account/device-session/v1\0".as_slice(), &[7; 16]].concat()
        ))
    );
}

#[test]
fn manifest_v3_domain_differs_from_v2() {
    let bytes = two_devices().signing_bytes().unwrap();
    assert!(bytes.starts_with(b"kutup/account/manifest/v3\0"));
}

#[test]
fn history_page_follows_the_hash_chain() {
    let first = two_devices();
    let mut second = manifest(vec![device(1, 10)]);
    second.sequence = 2;
    second.previous_hash = Some(first.manifest_hash().unwrap());
    sign(&mut second);
    let page = AccountManifestHistoryPageV3 {
        account: first.account.clone(),
        from_sequence: 1,
        to_sequence: 2,
        manifests: vec![first.clone(), second.clone()],
        next_sequence: None,
    };
    page.validate().unwrap();

    let mut forked = second.clone();
    forked.previous_hash = Some(hex::encode([1; 32]));
    sign(&mut forked);
    let page = AccountManifestHistoryPageV3 {
        manifests: vec![first, forked],
        ..page
    };
    assert!(page.validate().is_err());
}

fn ec(key_id: u32) -> EcPreKey {
    EcPreKey {
        key_id,
        public_key: identity(5),
        signature: Some(b64(&[6; 64])),
    }
}

fn kem(key_id: u32) -> KemPreKey {
    KemPreKey {
        key_id,
        public_key: b64(&[8; 1569]),
        signature: b64(&[6; 64]),
    }
}

fn bundle(device_id: u32, registration_id: u32) -> DevicePreKeyBundleV2 {
    DevicePreKeyBundleV2 {
        device_id,
        registration_id,
        suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
        signed_pre_key: ec(1),
        kyber_pre_key: kem(2),
        one_time_pre_key: None,
    }
}

#[test]
fn bundles_must_agree_with_the_manifest() {
    let manifest = two_devices();
    let good = AccountPreKeyBundlesResponse {
        account: manifest.account.clone(),
        identity_key: manifest.identity_key.clone().unwrap(),
        devices: vec![bundle(1, 10), bundle(2, 20)],
        manifest,
    };
    good.check_against_manifest().unwrap();

    // A device may lack a bundle (the caller decides); a bundle may never
    // disagree with the manifest.
    let mut fewer = good.clone();
    fewer.devices.pop();
    fewer.check_against_manifest().unwrap();

    let mut stale = good.clone();
    stale.devices[1].registration_id = 21;
    assert!(stale.check_against_manifest().is_err());
    let mut unlisted = good.clone();
    unlisted.devices.push(bundle(3, 30));
    assert!(unlisted.check_against_manifest().is_err());
    let mut twice = good.clone();
    twice.devices.push(bundle(1, 10));
    assert!(twice.check_against_manifest().is_err());
    let mut other_identity = good.clone();
    other_identity.identity_key = identity(4);
    assert!(other_identity.check_against_manifest().is_err());
}

#[test]
fn device_header_round_trips_and_is_strict() {
    let credential = [0xa5; 32];
    let header = format_device_header(12, &credential);
    assert_eq!(parse_device_header(&header).unwrap(), (12, credential));

    let encoded = header.split_once('.').unwrap().1.to_string();
    for bad in [
        format!("012.{encoded}"),
        format!("0.{encoded}"),
        format!("128.{encoded}"),
        format!("+1.{encoded}"),
        format!(".{encoded}"),
        format!("1.{encoded}="),
        format!("1.{}", b64(&credential)),
        "1".to_string(),
        format!("1.{}", b64url_encode(&[1; 31])),
    ] {
        assert!(parse_device_header(&bad).is_err(), "{bad}");
    }
    assert_eq!(decode_device_credential(&encoded).unwrap(), credential);
    assert!(decode_device_credential(&b64(&credential)).is_err());
    assert!(decode_device_credential(&b64url_encode(&[1; 31])).is_err());
}

#[test]
fn link_code_round_trips_and_refuses_anything_else() {
    let mut public_key = [9; 33];
    public_key[0] = DJB_KEY_TYPE;
    let code = ProvisioningLinkCodeV1 {
        address: [4; 16],
        public_key,
    };
    let uri = code.to_uri();
    assert!(uri.starts_with("kutup://link?address="));
    assert_eq!(ProvisioningLinkCodeV1::parse(&uri).unwrap(), code);
    assert_eq!(
        ProvisioningLinkCodeV1::parse(&format!("  {uri}\n")).unwrap(),
        code
    );

    let key = b64url_encode(&public_key);
    let address = b64url_encode(&[4; 16]);
    for bad in [
        format!("sgnl://linkdevice?uuid={address}&pub_key={key}"),
        format!("kutup://link?key={key}&address={address}"),
        format!("kutup://link?address={address}&key={key}&x=1"),
        format!(
            "kutup://link?address={address}&key={}",
            b64url_encode(&[9; 33])
        ),
        format!("kutup://link?address={}&key={key}", b64url_encode(&[4; 15])),
    ] {
        assert!(ProvisioningLinkCodeV1::parse(&bad).is_err(), "{bad}");
    }
}

#[test]
fn provision_envelope_shape() {
    let good = |len: usize| {
        let mut body = vec![0; len];
        body[0] = 1;
        ProvisionEnvelopeV1 {
            public_key: identity(2),
            body: b64(&body),
        }
    };
    good(65).validate().unwrap();
    good(65 + 16 * 4).validate().unwrap();
    assert!(good(64).validate().is_err());
    assert!(good(66).validate().is_err());
    good(MAX_PROVISION_BODY_BYTES - 15).validate().unwrap();
    assert!(good(MAX_PROVISION_BODY_BYTES + 1).validate().is_err());
    let mut version = good(65);
    version.body = b64(&[2; 65]);
    assert!(version.validate().is_err());

    let message = ProvisioningSocketMessage::Envelope { envelope: good(65) };
    let json = serde_json::to_value(&message).unwrap();
    assert_eq!(json["type"], "envelope");
    assert_eq!(
        serde_json::from_value::<ProvisioningSocketMessage>(json).unwrap(),
        message
    );
    let address = serde_json::to_value(ProvisioningSocketMessage::Address {
        address: b64url_encode(&[1; 16]),
    })
    .unwrap();
    assert_eq!(address["type"], "address");
}

fn provision() -> ChatProvisionV1 {
    ChatProvisionV1 {
        provisioning_version: PROVISIONING_VERSION,
        account: two_devices().account,
        identity_key_public: identity(3),
        identity_key_private: b64(&[0x42; 32]),
        link_token: b64url_encode(&[5; 32]),
        manifest_sequence: 1,
        manifest_hash: hex::encode([6; 32]),
        profile_key: b64(&[0x43; 32]),
        profile_suite: ProfileSuiteId::XChaCha20Poly1305V1,
        read_receipts: true,
        typing_indicators: false,
    }
}

#[test]
fn provision_message_validates_and_hides_secrets() {
    let message = provision();
    message.validate().unwrap();
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"identityKeyPrivate\""));
    assert!(json.contains("\"profileSuite\":1"));
    assert_eq!(
        serde_json::from_str::<ChatProvisionV1>(&json).unwrap(),
        message
    );
    let mut extra: serde_json::Value = serde_json::from_str(&json).unwrap();
    extra["masterKey"] = "x".into();
    assert!(serde_json::from_value::<ChatProvisionV1>(extra).is_err());

    let debug = format!("{message:?}");
    assert!(!debug.contains(&b64(&[0x42; 32])) && !debug.contains(&b64(&[0x43; 32])));

    let mut bad = provision();
    bad.provisioning_version = 2;
    assert!(bad.validate().is_err());
    let mut bad = provision();
    bad.manifest_sequence = 0;
    assert!(bad.validate().is_err());
    let mut bad = provision();
    bad.identity_key_private = b64(&[1; 33]);
    assert!(bad.validate().is_err());
    let mut bad = provision();
    bad.link_token = b64(&[5; 32]);
    assert!(bad.validate().is_err());
}

fn sync_envelope(device_id: u32, registration_id: u32) -> OutgoingEnvelope {
    OutgoingEnvelope {
        device_id,
        registration_id,
        envelope_type: EnvelopeType::Message,
        suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
        content: b64(b"sealed"),
    }
}

fn keys(device_id: u32, registration_id: u32) -> DistributedDeviceKeysV1 {
    DistributedDeviceKeysV1 {
        device_id,
        registration_id,
        signed_pre_key: ec(1),
        last_resort_kyber_pre_key: kem(2),
    }
}

fn distribution() -> AccountIdentityDistributionRequest {
    let mut manifest = manifest(vec![device(1, 11), device(3, 31)]);
    manifest.sequence = 2;
    manifest.previous_hash = Some(hex::encode([7; 32]));
    sign(&mut manifest);
    AccountIdentityDistributionRequest {
        identity_key: manifest.identity_key.clone().unwrap(),
        devices: vec![keys(1, 11), keys(3, 31)],
        // The message carries device 3's current registration id.
        device_messages: vec![sync_envelope(3, 30)],
        manifest,
    }
}

#[test]
fn distribution_names_exactly_the_manifest_devices() {
    distribution().validate(1).unwrap();

    // Device 3 sending: it keeps itself and messages device 1.
    let mut from_three = distribution();
    from_three.device_messages = vec![sync_envelope(1, 10)];
    from_three.validate(3).unwrap();

    // A sender that left itself out.
    assert!(matches!(
        distribution().validate(2),
        Err(DistributionError::Invalid(_))
    ));

    let mut missing_keys = distribution();
    missing_keys.devices.pop();
    assert_eq!(
        missing_keys.validate(1),
        Err(DistributionError::Mismatched(DeviceListMismatch {
            missing_devices: vec![3],
            ..Default::default()
        }))
    );
    let mut extra_message = distribution();
    extra_message.device_messages.push(sync_envelope(4, 40));
    assert_eq!(
        extra_message.validate(1),
        Err(DistributionError::Mismatched(DeviceListMismatch {
            extra_devices: vec![4],
            ..Default::default()
        }))
    );
    let mut to_self = distribution();
    to_self.device_messages.insert(0, sync_envelope(1, 10));
    assert!(matches!(
        to_self.validate(1),
        Err(DistributionError::Mismatched(_))
    ));

    let mut unordered = distribution();
    unordered.devices.reverse();
    assert!(matches!(
        unordered.validate(1),
        Err(DistributionError::Invalid(_))
    ));
    let mut registration = distribution();
    registration.devices[1].registration_id = 32;
    assert!(matches!(
        registration.validate(1),
        Err(DistributionError::Invalid(_))
    ));
    let mut other_identity = distribution();
    other_identity.identity_key = identity(4);
    assert!(matches!(
        other_identity.validate(1),
        Err(DistributionError::Invalid(_))
    ));
    let mut unsigned = distribution();
    unsigned.devices[0].signed_pre_key.signature = None;
    assert!(matches!(
        unsigned.validate(1),
        Err(DistributionError::Invalid(_))
    ));
}

fn registration(registration: DeviceRegistrationV1) -> RegisterChatDeviceRequestV2 {
    RegisterChatDeviceRequestV2 {
        suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
        registration_id: 10,
        identity_key: identity(3),
        signed_pre_key: ec(1),
        last_resort_kyber_pre_key: kem(2),
        one_time_pre_keys: Vec::new(),
        one_time_kyber_pre_keys: Vec::new(),
        name: "Firefox".into(),
        credential: b64url_encode(&[1; 32]),
        registration,
    }
}

fn link() -> DeviceRegistrationV1 {
    DeviceRegistrationV1::Link {
        link_token: b64url_encode(&[5; 32]),
    }
}

#[test]
fn registration_is_a_link_or_a_reregistration() {
    registration(link()).validate().unwrap();
    let json = serde_json::to_value(registration(link())).unwrap();
    assert_eq!(json["registration"]["type"], "link");
    assert!(json["registration"]["linkToken"].is_string());

    // Exactly one kind, a credential, and nothing else.
    let mut both = json.clone();
    both["registration"]["manifest"] = serde_json::to_value(manifest(vec![device(1, 10)])).unwrap();
    assert!(serde_json::from_value::<RegisterChatDeviceRequestV2>(both).is_err());
    let mut neither = json.clone();
    neither.as_object_mut().unwrap().remove("registration");
    assert!(serde_json::from_value::<RegisterChatDeviceRequestV2>(neither).is_err());
    let mut no_credential = json.clone();
    no_credential.as_object_mut().unwrap().remove("credential");
    assert!(serde_json::from_value::<RegisterChatDeviceRequestV2>(no_credential).is_err());
    let mut extra = json;
    extra["deviceSignature"] = "x".into();
    assert!(serde_json::from_value::<RegisterChatDeviceRequestV2>(extra).is_err());

    let mut padded = registration(link());
    padded.credential = b64(&[1; 32]);
    assert!(padded.validate().is_err());
    let bad_token = registration(DeviceRegistrationV1::Link {
        link_token: b64(&[5; 32]),
    });
    assert!(bad_token.validate().is_err());
}

#[test]
fn reregistration_lists_this_device_as_its_one_chat_device() {
    let alone = || DeviceRegistrationV1::Reregistration {
        manifest: Box::new(manifest(vec![device(1, 10)])),
    };
    registration(alone()).validate().unwrap();
    let json = serde_json::to_value(registration(alone())).unwrap();
    assert_eq!(json["registration"]["type"], "reregistration");
    assert!(json["registration"]["manifest"].is_object());

    let mut other_registration = registration(alone());
    other_registration.registration_id = 11;
    assert!(other_registration.validate().is_err());
    let mut other_identity = registration(alone());
    other_identity.identity_key = identity(4);
    assert!(other_identity.validate().is_err());

    // The account's other devices stay; this one takes the lowest id they
    // leave free.
    for devices in [
        vec![editor(1), device(2, 10)],
        vec![editor(1), device(2, 10), editor(3)],
        vec![device(1, 10), editor(2)],
    ] {
        registration(DeviceRegistrationV1::Reregistration {
            manifest: Box::new(manifest(devices)),
        })
        .validate()
        .unwrap();
    }
    for devices in [
        vec![device(1, 10), device(2, 20)],
        vec![device(2, 10)],
        vec![editor(1), device(3, 10)],
        vec![editor(1)],
    ] {
        let bad = registration(DeviceRegistrationV1::Reregistration {
            manifest: Box::new(manifest(devices)),
        });
        assert!(bad.validate().is_err());
    }
    assert_eq!(reregistration_device_id(&[]), 1);
    assert_eq!(reregistration_device_id(&[1, 2, 4]), 3);
}

fn successor(head: &AccountManifestV3, devices: Vec<AccountManifestDeviceV3>) -> AccountManifestV3 {
    let mut next = manifest(devices);
    next.sequence = head.sequence + 1;
    next.previous_hash = Some(head.manifest_hash().unwrap());
    sign(&mut next);
    next
}

#[test]
fn successors_continue_the_chain() {
    let head = two_devices();
    let first = manifest(vec![device(1, 10)]);
    first.verify_successor(None).unwrap();
    let next = successor(&head, vec![device(1, 10)]);
    next.verify_successor(Some(&head)).unwrap();

    // A chain that starts over: sequence 1 again, while a head exists.
    assert!(first.verify_successor(Some(&head)).is_err());
    // Not sequence 1 with no head.
    assert!(next.verify_successor(None).is_err());
    // A skipped sequence, or another predecessor.
    let mut skipped = next.clone();
    skipped.sequence = 3;
    sign(&mut skipped);
    assert!(skipped.verify_successor(Some(&head)).is_err());
    let mut forked = next.clone();
    forked.previous_hash = Some(hex::encode([1; 32]));
    sign(&mut forked);
    assert!(forked.verify_successor(Some(&head)).is_err());

    // Another authority (so another incarnation), signed by it.
    let other = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let public = other.verifying_key().to_bytes();
    let mut incarnation = Sha256::new();
    incarnation.update(b"kutup/account-incarnation/v1\0");
    incarnation.update(public);
    let mut foreign = next.clone();
    foreign.self_authority_key = b64(&public);
    foreign.authority_key_id = hex::encode(Sha256::digest(public));
    foreign.incarnation_id = hex::encode(incarnation.finalize());
    foreign.signature = b64(&other.sign(&foreign.signing_bytes().unwrap()).to_bytes());
    foreign.verify().unwrap();
    assert!(foreign.verify_successor(Some(&head)).is_err());

    // A distribution's manifest must be such a successor: sequence 1 is not.
    let mut distribution = distribution();
    distribution.manifest = manifest(vec![device(1, 11), device(3, 31)]);
    distribution.validate(1).unwrap();
    assert!(distribution.manifest.verify_successor(Some(&head)).is_err());
}

#[test]
fn history_page_pagination_and_authority() {
    let first = two_devices();
    let second = successor(&first, vec![device(1, 10)]);
    let page = AccountManifestHistoryPageV3 {
        account: first.account.clone(),
        from_sequence: 1,
        to_sequence: 3,
        manifests: vec![first.clone(), second.clone()],
        next_sequence: Some(3),
    };
    page.validate().unwrap();
    for next_sequence in [None, Some(2), Some(4)] {
        let bad = AccountManifestHistoryPageV3 {
            next_sequence,
            ..page.clone()
        };
        assert!(bad.validate().is_err(), "{next_sequence:?}");
    }
    let mut short = page.clone();
    short.to_sequence = 2;
    assert!(short.validate().is_err());
    short.next_sequence = None;
    short.validate().unwrap();
}

#[test]
fn manifest_v3_vector_is_pinned() {
    // The signing bytes and hash of the fixed test manifest: a change to the
    // encoding is a deliberate format change, never an accident.
    let mut cli = editor(3);
    cli.kind = DeviceKind::Cli;
    cli.chat = Some(ChatDeviceKeysV3 {
        direct_chat_suite: DirectChatSuiteId::PqxdhTripleRatchetV1,
        registration_id: 30,
    });
    let manifest = manifest(vec![device(1, 10), editor(2), cli]);
    let bytes = manifest.signing_bytes().unwrap();
    assert_eq!(hex::encode(Sha256::digest(&bytes)), SIGNING_BYTES_SHA256);
    assert_eq!(manifest.manifest_hash().unwrap(), MANIFEST_HASH);
}

const SIGNING_BYTES_SHA256: &str =
    "4df9d81e6392f894d842fd784e2a93be5ed47ad95e5c56d501100d350682f19f";
const MANIFEST_HASH: &str = "b7ee11e87ce4e3033173b5f5939feff90474cbcf7b7600d1488f1dff3dba8760";

#[test]
fn account_identity_sync_body() {
    let body = AccountIdentityBody {
        identity_key_public: identity(3),
        identity_key_private: b64(&[0x42; 32]),
        registration_id: 31,
        signed_pre_key: b64(&[1; 120]),
        last_resort_kyber_pre_key: b64(&[2; 4800]),
        manifest_sequence: 2,
        manifest_hash: hex::encode([6; 32]),
    };
    body.validate().unwrap();
    assert!(!format!("{body:?}").contains(&b64(&[0x42; 32])));

    let mut bad = body.clone();
    bad.registration_id = 0;
    assert!(bad.validate().is_err());
    let mut bad = body.clone();
    bad.last_resort_kyber_pre_key = b64(&vec![2; MAX_PREKEY_RECORD_BYTES + 1]);
    assert!(bad.validate().is_err());
    let mut bad = body.clone();
    bad.signed_pre_key = String::new();
    assert!(bad.validate().is_err());
    assert_eq!(crate::content::kind::ACCOUNT_IDENTITY, "accountIdentity");
}

#[test]
fn keys_check_digest_is_pinned() {
    // A fixed vector, so the server and every client compute the same bytes.
    let digest = repeated_use_keys_digest(&[5; 33], 7, &[6; 33], 9, &[8; 1569]);
    assert_eq!(
        hex::encode(digest),
        hex::encode(repeated_use_keys_digest(
            &[5; 33], 7, &[6; 33], 9, &[8; 1569]
        ))
    );
    assert_ne!(
        digest,
        repeated_use_keys_digest(&[5; 33], 8, &[6; 33], 9, &[8; 1569])
    );
    assert_ne!(
        digest,
        repeated_use_keys_digest(&[5; 33], 7, &[6; 33], 9, &[7; 1569])
    );
}

#[test]
fn the_identity_binding_is_signed_and_names_authority_incarnation_account_and_identity() {
    let manifest = two_devices();
    let bytes = manifest.identity_binding_bytes().unwrap();
    assert!(bytes.starts_with(b"kutup/account-identity-binding/v1\0"));
    assert_eq!(
        bytes.len(),
        34 + 32 + 32 + manifest.account.bytes().len() + 33
    );
    assert_eq!(
        bytes,
        identity_binding_bytes(
            &manifest.authority_key_id,
            &manifest.incarnation_id,
            &manifest.account,
            manifest.identity_key.as_deref().unwrap()
        )
        .unwrap()
    );
    // The same identity and authority: the same bytes, whatever the devices.
    let mut fewer = manifest.clone();
    fewer.devices.pop();
    assert_eq!(fewer.identity_binding_bytes().unwrap(), bytes);
    // The binding itself is under the authority's signature, and its length
    // is checked.
    let mut other = manifest.clone();
    other.identity_binding = Some(b64(&[0x5c; 64]));
    assert!(other.verify().is_err());
    other.identity_binding = Some(b64(&[0x5c; 63]));
    assert!(other.signing_bytes().is_err());
}
