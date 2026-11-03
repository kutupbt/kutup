use super::*;

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/profile-v1.json");

fn vectors() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap()
}

fn b64(value: &serde_json::Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}

fn array(value: &serde_json::Value) -> [u8; 32] {
    b64(value).try_into().unwrap()
}

/// The vectors chat-core's code made before the move
/// (docs/plans/chat-crypto-move.md): this code reproduces every derived key,
/// verifier and item envelope byte for byte, and opens the whole upload.
#[test]
fn the_moved_code_reproduces_the_vectors() {
    let v = vectors();
    let account: AccountRef = v["account"].as_str().unwrap().parse().unwrap();
    let master = array(&v["masterKey"]);
    let key = array(&v["profileKey"]);
    let wrapping = derive_wrapping_key(&master, v["binding"].as_str().unwrap()).unwrap();
    assert_eq!(STANDARD.encode(wrapping), v["wrappingKey"]);
    let version = profile_version(&key).unwrap();
    assert_eq!(version, v["version"]);
    let access = profile_access_key(&key).unwrap();
    assert_eq!(STANDARD.encode(access), v["accessKey"]);
    assert_eq!(access_key_verifier(&access), v["accessKeyVerifier"]);
    let delivery = derive_delivery_capability(&key, &account).unwrap();
    assert_eq!(hex::encode(capability_hash(&delivery)), v["deliveryCapabilityVerifier"]);

    for item in v["items"].as_array().unwrap() {
        let purpose = match item["purpose"].as_str().unwrap() {
            "DisplayName" => ProfileEnvelopePurpose::DisplayName,
            "Avatar" => ProfileEnvelopePurpose::Avatar,
            "About" => ProfileEnvelopePurpose::About,
            "WrappedProfileKey" => ProfileEnvelopePurpose::WrappedProfileKey,
            other => panic!("purpose {other}"),
        };
        let context = ProfileEnvelopeContextV1::new(
            purpose,
            &account,
            &version,
            item["revision"].as_u64().unwrap(),
            item["sourceDeviceId"].as_u64().unwrap() as u32,
        )
        .unwrap();
        let root = array(&item["rootKey"]);
        let nonce: [u8; NONCE_BYTES] = b64(&item["nonce"]).try_into().unwrap();
        let plaintext = b64(&item["plaintext"]);
        assert_eq!(
            seal_item_with_nonce(&plaintext, &root, &context, &nonce).unwrap(),
            item["envelope"].as_str().unwrap(),
            "{purpose:?}"
        );
        let opened = open_item(item["envelope"].as_str().unwrap(), &root, &context).unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    let upload: SealedProfile = serde_json::from_value(v["upload"]["request"].clone()).unwrap();
    let opened = open_own_profile(&upload, &wrapping, &account).unwrap();
    assert_eq!(STANDARD.encode(opened.key.as_slice()), v["upload"]["profileKey"]);
    assert_eq!(opened.contents.display_name, v["upload"]["displayName"]);
    assert_eq!(STANDARD.encode(opened.contents.avatar.unwrap()), v["upload"]["avatar"]);
    assert_eq!(opened.contents.avatar_content_type.as_deref(), v["upload"]["avatarContentType"].as_str());
    assert_eq!(opened.revision, v["upload"]["revision"].as_u64().unwrap());
    // The wire shape round-trips.
    assert_eq!(serde_json::to_value(&upload).unwrap(), v["upload"]["request"]);
}

#[test]
fn a_sealed_profile_opens_for_its_owner_and_with_its_key() {
    let v = vectors();
    let account: AccountRef = v["account"].as_str().unwrap().parse().unwrap();
    let master = array(&v["masterKey"]);
    let binding = v["binding"].as_str().unwrap();
    let contents = ProfileContents {
        display_name: "  Ayşe  ".into(),
        avatar: Some(vec![0x89, 0x50, 0x4e, 0x47]),
        avatar_content_type: Some("image/png".into()),
        about: Some("Merhaba".into()),
    };
    let first = seal_account_profile(&master, None, &contents, &account, binding).unwrap();
    assert_eq!((first.revision, first.source_device_id), (1, ACCOUNT_PROFILE_SOURCE));
    let opened = open_account_profile(&master, &first, &account, binding).unwrap();
    assert_eq!(opened.contents.display_name, "Ayşe");
    assert_eq!(opened.contents.about.as_deref(), Some("Merhaba"));

    // The next revision keeps the key.
    let next = seal_account_profile(&master, Some(&first), &contents, &account, binding).unwrap();
    assert_eq!((next.revision, next.version.as_str()), (2, first.version.as_str()));

    // Someone given the key opens it; another account's name, another key or
    // another master key don't.
    let peer = open_peer_profile(&first, &account, opened.key.as_slice()).unwrap();
    assert_eq!(peer.contents, opened.contents);
    let other: AccountRef = "aci:00000000-0000-4000-8000-000000000001@example.com".parse().unwrap();
    assert!(open_peer_profile(&first, &other, opened.key.as_slice()).is_err());
    assert!(open_peer_profile(&first, &account, &[7; 32]).is_err());
    assert!(open_account_profile(&[8; 32], &first, &account, binding).is_err());
}

#[test]
fn contents_are_validated_before_sealing() {
    assert!(validate_display_name("   ").is_err());
    assert!(validate_display_name(&"a".repeat(81)).is_err());
    assert_eq!(validate_about(Some("  ")).unwrap(), None);
    assert!(validate_about(Some("two\nlines")).is_err());
    assert!(validate_avatar(Some(&[1]), None).is_err());
    assert!(validate_avatar(Some(&[1]), Some("image/gif")).is_err());
    assert!(validate_avatar(Some(&[]), Some("image/png")).is_err());
    assert!(validate_avatar(None, None).is_ok());
}

#[test]
fn profile_envelope_parser_rejects_unknown_suite_and_trailing_data() {
    let alice: AccountRef = "aci:0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b@example.test".parse().unwrap();
    let context = ProfileEnvelopeContextV1::new(
        ProfileEnvelopePurpose::WrappedProfileKey,
        &alice,
        &"01".repeat(32),
        1,
        1,
    )
    .unwrap();
    let header = encode_profile_envelope_header(&context, &[3; 24], 48).unwrap();
    let mut encoded = header;
    encoded.extend_from_slice(&[4; 48]);
    let valid = STANDARD.encode(&encoded);
    assert_eq!(decode_profile_envelope(&valid).unwrap().context, context);

    encoded[8] = 0x7f;
    assert!(decode_profile_envelope(&STANDARD.encode(&encoded)).is_err());
    encoded[8] = 0;
    encoded.push(0);
    assert!(decode_profile_envelope(&STANDARD.encode(&encoded)).is_err());
    encoded.pop();

    // The account slot holds exactly one account's bytes: one more byte in
    // its length (taken from the nonce) is refused.
    let length_at = FIXED_PREFIX_BYTES - 2;
    let length = u16::from_be_bytes([encoded[length_at], encoded[length_at + 1]]);
    encoded[length_at..length_at + 2].copy_from_slice(&(length + 1).to_be_bytes());
    assert!(decode_profile_envelope(&STANDARD.encode(&encoded)).is_err());
}
