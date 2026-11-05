use super::*;

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/call-link-v1.json"
);

fn vectors() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap()
}

/// The nonce a sealed value starts with.
fn nonce_of(sealed: &str) -> [u8; NONCE_BYTES] {
    STANDARD.decode(sealed).unwrap()[..NONCE_BYTES]
        .try_into()
        .unwrap()
}

/// The nonce of a joined-meeting record: it ends where the ciphertext length
/// and the fixed-size ciphertext begin.
fn joined_nonce_of(sealed: &str) -> [u8; NONCE_BYTES] {
    let bytes = STANDARD.decode(sealed).unwrap();
    let end = bytes.len() - (JOINED_PADDED_BYTES + TAG_BYTES) - 4;
    bytes[end - NONCE_BYTES..end].try_into().unwrap()
}

/// The vectors chat-core's code made before the move
/// (docs/plans/chat-crypto-move.md): this code derives every key alike, opens
/// every sealed value, and reseals each byte for byte under its nonce.
#[test]
fn the_moved_code_reproduces_the_vectors() {
    let v = vectors();
    let text = |key: &str| v[key].as_str().unwrap().to_owned();
    let sealed = |key: &str| v[key]["sealed"].as_str().unwrap().to_owned();
    let secret = owner_call_link_secret(&text("masterKey"), &text("nonce")).unwrap();
    assert_eq!(secret.as_str(), text("ownerSecret"));
    let host = owner_call_link_host_token(&text("masterKey"), &text("nonce")).unwrap();
    assert_eq!(host.as_str(), text("hostToken"));
    assert_eq!(call_link_token_hash(&host).unwrap(), text("hostTokenHash"));
    let keys = CallLinkKeys::derive(&secret).unwrap();
    assert_eq!(keys.room_id, text("roomId"));
    assert_eq!(keys.access_token, text("accessToken"));
    assert_eq!(keys.access_token_hash, text("accessTokenHash"));
    assert_eq!(keys.frame_key.as_str(), text("frameKey"));
    assert_eq!(call_link_fragment(&secret).unwrap(), text("fragment"));
    assert_eq!(
        parse_call_link_fragment(&text("fragment"))
            .unwrap()
            .as_str(),
        secret.as_str()
    );

    let name = keys.open_name(&sealed("name")).unwrap();
    assert_eq!(name, v["name"]["plaintext"]);
    assert_eq!(
        keys.seal_with_nonce(Purpose::Name, name.as_bytes(), &nonce_of(&sealed("name")))
            .unwrap(),
        sealed("name")
    );

    let info = keys.open_info(&sealed("info")).unwrap();
    assert_eq!(serde_json::to_value(&info).unwrap(), v["info"]["plaintext"]);
    let json = serde_json::to_vec(&info).unwrap();
    assert_eq!(
        keys.seal_with_nonce(Purpose::Info, &json, &nonce_of(&sealed("info")))
            .unwrap(),
        sealed("info")
    );

    let message = keys.open_message(&sealed("message")).unwrap();
    assert_eq!(
        serde_json::to_value(&message).unwrap(),
        v["message"]["plaintext"]
    );
    let json = serde_json::to_vec(&message).unwrap();
    assert_eq!(
        keys.seal_with_nonce(Purpose::Message, &json, &nonce_of(&sealed("message")))
            .unwrap(),
        sealed("message")
    );

    let binding = v["joined"]["binding"].as_str().unwrap();
    let id = v["joined"]["id"].as_str().unwrap();
    let joined = open_joined_meeting(&text("masterKey"), binding, id, &sealed("joined")).unwrap();
    assert_eq!(
        serde_json::to_value(&joined).unwrap(),
        v["joined"]["plaintext"]
    );
    assert_eq!(
        seal_joined_meeting_with_nonce(
            &text("masterKey"),
            crate::account_record::MasterKeyGeneration::FIRST,
            binding,
            id,
            &joined,
            &joined_nonce_of(&sealed("joined"))
        )
        .unwrap(),
        sealed("joined")
    );
}

#[test]
fn a_value_opens_only_for_its_purpose_link_and_account() {
    let v = vectors();
    let text = |key: &str| v[key].as_str().unwrap().to_owned();
    let keys = CallLinkKeys::derive(&text("ownerSecret")).unwrap();
    let other = CallLinkKeys::derive(&STANDARD.encode([0x33u8; 32])).unwrap();
    let name = keys.seal_name("  Ali  ").unwrap();
    assert_eq!(keys.open_name(&name).unwrap(), "Ali");
    assert!(other.open_name(&name).is_err());
    // A name is not info, even when the sizes are made to match.
    assert!(keys.open_info(&name).is_err());
    assert!(keys.seal_name("").is_err());
    assert!(keys.seal_name("a\u{7}b").is_err());
    assert!(keys
        .seal_name(&"a".repeat(MAX_CALL_NAME_BYTES + 1))
        .is_err());

    let joined = v["joined"]["sealed"].as_str().unwrap();
    let binding = v["joined"]["binding"].as_str().unwrap();
    let id = v["joined"]["id"].as_str().unwrap();
    assert!(open_joined_meeting(&STANDARD.encode([0x22u8; 32]), binding, id, joined).is_err());
    let raw = STANDARD.decode(joined).unwrap();
    validate_joined_meeting(&raw, binding, id).unwrap();
    assert!(validate_joined_meeting(&raw, binding, &"ab".repeat(16)).is_err());
    assert!(validate_joined_meeting(&raw[1..], binding, id).is_err());
    assert!(owner_call_link_secret(&text("masterKey"), "0123").is_err());
    assert!(owner_call_link_secret(&text("masterKey"), &text("nonce").to_uppercase()).is_err());
    assert!(parse_call_link_fragment("AA").is_err());
    assert_eq!(new_call_link_nonce().len(), 32);
}
