//! Checked-in vector for mail between Kutup users (docs/plans/mail.md, C2):
//! one signed message encrypted to two keys and split into a key packet per
//! recipient and a shared data packet. Alice (the key of
//! `mail-address-key-v1.json`) sends to Bob and keeps her own copy.
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_MAIL_VECTORS=1 cargo test -p kutup-crypto --test mail_split_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::mail_key::{
    decrypt, encrypt_split, encryption_key_id, generate_address_key, key_packet_key_id,
};

const KEYS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-address-key-v1.json"
);
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-split-v1.json"
);

const MESSAGE: &[u8] = b"From: alice@kutup.dev\r\n\
To: bob@kutup.dev\r\n\
Subject: =?UTF-8?Q?=C3=96nemli?=\r\n\
Message-ID: <split-vector@kutup.dev>\r\n\
\r\n\
Merhaba Bob.\r\n";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Keys {
    secret_key: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    bob_secret_key: String,
    bob_public_key: String,
    plaintext: String,
    /// Alice's then Bob's key packet.
    key_packets: Vec<String>,
    data_packet: String,
}

fn alice() -> (Vec<u8>, Vec<u8>) {
    let keys: Keys = serde_json::from_str(&std::fs::read_to_string(KEYS).unwrap()).unwrap();
    (
        STANDARD.decode(keys.secret_key).unwrap(),
        STANDARD.decode(keys.public_key).unwrap(),
    )
}

fn join(key_packet: &[u8], data_packet: &[u8]) -> Vec<u8> {
    [key_packet, data_packet].concat()
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_MAIL_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let (alice_secret, alice_public) = alice();
    let bob = generate_address_key("bob@kutup.dev", 1_790_000_000).unwrap();
    let split = encrypt_split(&[&alice_public, &bob.public_key], &alice_secret, MESSAGE).unwrap();
    let vectors = Vectors {
        bob_secret_key: STANDARD.encode(&*bob.secret_key),
        bob_public_key: STANDARD.encode(&bob.public_key),
        plaintext: STANDARD.encode(MESSAGE),
        key_packets: split
            .key_packets
            .iter()
            .map(|p| STANDARD.encode(p))
            .collect(),
        data_packet: STANDARD.encode(&split.data_packet),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vector_opens_for_each_recipient() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let (alice_secret, alice_public) = alice();
    let bob_secret = STANDARD.decode(&v.bob_secret_key).unwrap();
    let bob_public = STANDARD.decode(&v.bob_public_key).unwrap();
    let data = STANDARD.decode(&v.data_packet).unwrap();
    let packets: Vec<Vec<u8>> = v
        .key_packets
        .iter()
        .map(|p| STANDARD.decode(p).unwrap())
        .collect();
    assert_eq!(STANDARD.decode(&v.plaintext).unwrap(), MESSAGE);

    for (packet, (secret, public)) in packets
        .iter()
        .zip([(&alice_secret, &alice_public), (&bob_secret, &bob_public)])
    {
        // Each key packet names its recipient's encryption key...
        assert_eq!(
            key_packet_key_id(packet).unwrap(),
            encryption_key_id(public).unwrap()
        );
        // ...and with the shared data packet opens to the signed message.
        let opened = decrypt(secret, &join(packet, &data), Some(&alice_public)).unwrap();
        assert_eq!(&*opened.data, MESSAGE);
        assert!(opened.signed && opened.verified);
    }
    // A key packet opens nothing for another key.
    assert!(decrypt(&bob_secret, &join(&packets[0], &data), None).is_err());
    // A signature from someone else does not verify.
    let opened = decrypt(&bob_secret, &join(&packets[1], &data), Some(&bob_public)).unwrap();
    assert!(opened.signed && !opened.verified);
}

#[test]
fn fresh_split_keeps_recipients_apart() {
    let (alice_secret, alice_public) = alice();
    let bob = generate_address_key("bob@kutup.dev", 1_790_000_000).unwrap();
    let carol = generate_address_key("carol@kutup.dev", 1_790_000_000).unwrap();
    let split = encrypt_split(
        &[&alice_public, &bob.public_key, &carol.public_key],
        &alice_secret,
        MESSAGE,
    )
    .unwrap();
    assert_eq!(split.key_packets.len(), 3);
    let ids: Vec<[u8; 8]> = split
        .key_packets
        .iter()
        .map(|p| key_packet_key_id(p).unwrap())
        .collect();
    assert_eq!(ids[1], encryption_key_id(&bob.public_key).unwrap());
    assert_eq!(ids[2], encryption_key_id(&carol.public_key).unwrap());
    // Carol's copy carries only her key packet: it says nothing of Bob.
    let carols = join(&split.key_packets[2], &split.data_packet);
    assert!(!carols.windows(8).any(|w| w == ids[1]));
    assert_eq!(
        &*decrypt(&carol.secret_key, &carols, None).unwrap().data,
        MESSAGE
    );
    // Limits and malformed input.
    assert!(encrypt_split(&[], &alice_secret, MESSAGE).is_err());
    assert!(key_packet_key_id(&split.data_packet).is_err());
    assert!(key_packet_key_id(&[]).is_err());
    let mut doubled = split.key_packets[0].clone();
    doubled.extend_from_slice(&split.key_packets[1]);
    assert!(key_packet_key_id(&doubled).is_err());
}
