//! Checked-in vector for mail stored on arrival (docs/plans/mail.md): a raw
//! message encrypted to the address key of `mail-address-key-v1.json` with
//! `encrypt_binary`. Encryption is randomised, so the vector pins that the
//! stored form keeps opening, not its bytes. Regenerate only for a
//! deliberate format change:
//! `KUTUP_WRITE_MAIL_VECTORS=1 cargo test -p kutup-crypto --test mail_arrival_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::mail_key::{decrypt, encrypt_binary};

const KEYS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-address-key-v1.json"
);
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-arrival-v1.json"
);

/// Byte-exact mail as an outside server sends it: CRLF line ends, an
/// encoded-word subject, 8-bit UTF-8 in the body and a dot-stuffable line.
const MESSAGE: &[u8] = b"Return-Path: <bob@example.org>\r\n\
From: Bob <bob@example.org>\r\n\
To: alice@kutup.dev\r\n\
Subject: =?UTF-8?B?w4dhcsWfYW1iYSB0b3BsYW50xLFzxLE=?=\r\n\
Date: Fri, 09 Oct 2026 10:00:00 +0000\r\n\
Message-ID: <arrival-vector@example.org>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: 8bit\r\n\
\r\n\
G\xc3\xbcnayd\xc4\xb1n Alice,\r\n\
.a line that starts with a dot\r\n";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Keys {
    secret_key: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    plaintext: String,
    ciphertext: String,
}

fn keys() -> (Vec<u8>, Vec<u8>) {
    let keys: Keys = serde_json::from_str(&std::fs::read_to_string(KEYS).unwrap()).unwrap();
    (
        STANDARD.decode(keys.secret_key).unwrap(),
        STANDARD.decode(keys.public_key).unwrap(),
    )
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_MAIL_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let (_, public) = keys();
    let vectors = Vectors {
        plaintext: STANDARD.encode(MESSAGE),
        ciphertext: STANDARD.encode(encrypt_binary(&public, MESSAGE).unwrap()),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vector_opens() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let (secret, _) = keys();
    let ciphertext = STANDARD.decode(&v.ciphertext).unwrap();
    // Binary, not armored: the first packet is a public-key encrypted
    // session key (tag 1), in either packet-header format.
    assert!(matches!(ciphertext[0], 0x84..=0x87 | 0xc1));
    let opened = decrypt(&secret, &ciphertext, None).unwrap();
    assert_eq!(&*opened.data, MESSAGE);
    assert_eq!(STANDARD.decode(&v.plaintext).unwrap(), MESSAGE);
    assert!(!opened.verified);
}

#[test]
fn fresh_encryption_round_trips_and_differs() {
    let (secret, public) = keys();
    let one = encrypt_binary(&public, MESSAGE).unwrap();
    let two = encrypt_binary(&public, MESSAGE).unwrap();
    assert_ne!(one, two, "each message gets its own session key");
    assert_eq!(&*decrypt(&secret, &one, None).unwrap().data, MESSAGE);
    // Another key cannot open it.
    let other =
        kutup_crypto::mail_key::generate_address_key("bob@kutup.dev", 1_790_000_000).unwrap();
    assert!(decrypt(&other.secret_key, &one, None).is_err());
    // A key that cannot encrypt is refused up front.
    assert!(encrypt_binary(b"not a key", MESSAGE).is_err());
}
