//! Checked-in vectors for the provisioning cipher
//! (docs/plans/account-identity-key.md, "The envelope"). They are written by
//! an independent implementation, `scripts/provisioning-vectors.mjs`
//! (node:crypto, following Signal Desktop's `encryptProvisionMessage`), so the
//! Rust cipher is checked against another implementation, not against itself.
//! The `signal` case uses Signal's own info string: the construction is
//! Signal's, and only the info string differs.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;

use kutup_crypto::provisioning::{self, vectors, ProvisioningKeyPair};

const VECTORS: &str = include_str!("vectors/provisioning-v1.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    kind: String,
    info: String,
    recipient_private: String,
    recipient_public: String,
    ephemeral_private: String,
    iv: String,
    message: String,
    sender_public: String,
    body: String,
}

#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

fn bytes(value: &str) -> Vec<u8> {
    STANDARD.decode(value).unwrap()
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    bytes(value).try_into().unwrap()
}

#[test]
fn provisioning_cipher_matches_the_independent_vectors() {
    let vectors: Vectors = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors.cases.len(), 4);
    for case in &vectors.cases {
        let recipient = ProvisioningKeyPair::from_private(array(&case.recipient_private));
        assert_eq!(
            recipient.public_key().to_vec(),
            bytes(&case.recipient_public)
        );

        let sealed = vectors::seal_with(
            case.info.as_bytes(),
            &array(&case.ephemeral_private),
            &array(&case.iv),
            &recipient.public_key(),
            &bytes(&case.message),
        )
        .unwrap();
        assert_eq!(sealed.sender_public.to_vec(), bytes(&case.sender_public));
        assert_eq!(sealed.body, bytes(&case.body), "{}", case.kind);

        let opened = vectors::open_with(
            case.info.as_bytes(),
            &array(&case.recipient_private),
            &bytes(&case.sender_public),
            &bytes(&case.body),
        )
        .unwrap();
        assert_eq!(opened.as_slice(), bytes(&case.message).as_slice());

        // Kutup's cipher opens Kutup's cases and refuses Signal's.
        let ours = recipient.open(&bytes(&case.sender_public), &bytes(&case.body));
        match case.kind.as_str() {
            "kutup" => {
                assert_eq!(case.info.as_bytes(), provisioning::INFO);
                assert_eq!(ours.unwrap().as_slice(), bytes(&case.message).as_slice());
            }
            "signal" => assert!(ours.is_err()),
            other => panic!("unknown case kind {other}"),
        }
    }
}
