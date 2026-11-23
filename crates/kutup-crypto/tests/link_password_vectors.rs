//! Checked-in vectors for a public link's password
//! (`kutup_crypto::link_password`, docs/plans/drive-link-password.md): the
//! proof, verifier and wrap key a URL secret and password derive, the link
//! key sealed under the wrap key (purpose 14), and the owner's copy of the
//! secret and password under the Drive root (purpose 15). The browser checks
//! the same file through the WASM build (`frontend/packages/crypto`).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;

use kutup_crypto::account_roots::{DriveRoot, RootGeneration};
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1};
use kutup_crypto::link_password;

const VECTORS: &str = include_str!("vectors/drive-link-password-v1.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    password: String,
    secret: String,
    salt: String,
    operations: u64,
    memory: u64,
    link_id: String,
    owner_account_id: String,
    key_revision: u32,
    proof: String,
    verifier: String,
    wrap_key: String,
    link_key: String,
    link_key_nonce: String,
    link_key_envelope: String,
    drive_root: String,
    drive_root_generation: u32,
    owner_secret_nonce: String,
    owner_secret_envelope: String,
}

#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

fn b(value: &str) -> Vec<u8> {
    STANDARD.decode(value).unwrap()
}

fn arr<const N: usize>(value: &str) -> [u8; N] {
    b(value).try_into().unwrap()
}

#[test]
fn link_password_matches_the_vectors() {
    let vectors: Vectors = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.cases.len() >= 2);
    for case in &vectors.cases {
        let params = link_password::check_params(case.operations, case.memory).unwrap();
        let keys = link_password::derive(
            &b(&case.secret),
            &case.password,
            &b(&case.salt),
            &params,
            &case.link_id,
        )
        .unwrap();
        assert_eq!(keys.proof.as_slice(), b(&case.proof).as_slice());
        assert_eq!(keys.wrap_key.as_slice(), b(&case.wrap_key).as_slice());
        assert_eq!(
            link_password::verifier(keys.proof.as_slice())
                .unwrap()
                .as_slice(),
            b(&case.verifier).as_slice()
        );
        let protection = link_password::protect_with(
            &b(&case.secret),
            &case.password,
            &b(&case.link_key),
            &case.link_id,
            &case.owner_account_id,
            case.key_revision,
            &params,
            &arr(&case.salt),
            &arr(&case.link_key_nonce),
        )
        .unwrap();
        assert_eq!(protection.link_key_envelope, case.link_key_envelope);
        assert_eq!(
            link_password::open_link_key(
                &case.link_key_envelope,
                &b(&case.wrap_key),
                &case.link_id,
                &case.owner_account_id,
                case.key_revision,
            )
            .unwrap()
            .as_slice(),
            b(&case.link_key).as_slice()
        );

        let root = DriveRoot::from_slice(&b(&case.drive_root)).unwrap();
        let generation = RootGeneration::new(case.drive_root_generation).unwrap();
        let mut plain = b(&case.secret);
        plain.extend_from_slice(link_password::normalize(&case.password).unwrap().as_bytes());
        let context = DriveEnvelopeContextV1::owner_link_secret(
            &case.link_id,
            &case.owner_account_id,
            generation,
        )
        .unwrap();
        let sealed = drive_envelope::seal_with_nonce(
            &plain,
            root.as_bytes(),
            context,
            &b(&case.owner_secret_nonce),
        )
        .unwrap();
        assert_eq!(STANDARD.encode(sealed), case.owner_secret_envelope);
        let opened = link_password::open_owner_secret(
            &case.owner_secret_envelope,
            &root,
            &case.link_id,
            &case.owner_account_id,
            generation,
        )
        .unwrap();
        assert_eq!(opened.secret.as_slice(), b(&case.secret).as_slice());
        assert_eq!(
            opened.password.as_str(),
            link_password::normalize(&case.password).unwrap().as_str()
        );
    }
}

/// Prints `vectors/drive-link-password-v1.json`.
/// `cargo test -p kutup-crypto --test link_password_vectors print -- --ignored --nocapture`.
#[test]
#[ignore]
fn print_link_password_vectors() {
    let e = |bytes: &[u8]| STANDARD.encode(bytes);
    let link = "33333333-3333-4333-8333-333333333333";
    let owner = "22222222-2222-4222-8222-222222222222";
    let root = DriveRoot::from_slice(&[0x63; 32]).unwrap();
    let generation = RootGeneration::new(2).unwrap();
    let cases: Vec<_> = [
        (
            "correct horse battery staple",
            1u64,
            8u64 * 1024 * 1024,
            2u32,
        ),
        // Decomposed: stretched composed (NFC), as typed on another device.
        ("s\u{327}ifre-c\u{327}ok-gizli", 2, 16 * 1024 * 1024, 5),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (password, operations, memory, key_revision))| {
        let i = i as u8;
        let secret = [0x40 + i; 32];
        let salt = [0x50 + i; 16];
        let link_key = [0x60 + i; 32];
        let nonce = [0x70 + i; 24];
        let secret_nonce = [0x78 + i; 24];
        let params = link_password::check_params(operations, memory).unwrap();
        let keys = link_password::derive(&secret, password, &salt, &params, link).unwrap();
        let protection = link_password::protect_with(
            &secret,
            password,
            &link_key,
            link,
            owner,
            key_revision,
            &params,
            &salt,
            &nonce,
        )
        .unwrap();
        let mut plain = secret.to_vec();
        plain.extend_from_slice(link_password::normalize(password).unwrap().as_bytes());
        let context = DriveEnvelopeContextV1::owner_link_secret(link, owner, generation).unwrap();
        let owner_secret =
            drive_envelope::seal_with_nonce(&plain, root.as_bytes(), context, &secret_nonce)
                .unwrap();
        serde_json::json!({
            "password": password,
            "secret": e(&secret),
            "salt": e(&salt),
            "operations": operations,
            "memory": memory,
            "linkId": link,
            "ownerAccountId": owner,
            "keyRevision": key_revision,
            "proof": e(keys.proof.as_slice()),
            "verifier": e(&protection.verifier),
            "wrapKey": e(keys.wrap_key.as_slice()),
            "linkKey": e(&link_key),
            "linkKeyNonce": e(&nonce),
            "linkKeyEnvelope": protection.link_key_envelope,
            "driveRoot": e(root.as_bytes()),
            "driveRootGeneration": generation.get(),
            "ownerSecretNonce": e(&secret_nonce),
            "ownerSecretEnvelope": e(&owner_secret),
        })
    })
    .collect();
    let v = serde_json::json!({
        "description": "A public link's password (kutup-crypto/src/link_password.rs, docs/plans/drive-link-password.md): Argon2id(NFC(password), salt) with the URL secret through HKDF-SHA256 to the proof and wrap key; the verifier; the link key under the wrap key (Drive envelope purpose 14, revision = key revision); the owner's secret and password under the Drive root (purpose 15).",
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
}
