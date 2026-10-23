//! Suite V1 against answers from other implementations
//! (`scripts/primitives-vectors.mjs`: OpenSSL and libsodium) and the
//! libcrux HPKE message.

use super::*;

#[derive(serde::Deserialize)]
struct Vectors {
    hash: Vec<HashCase>,
    mac: Vec<MacCase>,
    kdf: Vec<KdfCase>,
    aead: Vec<AeadCase>,
    signature: Vec<SignatureCase>,
    pwhash: Vec<PwhashCase>,
}
#[derive(serde::Deserialize)]
struct HashCase {
    data: String,
    digest: String,
}
#[derive(serde::Deserialize)]
struct MacCase {
    key: String,
    data: String,
    tag: String,
}
#[derive(serde::Deserialize)]
struct KdfCase {
    ikm: String,
    salt: String,
    info: String,
    okm: String,
}
#[derive(serde::Deserialize)]
struct AeadCase {
    key: String,
    nonce: String,
    aad: String,
    plaintext: String,
    ciphertext: String,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureCase {
    seed: String,
    public_key: String,
    message: String,
    signature: String,
}
#[derive(serde::Deserialize)]
struct PwhashCase {
    password: String,
    salt: String,
    ops: u64,
    mem: usize,
    output: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("../../tests/vectors/primitives-v1.json")).unwrap()
}

fn h(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
}

const S: Suite = Suite::V1;

#[test]
fn hash_matches_openssl() {
    for case in vectors().hash {
        assert_eq!(hash(S, h(&case.data)).as_bytes(), h(&case.digest));
        // In parts, the same.
        let data = h(&case.data);
        let (a, b) = data.split_at(data.len() / 2);
        let mut hasher = Hasher::new(S);
        hasher.update(a).update(b);
        assert_eq!(hasher.finish().as_bytes(), h(&case.digest));
    }
}

#[test]
fn mac_and_subkey_match_openssl_and_verify_only_their_tag() {
    for case in vectors().mac {
        let (key, data) = (h(&case.key), h(&case.data));
        assert_eq!(mac(S, &key, &[&data]).as_bytes(), h(&case.tag));
        mac_verify(S, &key, &[&data], &h(&case.tag)).unwrap();
        let mut wrong = h(&case.tag);
        wrong[0] ^= 1;
        assert!(mac_verify(S, &key, &[&data], &wrong).is_err());
        assert_eq!(subkey(S, &key, &data).as_slice(), h(&case.tag));
    }
}

#[test]
fn kdf_matches_openssl() {
    for case in vectors().kdf {
        let mut out = vec![0u8; h(&case.okm).len()];
        kdf(S, &h(&case.ikm), &h(&case.salt), &h(&case.info), &mut out).unwrap();
        assert_eq!(out, h(&case.okm));
    }
    let mut too_long = vec![0u8; S.params().kdf_max_output + 1];
    assert!(kdf(S, b"ikm", b"", b"info", &mut too_long).is_err());
}

#[test]
fn aead_matches_libsodium_and_refuses_any_change() {
    for case in vectors().aead {
        let key: [u8; 32] = h(&case.key).try_into().unwrap();
        let aead = Aead::new(S, &key).unwrap();
        let (nonce, aad) = (h(&case.nonce), h(&case.aad));
        let sealed = aead
            .seal_with_nonce(&nonce, &aad, &h(&case.plaintext))
            .unwrap();
        assert_eq!(sealed, h(&case.ciphertext));
        assert_eq!(
            *aead.open_with_nonce(&nonce, &aad, &sealed).unwrap(),
            h(&case.plaintext)
        );
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert!(aead.open_with_nonce(&nonce, &aad, &tampered).is_err());
        assert!(aead.open_with_nonce(&nonce, b"other", &sealed).is_err());
        assert!(aead.open_with_nonce(&nonce[1..], &aad, &sealed).is_err());
    }
    // A random nonce, carried in front.
    let aead = Aead::new(S, random_key().as_slice()).unwrap();
    assert!(Aead::new(S, &[0; 31]).is_err());
    let sealed = aead.seal(b"aad", b"hello").unwrap();
    assert_eq!(
        sealed.len(),
        S.params().aead_nonce_len + 5 + S.params().aead_tag_len
    );
    assert_eq!(*aead.open(b"aad", &sealed).unwrap(), b"hello");
    assert_ne!(aead.seal(b"aad", b"hello").unwrap(), sealed);
    assert!(aead.open(b"aad", &sealed[..10]).is_err());
}

#[test]
fn signatures_match_rfc_8032_and_verify_strictly() {
    for case in vectors().signature {
        let seed: [u8; 32] = h(&case.seed).try_into().unwrap();
        let key = SigningKey::from_seed(S, &seed);
        assert_eq!(key.verifying_key().to_bytes(), h(&case.public_key));
        let message = h(&case.message);
        assert_eq!(key.sign(&message), h(&case.signature));
        let verifying = VerifyingKey::from_bytes(S, &h(&case.public_key)).unwrap();
        verifying.verify(&message, &h(&case.signature)).unwrap();
        assert!(verifying.verify(b"other", &h(&case.signature)).is_err());
    }
    // Strict: a small-order key is refused even for a signature that would
    // check loosely (the identity point, all zeros but the 1).
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let small = VerifyingKey::from_bytes(S, &identity).unwrap();
    let mut forged = [0u8; 64];
    forged[0] = 1;
    assert!(small.verify(b"anything", &forged).is_err());
}

#[test]
fn hpke_opens_the_libcrux_message_and_round_trips() {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Libcrux {
        seed: String,
        public_key: String,
        info: String,
        aad: String,
        plaintext: String,
        enc: String,
        ciphertext: String,
    }
    let v: Libcrux = serde_json::from_str(include_str!(
        "../../tests/vectors/hpke-xwing-libcrux-v1.json"
    ))
    .unwrap();
    let seed: [u8; 32] = h(&v.seed).try_into().unwrap();
    assert_eq!(hpke_public_key(S, &seed), h(&v.public_key));
    let opened = hpke_open(
        S,
        &seed,
        &h(&v.enc),
        &h(&v.info),
        &h(&v.aad),
        &h(&v.ciphertext),
    )
    .unwrap();
    assert_eq!(*opened, h(&v.plaintext));
    let sealed = hpke_seal(S, &h(&v.public_key), b"info", b"aad", b"to you").unwrap();
    assert_eq!(sealed.encapsulated.len(), S.params().hpke_encapsulated_len);
    assert_eq!(
        *hpke_open(
            S,
            &seed,
            &sealed.encapsulated,
            b"info",
            b"aad",
            &sealed.ciphertext
        )
        .unwrap(),
        b"to you"
    );
    assert!(hpke_open(
        S,
        &seed,
        &sealed.encapsulated,
        b"other",
        b"aad",
        &sealed.ciphertext
    )
    .is_err());
}

#[test]
fn pwhash_matches_libsodium() {
    for case in vectors().pwhash {
        let salt: [u8; 16] = h(&case.salt).try_into().unwrap();
        let mut out = vec![0u8; h(&case.output).len()];
        pwhash(
            &PwhashParams {
                operations: case.ops,
                memory: case.mem,
            },
            &h(&case.password),
            &salt,
            &mut out,
        )
        .unwrap();
        assert_eq!(out, h(&case.output));
    }
}

#[test]
fn random_and_ct_eq() {
    assert_ne!(random_array::<32>(), random_array::<32>());
    assert_ne!(*random_key(), *random_key());
    assert!(ct_eq(b"same", b"same"));
    assert!(!ct_eq(b"same", b"sane"));
    assert!(!ct_eq(b"same", b"same!"));
}

/// The table names every length the code uses, so a new row can't leave one out.
#[test]
fn the_table_is_what_the_code_does() {
    let p = S.params();
    assert_eq!(hash(S, b"").as_bytes().len(), p.digest_len);
    assert_eq!(mac(S, b"k", &[b""]).as_bytes().len(), p.mac_tag_len);
    let aead = Aead::new(S, &[0; 32]).unwrap();
    assert_eq!(
        (aead.nonce_len(), aead.tag_len()),
        (p.aead_nonce_len, p.aead_tag_len)
    );
    let (key, seed) = SigningKey::generate(S);
    assert_eq!(
        (
            seed.len(),
            key.verifying_key().to_bytes().len(),
            key.sign(b"").len()
        ),
        (p.signing_seed_len, p.verifying_key_len, p.signature_len)
    );
    assert_eq!(hpke_public_key(S, &[7; 32]).len(), p.hpke_public_key_len);
    assert_eq!(
        (p.hpke_kem_id, p.hpke_kdf_id, p.hpke_aead_id),
        (crate::hpke_xwing::KEM_ID, 1, 3)
    );
}
