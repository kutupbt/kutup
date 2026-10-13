//! Checked-in vectors for account envelopes: one sealed envelope per purpose,
//! and for every purpose the envelopes that must be refused, each with the
//! step that refuses it (`inspect`, which the server runs before storing, or
//! `open`). The WASM tests read the same file. Regenerate only for a
//! deliberate format change:
//! `KUTUP_WRITE_ACCOUNT_ENVELOPE_VECTORS=1 cargo test -p kutup-crypto --test account_envelope_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_envelope::{
    self, seal_suite, seal_unchecked_for_vectors, AccountEnvelopePurpose, AccountEnvelopeSuiteId,
    Length, ObjectPolicy,
};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/account-envelope-v2.json"
);
const KEY: [u8; 32] = [0x24; 32];
const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
const OTHER_BINDING: &str = "1b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
const NONCE: [u8; 24] = [0x11; 24];

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    key: String,
    binding: String,
    purposes: Vec<PurposeVectors>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PurposeVectors {
    purpose: u8,
    object_id: String,
    plaintext: String,
    nonce: String,
    envelope: String,
    refused: Vec<Refused>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Refused {
    why: String,
    /// `inspect`: malformed, refused before any key is used; `open`: well
    /// formed, refused when opened for this purpose, binding and object.
    step: String,
    envelope: String,
}

fn object_for(purpose: AccountEnvelopePurpose) -> Vec<u8> {
    match purpose.policy().object {
        ObjectPolicy::None => vec![],
        ObjectPolicy::Required(len) => (0..len as u8).map(|i| 0x3f ^ i).collect(),
    }
}

fn plaintext_for(purpose: AccountEnvelopePurpose) -> Vec<u8> {
    match purpose.policy().length {
        Length::Exact(n) => vec![0x42; n],
        Length::Fixed(_) | Length::Bucket(_) => b"a secret whose length is hidden".to_vec(),
    }
}

/// The plaintext padded as the purpose pads it, then made wrong.
fn padded(purpose: AccountEnvelopePurpose) -> Vec<u8> {
    purpose
        .policy()
        .length
        .pad(&plaintext_for(purpose))
        .unwrap()
}

fn refused_for(purpose: AccountEnvelopePurpose, envelope: &[u8]) -> Vec<Refused> {
    let object = object_for(purpose);
    let unchecked = |plain: &[u8], binding: &str, object: &[u8], revision: Option<u64>| {
        seal_unchecked_for_vectors(plain, &KEY, purpose, binding, object, revision, &NONCE).unwrap()
    };
    let mut refused = Vec::new();
    let mut add = |why: &str, step: &str, envelope: Vec<u8>| {
        refused.push(Refused {
            why: why.into(),
            step: step.into(),
            envelope: STANDARD.encode(envelope),
        })
    };
    let mut suite_one = envelope.to_vec();
    suite_one[9] = 1;
    add("suite 1, retired", "inspect", suite_one);
    let mut reserved = envelope.to_vec();
    reserved[11] = 1;
    add("reserved byte set", "inspect", reserved);
    let mut upper = envelope.to_vec();
    upper[14] = b'B';
    add("binding not a canonical key binding", "inspect", upper);
    let mut trailing = envelope.to_vec();
    trailing.push(0);
    add("trailing byte", "inspect", trailing);
    match purpose.policy().object {
        ObjectPolicy::None => add(
            "an object id where the purpose has none",
            "inspect",
            unchecked(&padded(purpose), BINDING, &[7; 16], None),
        ),
        ObjectPolicy::Required(len) => {
            add(
                "no object id",
                "inspect",
                unchecked(&padded(purpose), BINDING, &[], None),
            );
            add(
                "an object id of the wrong length",
                "inspect",
                unchecked(&padded(purpose), BINDING, &vec![7; len + 1], None),
            );
        }
    }
    if purpose.policy().mutable {
        add(
            "no revision",
            "inspect",
            unchecked(&padded(purpose), BINDING, &object, None),
        );
        // The revision changed in the header: well formed, but the AEAD
        // covers it, so an older secret cannot pass as newer.
        let header = account_envelope::inspect(envelope).unwrap();
        let last_revision_byte = envelope.len() - header.ciphertext_len as usize - 4 - 24 - 1;
        let mut relabelled = envelope.to_vec();
        relabelled[last_revision_byte] ^= 2;
        add("revision relabelled", "open", relabelled);
    } else {
        add(
            "a revision where the purpose has none",
            "inspect",
            unchecked(&padded(purpose), BINDING, &object, Some(1)),
        );
    }
    let mut long = padded(purpose);
    long.push(0);
    add(
        "a length its padding policy never gives",
        "inspect",
        unchecked(&long, BINDING, &object, None),
    );
    if !matches!(purpose.policy().length, Length::Exact(_)) {
        let mut no_marker = padded(purpose);
        let marker = no_marker.iter().rposition(|&b| b != 0).unwrap();
        no_marker[marker] = 0x01;
        add(
            "padding without its 0x80 marker",
            "open",
            unchecked(&no_marker, BINDING, &object, None),
        );
    }
    add(
        "sealed for another account",
        "open",
        unchecked(&padded(purpose), OTHER_BINDING, &object, None),
    );
    let mut swapped = envelope.to_vec();
    swapped[10] = if purpose == AccountEnvelopePurpose::PasswordMasterKey {
        AccountEnvelopePurpose::RecoveryMasterKey.as_u8()
    } else {
        AccountEnvelopePurpose::PasswordMasterKey.as_u8()
    };
    add("purpose byte changed", "inspect-or-open", swapped);
    refused
}

fn sealed(purpose: AccountEnvelopePurpose) -> Vec<u8> {
    seal_suite(
        AccountEnvelopeSuiteId::XChaCha20Poly1305HkdfV2,
        &plaintext_for(purpose),
        &KEY,
        purpose,
        BINDING,
        &object_for(purpose),
        purpose.policy().mutable.then_some(1),
        &NONCE,
    )
    .unwrap()
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_ACCOUNT_ENVELOPE_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let purposes = AccountEnvelopePurpose::ALL
        .iter()
        .map(|&purpose| {
            let envelope = sealed(purpose);
            PurposeVectors {
                purpose: purpose.as_u8(),
                object_id: STANDARD.encode(object_for(purpose)),
                plaintext: STANDARD.encode(plaintext_for(purpose)),
                nonce: STANDARD.encode(NONCE),
                refused: refused_for(purpose, &envelope),
                envelope: STANDARD.encode(envelope),
            }
        })
        .collect();
    let vectors = Vectors {
        key: STANDARD.encode(KEY),
        binding: BINDING.into(),
        purposes,
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

fn open_for(purpose: AccountEnvelopePurpose, envelope: &[u8], object: &[u8]) -> bool {
    if purpose.policy().mutable {
        account_envelope::open_revision(envelope, &KEY, purpose, BINDING, object).is_ok()
    } else {
        account_envelope::open_object(envelope, &KEY, purpose, BINDING, object).is_ok()
    }
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(v.purposes.len(), AccountEnvelopePurpose::ALL.len());
    for p in &v.purposes {
        let purpose = AccountEnvelopePurpose::try_from(p.purpose).unwrap();
        let object = STANDARD.decode(&p.object_id).unwrap();
        let envelope = STANDARD.decode(&p.envelope).unwrap();
        assert_eq!(sealed(purpose), envelope, "{purpose:?} seals as checked in");
        let header =
            account_envelope::validate_for(&envelope, purpose, &v.binding, &object).unwrap();
        assert_eq!(header.revision, purpose.policy().mutable.then_some(1));
        assert!(open_for(purpose, &envelope, &object), "{purpose:?} opens");
        assert!(
            account_envelope::validate_for(&envelope, purpose, OTHER_BINDING, &object).is_err()
        );
        assert!(!p.refused.is_empty());
        for refused in &p.refused {
            let bad = STANDARD.decode(&refused.envelope).unwrap();
            let inspected = account_envelope::inspect(&bad);
            match refused.step.as_str() {
                "inspect" => assert!(inspected.is_err(), "{purpose:?}: {}", refused.why),
                "open" => assert!(inspected.is_ok(), "{purpose:?}: {}", refused.why),
                _ => {}
            }
            assert!(
                account_envelope::validate_for(&bad, purpose, &v.binding, &object).is_err()
                    || refused.step == "open",
                "{purpose:?}: {}",
                refused.why
            );
            assert!(
                !open_for(purpose, &bad, &object),
                "{purpose:?}: {}",
                refused.why
            );
        }
    }
}
