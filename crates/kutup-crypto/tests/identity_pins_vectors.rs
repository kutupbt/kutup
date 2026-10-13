//! Checked-in vectors for Drive identity (docs/plans/drive-identity-pins.md):
//! an account's Drive key binding (bound to its address, a statement to
//! others), and a sealed identity pin list (suite 2, bound to the account's
//! key binding), with the values that must be refused. Regenerate only for a
//! deliberate format change:
//! `KUTUP_WRITE_IDENTITY_VECTORS=1 cargo test -p kutup-crypto --test identity_pins_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::drive_key_binding;
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::identity_pins::{self, IdentityPinV1, IdentityPinsV1, PinState};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/identity-pins-v2.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    account: String,
    /// The owner's key binding, which the sealed list binds.
    binding: String,
    authority_public_key: String,
    drive_hpke_public_key: String,
    drive_signing_public_key: String,
    drive_key_binding: String,
    pins_key: String,
    revision: u64,
    pins: String,
    nonce: String,
    sealed: String,
    /// Values that must not open: each with the binding and revision tried.
    refused: Vec<Refused>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Refused {
    case: String,
    binding: String,
    revision: u64,
    sealed: String,
}

const BINDING: &str = "3f2a6c1e-8b4d-4e7a-9c5f-1d2e3a4b5c6d";
const OTHER_BINDING: &str = "9e8d7c6b-5a49-4382-a716-05f4e3d2c1b0";
/// The same list as suite 1 sealed it (bound to `alice@kutup.dev`, revision 7):
/// no longer read.
const SUITE_1_SEALED: &str = "S1VUSVAxAAAAAUREREREREREREREREREREREREREREREROUZuOGzIGeJ+2idGGW9o5mztCqfGsWL09FEhMBoOCd+VuGuFcWXQEfc0V1Jt641IDC3je2OLpq3JjHBld+CeSRn0VX20dpk4Y5zBADJDOQUlTqMnal4XnidpixX5i7dWl/IDTWQyY92EBc70OrE7DV6axGTzCXIba5g0Ed7BTCmY3WwmqZTL5NGLnFLZYsfLznsBLlFk5g30uNbU54LL7WJTsqbxR4AB1Y0u9HqOsm62PYtD9W67uk/qRVoDILdzcieXIbgK5zfaHnTNAkZcv3KLIYlZlS7JljpgRAGe13rCJHwW8miT37mu2VMiLghR4XoXLbaH1eVcu7rpnTac4MBqxvXN/S7ezuc3tdJWv5LAbPT2UpZC2cex3NGIG+jbQMJrVUn43JTYjF9iN7bsA6Jr5aRlA2I+Y/akTiq8vNbCKI51+VJtc1ukFtkoFJasFhn+RSFlBkV7AHCG3HaF8c1bRXkI9QjUcaQxfHo6tHU3OehWcVH0+QWOXryok64bcnGI32szt2Ok9+VqY3i0ASW0Q==";

fn refused(sealed: &[u8]) -> Vec<Refused> {
    let case = |case: &str, binding: &str, revision: u64, sealed: &[u8]| Refused {
        case: case.into(),
        binding: binding.into(),
        revision,
        sealed: STANDARD.encode(sealed),
    };
    let mut magic = sealed.to_vec();
    magic[5] = b'1';
    let mut suite = sealed.to_vec();
    suite[9] = 1;
    let mut nonce = sealed.to_vec();
    nonce[10] ^= 1;
    let mut tag = sealed.to_vec();
    *tag.last_mut().unwrap() ^= 1;
    let old = STANDARD.decode(SUITE_1_SEALED).unwrap();
    vec![
        case("another account's key binding", OTHER_BINDING, 7, sealed),
        case(
            "the owner's address instead of its binding",
            "alice@kutup.dev",
            7,
            sealed,
        ),
        case("another revision", BINDING, 8, sealed),
        case("magic changed", BINDING, 7, &magic),
        case("suite changed", BINDING, 7, &suite),
        case("nonce changed", BINDING, 7, &nonce),
        case("ciphertext changed", BINDING, 7, &tag),
        case("suite 1, bound to the address", BINDING, 7, &old),
        case(
            "suite 1, opened with the address",
            "alice@kutup.dev",
            7,
            &old,
        ),
    ]
}

fn pins() -> IdentityPinsV1 {
    let bob = AccountIdentityKeysV1::derive(&[0x22u8; 32]).unwrap();
    let carol = AccountIdentityKeysV1::derive(&[0x33u8; 32]).unwrap();
    let carol_before = AccountIdentityKeysV1::derive(&[0x34u8; 32]).unwrap();
    IdentityPinsV1 {
        pins: vec![
            IdentityPinV1 {
                account: "bob@kutup.dev".into(),
                authority_public_key: STANDARD.encode(bob.authority_public_key()),
                state: PinState::Seen,
                since: "2026-10-10T12:00:00Z".into(),
                replaced: vec![],
            },
            IdentityPinV1 {
                account: "carol@example.org".into(),
                authority_public_key: STANDARD.encode(carol.authority_public_key()),
                state: PinState::Verified,
                since: "2026-10-11T08:30:00.250Z".into(),
                replaced: vec![carol_before.incarnation_id()],
            },
        ],
    }
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_IDENTITY_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let master = [0x11u8; 32];
    let account = "alice@kutup.dev";
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    let binding = drive_key_binding::sign(&identity, account).unwrap();
    let key = identity_pins::derive_key(&master).unwrap();
    let nonce = [0x44u8; 24];
    let sealed = identity_pins::seal_with_nonce(&key, BINDING, 7, &pins(), &nonce).unwrap();
    let vectors = Vectors {
        master_key: STANDARD.encode(master),
        account: account.into(),
        binding: BINDING.into(),
        authority_public_key: STANDARD.encode(identity.authority_public_key()),
        drive_hpke_public_key: STANDARD.encode(identity.drive_hpke_public_key()),
        drive_signing_public_key: STANDARD.encode(identity.drive_signing_public_key()),
        drive_key_binding: STANDARD.encode(binding),
        pins_key: STANDARD.encode(*key),
        revision: 7,
        pins: String::from_utf8(identity_pins::encode(&pins()).unwrap()).unwrap(),
        nonce: STANDARD.encode(nonce),
        refused: refused(&sealed),
        sealed: STANDARD.encode(sealed),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

fn key32(value: &str) -> [u8; 32] {
    STANDARD.decode(value).unwrap().try_into().unwrap()
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let master = key32(&v.master_key);
    let identity = AccountIdentityKeysV1::derive(&master).unwrap();
    assert_eq!(
        STANDARD.encode(identity.authority_public_key()),
        v.authority_public_key
    );
    assert_eq!(
        STANDARD.encode(identity.drive_hpke_public_key()),
        v.drive_hpke_public_key
    );
    assert_eq!(
        STANDARD.encode(identity.drive_signing_public_key()),
        v.drive_signing_public_key
    );
    assert_eq!(
        STANDARD.encode(drive_key_binding::sign(&identity, &v.account).unwrap()),
        v.drive_key_binding
    );
    drive_key_binding::verify(
        &v.account,
        &key32(&v.authority_public_key),
        &key32(&v.drive_hpke_public_key),
        &key32(&v.drive_signing_public_key),
        &STANDARD.decode(&v.drive_key_binding).unwrap(),
    )
    .unwrap();

    let key = identity_pins::derive_key(&master).unwrap();
    assert_eq!(STANDARD.encode(*key), v.pins_key);
    assert_eq!(
        String::from_utf8(identity_pins::encode(&pins()).unwrap()).unwrap(),
        v.pins
    );
    let nonce: [u8; 24] = STANDARD.decode(&v.nonce).unwrap().try_into().unwrap();
    let sealed =
        identity_pins::seal_with_nonce(&key, &v.binding, v.revision, &pins(), &nonce).unwrap();
    assert_eq!(STANDARD.encode(&sealed), v.sealed);
    assert_eq!(
        identity_pins::open(&key, &v.binding, v.revision, &sealed).unwrap(),
        pins()
    );
    let expected = refused(&sealed);
    assert_eq!(v.refused.len(), expected.len());
    for (case, want) in v.refused.iter().zip(&expected) {
        assert_eq!(
            (&case.case, &case.binding, case.revision, &case.sealed),
            (&want.case, &want.binding, want.revision, &want.sealed)
        );
        let bytes = STANDARD.decode(&case.sealed).unwrap();
        assert!(
            identity_pins::open(&key, &case.binding, case.revision, &bytes).is_err(),
            "{} opened",
            case.case
        );
    }
    // The address is not a key binding, so nothing seals to it either.
    assert!(identity_pins::seal_with_nonce(&key, &v.account, v.revision, &pins(), &nonce).is_err());
}
