//! Checked-in vectors for sealed mail names (docs/plans/mail-filters.md):
//! account records (purpose `MailName`, object kind ‖ id), bound to the
//! account's key binding, with the values that must be refused. Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_MAIL_NAME_VECTORS=1 cargo test -p kutup-crypto --test mail_names_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_record::{self, MasterKeyGeneration};
use kutup_crypto::mail_names::{open_name, seal_name_with_nonce, validate_name, MailNameKind};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mail-names-v3.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    /// The account's key binding, which the name binds.
    binding: String,
    kind: String,
    id: String,
    /// The name's revision, in its header and bound.
    revision: u64,
    name: String,
    nonce: String,
    sealed: String,
    /// Names that must not open, with the binding, kind and id tried.
    refused: Vec<Refused>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Refused {
    case: String,
    binding: String,
    kind: String,
    id: String,
    sealed: String,
}

const ID: &str = "3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70";
const OTHER_ID: &str = "00000000-0000-4000-8000-000000000000";
const BINDING: &str = "3f2a6c1e-8b4d-4e7a-9c5f-1d2e3a4b5c6d";
const OTHER_BINDING: &str = "9e8d7c6b-5a49-4382-a716-05f4e3d2c1b0";
const ADDRESS: &str = "alice@kutup.dev";
/// 2026-10-10T12:00:00Z in unix milliseconds.
const REVISION: u64 = 1_791_633_600_000;

fn refused(sealed: &[u8]) -> Vec<Refused> {
    let case = |case: &str, binding: &str, kind: &str, id: &str, sealed: &[u8]| Refused {
        case: case.into(),
        binding: binding.into(),
        kind: kind.into(),
        id: id.into(),
        sealed: STANDARD.encode(sealed),
    };
    // The record's header ends with revision ‖ nonce ‖ length.
    let header = account_record::inspect(sealed).unwrap();
    let length_at = sealed.len() - header.ciphertext_len as usize - 4;
    let mut revision = sealed.to_vec();
    revision[length_at - 24 - 32 - 1] ^= 1;
    let mut nonce = sealed.to_vec();
    nonce[length_at - 1] ^= 1;
    let mut tag = sealed.to_vec();
    *tag.last_mut().unwrap() ^= 1;
    vec![
        case(
            "another account's key binding",
            OTHER_BINDING,
            "folder",
            ID,
            sealed,
        ),
        case(
            "the account's address instead of its binding",
            ADDRESS,
            "folder",
            ID,
            sealed,
        ),
        case("another kind", BINDING, "label", ID, sealed),
        case("another id", BINDING, "folder", OTHER_ID, sealed),
        case("revision changed", BINDING, "folder", ID, &revision),
        case("nonce changed", BINDING, "folder", ID, &nonce),
        case("ciphertext changed", BINDING, "folder", ID, &tag),
    ]
}

fn id_bytes() -> [u8; 16] {
    uuid_bytes(ID)
}

fn uuid_bytes(id: &str) -> [u8; 16] {
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_MAIL_NAME_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let master = [0x5au8; 32];
    let key = master;
    let nonce = [0x44u8; 24];
    let name = "İş başvuruları";
    let sealed = seal_name_with_nonce(
        &key,
        MasterKeyGeneration::FIRST,
        BINDING,
        MailNameKind::Folder,
        &id_bytes(),
        REVISION,
        name,
        &nonce,
    )
    .unwrap();
    let vectors = Vectors {
        master_key: STANDARD.encode(master),
        binding: BINDING.into(),
        kind: "folder".into(),
        id: ID.into(),
        revision: REVISION,
        name: name.into(),
        nonce: STANDARD.encode(nonce),
        refused: refused(&sealed),
        sealed: STANDARD.encode(sealed),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn vectors_hold() {
    let vectors: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let master: [u8; 32] = STANDARD
        .decode(&vectors.master_key)
        .unwrap()
        .try_into()
        .unwrap();
    let key = master;
    let nonce: [u8; 24] = STANDARD.decode(&vectors.nonce).unwrap().try_into().unwrap();
    let kind = MailNameKind::parse(&vectors.kind).unwrap();
    let sealed = seal_name_with_nonce(
        &key,
        MasterKeyGeneration::FIRST,
        &vectors.binding,
        kind,
        &id_bytes(),
        vectors.revision,
        &vectors.name,
        &nonce,
    )
    .unwrap();
    assert_eq!(STANDARD.encode(&sealed), vectors.sealed);
    assert_eq!(
        validate_name(&sealed, &vectors.binding, kind, &id_bytes()).unwrap(),
        vectors.revision
    );
    assert_eq!(
        open_name(&key, &vectors.binding, kind, &id_bytes(), &sealed).unwrap(),
        (vectors.name.clone(), vectors.revision)
    );
    let expected = refused(&sealed);
    assert_eq!(vectors.refused.len(), expected.len());
    for (case, want) in vectors.refused.iter().zip(&expected) {
        assert_eq!(
            (
                &case.case,
                &case.binding,
                &case.kind,
                &case.id,
                &case.sealed
            ),
            (
                &want.case,
                &want.binding,
                &want.kind,
                &want.id,
                &want.sealed
            )
        );
        assert!(
            open_name(
                &key,
                &case.binding,
                MailNameKind::parse(&case.kind).unwrap(),
                &uuid_bytes(&case.id),
                &STANDARD.decode(&case.sealed).unwrap()
            )
            .is_err(),
            "{} opened",
            case.case
        );
    }
    // The address is not a key binding: nothing seals to it.
    assert!(seal_name_with_nonce(
        &key,
        MasterKeyGeneration::FIRST,
        ADDRESS,
        kind,
        &id_bytes(),
        vectors.revision,
        &vectors.name,
        &nonce
    )
    .is_err());
}
