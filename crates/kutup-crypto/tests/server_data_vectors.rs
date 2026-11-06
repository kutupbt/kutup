//! Checked-in vectors for account data keys and the fields they seal
//! (docs/plans/server-personal-data.md, A2), with the values that must be
//! refused. Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_SERVER_DATA_VECTORS=1 cargo test -p kutup-crypto --test server_data_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::server_data::{destruction_subject, inspect_wrapped, DataKey, Field};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/server-data-v1.json"
);

const ENTRY: [u8; 32] = [0x31; 32];
const ENTRY_ID: u16 = 2;
const ACCOUNT: [u8; 16] = [0x41; 16];
const ROW: &str = "41414141-4141-4141-4141-414141414141";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    entry: String,
    entry_id: u16,
    account_id: String,
    wrapped_key: String,
    table: String,
    column: String,
    row: String,
    value: String,
    sealed: String,
    /// The account as the destruction log names it under `entry`.
    destruction_subject: String,
    /// Each must be refused.
    refused: Vec<Refused>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Refused {
    why: String,
    /// `wrap` (unwrapped for `accountId`) or `field` (opened as the field).
    kind: String,
    bytes: String,
}

fn field<'a>(row: &'a str, account: &'a [u8; 16]) -> Field<'a> {
    Field {
        table: "users",
        column: "totp_secret",
        row,
        account_id: account,
    }
}

fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] ^= 1;
    out
}

/// The data key the vectors use: the wrapped key, opened.
fn key_of(wrapped: &[u8]) -> DataKey {
    DataKey::unwrap(wrapped, &ACCOUNT, |id| (id == ENTRY_ID).then_some(&ENTRY)).unwrap()
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_SERVER_DATA_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let key = DataKey::generate(1).unwrap();
    let wrapped = key
        .wrap_with_nonce(&ENTRY, ENTRY_ID, &ACCOUNT, &[0x51; 24])
        .unwrap();
    let value = b"JBSWY3DPEHPK3PXP";
    let sealed = key
        .seal_with_nonce(&field(ROW, &ACCOUNT), value, &[0x61; 24])
        .unwrap();
    let other_row = key
        .seal_with_nonce(
            &field("51515151-5151-4151-8151-515151515151", &ACCOUNT),
            value,
            &[0x61; 24],
        )
        .unwrap();
    let refused = |why: &str, kind: &str, bytes: Vec<u8>| Refused {
        why: why.into(),
        kind: kind.into(),
        bytes: STANDARD.encode(bytes),
    };
    let vectors = Vectors {
        entry: STANDARD.encode(ENTRY),
        entry_id: ENTRY_ID,
        account_id: STANDARD.encode(ACCOUNT),
        wrapped_key: STANDARD.encode(&wrapped),
        table: "users".into(),
        column: "totp_secret".into(),
        row: ROW.into(),
        value: STANDARD.encode(value),
        sealed: STANDARD.encode(&sealed),
        destruction_subject: STANDARD.encode(destruction_subject(&ENTRY, &ACCOUNT).unwrap()),
        refused: vec![
            refused("a flipped magic byte", "wrap", flipped(&wrapped, 0)),
            refused("another entry id named", "wrap", flipped(&wrapped, 9)),
            refused("a flipped generation byte", "wrap", flipped(&wrapped, 13)),
            refused(
                "a flipped tag byte",
                "wrap",
                flipped(&wrapped, wrapped.len() - 1),
            ),
            refused("cut short", "wrap", wrapped[..wrapped.len() - 1].to_vec()),
            refused("an unknown field suite", "field", flipped(&sealed, 1)),
            refused("another generation named", "field", flipped(&sealed, 5)),
            refused(
                "a flipped tag byte",
                "field",
                flipped(&sealed, sealed.len() - 1),
            ),
            refused("sealed for another row", "field", other_row),
        ],
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let wrapped = STANDARD.decode(&v.wrapped_key).unwrap();
    assert_eq!(inspect_wrapped(&wrapped).unwrap(), (v.entry_id, 1));
    let key = key_of(&wrapped);
    // The same key wraps and seals to the same bytes under the same nonces.
    assert_eq!(
        key.wrap_with_nonce(&ENTRY, ENTRY_ID, &ACCOUNT, &[0x51; 24])
            .unwrap(),
        wrapped
    );
    let sealed = STANDARD.decode(&v.sealed).unwrap();
    let value = STANDARD.decode(&v.value).unwrap();
    assert_eq!(
        key.seal_with_nonce(&field(&v.row, &ACCOUNT), &value, &[0x61; 24])
            .unwrap(),
        sealed
    );
    assert_eq!(
        &*key.open(&field(&v.row, &ACCOUNT), &sealed).unwrap(),
        &value[..]
    );
    assert_eq!(
        STANDARD.encode(destruction_subject(&ENTRY, &ACCOUNT).unwrap()),
        v.destruction_subject
    );
    // Another account can't unwrap it, nor open the field.
    assert!(DataKey::unwrap(&wrapped, &[0x42; 16], |_| Some(&ENTRY)).is_err());
    assert!(key.open(&field(&v.row, &[0x42; 16]), &sealed).is_err());
    for refused in &v.refused {
        let bytes = STANDARD.decode(&refused.bytes).unwrap();
        let failed = match refused.kind.as_str() {
            "wrap" => {
                DataKey::unwrap(&bytes, &ACCOUNT, |id| (id == ENTRY_ID).then_some(&ENTRY)).is_err()
            }
            "field" => key.open(&field(&v.row, &ACCOUNT), &bytes).is_err(),
            other => panic!("unknown kind {other}"),
        };
        assert!(failed, "must be refused: {}", refused.why);
    }
}
