//! Checked-in vectors for Kutup Pass vault secrets (docs/plans/pass.md,
//! "Vault secrets"). Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_PASS_VAULT_VECTORS=1 cargo test -p kutup-crypto --test pass_vault_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kutup_crypto::pass_vault::{open_vault_secret, seal_vault_secret_with_nonce, VaultSecretV1};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/pass-vault-secret-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    login_email: String,
    file_id: String,
    password: String,
    key_file: String,
    nonce: String,
    /// Suite 2: the vault's id in the header, a key of its own.
    sealed: String,
    /// The same secret as suite 1 sealed it (still opened, until the account
    /// re-seals).
    #[serde(default)]
    sealed_v1: String,
}

const KEY_FILE: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"A65F1F33\">6E0A1A8C 6D8F4B2E 9C7A1F52 0B3D4E5F 61728394 A5B6C7D8 E9FA0B1C 2D3E4F50</Data></Key></KeyFile>\n";

fn secret(password: &str, key_file: &[u8]) -> VaultSecretV1 {
    VaultSecretV1 {
        password: Some(Zeroizing::new(password.to_owned())),
        key_file: Some(Zeroizing::new(key_file.to_vec())),
    }
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_PASS_VAULT_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let master = [0x5au8; 32];
    let email = "alice@kutup.dev";
    let file_id = uuid::Uuid::parse_str("3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70").unwrap();
    let password = "Parola çğış 1";
    let nonce = [0x44u8; 24];
    let sealed = seal_vault_secret_with_nonce(
        &master,
        email,
        file_id.as_bytes(),
        &secret(password, KEY_FILE.as_bytes()),
        &nonce,
    )
    .unwrap();
    // Suite 1 bytes are kept as they were first written.
    let before: Option<Vectors> = std::fs::read_to_string(PATH)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok());
    let sealed_v1 = before
        .map(|b| {
            if b.sealed_v1.is_empty() {
                b.sealed
            } else {
                b.sealed_v1
            }
        })
        .unwrap_or_default();
    let vectors = Vectors {
        sealed_v1,
        master_key: STANDARD.encode(master),
        login_email: email.into(),
        file_id: file_id.to_string(),
        password: password.into(),
        key_file: STANDARD.encode(KEY_FILE),
        nonce: STANDARD.encode(nonce),
        sealed: STANDARD.encode(sealed),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let master = STANDARD.decode(&v.master_key).unwrap();
    let file_id = uuid::Uuid::parse_str(&v.file_id).unwrap();
    let key_file = STANDARD.decode(&v.key_file).unwrap();
    let nonce = STANDARD.decode(&v.nonce).unwrap();
    let expected = secret(&v.password, &key_file);
    let sealed = seal_vault_secret_with_nonce(
        &master,
        &v.login_email,
        file_id.as_bytes(),
        &expected,
        &nonce,
    )
    .unwrap();
    assert_eq!(STANDARD.encode(&sealed), v.sealed);
    assert_eq!(
        open_vault_secret(&sealed, &master, &v.login_email, file_id.as_bytes()).unwrap(),
        expected
    );
    // Another vault's id does not open it.
    assert!(open_vault_secret(&sealed, &master, &v.login_email, &[0; 16]).is_err());
    assert_eq!(
        kutup_crypto::account_envelope::inspect(&sealed)
            .unwrap()
            .object_id,
        file_id.as_bytes()
    );
    // Suite 1, as kept before the re-seal, still opens.
    let v1 = STANDARD.decode(&v.sealed_v1).unwrap();
    assert_eq!(
        kutup_crypto::account_envelope::inspect(&v1).unwrap().suite,
        kutup_crypto::account_envelope::AccountEnvelopeSuiteId::XChaCha20Poly1305V1
    );
    assert_eq!(
        open_vault_secret(&v1, &master, &v.login_email, file_id.as_bytes()).unwrap(),
        expected
    );
}
