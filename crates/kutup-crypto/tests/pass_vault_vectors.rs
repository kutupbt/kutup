//! Checked-in vectors for Kutup Pass vault secrets (docs/plans/pass.md,
//! "Vault secrets"). Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_PASS_VAULT_VECTORS=1 cargo test -p kutup-crypto --test pass_vault_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::pass_vault::{
    open_vault_secret, password_hash, seal_vault_secret_with_nonce, VaultSecret,
};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/pass-vault-secret-v2.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    master_key: String,
    binding: String,
    file_id: String,
    nonce: String,
    /// A password the person chose (kept only as its SHA-256) and a key file.
    chosen_password: String,
    chosen_password_hash: String,
    key_file: String,
    sealed_chosen: String,
    /// A password Kutup Pass generated (kept as it is), no key file.
    generated_password: String,
    sealed_generated: String,
}

const KEY_FILE: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"A65F1F33\">6E0A1A8C 6D8F4B2E 9C7A1F52 0B3D4E5F 61728394 A5B6C7D8 E9FA0B1C 2D3E4F50</Data></Key></KeyFile>\n";

struct Fixed {
    master: [u8; 32],
    binding: &'static str,
    file_id: uuid::Uuid,
    nonce: [u8; 24],
}

fn fixed() -> Fixed {
    Fixed {
        master: [0x5a; 32],
        binding: "6f1d2c3b-4a59-4e8f-9a0b-1c2d3e4f5a6b",
        file_id: uuid::Uuid::parse_str("3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70").unwrap(),
        nonce: [0x44; 24],
    }
}

fn seal(f: &Fixed, secret: &VaultSecret) -> Vec<u8> {
    seal_vault_secret_with_nonce(&f.master, f.binding, f.file_id.as_bytes(), secret, &f.nonce)
        .unwrap()
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_PASS_VAULT_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let f = fixed();
    let chosen = "Parola çğış 1";
    let generated = "k7m2-q9xd-4tpa-v3wf-8hcn-r6je";
    let vectors = Vectors {
        master_key: STANDARD.encode(f.master),
        binding: f.binding.into(),
        file_id: f.file_id.to_string(),
        nonce: STANDARD.encode(f.nonce),
        chosen_password: chosen.into(),
        chosen_password_hash: STANDARD.encode(password_hash(chosen).as_slice()),
        key_file: STANDARD.encode(KEY_FILE),
        sealed_chosen: STANDARD.encode(seal(
            &f,
            &VaultSecret::chosen(Some(chosen), Some(KEY_FILE.as_bytes())),
        )),
        generated_password: generated.into(),
        sealed_generated: STANDARD.encode(seal(&f, &VaultSecret::generated(generated, None))),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let f = fixed();
    assert_eq!(STANDARD.decode(&v.master_key).unwrap(), f.master);
    assert_eq!(v.binding, f.binding);
    assert_eq!(v.file_id, f.file_id.to_string());
    assert_eq!(STANDARD.decode(&v.nonce).unwrap(), f.nonce);
    let key_file = STANDARD.decode(&v.key_file).unwrap();
    assert_eq!(
        STANDARD.encode(password_hash(&v.chosen_password).as_slice()),
        v.chosen_password_hash
    );

    for (expected, sealed) in [
        (
            VaultSecret::chosen(Some(&v.chosen_password), Some(&key_file)),
            &v.sealed_chosen,
        ),
        (
            VaultSecret::generated(&v.generated_password, None),
            &v.sealed_generated,
        ),
    ] {
        let resealed = seal(&f, &expected);
        assert_eq!(&STANDARD.encode(&resealed), sealed);
        let opened =
            open_vault_secret(&resealed, &f.master, f.binding, f.file_id.as_bytes()).unwrap();
        assert_eq!(opened, expected);
        // Another vault's id does not open it.
        assert!(open_vault_secret(&resealed, &f.master, f.binding, &[0; 16]).is_err());
        assert_eq!(
            kutup_crypto::account_envelope::inspect(&resealed)
                .unwrap()
                .object_id,
            f.file_id.as_bytes()
        );
    }
}
