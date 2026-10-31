//! Checked-in vectors for OPAQUE suite 1 (docs/plans/opaque.md): one
//! registration and one sign-in, replayed byte for byte from seeded
//! randomness; the export key, the key it derives for the master key, and the
//! master key envelope; a password change; the sealed server setup; and what
//! must fail. Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_OPAQUE_VECTORS=1 cargo test -p kutup-crypto --test opaque_vectors -- --ignored`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use kutup_crypto::error::CryptoError;
use kutup_crypto::opaque::{self, ServerSecrets};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/opaque-v1.json");

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    suite: u16,
    context: String,
    password: String,
    key_binding: String,
    master_key: String,
    /// The server's setup sealed under `setupKey` (as `OPAQUE_SETUP_KEYS`
    /// holds it) for key id `setupKeyId`, with `setupNonce`.
    setup_key: String,
    setup_key_id: u16,
    setup_nonce: String,
    sealed_setup: String,
    server_public_key: String,
    registration_request: String,
    registration_response: String,
    registration_upload: String,
    stored_record: String,
    login_request: String,
    login_response: String,
    login_finalization: String,
    /// What the client takes away; the server never sees it.
    export_key: String,
    master_key_kek: String,
    /// Sealed under `masterKeyKek` (a random nonce: checked by opening).
    master_key_envelope: String,
    unknown_credential: String,
    new_password: String,
    new_stored_record: String,
    new_master_key_envelope: String,
}

const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "Tr: İstanbul ılık şişli";
const BINDING: &str = "3f2a6c1e-8b4d-4e7a-9c5f-1d2e3a4b5c6d";

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn unb64(value: &str) -> Vec<u8> {
    STANDARD.decode(value).unwrap()
}

/// Every value from the seeds; the envelopes (random nonces) are passed in.
fn derive(master_key_envelope: &str, new_master_key_envelope: &str) -> Vectors {
    let secrets = ServerSecrets::generate_with(&mut rng(1));
    let setup_key = [0x5au8; 32];
    let setup_nonce = [0x3cu8; 24];
    let sealed =
        opaque::seal_server_setup_for_vectors(&secrets, &setup_key, 1, &setup_nonce).unwrap();

    let (client, request) = opaque::client_registration_start_with(&mut rng(2), PASSWORD).unwrap();
    let response = opaque::server_registration_response(&secrets, &request, BINDING).unwrap();
    let registered = client.finish_with(&mut rng(3), &response).unwrap();
    let record = opaque::server_registration_record(&registered.record).unwrap();

    let credential = opaque::credential_identifier(BINDING).unwrap();
    let (client, login_request) = opaque::client_login_start_with(&mut rng(4), PASSWORD).unwrap();
    let server = opaque::server_login_start_with(
        &mut rng(5),
        &secrets,
        Some(&record),
        &login_request,
        &credential,
    )
    .unwrap();
    let signed = client.finish_with(&mut rng(6), &server.response).unwrap();
    opaque::server_login_finish(&server.state, &signed.finalization).unwrap();
    assert_eq!(signed.export_key.bytes(), registered.export_key.bytes());

    let (client, request) =
        opaque::client_registration_start_with(&mut rng(7), NEW_PASSWORD).unwrap();
    let response = opaque::server_registration_response(&secrets, &request, BINDING).unwrap();
    let changed = client.finish_with(&mut rng(8), &response).unwrap();

    Vectors {
        suite: opaque::SUITE,
        context: String::from_utf8(opaque::CONTEXT.to_vec()).unwrap(),
        password: PASSWORD.into(),
        key_binding: BINDING.into(),
        master_key: b64(&[0x11; 32]),
        setup_key: b64(&setup_key),
        setup_key_id: 1,
        setup_nonce: b64(&setup_nonce),
        sealed_setup: b64(&sealed),
        server_public_key: b64(&secrets.public_key()),
        registration_request: b64(&request_of(PASSWORD)),
        registration_response: b64(&opaque::server_registration_response(
            &secrets,
            &request_of(PASSWORD),
            BINDING,
        )
        .unwrap()),
        registration_upload: b64(&registered.record),
        stored_record: b64(&record),
        login_request: b64(&login_request),
        login_response: b64(&server.response),
        login_finalization: b64(&signed.finalization),
        export_key: b64(signed.export_key.bytes()),
        master_key_kek: b64(signed
            .export_key
            .master_key_kek(BINDING)
            .unwrap()
            .as_slice()),
        master_key_envelope: master_key_envelope.into(),
        unknown_credential: b64(&opaque::unknown_credential_identifier(
            &opaque::CanonicalName::parse("nobody").unwrap(),
        )),
        new_password: NEW_PASSWORD.into(),
        new_stored_record: b64(&opaque::server_registration_record(&changed.record).unwrap()),
        new_master_key_envelope: new_master_key_envelope.into(),
    }
}

fn request_of(password: &str) -> Vec<u8> {
    opaque::client_registration_start_with(&mut rng(2), password)
        .unwrap()
        .1
}

fn export_keys() -> (opaque::ExportKey, opaque::ExportKey) {
    let secrets = ServerSecrets::generate_with(&mut rng(1));
    let register = |seed: u8, password: &str| {
        let (client, request) =
            opaque::client_registration_start_with(&mut rng(seed), password).unwrap();
        let response = opaque::server_registration_response(&secrets, &request, BINDING).unwrap();
        client
            .finish_with(&mut rng(seed + 1), &response)
            .unwrap()
            .export_key
    };
    (register(2, PASSWORD), register(7, NEW_PASSWORD))
}

#[test]
#[ignore = "writes the vectors file"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_OPAQUE_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let (old, new) = export_keys();
    let envelope = old
        .seal_master_key(
            &[0x11; 32],
            kutup_crypto::account_envelope::MasterKeyGeneration::FIRST,
            BINDING,
        )
        .unwrap();
    let new_envelope = new
        .seal_master_key(
            &[0x11; 32],
            kutup_crypto::account_envelope::MasterKeyGeneration::FIRST,
            BINDING,
        )
        .unwrap();
    let vectors = derive(&envelope, &new_envelope);
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    // Every message replays byte for byte from the same seeds.
    assert_eq!(
        derive(&v.master_key_envelope, &v.new_master_key_envelope),
        v
    );

    // The sealed setup opens under its key and id only.
    let key: [u8; 32] = unb64(&v.setup_key).try_into().unwrap();
    let sealed = unb64(&v.sealed_setup);
    let secrets = opaque::open_server_setup(&sealed, &key, v.setup_key_id).unwrap();
    assert_eq!(b64(&secrets.public_key()), v.server_public_key);
    assert!(opaque::open_server_setup(&sealed, &[0u8; 32], v.setup_key_id).is_err());
    assert!(opaque::open_server_setup(&sealed, &key, v.setup_key_id + 1).is_err());

    // A sign-in against the stored record gives the vectors' export key: it
    // opens the master key envelope.
    let credential = opaque::credential_identifier(&v.key_binding).unwrap();
    let sign_in = |record: &str, password: &str| {
        let (client, request) = opaque::client_login_start(password)?;
        let server =
            opaque::server_login_start(&secrets, Some(&unb64(record)), &request, &credential)?;
        let signed = client.finish(&server.response)?;
        opaque::server_login_finish(&server.state, &signed.finalization)?;
        Ok::<_, CryptoError>(signed.export_key)
    };
    let export = sign_in(&v.stored_record, &v.password).unwrap();
    assert_eq!(b64(export.bytes()), v.export_key);
    assert_eq!(
        b64(export.master_key_kek(&v.key_binding).unwrap().as_slice()),
        v.master_key_kek
    );
    assert_eq!(
        b64(export
            .open_master_key(&v.master_key_envelope, &v.key_binding)
            .unwrap()
            .as_slice()),
        v.master_key
    );
    // Another key binding derives another key.
    assert!(export
        .open_master_key(
            &v.master_key_envelope,
            "9e8d7c6b-5a49-4382-a716-05f4e3d2c1b0"
        )
        .is_err());

    // A wrong password, and an unknown name, fail at the client's finish.
    assert!(matches!(
        sign_in(&v.stored_record, "wrong"),
        Err(CryptoError::AuthFailed)
    ));
    let (client, request) = opaque::client_login_start(&v.password).unwrap();
    let fake = opaque::server_login_start(&secrets, None, &request, &unb64(&v.unknown_credential))
        .unwrap();
    assert!(matches!(
        client.finish(&fake.response),
        Err(CryptoError::AuthFailed)
    ));
    // A server with other secrets cannot answer for this record.
    let other = ServerSecrets::generate_with(&mut rng(9));
    let (client, request) = opaque::client_login_start(&v.password).unwrap();
    let wrong = opaque::server_login_start(
        &other,
        Some(&unb64(&v.stored_record)),
        &request,
        &credential,
    )
    .unwrap();
    assert!(client.finish(&wrong.response).is_err());

    // A password change: the new record signs in with the new password only,
    // and the old export key does not open the new envelope.
    let new_export = sign_in(&v.new_stored_record, &v.new_password).unwrap();
    assert_eq!(
        b64(new_export
            .open_master_key(&v.new_master_key_envelope, &v.key_binding)
            .unwrap()
            .as_slice()),
        v.master_key
    );
    assert!(sign_in(&v.new_stored_record, &v.password).is_err());
    assert!(export
        .open_master_key(&v.new_master_key_envelope, &v.key_binding)
        .is_err());
}
