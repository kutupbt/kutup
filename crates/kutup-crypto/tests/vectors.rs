//! Checked-in canonical vectors for Kutup-owned cryptographic formats. The
//! browser WASM bridge and native clients consume this same Rust implementation.

use base64::Engine;
use serde::Deserialize;

use kutup_crypto::{
    account_envelope::{self, AccountEnvelopePurpose},
    asset,
    drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose},
    drive_object::{self, DriveFileBlobContextV1},
    envelope,
    identity::AccountIdentityKeysV1,
    kdf,
    local_state::{self, LocalStatePurpose},
    stream,
};

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("valid base64")
}

#[derive(Deserialize)]
struct CryptoVectors {
    kdf: Vec<KdfVec>,
    #[serde(rename = "recoveryAuth")]
    recovery_auth: RecoveryAuthVec,
    #[serde(rename = "accountIdentity")]
    account_identity: AccountIdentityVec,
    #[serde(rename = "accountEnvelope")]
    account_envelope: AccountEnvelopeVec,
    #[serde(rename = "driveEnvelope")]
    drive_envelope: DriveEnvelopeVec,
    #[serde(rename = "driveFileBlob")]
    drive_file_blob: DriveFileBlobVec,
    stream: Vec<StreamVec>,
    asset: AssetVec,
    thumbnail: ThumbnailVec,
    #[serde(rename = "collectionKeyring")]
    collection_keyring: KeyringVec,
    #[serde(rename = "fileKeyring")]
    file_keyring: FileKeyringVec,
    #[serde(rename = "collabFrame")]
    collab_frame: CollabFrameVec,
    #[serde(rename = "localState")]
    local_state: LocalStateVecs,
}

#[derive(Deserialize)]
struct LocalStateVecs {
    key: String,
    #[serde(rename = "sessionFork")]
    session_fork: LocalStateVec,
    #[serde(rename = "webSession")]
    web_session: LocalStateVec,
}

#[derive(Deserialize)]
struct LocalStateVec {
    profile: String,
    nonce: String,
    plaintext: String,
    envelope: String,
}

#[derive(Deserialize)]
struct KdfVec {
    password: String,
    salt: String,
    #[serde(rename = "expectedRoot")]
    expected_root: String,
    #[serde(rename = "expectedKek")]
    expected_kek: String,
    #[serde(rename = "expectedLoginKey")]
    expected_login_key: String,
}
#[derive(Deserialize)]
struct RecoveryAuthVec {
    entropy: String,
    #[serde(rename = "loginEmail")]
    login_email: String,
    expected: String,
}
#[derive(Deserialize)]
struct AccountIdentityVec {
    #[serde(rename = "masterKey")]
    master_key: String,
    #[serde(rename = "authorityPublicKey")]
    authority_public_key: String,
    #[serde(rename = "authorityKeyId")]
    authority_key_id: String,
    #[serde(rename = "incarnationId")]
    incarnation_id: String,
    #[serde(rename = "driveHpkePublicKey")]
    drive_hpke_public_key: String,
    #[serde(rename = "driveHpkePrivateKey")]
    drive_hpke_private_key: String,
    #[serde(rename = "driveSigningPublicKey")]
    drive_signing_public_key: String,
}
#[derive(Deserialize)]
struct AccountEnvelopeVec {
    plaintext: String,
    key: String,
    purpose: u8,
    #[serde(rename = "loginEmail")]
    login_email: String,
    nonce: String,
    envelope: String,
}
#[derive(Deserialize)]
struct DriveEnvelopeVec {
    plaintext: String,
    #[serde(rename = "rootKey")]
    root_key: String,
    purpose: u8,
    epoch: u32,
    revision: u64,
    #[serde(rename = "objectId")]
    object_id: String,
    #[serde(rename = "parentId")]
    parent_id: String,
    nonce: String,
    envelope: String,
}
#[derive(Deserialize)]
struct DriveFileBlobVec {
    #[serde(rename = "fileKey")]
    file_key: String,
    #[serde(rename = "fileId")]
    file_id: String,
    generation: u32,
    #[serde(rename = "objectHeader")]
    object_header: String,
    #[serde(rename = "derivedStreamKey")]
    derived_stream_key: String,
}
#[derive(Deserialize)]
struct StreamVec {
    key: String,
    plaintext: String,
    ciphertext: String,
}
#[derive(Deserialize)]
struct AssetVec {
    #[serde(rename = "fileKey")]
    file_key: String,
    #[serde(rename = "fileId")]
    file_id: String,
    #[serde(rename = "assetId")]
    asset_id: String,
    generation: u32,
    nonce: String,
    plaintext: String,
    envelope: String,
}
#[derive(Deserialize)]
struct ThumbnailVec {
    #[serde(rename = "fileKey")]
    file_key: String,
    #[serde(rename = "fileId")]
    file_id: String,
    generation: u32,
    variant: String,
    nonce: String,
    format: String,
    width: u16,
    height: u16,
    image: String,
    envelope: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyringVec {
    collection_id: String,
    owner_user_id: String,
    authority_public_key: String,
    keys: Vec<String>,
    chain: Vec<KeyringLinkVec>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyringLinkVec {
    epoch: u32,
    statement: String,
    previous_key_envelope: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileKeyringVec {
    file_id: String,
    keys: Vec<String>,
    chain: Vec<FileKeyLinkVec>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileKeyLinkVec {
    generation: u32,
    previous_key_envelope: String,
}
#[derive(Deserialize)]
struct CollabFrameVec {
    #[serde(rename = "fileKey")]
    file_key: String,
    #[serde(rename = "signingSeed")]
    signing_seed: String,
    #[serde(rename = "signingPublicKey")]
    signing_public_key: String,
    kind: u8,
    #[serde(rename = "keyGeneration")]
    key_generation: u32,
    #[serde(rename = "docKeyId")]
    doc_key_id: u32,
    #[serde(rename = "fileId")]
    file_id: String,
    #[serde(rename = "senderDeviceId")]
    sender_device_id: u64,
    sequence: u64,
    nonce: String,
    plaintext: String,
    frame: String,
}

fn load_crypto() -> CryptoVectors {
    let raw = include_str!("vectors/crypto.json");
    serde_json::from_str(raw).expect("parse crypto.json")
}

#[test]
fn kdf_matches_go() {
    for v in load_crypto().kdf {
        let salt = b64(&v.salt);
        let keys = kdf::derive_account_protection_keys(
            &v.password,
            &salt,
            kdf::AccountProtectionParameters::V1,
        )
        .unwrap();
        assert_eq!(
            keys.key_encryption_key.as_slice(),
            &b64(&v.expected_kek),
            "account KEK mismatch for root {}",
            v.expected_root
        );
        assert_eq!(
            keys.login_key.as_slice(),
            &b64(&v.expected_login_key),
            "account login key mismatch"
        );
        assert_ne!(
            keys.key_encryption_key.as_slice(),
            keys.login_key.as_slice()
        );
    }
}

#[test]
fn recovery_auth_proof_vector() {
    let v = load_crypto().recovery_auth;
    let proof = kdf::derive_recovery_auth_proof(&b64(&v.entropy), &v.login_email).unwrap();
    assert_eq!(proof.as_slice(), &b64(&v.expected));
}

#[test]
fn account_identity_vector() {
    let vector = load_crypto().account_identity;
    let master_key: [u8; 32] = b64(&vector.master_key).try_into().unwrap();
    let identity = AccountIdentityKeysV1::derive(&master_key).unwrap();
    assert_eq!(
        identity.authority_public_key().as_slice(),
        b64(&vector.authority_public_key)
    );
    assert_eq!(identity.authority_key_id(), vector.authority_key_id);
    assert_eq!(identity.incarnation_id(), vector.incarnation_id);
    assert_eq!(
        identity.drive_hpke_public_key().as_slice(),
        b64(&vector.drive_hpke_public_key)
    );
    assert_eq!(
        identity.drive_hpke_private_key().as_slice(),
        b64(&vector.drive_hpke_private_key)
    );
    assert_eq!(
        identity.drive_signing_public_key().as_slice(),
        b64(&vector.drive_signing_public_key)
    );
}

#[test]
fn account_envelope_vector() {
    let vector = load_crypto().account_envelope;
    let purpose = AccountEnvelopePurpose::try_from(vector.purpose).unwrap();
    let envelope = account_envelope::seal_with_nonce(
        &b64(&vector.plaintext),
        &b64(&vector.key),
        purpose,
        &vector.login_email,
        &b64(&vector.nonce),
    )
    .unwrap();
    assert_eq!(envelope, b64(&vector.envelope));
    assert_eq!(
        account_envelope::open(&envelope, &b64(&vector.key), purpose, "alice@example.com",)
            .unwrap(),
        b64(&vector.plaintext)
    );
}

#[test]
fn drive_envelope_vector() {
    let vector = load_crypto().drive_envelope;
    let context = DriveEnvelopeContextV1::new(
        DriveEnvelopePurpose::try_from(vector.purpose).unwrap(),
        vector.epoch,
        vector.revision,
        &vector.object_id,
        &vector.parent_id,
    )
    .unwrap();
    let envelope = drive_envelope::seal_with_nonce(
        &b64(&vector.plaintext),
        &b64(&vector.root_key),
        context,
        &b64(&vector.nonce),
    )
    .unwrap();
    assert_eq!(envelope, b64(&vector.envelope));
    assert_eq!(
        drive_envelope::open(&envelope, &b64(&vector.root_key), context).unwrap(),
        b64(&vector.plaintext)
    );
}

#[test]
fn drive_file_blob_header_and_key_vector() {
    let vector = load_crypto().drive_file_blob;
    let context = DriveFileBlobContextV1::new(&vector.file_id, vector.generation).unwrap();
    assert_eq!(
        drive_object::file_blob_header(context).as_slice(),
        b64(&vector.object_header)
    );
    assert_eq!(
        drive_object::derive_file_blob_key(&b64(&vector.file_key), context)
            .unwrap()
            .as_slice(),
        b64(&vector.derived_stream_key)
    );
    drive_object::validate_file_blob_header(&b64(&vector.object_header), context).unwrap();
}

#[test]
fn stream_decrypts_go_output() {
    for v in load_crypto().stream {
        let dec = stream::decrypt_stream(&b64(&v.ciphertext), &b64(&v.key)).unwrap();
        assert_eq!(dec, b64(&v.plaintext), "stream plaintext mismatch");
    }
}

#[test]
fn whiteboard_asset_matches_canonical_vector() {
    let v = load_crypto().asset;
    let context =
        DriveEnvelopeContextV1::whiteboard_asset(&v.file_id, &v.asset_id, v.generation).unwrap();
    let envelope = drive_envelope::seal_with_nonce(
        &b64(&v.plaintext),
        &b64(&v.file_key),
        context,
        &b64(&v.nonce),
    )
    .unwrap();
    assert_eq!(envelope, b64(&v.envelope));
    let dec = asset::decrypt_asset(
        &envelope,
        &v.file_id,
        &v.asset_id,
        v.generation,
        &b64(&v.file_key),
    )
    .unwrap();
    assert_eq!(dec, b64(&v.plaintext), "asset plaintext mismatch");
}

// --- Rust-only round-trips that complement the Go-cross vectors -------------

#[test]
fn stream_multichunk_roundtrip() {
    // Exercise the 5 MiB chunk boundary (intermediate TAG_MESSAGE + final).
    let key = [0x33u8; 32];
    let plain: Vec<u8> = (0..stream::CHUNK_SIZE + 1)
        .map(|i| (i % 251) as u8)
        .collect();
    let ct = stream::encrypt_stream(&plain, &key).unwrap();
    // header + 2 chunks: (CHUNK_SIZE + 1) plaintext + 2*ABYTES overhead.
    assert_eq!(
        ct.len(),
        stream::HEADER_BYTES + plain.len() + 2 * stream::ABYTES,
        "expected exactly two chunks",
    );
    let dec = stream::decrypt_stream(&ct, &key).unwrap();
    assert_eq!(dec, plain);
}

#[test]
fn stream_tamper_fails() {
    let key = [0x33u8; 32];
    let mut ct = stream::encrypt_stream(b"sensitive content", &key).unwrap();
    let n = ct.len();
    ct[n / 2] ^= 0xff;
    assert!(stream::decrypt_stream(&ct, &key).is_err());
}

#[test]
fn asset_tamper_and_aad_fail() {
    let file_key = [0xCDu8; 32];
    let file_id = "11111111-1111-4111-8111-111111111111";
    let other_file_id = "33333333-3333-4333-8333-333333333333";
    let blob = asset::encrypt_asset(b"payload", file_id, "asset", 1, &file_key).unwrap();
    assert!(asset::decrypt_asset(&blob, file_id, "other", 1, &file_key).is_err());
    assert!(asset::decrypt_asset(&blob, other_file_id, "asset", 1, &file_key).is_err());
    assert!(asset::decrypt_asset(&blob, file_id, "asset", 2, &file_key).is_err());
    // Tampered ciphertext fails.
    let mut bad = blob.clone();
    let n = bad.len();
    bad[n - 1] ^= 0xff;
    assert!(asset::decrypt_asset(&bad, file_id, "asset", 1, &file_key).is_err());
}

// --- envelope -------------------------------------------------------------

#[test]
fn collaboration_frame_matches_canonical_vector() {
    let v = load_crypto().collab_frame;
    let context = envelope::CollabFrameContextV1::new(
        v.kind,
        v.key_generation,
        v.doc_key_id,
        &v.file_id,
        v.sender_device_id,
        v.sequence,
    )
    .unwrap();
    let unsigned = envelope::seal_unsigned_with_nonce(
        &b64(&v.plaintext),
        &b64(&v.file_key),
        context,
        &b64(&v.nonce),
    )
    .unwrap();
    let signed = envelope::sign(
        &envelope::Frame::unpack(&unsigned).unwrap(),
        &b64(&v.signing_seed),
    )
    .unwrap();
    assert_eq!(signed, b64(&v.frame));
    envelope::verify(&signed, &b64(&v.signing_public_key)).unwrap();
    let (parsed, plaintext) =
        envelope::open(&signed, &b64(&v.file_key), &v.file_id, v.key_generation).unwrap();
    assert_eq!(parsed.context(), context);
    assert_eq!(plaintext, b64(&v.plaintext));

    let mut tampered = signed;
    tampered[100] ^= 0x01;
    assert!(envelope::verify(&tampered, &b64(&v.signing_public_key)).is_err());
}

#[test]
fn local_state_fork_and_web_session_match_canonical_vectors() {
    let v = load_crypto().local_state;
    let key = b64(&v.key);
    for (vec, purpose) in [
        (&v.session_fork, LocalStatePurpose::SessionFork),
        (&v.web_session, LocalStatePurpose::WebSession),
    ] {
        let nonce: [u8; 24] = b64(&vec.nonce).try_into().expect("24-byte nonce");
        let sealed =
            local_state::seal_with_nonce(&b64(&vec.plaintext), &key, purpose, &vec.profile, &nonce)
                .unwrap();
        assert_eq!(sealed, b64(&vec.envelope), "{purpose:?} envelope mismatch");
        let opened = local_state::open(&sealed, &key, purpose, &vec.profile).unwrap();
        assert_eq!(opened, b64(&vec.plaintext));
    }
}

#[test]
fn local_state_payloads_are_bound_to_purpose_and_profile() {
    let v = load_crypto().local_state;
    let key = b64(&v.key);
    let fork = b64(&v.session_fork.envelope);
    // A fork payload minted for drive opens neither as chat's nor as a
    // persisted web session.
    assert!(local_state::open(&fork, &key, LocalStatePurpose::SessionFork, "web-chat").is_err());
    assert!(local_state::open(&fork, &key, LocalStatePurpose::WebSession, "web-drive").is_err());
    let mut tampered = fork.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        local_state::open(&tampered, &key, LocalStatePurpose::SessionFork, "web-drive").is_err()
    );
}

#[test]
fn thumbnail_matches_canonical_vector() {
    use kutup_crypto::thumbnail::{self, Thumbnail, ThumbnailFormat, ThumbnailVariant};
    let v = load_crypto().thumbnail;
    let variant = ThumbnailVariant::try_from(v.variant.as_str()).unwrap();
    assert_eq!(v.format, "jpeg");
    let expected = Thumbnail {
        format: ThumbnailFormat::Jpeg,
        width: v.width,
        height: v.height,
        image: b64(&v.image),
    };
    let envelope = thumbnail::seal_with_nonce(
        &expected,
        variant,
        &b64(&v.file_key),
        &v.file_id,
        v.generation,
        &b64(&v.nonce),
    )
    .unwrap();
    assert_eq!(envelope, b64(&v.envelope));
    thumbnail::validate(&envelope, variant, &v.file_id, v.generation).unwrap();
    let opened = thumbnail::open(
        &envelope,
        variant,
        &b64(&v.file_key),
        &v.file_id,
        v.generation,
    )
    .unwrap();
    assert_eq!(opened, expected);
    assert!(thumbnail::open(
        &envelope,
        ThumbnailVariant::Large,
        &b64(&v.file_key),
        &v.file_id,
        v.generation
    )
    .is_err());
}

#[test]
fn collection_keyring_matches_canonical_vector() {
    use kutup_crypto::collection_keyring::{self, EpochLinkV1};
    let v = load_crypto().collection_keyring;
    let chain: Vec<EpochLinkV1> = v
        .chain
        .iter()
        .map(|l| EpochLinkV1 {
            epoch: l.epoch,
            statement: l.statement.clone(),
            previous_key_envelope: l.previous_key_envelope.clone(),
        })
        .collect();
    let current = b64(v.keys.last().unwrap());
    let keys = collection_keyring::unlock(
        &current,
        &v.collection_id,
        &v.owner_user_id,
        &b64(&v.authority_public_key),
        &chain,
    )
    .unwrap();
    assert_eq!(keys.len(), v.keys.len());
    for (got, want) in keys.iter().zip(&v.keys) {
        assert_eq!(got.as_slice(), b64(want).as_slice());
    }
    // An earlier key (a removed member's) does not unlock the history.
    assert!(collection_keyring::unlock(
        &b64(&v.keys[1]),
        &v.collection_id,
        &v.owner_user_id,
        &b64(&v.authority_public_key),
        &chain,
    )
    .is_err());
}

#[test]
fn file_keyring_matches_canonical_vector() {
    use kutup_crypto::file_keyring::{self, FileKeyLinkV1};
    let v = load_crypto().file_keyring;
    let chain: Vec<FileKeyLinkV1> = v
        .chain
        .iter()
        .map(|l| FileKeyLinkV1 {
            generation: l.generation,
            previous_key_envelope: l.previous_key_envelope.clone(),
        })
        .collect();
    let generation = v.keys.len() as u32;
    let current = b64(v.keys.last().unwrap());
    for (index, want) in v.keys.iter().enumerate() {
        let key = file_keyring::key_at(&current, &v.file_id, generation, &chain, index as u32 + 1)
            .unwrap();
        assert_eq!(key.as_slice(), b64(want).as_slice());
    }
    // An earlier key (a removed member's) does not open the newer links.
    assert!(file_keyring::key_at(&b64(&v.keys[1]), &v.file_id, generation, &chain, 1).is_err());
}

/// Prints the vectors that bind Drive file objects to their file and key
/// generation, for `tests/vectors/crypto.json`:
/// `cargo test -p kutup-crypto --test vectors print_file_bound_vectors -- --ignored --nocapture`.
#[test]
#[ignore]
fn print_file_bound_vectors() {
    let e = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let file_id = "11111111-1111-4111-8111-111111111111";

    let file_key = [0x42u8; 32];
    let context = DriveFileBlobContextV1::new(file_id, 7).unwrap();
    let blob = serde_json::json!({
        "fileKey": e(&file_key),
        "fileId": file_id,
        "generation": 7,
        "objectHeader": e(&drive_object::file_blob_header(context)),
        "derivedStreamKey": e(drive_object::derive_file_blob_key(&file_key, context).unwrap().as_slice()),
    });

    let asset_key = [0x41u8; 32];
    let asset_plain = b"data:image/png;base64,iVBORw0KGgo=";
    let asset_nonce = [0x44u8; 24];
    let asset = serde_json::json!({
        "fileKey": e(&asset_key),
        "fileId": file_id,
        "assetId": "asset-abc",
        "generation": 3,
        "nonce": e(&asset_nonce),
        "plaintext": e(asset_plain),
        "envelope": e(&drive_envelope::seal_with_nonce(
            asset_plain,
            &asset_key,
            DriveEnvelopeContextV1::whiteboard_asset(file_id, "asset-abc", 3).unwrap(),
            &asset_nonce,
        ).unwrap()),
    });

    let keys = [[0x71u8; 32], [0x72u8; 32], [0x73u8; 32]];
    let chain: Vec<_> = (2..=3u32)
        .map(|generation| {
            serde_json::json!({
                "generation": generation,
                "previousKeyEnvelope": e(&drive_envelope::seal_with_nonce(
                    &keys[generation as usize - 2],
                    &keys[generation as usize - 1],
                    DriveEnvelopeContextV1::previous_file_key(file_id, generation).unwrap(),
                    &[0x50u8 + generation as u8; 24],
                ).unwrap()),
            })
        })
        .collect();
    let keyring = serde_json::json!({
        "fileId": file_id,
        "keys": keys.iter().map(|k| e(k)).collect::<Vec<_>>(),
        "chain": chain,
    });

    let frame_key = [0x41u8; 32];
    let seed = [0x55u8; 32];
    let plaintext = b"canonical collaboration update";
    let nonce = [0x66u8; 24];
    let context = envelope::CollabFrameContextV1::new(1, 3, 7, file_id, 42, 9).unwrap();
    let unsigned =
        envelope::seal_unsigned_with_nonce(plaintext, &frame_key, context, &nonce).unwrap();
    let signed = envelope::sign(&envelope::Frame::unpack(&unsigned).unwrap(), &seed).unwrap();
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let frame = serde_json::json!({
        "fileKey": e(&frame_key),
        "signingSeed": e(&seed),
        "signingPublicKey": e(&public),
        "kind": 1,
        "keyGeneration": 3,
        "docKeyId": 7,
        "fileId": file_id,
        "senderDeviceId": 42,
        "sequence": 9,
        "nonce": e(&nonce),
        "plaintext": e(plaintext),
        "frame": e(&signed),
    });

    println!(
        "{}",
        serde_json::json!({
            "driveFileBlob": blob,
            "asset": asset,
            "fileKeyring": keyring,
            "collabFrame": frame,
        })
    );
}
