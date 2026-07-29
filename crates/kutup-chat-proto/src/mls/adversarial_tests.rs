//! Parser and protocol-ceiling tests for untrusted anonymous MLS traffic.

use super::*;
use base64::engine::general_purpose::STANDARD as BASE64;

fn valid_encapsulated_key() -> String {
    let signing_key = p256::ecdsa::SigningKey::from_bytes((&[37u8; 32]).into()).unwrap();
    BASE64.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
}

fn envelope(device_id: u32, ciphertext_bytes: usize) -> AnonymousMlsDeviceEnvelopeV1 {
    AnonymousMlsDeviceEnvelopeV1 {
        device_id,
        encapsulated_key: valid_encapsulated_key(),
        ciphertext: BASE64.encode(vec![0x5a; ciphertext_bytes]),
    }
}

fn valid_submission() -> AnonymousMlsSubmissionV1 {
    AnonymousMlsSubmissionV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        recipient: "recipient@example.test".parse().unwrap(),
        send_id: Uuid::from_u128(1),
        capability: BASE64.encode([0x33; 16]),
        suite: MlsAnonymousDeliverySuiteV1::DhKemP256HkdfSha256Aes128Gcm,
        envelopes: vec![envelope(1, 17)],
    }
}

#[test]
fn anonymous_submission_enforces_exact_envelope_and_byte_ceilings() {
    let mut too_many = valid_submission();
    too_many.envelopes = (1..=MAX_ANONYMOUS_ENVELOPES as u32 + 1)
        .map(|device_id| envelope(device_id, 17))
        .collect();
    assert!(too_many.validate().is_err());

    let mut too_large = valid_submission();
    too_large.envelopes = vec![
        envelope(1, MAX_ANONYMOUS_REQUEST_BYTES / 2),
        envelope(2, MAX_ANONYMOUS_REQUEST_BYTES / 2),
    ];
    assert!(too_large.validate().is_err());

    let mut at_ceiling = valid_submission();
    at_ceiling.envelopes = vec![envelope(1, MAX_ANONYMOUS_REQUEST_BYTES - 65)];
    at_ceiling.validate().unwrap();
}

#[test]
fn anonymous_submission_rejects_reordering_invalid_kem_and_suite_downgrade() {
    let mut reordered = valid_submission();
    reordered.envelopes = vec![envelope(2, 17), envelope(1, 17)];
    assert!(reordered.validate().is_err());

    let mut duplicate = valid_submission();
    duplicate.envelopes = vec![envelope(1, 17), envelope(1, 17)];
    assert!(duplicate.validate().is_err());

    let mut invalid_kem = valid_submission();
    invalid_kem.envelopes[0].encapsulated_key = BASE64.encode([4u8; 65]);
    assert!(invalid_kem.validate().is_err());

    let mut downgraded = serde_json::to_value(valid_submission()).unwrap();
    downgraded["suite"] = serde_json::json!(2);
    assert!(serde_json::from_value::<AnonymousMlsSubmissionV1>(downgraded).is_err());
}

#[test]
fn anonymous_submission_rejects_noncanonical_and_extended_wire_forms() {
    let mut noncanonical_capability = valid_submission();
    noncanonical_capability.capability.pop();
    assert!(noncanonical_capability.validate().is_err());

    let mut extended = serde_json::to_value(valid_submission()).unwrap();
    extended["sender"] = serde_json::json!("mallory@example.test");
    assert!(serde_json::from_value::<AnonymousMlsSubmissionV1>(extended).is_err());
}
