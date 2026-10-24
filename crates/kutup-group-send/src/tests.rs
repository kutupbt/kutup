use super::*;
use crate::zk::{params_bytes, ServerKey};

/// 2026-10-24 10:00 UTC.
const NOW: u64 = 1_793_008_800;
const ADA: Uuid = Uuid::from_u128(0x0b6b5e0c_4c1e_4b8e_9c2d_6a1f3e5d7c9b);
const BEN: Uuid = Uuid::from_u128(0x5f3c2a10_8d4e_4f6a_b1c2_d3e4f5a6b7c8);
const CEM: Uuid = Uuid::from_u128(0x9a8b7c6d_5e4f_4a3b_8c2d_1e0f9a8b7c6d);

fn key(seed: u8) -> ServerKey {
    ServerKey::from_randomness([seed; 32])
}

fn endorse(server: &ServerKey, account: Uuid) -> Endorsement {
    let issued = server.issue(account, NOW);
    receive(&issued.response, account, NOW, &server.public_key()).unwrap()
}

#[test]
fn the_server_issues_libsignals_default_expiration() {
    let issued = key(1).issue(ADA, NOW);
    assert_eq!(issued.expiration % SECONDS_PER_DAY, 0);
    // The end of the next day UTC: 2026-10-26 00:00.
    assert_eq!(issued.expiration, 1_793_145_600);
    assert_eq!(default_expiration(NOW), issued.expiration);
    // Under 25 hours to the end of the next day: the day after.
    let late = 1_793_145_600 - 24 * 60 * 60 + 60;
    assert_eq!(default_expiration(late), 1_793_145_600 + SECONDS_PER_DAY);
}

#[test]
fn a_response_is_taken_only_for_its_account_and_server() {
    let server = key(1);
    let issued = server.issue(ADA, NOW);
    let endorsement = receive(&issued.response, ADA, NOW, &server.public_key()).unwrap();
    assert_eq!(endorsement.expiration, issued.expiration);
    assert_eq!(
        receive(&issued.response, BEN, NOW, &server.public_key()),
        Err(Error::Invalid)
    );
    assert_eq!(
        receive(&issued.response, ADA, NOW, &key(2).public_key()),
        Err(Error::Invalid)
    );
    let mut tampered = issued.response.clone();
    let last = tampered.len() - 9;
    tampered[last] ^= 1;
    assert!(receive(&tampered, ADA, NOW, &server.public_key()).is_err());
    assert_eq!(
        receive(b"junk", ADA, NOW, &server.public_key()),
        Err(Error::Malformed("endorsement response"))
    );
}

#[test]
fn a_response_past_its_time_or_the_cap_is_refused() {
    let server = key(1);
    let issued = server.issue(ADA, NOW);
    // Within two hours of its expiration (libsignal's floor), or past it.
    let late = issued.expiration - 60 * 60;
    assert!(receive(&issued.response, ADA, late, &server.public_key()).is_err());
    assert_eq!(
        receive(
            &issued.response,
            ADA,
            issued.expiration + 1,
            &server.public_key()
        ),
        Err(Error::Expiration)
    );
    // More than three days ahead (a server fingerprinting its users).
    let far = server.issue_for_expiration(ADA, NOW + 4 * SECONDS_PER_DAY);
    assert_eq!(
        receive(&far, ADA, NOW, &server.public_key()),
        Err(Error::Expiration)
    );
}

#[test]
fn expirations_are_day_aligned_future_and_capped() {
    let midnight = 1_793_145_600;
    assert_eq!(check_expiration(midnight, NOW), Ok(()));
    assert_eq!(check_expiration(midnight + 1, NOW), Err(Error::Expiration));
    assert_eq!(check_expiration(midnight, midnight), Err(Error::Expiration));
    let cap = NOW + MAX_ENDORSEMENT_LIFETIME_SECS;
    let last = cap - cap % SECONDS_PER_DAY;
    assert_eq!(check_expiration(last, NOW), Ok(()));
    assert_eq!(
        check_expiration(last + SECONDS_PER_DAY, NOW),
        Err(Error::Expiration)
    );
}

#[test]
fn a_token_verifies_for_exactly_its_recipients() {
    let server = key(1);
    let token = token(&[endorse(&server, ADA), endorse(&server, BEN)]).unwrap();
    assert_eq!(verify_token(&[&server], &token, &[ADA, BEN], NOW), Ok(()));
    // Order doesn't matter.
    assert_eq!(verify_token(&[&server], &token, &[BEN, ADA], NOW), Ok(()));
    // A recipient added or missing.
    assert_eq!(
        verify_token(&[&server], &token, &[ADA, BEN, CEM], NOW),
        Err(Error::Invalid)
    );
    assert_eq!(
        verify_token(&[&server], &token, &[ADA], NOW),
        Err(Error::Invalid)
    );
    // Another server's key.
    assert_eq!(
        verify_token(&[&key(2)], &token, &[ADA, BEN], NOW),
        Err(Error::Invalid)
    );
    assert_eq!(
        verify_token(&[&server], b"junk", &[ADA], NOW),
        Err(Error::Invalid)
    );
}

#[test]
fn a_duplicate_recipient_is_refused_before_the_token_is_checked() {
    let server = key(1);
    let token = token(&[endorse(&server, ADA)]).unwrap();
    assert_eq!(
        verify_token(&[&server], &token, &[ADA, ADA], NOW),
        Err(Error::DuplicateRecipient)
    );
    // Combining one endorsement twice doesn't make it a token for one.
    let twice = token_of(&[endorse(&server, ADA), endorse(&server, ADA)]);
    assert_eq!(
        verify_token(&[&server], &twice, &[ADA], NOW),
        Err(Error::Invalid)
    );
    assert_eq!(
        verify_token(&[&server], &twice, &[], NOW),
        Err(Error::NoRecipients)
    );
}

fn token_of(endorsements: &[Endorsement]) -> Vec<u8> {
    token(endorsements).unwrap()
}

#[test]
fn a_token_verifies_under_the_previous_key_in_its_window() {
    let old = key(1);
    let new = key(2);
    let token = token_of(&[endorse(&old, ADA)]);
    assert_eq!(verify_token(&[&new, &old], &token, &[ADA], NOW), Ok(()));
    // Once the old key has left the window, it isn't offered.
    assert_eq!(
        verify_token(&[&new], &token, &[ADA], NOW),
        Err(Error::Invalid)
    );
}

#[test]
fn a_token_stops_at_its_expiration() {
    let server = key(1);
    let endorsement = endorse(&server, ADA);
    let token = token_of(std::slice::from_ref(&endorsement));
    assert_eq!(
        verify_token(&[&server], &token, &[ADA], endorsement.expiration - 1),
        Ok(())
    );
    assert_eq!(
        verify_token(&[&server], &token, &[ADA], endorsement.expiration),
        Err(Error::Invalid)
    );
}

#[test]
fn only_endorsements_of_one_expiration_combine() {
    let server = key(1);
    let today = endorse(&server, ADA);
    let tomorrow_now = NOW + SECONDS_PER_DAY;
    let issued = server.issue(BEN, tomorrow_now);
    let tomorrow = receive(&issued.response, BEN, tomorrow_now, &server.public_key()).unwrap();
    assert_ne!(today.expiration, tomorrow.expiration);
    assert_eq!(token(&[today, tomorrow]), Err(Error::MixedExpirations));
    assert_eq!(token(&[]), Err(Error::NoRecipients));
}

#[test]
fn an_endorsement_round_trips_as_stored() {
    let endorsement = endorse(&key(1), ADA);
    let bytes = endorsement.to_bytes();
    assert_eq!(Endorsement::from_bytes(&bytes).unwrap(), endorsement);
    assert!(Endorsement::from_bytes(&bytes[..8]).is_err());
    assert!(Endorsement::from_bytes(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn keys_round_trip_as_stored_and_published() {
    let server = key(1);
    let restored = ServerKey::from_bytes(&server.to_bytes()).unwrap();
    assert_eq!(
        restored.public_key().to_bytes(),
        server.public_key().to_bytes()
    );
    let public = EndorsementKey::from_bytes(&server.public_key().to_bytes()).unwrap();
    let issued = server.issue(ADA, NOW);
    assert!(receive(&issued.response, ADA, NOW, &public).is_ok());
    assert!(ServerKey::from_bytes(b"junk").is_err());
    assert!(EndorsementKey::from_bytes(b"junk").is_err());
    // The secret never shows in a debug print.
    assert_eq!(format!("{server:?}"), "ServerKey(..)");
}

fn blob(server: &str) -> EndorsementBlob {
    EndorsementBlob {
        server: server.to_string(),
        key_id: 7,
        response: key(1).issue(ADA, NOW).response,
    }
}

/// A canonical server name of the longest length: four labels, 253 bytes.
fn longest_server() -> String {
    let name = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert_eq!(name.len(), MAX_SERVER_LEN);
    name
}

#[test]
fn a_blob_round_trips_at_one_size() {
    let short = blob("kutup.dev");
    let encoded = short.encode().unwrap();
    assert_eq!(encoded.len(), ENDORSEMENT_BLOB_BYTES);
    assert_eq!(EndorsementBlob::decode(&encoded).unwrap(), short);
    // The longest server name still fits beside a response.
    let longest = blob(&longest_server());
    assert_eq!(
        EndorsementBlob::decode(&longest.encode().unwrap()).unwrap(),
        longest
    );
    assert_eq!(
        ENDORSEMENT_SEALED_BYTES,
        kutup_crypto::chat_group::sealed_len(512)
    );
}

#[test]
fn a_malformed_blob_is_refused() {
    let encoded = blob("kutup.dev").encode().unwrap();
    let malformed = Err(Error::Malformed("endorsement blob"));
    assert_eq!(EndorsementBlob::decode(&encoded[..511]), malformed);
    let mut padded = encoded;
    padded[511] = 1;
    assert_eq!(EndorsementBlob::decode(&padded), malformed);
    let mut version = encoded;
    version[0] = 2;
    assert_eq!(EndorsementBlob::decode(&version), malformed);
    for server in [
        "",
        "Kutup.dev",
        "kutup dev",
        &"a".repeat(MAX_SERVER_LEN + 1),
    ] {
        assert!(blob(server).encode().is_err(), "{server:?}");
    }
    let empty = EndorsementBlob {
        response: Vec::new(),
        ..blob("kutup.dev")
    };
    assert_eq!(EndorsementBlob::decode(&empty.encode().unwrap()), malformed);
}

/// The checked-in vectors (`tests/vectors/group-send-v1.json`): P0, a
/// response issued with fixed randomness, the token for two accounts and the
/// blob carrying the response. Regenerate with `KUTUP_WRITE_VECTORS=1` only
/// for a new version.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Vectors {
    params_label: String,
    params_master_key: String,
    params: String,
    server_randomness: String,
    issue_randomness: String,
    now: u64,
    accounts: Vec<Uuid>,
    public_key: String,
    expiration: u64,
    responses: Vec<String>,
    token: String,
    blob_server: String,
    blob_key_id: u32,
    blob: String,
}

fn vectors() -> Vectors {
    let server = key(0x42);
    let accounts = vec![ADA, BEN];
    let responses: Vec<Vec<u8>> = accounts
        .iter()
        .map(|&account| server.issue_with(account, NOW, [0x24; 32]).response)
        .collect();
    let endorsements: Vec<Endorsement> = accounts
        .iter()
        .zip(&responses)
        .map(|(&account, response)| receive(response, account, NOW, &server.public_key()).unwrap())
        .collect();
    let blob = EndorsementBlob {
        server: "kutup.dev".into(),
        key_id: 1,
        response: responses[0].clone(),
    };
    Vectors {
        params_label: String::from_utf8(PARAMS_LABEL.to_vec()).unwrap(),
        params_master_key: hex::encode(params_master_key()),
        params: hex::encode(params_bytes()),
        server_randomness: hex::encode([0x42; 32]),
        issue_randomness: hex::encode([0x24; 32]),
        now: NOW,
        accounts,
        public_key: hex::encode(server.public_key().to_bytes()),
        expiration: endorsements[0].expiration,
        responses: responses.iter().map(hex::encode).collect(),
        token: hex::encode(token(&endorsements).unwrap()),
        blob_server: blob.server.clone(),
        blob_key_id: blob.key_id,
        blob: hex::encode(blob.encode().unwrap()),
    }
}

#[test]
fn the_vectors_hold() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/group-send-v1.json"
    );
    let computed = vectors();
    if std::env::var_os("KUTUP_WRITE_VECTORS").is_some() {
        let json = serde_json::to_string_pretty(&computed).unwrap();
        std::fs::write(path, json + "\n").unwrap();
    }
    let pinned: Vectors = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(computed, pinned);
    // The pinned token verifies with the pinned key, as a server built from
    // these bytes would.
    let server = key(0x42);
    assert_eq!(
        verify_token(
            &[&server],
            &hex::decode(&pinned.token).unwrap(),
            &pinned.accounts,
            NOW
        ),
        Ok(())
    );
}
