use std::sync::Arc;

use ed25519_dalek::SigningKey;
use kutup_federation_proto::{
    FederationCapabilityId, FederationDiscoveryV2, FederationFeature, FederationHttpRequest,
    FederationIdentityDocumentV1, FederationProtocolVersion, FederationReplayMetadata,
    FederationSignedRequest, FederationVerifiedRequest,
};
use sqlx::{postgres::PgPoolOptions, Connection as _, PgConnection};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{
    identity::LocalFederationIdentity, policy, replay, trust, FederationRuntimeConfig,
    FederationStack,
};

const MIGRATION: &str = include_str!("../../migrations/033_unified_federation_foundation.up.sql");

#[tokio::test]
async fn live_identity_trust_policy_and_replay_invariants() {
    let Ok(database_url) = std::env::var("KUTUP_TEST_DB") else {
        return;
    };
    let mut administrator = PgConnection::connect(&database_url).await.unwrap();
    let schema = format!("federation_services_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut administrator)
        .await
        .unwrap();
    sqlx::query(&format!("SET search_path TO {schema}"))
        .execute(&mut administrator)
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE TABLE admin_audit_log (
             id BIGSERIAL PRIMARY KEY,
             admin_user_id UUID NOT NULL,
             action TEXT NOT NULL,
             target_user_id UUID,
             payload JSONB NOT NULL DEFAULT '{}',
             occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
         );",
    )
    .execute(&mut administrator)
    .await
    .unwrap();
    sqlx::raw_sql(MIGRATION)
        .execute(&mut administrator)
        .await
        .unwrap();

    let connection_search_path = format!("SET search_path TO {schema}");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .after_connect(move |connection, _| {
            let sql = connection_search_path.clone();
            Box::pin(async move {
                sqlx::query(&sql).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await
        .unwrap();

    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let local_current = SigningKey::from_bytes(&[1; 32]);
    let local_next = SigningKey::from_bytes(&[2; 32]);
    let local_config = runtime_config("local.example", local_current.clone(), None);
    let genesis = LocalFederationIdentity::load_or_create(&pool, &local_config, now)
        .await
        .unwrap();
    let reloaded = LocalFederationIdentity::load_or_create(&pool, &local_config, now)
        .await
        .unwrap();
    assert_eq!(genesis.document(), reloaded.document());
    assert_eq!(genesis.document().sequence, 0);

    let rotation_config = runtime_config("local.example", local_current, Some(local_next.clone()));
    let rotated =
        super::identity::rotate_local_identity(&pool, &rotation_config, now + Duration::seconds(1))
            .await
            .unwrap();
    assert!(!rotated.already_rotated);
    assert_eq!(rotated.document.sequence, 1);
    let retry =
        super::identity::rotate_local_identity(&pool, &rotation_config, now + Duration::seconds(2))
            .await
            .unwrap();
    assert!(retry.already_rotated);
    assert_eq!(retry.document, rotated.document);
    let active_local_config = runtime_config("local.example", local_next, None);
    let active_local_identity = LocalFederationIdentity::load_or_create(
        &pool,
        &active_local_config,
        now + Duration::seconds(3),
    )
    .await
    .unwrap();
    let federation_stack = FederationStack {
        pool: pool.clone(),
        config: active_local_config,
        local_identity: Arc::new(active_local_identity),
        trust: trust::FederationTrustStore::new(pool.clone()),
        replay: replay::FederationReplayStore::new(pool.clone()),
        policy: policy::FederationPolicyStore::new(pool.clone()),
        transport: Default::default(),
    };
    let local_discovery = federation_stack
        .signed_discovery(
            vec![
                FederationCapabilityId::identity_v1(),
                FederationCapabilityId::chat_v1(),
            ],
            now + Duration::seconds(3),
        )
        .unwrap();
    local_discovery
        .verify_at(
            "local.example",
            (now + Duration::seconds(4)).unix_timestamp(),
        )
        .unwrap();
    assert_eq!(local_discovery.identity.sequence, 1);
    assert_eq!(
        federation_stack
            .identity_document(0)
            .await
            .unwrap()
            .unwrap()
            .sequence,
        0
    );
    assert_eq!(
        federation_stack
            .identity_document(1)
            .await
            .unwrap()
            .unwrap(),
        rotated.document
    );
    assert!(federation_stack
        .identity_document(2)
        .await
        .unwrap()
        .is_none());

    let peer_current = SigningKey::from_bytes(&[11; 32]);
    let peer_next = SigningKey::from_bytes(&[12; 32]);
    let peer_genesis =
        FederationIdentityDocumentV1::genesis("peer.example", now.unix_timestamp(), &peer_current)
            .unwrap();
    let trust_store = trust::FederationTrustStore::new(pool.clone());

    let convergent_key = SigningKey::from_bytes(&[31; 32]);
    let convergent_identity = FederationIdentityDocumentV1::genesis(
        "convergent.example",
        now.unix_timestamp(),
        &convergent_key,
    )
    .unwrap();
    let convergent_discovery = discovery(&convergent_identity, &convergent_key, now);
    let convergent_first = trust_store.clone();
    let convergent_second = trust_store.clone();
    let (first_contact, second_contact) = tokio::join!(
        convergent_first.observe_peer(
            &convergent_discovery,
            std::slice::from_ref(&convergent_identity),
            now,
        ),
        convergent_second.observe_peer(
            &convergent_discovery,
            std::slice::from_ref(&convergent_identity),
            now,
        ),
    );
    let convergent_outcomes = [first_contact.unwrap(), second_contact.unwrap()];
    assert_eq!(
        convergent_outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                trust::FederationPeerObservation::FirstPinned { .. }
            ))
            .count(),
        1
    );
    assert_eq!(
        convergent_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, trust::FederationPeerObservation::Unchanged { .. }))
            .count(),
        1
    );

    let competing_first_key = SigningKey::from_bytes(&[41; 32]);
    let competing_second_key = SigningKey::from_bytes(&[42; 32]);
    let competing_first_identity = FederationIdentityDocumentV1::genesis(
        "competing.example",
        now.unix_timestamp(),
        &competing_first_key,
    )
    .unwrap();
    let competing_second_identity = FederationIdentityDocumentV1::genesis(
        "competing.example",
        now.unix_timestamp(),
        &competing_second_key,
    )
    .unwrap();
    let competing_first_discovery = discovery(&competing_first_identity, &competing_first_key, now);
    let competing_second_discovery =
        discovery(&competing_second_identity, &competing_second_key, now);
    let competing_first_store = trust_store.clone();
    let competing_second_store = trust_store.clone();
    let (first_candidate, second_candidate) = tokio::join!(
        competing_first_store.observe_peer(
            &competing_first_discovery,
            std::slice::from_ref(&competing_first_identity),
            now,
        ),
        competing_second_store.observe_peer(
            &competing_second_discovery,
            std::slice::from_ref(&competing_second_identity),
            now,
        ),
    );
    let competing_outcomes = [first_candidate.unwrap(), second_candidate.unwrap()];
    assert_eq!(
        competing_outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                trust::FederationPeerObservation::FirstPinned { .. }
            ))
            .count(),
        1
    );
    assert_eq!(
        competing_outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                trust::FederationPeerObservation::Quarantined { .. }
            ))
            .count(),
        1
    );
    let competing_state: String = sqlx::query_scalar(
        "SELECT trust_state FROM federation_peer_identities WHERE domain = 'competing.example'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(competing_state, "quarantined");

    let first_discovery = discovery(&peer_genesis, &peer_current, now);
    let first = trust_store
        .observe_peer(&first_discovery, std::slice::from_ref(&peer_genesis), now)
        .await
        .unwrap();
    assert!(matches!(
        first,
        trust::FederationPeerObservation::FirstPinned { sequence: 0, .. }
    ));

    let admin_id = Uuid::new_v4();
    trust_store
        .verify_peer("peer.example", &peer_genesis.key.key_id, admin_id, now)
        .await
        .unwrap();
    let peer_rotated = FederationIdentityDocumentV1::rotate(
        &peer_genesis,
        (now + Duration::seconds(1)).unix_timestamp(),
        &peer_current,
        &peer_next,
    )
    .unwrap();
    let advanced = trust_store
        .observe_peer(
            &discovery(&peer_rotated, &peer_next, now + Duration::seconds(2)),
            &[peer_genesis.clone(), peer_rotated.clone()],
            now + Duration::seconds(2),
        )
        .await
        .unwrap();
    assert!(matches!(
        advanced,
        trust::FederationPeerObservation::Advanced {
            previous_sequence: 0,
            sequence: 1,
            trust: trust::PeerTrustState::Verified,
        }
    ));

    sqlx::query(
        "INSERT INTO federation_domain_rules
         (domain, feature, inbound_action) VALUES ('peer.example', 'chat', 'allow')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let policy_store = policy::FederationPolicyStore::new(pool.clone());
    sqlx::query(
        "INSERT INTO federation_domain_rules
         (domain, feature, inbound_action) VALUES ('undiscovered.example', 'chat', 'allow')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(policy_store
        .check_admission(
            "undiscovered.example",
            policy::FederationPolicyFeature::Chat,
            policy::FederationDirection::Inbound,
        )
        .await
        .unwrap()
        .is_allowed());
    assert!(!policy_store
        .check_admission(
            "undiscovered.example",
            policy::FederationPolicyFeature::Chat,
            policy::FederationDirection::Outbound,
        )
        .await
        .unwrap()
        .is_allowed());
    assert!(!policy_store
        .evaluate(
            "undiscovered.example",
            policy::FederationPolicyFeature::Chat,
            policy::FederationDirection::Inbound,
        )
        .await
        .unwrap()
        .is_allowed());
    assert!(policy_store
        .evaluate(
            "peer.example",
            policy::FederationPolicyFeature::Chat,
            policy::FederationDirection::Inbound,
        )
        .await
        .unwrap()
        .is_allowed());
    assert!(!policy_store
        .evaluate(
            "peer.example",
            policy::FederationPolicyFeature::Drive,
            policy::FederationDirection::Inbound,
        )
        .await
        .unwrap()
        .is_allowed());

    // Bad chain input is rejected before mutation and does not quarantine.
    let mut malformed = peer_rotated.clone();
    malformed.current_signature = "bad".into();
    assert!(trust_store
        .observe_peer(
            &discovery(&peer_rotated, &peer_next, now + Duration::seconds(3)),
            &[peer_genesis.clone(), malformed],
            now + Duration::seconds(3),
        )
        .await
        .is_err());
    let trust_after_bad_input: String = sqlx::query_scalar(
        "SELECT trust_state FROM federation_peer_identities WHERE domain = 'peer.example'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(trust_after_bad_input, "verified");

    // A fully self-consistent alternate history is evidence of replacement,
    // so retain the old key and quarantine globally.
    let replacement_key = SigningKey::from_bytes(&[21; 32]);
    let replacement = FederationIdentityDocumentV1::genesis(
        "peer.example",
        (now + Duration::seconds(4)).unix_timestamp(),
        &replacement_key,
    )
    .unwrap();
    let quarantine = trust_store
        .observe_peer(
            &discovery(&replacement, &replacement_key, now + Duration::seconds(5)),
            std::slice::from_ref(&replacement),
            now + Duration::seconds(5),
        )
        .await
        .unwrap();
    assert!(matches!(
        quarantine,
        trust::FederationPeerObservation::Quarantined {
            retained_sequence: 1,
            candidate_sequence: 0,
            ..
        }
    ));
    assert_eq!(
        policy_store
            .evaluate(
                "peer.example",
                policy::FederationPolicyFeature::Chat,
                policy::FederationDirection::Inbound,
            )
            .await
            .unwrap(),
        policy::FederationAdmissionDecision::Denied {
            reason: policy::FederationAdmissionDenial::QuarantinedIdentity,
        }
    );
    trust_store
        .repin_quarantined_peer(
            "peer.example",
            &peer_rotated.key.key_id,
            &replacement.key.key_id,
            "peer.example",
            admin_id,
            now + Duration::seconds(6),
        )
        .await
        .unwrap();

    let replay_store = replay::FederationReplayStore::new(pool.clone());
    let original_replay = replay_metadata(&replacement_key, "nonce-1", b"original", now);
    assert_eq!(
        replay_store
            .reserve_verified(&original_replay, now)
            .await
            .unwrap(),
        replay::FederationReplayOutcome::FirstSeen
    );
    assert_eq!(
        replay_store
            .reserve_verified(&original_replay, now)
            .await
            .unwrap(),
        replay::FederationReplayOutcome::ExactReplay
    );
    let conflicting_replay = replay_metadata(&replacement_key, "nonce-1", b"changed", now);
    assert_eq!(
        replay_store
            .reserve_verified(&conflicting_replay, now)
            .await
            .unwrap(),
        replay::FederationReplayOutcome::Conflict
    );

    let first_race = replay_store.clone();
    let second_race = replay_store.clone();
    let first_race_metadata = replay_metadata(&replacement_key, "race", b"first", now);
    let second_race_metadata = replay_metadata(&replacement_key, "race", b"second", now);
    let (first_result, second_result) = tokio::join!(
        first_race.reserve_verified(&first_race_metadata, now),
        second_race.reserve_verified(&second_race_metadata, now),
    );
    let outcomes = [first_result.unwrap(), second_result.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == replay::FederationReplayOutcome::FirstSeen)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == replay::FederationReplayOutcome::Conflict)
            .count(),
        1
    );

    let audit_actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM admin_audit_log
         WHERE action LIKE 'federation.identity.%' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for required in [
        "federation.identity.genesis",
        "federation.identity.rotate-local",
        "federation.identity.pin",
        "federation.identity.verify",
        "federation.identity.advance-remote",
        "federation.identity.quarantine",
        "federation.identity.repin",
    ] {
        assert!(audit_actions.iter().any(|action| action == required));
    }

    pool.close().await;
    sqlx::query("SET search_path TO public")
        .execute(&mut administrator)
        .await
        .unwrap();
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut administrator)
        .await
        .unwrap();
}

fn runtime_config(
    server_name: &str,
    signing_key: SigningKey,
    next_signing_key: Option<SigningKey>,
) -> FederationRuntimeConfig {
    FederationRuntimeConfig {
        server_name: server_name.into(),
        api_base: format!("https://{server_name}"),
        signing_key,
        next_signing_key,
        allow_private_test_network: false,
    }
}

fn discovery(
    identity: &FederationIdentityDocumentV1,
    signing_key: &SigningKey,
    now: OffsetDateTime,
) -> FederationDiscoveryV2 {
    FederationDiscoveryV2::sign(
        &identity.server,
        format!("https://{}", identity.server),
        vec![
            FederationCapabilityId::identity_v1(),
            FederationCapabilityId::chat_v1(),
        ],
        identity.clone(),
        now.unix_timestamp(),
        (now + Duration::hours(1)).unix_timestamp(),
        signing_key,
    )
    .unwrap()
}

fn replay_metadata(
    signing_key: &SigningKey,
    request_id: &str,
    body: &[u8],
    now: OffsetDateTime,
) -> FederationReplayMetadata {
    let signed = FederationSignedRequest::sign(
        FederationHttpRequest {
            method: "POST".into(),
            authority: "local.example".into(),
            path: "/api/fed/chat/v1/transactions".into(),
            query: "?".into(),
            content_type: "application/json".into(),
            body: body.to_vec(),
            federation_version: FederationProtocolVersion::V2,
            feature: FederationFeature::ChatV1,
            origin: "peer.example".into(),
            destination: "local.example".into(),
        },
        request_id,
        now.unix_timestamp(),
        (now + Duration::minutes(5)).unix_timestamp(),
        signing_key,
    )
    .unwrap();
    FederationVerifiedRequest::verify(
        signed.request,
        signed.headers,
        &signing_key.verifying_key().to_bytes(),
        now.unix_timestamp(),
    )
    .unwrap()
    .replay_metadata()
    .unwrap()
}
