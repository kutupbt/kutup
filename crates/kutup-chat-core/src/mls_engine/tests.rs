//! Native MLS state-machine, restart, and adversarial integration tests.

use super::*;
use crate::SqliteChatDb;

fn ordering_policy(domain: &str, seed: u8) -> MlsOrderingServicePolicyV1 {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let public_key = signer.verifying_key().to_bytes();
    MlsOrderingServicePolicyV1 {
        policy_version: kutup_chat_proto::MLS_ORDERING_SERVICE_POLICY_VERSION,
        canonical_domain: domain.into(),
        suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
        anonymous_delivery_suite:
            kutup_chat_proto::MlsAnonymousDeliverySuiteV1::DhKemP256HkdfSha256Aes128Gcm,
        control_signing_key_id: hex::encode(Sha256::digest(public_key)),
        control_signing_public_key: BASE64.encode(public_key),
        accepts_group_ordering: true,
        maximum_group_members: 1000,
        maximum_authorities: 64,
        maximum_control_payload_bytes: 1024 * 1024,
        pending_message_requests: kutup_chat_proto::PendingMessageRequestPolicyV1::default(),
        abuse_limits: kutup_chat_proto::MlsAbuseLimitsV1::default(),
    }
}

async fn persist_owner_candidate(
    client: &MlsClient,
    mls_group_id: &[u8],
    candidate: MlsOwnerCandidateV1,
) {
    let (provider, mut metadata) = client.load_provider().await.unwrap();
    metadata
        .owner_candidates
        .entry(BASE64.encode(mls_group_id))
        .or_default()
        .insert(candidate.account.canonical(), candidate);
    let state = snapshot_provider(&provider, &metadata).unwrap();
    client
        .db
        .apply(&Pending {
            mls_state: Some(state),
            ..Pending::default()
        })
        .await
        .unwrap();
}

#[test]
fn exact_suite_is_rfc9420_suite_two() {
    assert_eq!(
        KUTUP_MLS_V1_CIPHERSUITE as u16,
        MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256
    );
    assert_eq!(
        KUTUP_MLS_V1_CIPHERSUITE.signature_algorithm(),
        SignatureScheme::ECDSA_SECP256R1_SHA256
    );
}

#[test]
fn private_roster_actions_cannot_hide_membership_or_owner_changes() {
    let owner_id = "11".repeat(32);
    let previous = vec![
        MlsConversationMemberV1 {
            address: "alice@alpha.example".parse().unwrap(),
            is_admin: true,
            owner_id: Some(owner_id.clone()),
        },
        MlsConversationMemberV1 {
            address: "bobby@beta.example".parse().unwrap(),
            is_admin: false,
            owner_id: None,
        },
    ];
    let mut promoted = previous.clone();
    promoted[1].is_admin = true;
    validate_private_roster_action(&previous, &promoted, MlsControlActionTypeV1::RoutineAdmin)
        .unwrap();

    let mut replaced = promoted.clone();
    replaced[1].address = "carol@beta.example".parse().unwrap();
    assert!(validate_private_roster_action(
        &previous,
        &replaced,
        MlsControlActionTypeV1::RoutineAdmin,
    )
    .is_err());

    let mut transferred_owner = promoted.clone();
    transferred_owner[0].owner_id = None;
    transferred_owner[1].owner_id = Some(owner_id);
    assert!(validate_private_roster_action(
        &previous,
        &transferred_owner,
        MlsControlActionTypeV1::RoutineAdmin,
    )
    .is_err());

    let mut added = previous.clone();
    added.push(MlsConversationMemberV1 {
        address: "carol@gamma.example".parse().unwrap(),
        is_admin: false,
        owner_id: None,
    });
    validate_private_roster_action(&previous, &added, MlsControlActionTypeV1::MembershipChange)
        .unwrap();
    let mut add_and_promote = added;
    add_and_promote[1].is_admin = true;
    assert!(validate_private_roster_action(
        &previous,
        &add_and_promote,
        MlsControlActionTypeV1::MembershipChange,
    )
    .is_err());
}

#[test]
fn group_genesis_owner_and_exact_retry_survive_restart() {
    futures_executor::block_on(async {
        let path = std::env::temp_dir().join(format!(
            "kutup-openmls-genesis-{}.db",
            crate::clock::unix_millis()
        ));
        let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(db.clone());
        client.initialize("alice@example.test#1").await.unwrap();
        let conversation_id = Uuid::from_u128(0x81);
        let group_id = b"group-genesis-id";
        let creator: AccountAddress = "alice@example.test".parse().unwrap();
        let policies = vec![
            ordering_policy("beta.example", 12),
            ordering_policy("alpha.example", 11),
            ordering_policy("gamma.example", 13),
        ];

        let prepared = client
            .prepare_group_genesis(
                conversation_id,
                group_id,
                creator.clone(),
                &policies,
                1_700_000_000,
            )
            .await
            .unwrap();
        assert_eq!(prepared.group.epoch, 0);
        assert_eq!(
            prepared.conversation.status,
            LocalMlsConversationStatus::PendingGenesis
        );
        prepared.conversation.request.validate().unwrap();
        assert_eq!(
            prepared
                .conversation
                .request
                .genesis
                .authority_set
                .required_quorum,
            3
        );
        assert_eq!(
            prepared
                .conversation
                .request
                .genesis
                .authority_set
                .authorities
                .iter()
                .map(|authority| authority.domain.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha.example", "beta.example", "gamma.example"]
        );
        let owner = client.group_owner_credential(group_id).await.unwrap();
        let declared = &prepared
            .conversation
            .request
            .genesis
            .owner_set
            .as_ref()
            .unwrap()
            .owners[0];
        assert_eq!(declared.owner_id, owner.owner_id);
        assert_eq!(declared.public_key, BASE64.encode(&owner.public_key));

        drop(client);
        drop(db);
        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(reopened.clone());
        client.initialize("alice@example.test#1").await.unwrap();
        let retry = client
            .prepare_group_genesis(conversation_id, group_id, creator, &policies, 1_700_000_000)
            .await
            .unwrap();
        assert_eq!(retry, prepared);
        assert_eq!(
            client.group_owner_credential(group_id).await.unwrap(),
            owner
        );

        assert!(client
            .mark_group_genesis_published(conversation_id, &"00".repeat(32))
            .await
            .is_err());
        assert_eq!(
            client.local_conversations().await.unwrap()[0].status,
            LocalMlsConversationStatus::PendingGenesis
        );
        let hash = prepared
            .conversation
            .request
            .genesis
            .genesis_hash()
            .unwrap();
        let active = client
            .mark_group_genesis_published(conversation_id, &hash)
            .await
            .unwrap();
        assert_eq!(active.status, LocalMlsConversationStatus::Active);
        assert_eq!(active.server_genesis_hash.as_deref(), Some(hash.as_str()));
        assert_eq!(
            client
                .mark_group_genesis_published(conversation_id, &hash)
                .await
                .unwrap(),
            active
        );

        drop(client);
        drop(reopened);
        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(reopened.clone());
        client.initialize("alice@example.test#1").await.unwrap();
        assert_eq!(client.local_conversations().await.unwrap(), vec![active]);
        drop(client);
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    });
}

#[test]
fn owner_recovery_survives_restart_and_archives_the_previous_incarnation() {
    futures_executor::block_on(async {
        let path = std::env::temp_dir().join(format!(
            "kutup-openmls-recovery-{}.db",
            crate::clock::unix_millis()
        ));
        let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(db.clone());
        client.initialize("alice@example.test#1").await.unwrap();
        let conversation_id = Uuid::from_u128(0x831);
        let group_id = b"recovery-group-01";
        let new_group_id = b"recovery-group-02";
        let policy = ordering_policy("alpha.example", 41);
        let prepared = client
            .prepare_group_genesis(
                conversation_id,
                group_id,
                "alice@example.test".parse().unwrap(),
                std::slice::from_ref(&policy),
                1_700_002_000,
            )
            .await
            .unwrap();
        let genesis_hash = prepared
            .conversation
            .request
            .genesis
            .genesis_hash()
            .unwrap();
        client
            .mark_group_genesis_published(conversation_id, &genesis_hash)
            .await
            .unwrap();
        let recovery = client
            .prepare_group_recovery(
                group_id,
                new_group_id,
                Uuid::from_u128(0x832),
                &[policy],
                &[],
                1_700_002_001,
            )
            .await
            .unwrap();
        assert_eq!(recovery.pending.epoch_before, 0);
        assert_eq!(recovery.pending.epoch_after, 1);
        assert!(recovery.pending.welcome.is_none());
        assert_eq!(
            recovery.control.request.recovery.plan.previous_genesis_hash,
            genesis_hash
        );
        assert_eq!(
            recovery
                .control
                .request
                .recovery
                .plan
                .new_genesis
                .incarnation,
            2
        );
        assert!(client.recovery_has_owner_quorum(group_id).await.unwrap());

        drop(client);
        drop(db);
        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(reopened.clone());
        client.initialize("alice@example.test#1").await.unwrap();
        assert_eq!(
            client.pending_recoveries().await.unwrap(),
            vec![recovery.control.clone()]
        );
        let recovery_digest = recovery
            .control
            .request
            .recovery
            .plan
            .transition_digest()
            .unwrap();
        assert!(client
            .finalize_group_recovery(
                group_id,
                &RecoverMlsConversationResponseV1 {
                    conversation_id,
                    previous_incarnation: 1,
                    incarnation: 2,
                    recovery_digest: "00".repeat(32),
                    status: "active".into(),
                },
            )
            .await
            .is_err());
        let finalized = client
            .finalize_group_recovery(
                group_id,
                &RecoverMlsConversationResponseV1 {
                    conversation_id,
                    previous_incarnation: 1,
                    incarnation: 2,
                    recovery_digest,
                    status: "active".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(finalized.group.mls_group_id, new_group_id);
        assert_eq!(finalized.group.epoch, 1);
        assert_eq!(finalized.conversation.request.genesis.incarnation, 2);
        assert_eq!(
            finalized.archived_incarnation.status,
            LocalMlsConversationStatus::ReadOnly
        );
        assert!(client.pending_recoveries().await.unwrap().is_empty());
        assert_eq!(
            client.local_incarnation_history().await.unwrap(),
            vec![finalized.archived_incarnation.clone()]
        );
        assert!(client
            .create_text_application_message(
                &Uuid::from_u128(0x833).to_string(),
                conversation_id,
                1,
                group_id,
                "1700002002",
                "must not use old incarnation",
                1_700_002_002_000,
            )
            .await
            .is_err());

        drop(client);
        drop(reopened);
        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(reopened.clone());
        client.initialize("alice@example.test#1").await.unwrap();
        assert_eq!(client.local_conversations().await.unwrap().len(), 1);
        assert_eq!(
            client.local_conversations().await.unwrap()[0]
                .request
                .genesis
                .incarnation,
            2
        );
        assert_eq!(client.local_incarnation_history().await.unwrap().len(), 1);
        drop(client);
        drop(reopened);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    });
}

#[test]
fn recipient_verifies_and_joins_owner_signed_recovery_welcome() {
    futures_executor::block_on(async {
        let alice_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let bob_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let alice = MlsClient::new(alice_db);
        let bob = MlsClient::new(bob_db);
        let alice_public = alice.initialize("alice@alpha.example#1").await.unwrap();
        let bob_public = bob.initialize("bobby@beta.example#1").await.unwrap();
        let now = crate::clock::unix_millis() / 1000;
        let conversation_id = Uuid::from_u128(0x841);
        let group_id = b"recovery-live-01";
        let new_group_id = b"recovery-live-02";
        let policy = ordering_policy("authority.example", 51);
        let bob_package = bob
            .generate_key_package(1, 1, now, now + 86_400)
            .await
            .unwrap();
        let verified_bob = VerifiedMlsKeyPackage {
            wire: bob_package,
            credential: VerifiedMlsCredential::new(
                "bobby@beta.example#1".into(),
                bob_public.credential_public_key.clone(),
            )
            .unwrap(),
            anonymous_delivery_public_key: bob_public.anonymous_delivery_public_key.clone(),
        };
        let genesis = alice
            .prepare_group_genesis(
                conversation_id,
                group_id,
                "alice@alpha.example".parse().unwrap(),
                std::slice::from_ref(&policy),
                now,
            )
            .await
            .unwrap();
        let genesis_hash = genesis.conversation.request.genesis.genesis_hash().unwrap();
        let active = alice
            .mark_group_genesis_published(conversation_id, &genesis_hash)
            .await
            .unwrap();
        let next_roster = vec![
            active.current_roster[0].clone(),
            MlsConversationMemberV1 {
                address: "bobby@beta.example".parse().unwrap(),
                is_admin: false,
                owner_id: None,
            },
        ];
        let prepared = alice
            .prepare_membership_change(
                group_id,
                Uuid::from_u128(0x842),
                &next_roster,
                std::slice::from_ref(&verified_bob),
                now + 1,
            )
            .await
            .unwrap();
        let block = &prepared.control.vote_request.block;
        let block_hash = block.block_hash().unwrap();
        let authority_key = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let authority = &prepared.control.vote_request.authority_set.authorities[0];
        let mut vote = kutup_chat_proto::MlsOrderingVoteV1 {
            conversation_id,
            incarnation: 1,
            authority_set_sequence: 1,
            height: 1,
            round: 0,
            vote_type: kutup_chat_proto::MlsOrderingVoteTypeV1::Precommit,
            block_hash: block_hash.clone(),
            authority_domain: authority.domain.clone(),
            authority_key_id: authority.key_id.clone(),
            signature: String::new(),
        };
        vote.signature = BASE64.encode(
            authority_key
                .sign(&vote.signing_bytes().unwrap())
                .to_bytes(),
        );
        let ordered = alice
            .build_membership_commit_request(
                group_id,
                MlsOrderingQuorumCertificateV1 {
                    authority_set_sequence: 1,
                    height: 1,
                    round: 0,
                    block_hash: block_hash.clone(),
                    votes: vec![vote],
                },
            )
            .await
            .unwrap();
        let welcome = prepared
            .control
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "beta.example")
            .unwrap()
            .envelopes[0]
            .opaque_message
            .as_str();
        let welcome = BASE64.decode(welcome).unwrap();
        let expected = vec![
            VerifiedMlsCredential::new(
                "alice@alpha.example#1".into(),
                alice_public.credential_public_key.clone(),
            )
            .unwrap(),
            verified_bob.credential.clone(),
        ];
        let history = MlsClientControlHistoryPageV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            genesis: genesis.conversation.request.genesis,
            genesis_participant_domains: vec!["alpha.example".into()],
            after_height: "0".into(),
            commits: vec![ordered.clone()],
            next_height: Some("1".into()),
        }
        .canonical_bytes()
        .unwrap();
        bob.join_from_welcome_with_control_history(
            &MlsControlEnvelopeContext {
                envelope_id: Uuid::from_u128(0x843),
                cursor: "1".into(),
                send_id: Uuid::from_u128(0x844),
            },
            group_id,
            &welcome,
            &expected,
            &[history],
        )
        .await
        .unwrap();
        alice
            .finalize_membership_change(
                group_id,
                &CommitMlsControlBlockResponseV1 {
                    conversation_id,
                    incarnation: 1,
                    height: 1,
                    epoch: 1,
                    block_hash,
                    idempotent: false,
                },
            )
            .await
            .unwrap();

        let fresh_bob_package = bob
            .generate_key_package(1, 1, now + 2, now + 86_400)
            .await
            .unwrap();
        let fresh_verified_bob = VerifiedMlsKeyPackage {
            wire: fresh_bob_package,
            credential: expected[1].clone(),
            anonymous_delivery_public_key: bob_public.anonymous_delivery_public_key,
        };
        let recovery = alice
            .prepare_group_recovery(
                group_id,
                new_group_id,
                Uuid::from_u128(0x845),
                std::slice::from_ref(&policy),
                std::slice::from_ref(&fresh_verified_bob),
                now + 3,
            )
            .await
            .unwrap();
        let recovery_welcome = recovery
            .control
            .request
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "beta.example")
            .unwrap()
            .envelopes[0]
            .opaque_message
            .as_str();
        let recovery_welcome = BASE64.decode(recovery_welcome).unwrap();
        let recovery_envelope = MlsControlEnvelopeContext {
            envelope_id: Uuid::from_u128(0x846),
            cursor: "2".into(),
            send_id: Uuid::from_u128(0x847),
        };
        let mut forged = recovery.control.request.recovery.clone();
        forged.plan.previous_genesis_hash = "00".repeat(32);
        assert!(bob
            .join_from_recovery_welcome(
                &recovery_envelope,
                new_group_id,
                &recovery_welcome,
                &expected,
                &forged,
            )
            .await
            .is_err());
        assert!(bob.group_state(new_group_id).await.unwrap().is_none());

        let joined = bob
            .join_from_recovery_welcome(
                &recovery_envelope,
                new_group_id,
                &recovery_welcome,
                &expected,
                &recovery.control.request.recovery,
            )
            .await
            .unwrap();
        assert_eq!(joined.group.epoch, 1);
        assert_eq!(joined.conversation.request.genesis.incarnation, 2);
        assert_eq!(joined.conversation.current_roster, next_roster);
        assert_eq!(bob.local_incarnation_history().await.unwrap().len(), 1);
        assert_eq!(
            bob.processed_control_envelope(recovery_envelope.envelope_id)
                .await
                .unwrap()
                .unwrap()
                .send_id,
            recovery_envelope.send_id
        );
        assert_eq!(
            bob.join_from_recovery_welcome(
                &recovery_envelope,
                new_group_id,
                &recovery_welcome,
                &expected,
                &recovery.control.request.recovery,
            )
            .await
            .unwrap(),
            joined
        );

        let recovery_digest = recovery
            .control
            .request
            .recovery
            .plan
            .transition_digest()
            .unwrap();
        alice
            .finalize_group_recovery(
                group_id,
                &RecoverMlsConversationResponseV1 {
                    conversation_id,
                    previous_incarnation: 1,
                    incarnation: 2,
                    recovery_digest,
                    status: "active".into(),
                },
            )
            .await
            .unwrap();
        let outbound = alice
            .create_application_message(
                "16811fc6-27b8-4f32-81c4-c3888ca60f5f",
                *conversation_id.as_bytes(),
                2,
                new_group_id,
                b"after recovery",
                (now + 4) * 1000,
            )
            .await
            .unwrap();
        let decrypted = bob
            .decrypt_application_message(new_group_id, &outbound.ciphertext, &expected[0])
            .await
            .unwrap();
        assert_eq!(decrypted.plaintext, b"after recovery");
        assert_eq!(decrypted.epoch, 1);
    });
}

#[test]
fn authority_change_survives_restart_and_requires_both_exact_quorums() {
    futures_executor::block_on(async {
        fn certificate(
            request: &FederatedMlsOrderingVoteRequestV1,
            seeds: &[(&str, u8)],
        ) -> MlsOrderingQuorumCertificateV1 {
            let block_hash = request.block.block_hash().unwrap();
            let votes = request
                .authority_set
                .authorities
                .iter()
                .map(|authority| {
                    let seed = seeds
                        .iter()
                        .find(|(domain, _)| *domain == authority.domain)
                        .unwrap()
                        .1;
                    let signer = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
                    let mut vote = kutup_chat_proto::MlsOrderingVoteV1 {
                        conversation_id: request.block.conversation_id,
                        incarnation: request.block.incarnation,
                        authority_set_sequence: request.authority_set.sequence,
                        height: request.block.height,
                        round: 0,
                        vote_type: kutup_chat_proto::MlsOrderingVoteTypeV1::Precommit,
                        block_hash: block_hash.clone(),
                        authority_domain: authority.domain.clone(),
                        authority_key_id: authority.key_id.clone(),
                        signature: String::new(),
                    };
                    vote.signature =
                        BASE64.encode(signer.sign(&vote.signing_bytes().unwrap()).to_bytes());
                    vote
                })
                .collect();
            MlsOrderingQuorumCertificateV1 {
                authority_set_sequence: request.authority_set.sequence,
                height: request.block.height,
                round: 0,
                block_hash,
                votes,
            }
        }

        let path = std::env::temp_dir().join(format!(
            "kutup-openmls-authority-control-{}.db",
            crate::clock::unix_millis()
        ));
        let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(db.clone());
        client.initialize("alice@alpha.example#1").await.unwrap();
        let now = crate::clock::unix_millis() / 1000;
        let conversation_id = Uuid::from_u128(0x91);
        let proposal_id = Uuid::from_u128(0x92);
        let group_id = b"authority-ctrl!!";
        let policies = vec![
            ordering_policy("alpha.example", 11),
            ordering_policy("beta.example", 12),
        ];
        let genesis = client
            .prepare_group_genesis(
                conversation_id,
                group_id,
                "alice@alpha.example".parse().unwrap(),
                &policies,
                now,
            )
            .await
            .unwrap();
        let genesis_hash = genesis.conversation.request.genesis.genesis_hash().unwrap();
        client
            .mark_group_genesis_published(conversation_id, &genesis_hash)
            .await
            .unwrap();
        let prepared = client
            .prepare_authority_change_from_policies(
                group_id,
                proposal_id,
                std::slice::from_ref(&policies[0]),
                now + 1,
            )
            .await
            .unwrap();
        assert_eq!(prepared.pending.epoch_before, 0);
        assert_eq!(prepared.pending.epoch_after, 1);
        assert_eq!(prepared.control.deliveries.len(), 1);
        assert!(prepared.control.vote_request.block.owner_approval.is_some());
        assert_eq!(
            prepared
                .control
                .authority_change
                .next_authority_set
                .sequence,
            2
        );
        assert_eq!(
            prepared
                .control
                .authority_change
                .delivery_transition
                .previous_roster_commitment,
            prepared
                .control
                .authority_change
                .delivery_transition
                .next_roster_commitment
        );

        drop(client);
        drop(db);
        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(reopened.clone());
        client.initialize("alice@alpha.example#1").await.unwrap();
        assert_eq!(
            client.pending_authority_changes().await.unwrap(),
            vec![prepared.control.clone()]
        );

        let previous = certificate(
            &prepared.control.vote_request,
            &[("alpha.example", 11), ("beta.example", 12)],
        );
        let next_request = client
            .record_authority_previous_quorum(group_id, previous)
            .await
            .unwrap();
        assert_eq!(
            next_request.authority_set,
            prepared.control.authority_change.next_authority_set
        );
        assert!(next_request.previous_set_certificate.is_some());
        let wrong_new = certificate(
            &prepared.control.vote_request,
            &[("alpha.example", 11), ("beta.example", 12)],
        );
        assert!(client
            .build_authority_commit_request(group_id, wrong_new)
            .await
            .is_err());
        let next = certificate(&next_request, &[("alpha.example", 11)]);
        let request = client
            .build_authority_commit_request(group_id, next)
            .await
            .unwrap();
        request.validate_shape().unwrap();
        let acknowledgement = CommitMlsControlBlockResponseV1 {
            conversation_id,
            incarnation: 1,
            height: 1,
            epoch: 1,
            block_hash: request.finalized.block.block_hash().unwrap(),
            idempotent: false,
        };
        let finalized = client
            .finalize_authority_change(group_id, &acknowledgement)
            .await
            .unwrap();
        assert_eq!(finalized.group.epoch, 1);
        assert_eq!(finalized.conversation.current_authority_set.sequence, 2);
        assert_eq!(
            finalized.conversation.current_authority_set.authorities[0].domain,
            "alpha.example"
        );
        assert!(client.pending_authority_changes().await.unwrap().is_empty());
        assert!(client.pending_commit(group_id).await.unwrap().is_none());
        drop(client);
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    });
}

#[test]
fn atomic_membership_control_survives_restart_and_requires_exact_quorum_ack() {
    futures_executor::block_on(async {
        let path = std::env::temp_dir().join(format!(
            "kutup-openmls-membership-control-{}.db",
            crate::clock::unix_millis()
        ));
        let alice_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let bob_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let charlie_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let alice = MlsClient::new(alice_db.clone());
        let bob = MlsClient::new(bob_db.clone());
        let charlie = MlsClient::new(charlie_db);
        let alice_public = alice.initialize("alice@alpha.example#1").await.unwrap();
        let bob_public = bob.initialize("bobby@beta.example#1").await.unwrap();
        let charlie_public = charlie.initialize("carol@gamma.example#1").await.unwrap();
        let now = crate::clock::unix_millis() / 1000;
        let bob_package = bob
            .generate_key_package(1, 1, now, now + 86_400)
            .await
            .unwrap();
        let charlie_package = charlie
            .generate_key_package(1, 1, now, now + 86_400)
            .await
            .unwrap();
        let verified_bob = VerifiedMlsKeyPackage {
            wire: bob_package,
            credential: VerifiedMlsCredential::new(
                "bobby@beta.example#1".into(),
                bob_public.credential_public_key.clone(),
            )
            .unwrap(),
            anonymous_delivery_public_key: bob_public.anonymous_delivery_public_key,
        };
        let verified_charlie = VerifiedMlsKeyPackage {
            wire: charlie_package,
            credential: VerifiedMlsCredential::new(
                "carol@gamma.example#1".into(),
                charlie_public.credential_public_key.clone(),
            )
            .unwrap(),
            anonymous_delivery_public_key: charlie_public.anonymous_delivery_public_key,
        };
        let conversation_id = Uuid::from_u128(0xa1);
        let proposal_id = Uuid::from_u128(0xa2);
        let group_id = b"membership-ctrl!";
        let policy = ordering_policy("authority.example", 31);
        let genesis = alice
            .prepare_group_genesis(
                conversation_id,
                group_id,
                "alice@alpha.example".parse().unwrap(),
                std::slice::from_ref(&policy),
                now,
            )
            .await
            .unwrap();
        let genesis_hash = genesis.conversation.request.genesis.genesis_hash().unwrap();
        let active = alice
            .mark_group_genesis_published(conversation_id, &genesis_hash)
            .await
            .unwrap();
        let next_roster = vec![
            active.current_roster[0].clone(),
            MlsConversationMemberV1 {
                address: "bobby@beta.example".parse().unwrap(),
                is_admin: false,
                owner_id: None,
            },
            MlsConversationMemberV1 {
                address: "carol@gamma.example".parse().unwrap(),
                is_admin: false,
                owner_id: None,
            },
        ];
        let additions = vec![verified_bob, verified_charlie];
        let mut owner_transfer = next_roster.clone();
        let owner_id = owner_transfer[0].owner_id.take().unwrap();
        owner_transfer[1].is_admin = true;
        owner_transfer[1].owner_id = Some(owner_id);
        assert!(alice
            .prepare_membership_change(
                group_id,
                Uuid::from_u128(0xa0),
                &owner_transfer,
                &additions,
                now + 1,
            )
            .await
            .is_err());
        assert!(alice.pending_membership_changes().await.unwrap().is_empty());
        assert!(alice.pending_commit(group_id).await.unwrap().is_none());
        let prepared = alice
            .prepare_membership_change(group_id, proposal_id, &next_roster, &additions, now + 1)
            .await
            .unwrap();
        assert_eq!(prepared.pending.epoch_before, 0);
        assert_eq!(prepared.pending.epoch_after, 1);
        assert_eq!(prepared.control.deliveries.len(), 3);
        assert_eq!(
            prepared
                .control
                .deliveries
                .iter()
                .map(|delivery| delivery.destination.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha.example", "beta.example", "gamma.example"]
        );
        assert!(prepared.control.deliveries[0].envelopes.is_empty());
        assert_eq!(
            prepared.control.deliveries[1].envelopes[0].kind,
            MlsMembershipEnvelopeKindV1::Welcome
        );
        assert_eq!(
            prepared.control.deliveries[2].envelopes[0].kind,
            MlsMembershipEnvelopeKindV1::Welcome
        );

        drop(alice);
        drop(alice_db);
        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let alice = MlsClient::new(reopened.clone());
        alice.initialize("alice@alpha.example#1").await.unwrap();
        assert_eq!(
            alice.pending_membership_changes().await.unwrap(),
            vec![prepared.control.clone()]
        );
        assert_eq!(
            alice
                .prepare_membership_change(group_id, proposal_id, &next_roster, &[], now + 2,)
                .await
                .unwrap(),
            prepared
        );

        let block = &prepared.control.vote_request.block;
        let block_hash = block.block_hash().unwrap();
        let authority_key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let authority = &prepared.control.vote_request.authority_set.authorities[0];
        let mut vote = kutup_chat_proto::MlsOrderingVoteV1 {
            conversation_id,
            incarnation: 1,
            authority_set_sequence: 1,
            height: 1,
            round: 0,
            vote_type: kutup_chat_proto::MlsOrderingVoteTypeV1::Precommit,
            block_hash: block_hash.clone(),
            authority_domain: authority.domain.clone(),
            authority_key_id: authority.key_id.clone(),
            signature: String::new(),
        };
        let signature: ed25519_dalek::Signature =
            authority_key.sign(&vote.signing_bytes().unwrap());
        vote.signature = BASE64.encode(signature.to_bytes());
        let certificate = MlsOrderingQuorumCertificateV1 {
            authority_set_sequence: 1,
            height: 1,
            round: 0,
            block_hash: block_hash.clone(),
            votes: vec![vote],
        };
        let request = alice
            .build_membership_commit_request(group_id, certificate)
            .await
            .unwrap();
        request.validate_shape().unwrap();
        let welcome = prepared
            .control
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "beta.example")
            .unwrap()
            .envelopes[0]
            .opaque_message
            .as_str();
        let welcome = BASE64.decode(welcome).unwrap();
        let history = MlsClientControlHistoryPageV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            genesis: genesis.conversation.request.genesis.clone(),
            genesis_participant_domains: vec!["alpha.example".into()],
            after_height: "0".into(),
            commits: vec![request.clone()],
            next_height: Some("1".into()),
        };
        let history_page = history.canonical_bytes().unwrap();
        let three_device_roster = vec![
            VerifiedMlsCredential::new(
                "alice@alpha.example#1".into(),
                alice_public.credential_public_key.clone(),
            )
            .unwrap(),
            additions[0].credential.clone(),
            additions[1].credential.clone(),
        ];
        let welcome_envelope = MlsControlEnvelopeContext {
            envelope_id: Uuid::from_u128(0xa4),
            cursor: "16".into(),
            send_id: Uuid::from_u128(0xa5),
        };
        let mut truncated = history;
        truncated.commits.clear();
        truncated.next_height = None;
        assert!(bob
            .join_from_welcome_with_control_history(
                &welcome_envelope,
                group_id,
                &welcome,
                &three_device_roster,
                &[truncated.canonical_bytes().unwrap()],
            )
            .await
            .is_err());
        assert!(bob.group_state(group_id).await.unwrap().is_none());
        assert!(bob
            .processed_control_envelope(welcome_envelope.envelope_id)
            .await
            .unwrap()
            .is_none());
        let joined = bob
            .join_from_welcome_with_control_history(
                &welcome_envelope,
                group_id,
                &welcome,
                &three_device_roster,
                &[history_page.clone()],
            )
            .await
            .unwrap();
        assert_eq!(joined.group.epoch, 1);
        assert_eq!(joined.conversation.last_finalized_height, 1);
        assert_eq!(joined.conversation.current_roster, next_roster);
        let mut unauthorized_administrator_roster = next_roster.clone();
        unauthorized_administrator_roster
            .iter_mut()
            .find(|member| member.address.canonical() == "bobby@beta.example")
            .unwrap()
            .is_admin = true;
        assert!(bob
            .prepare_membership_change(
                group_id,
                Uuid::from_u128(0xa8),
                &unauthorized_administrator_roster,
                &[],
                now + 2,
            )
            .await
            .is_err());
        assert!(bob.pending_membership_changes().await.unwrap().is_empty());
        assert_eq!(
            bob.join_from_welcome_with_control_history(
                &welcome_envelope,
                group_id,
                &welcome,
                &three_device_roster,
                &[history_page.clone()],
            )
            .await
            .unwrap(),
            joined
        );
        let durable_final = alice.pending_membership_changes().await.unwrap();
        assert_eq!(durable_final[0].final_request.as_ref(), Some(&request));
        drop(alice);
        drop(reopened);
        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let alice = MlsClient::new(reopened.clone());
        alice.initialize("alice@alpha.example#1").await.unwrap();
        assert_eq!(
            alice.pending_membership_changes().await.unwrap(),
            durable_final
        );

        let wrong = CommitMlsControlBlockResponseV1 {
            conversation_id,
            incarnation: 1,
            height: 1,
            epoch: 1,
            block_hash: "00".repeat(32),
            idempotent: false,
        };
        assert!(alice
            .finalize_membership_change(group_id, &wrong)
            .await
            .is_err());
        assert_eq!(
            alice.pending_membership_changes().await.unwrap(),
            durable_final
        );

        let acknowledgement = CommitMlsControlBlockResponseV1 {
            block_hash,
            ..wrong
        };
        let finalized = alice
            .finalize_membership_change(group_id, &acknowledgement)
            .await
            .unwrap();
        assert_eq!(finalized.group.epoch, 1);
        assert_eq!(finalized.conversation.last_finalized_height, 1);
        assert_eq!(finalized.conversation.current_roster, next_roster);
        assert!(alice.pending_membership_changes().await.unwrap().is_empty());
        assert_eq!(
            alice
                .finalize_membership_change(group_id, &acknowledgement)
                .await
                .unwrap(),
            finalized
        );
        let candidate_signer = ed25519_dalek::SigningKey::from_bytes(&[47; 32]);
        let candidate_public_key = candidate_signer.verifying_key().to_bytes();
        let mut removed_candidate = MlsOwnerCandidateV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            account: "carol@gamma.example".parse().unwrap(),
            owner_id: hex::encode(Sha256::digest(candidate_public_key)),
            public_key: BASE64.encode(candidate_public_key),
            created_at: now + 1,
            signature: String::new(),
        };
        removed_candidate.signature = BASE64.encode(
            candidate_signer
                .sign(&removed_candidate.signing_bytes().unwrap())
                .to_bytes(),
        );
        removed_candidate.verify().unwrap();
        persist_owner_candidate(&alice, group_id, removed_candidate.clone()).await;
        persist_owner_candidate(&bob, group_id, removed_candidate.clone()).await;
        assert_eq!(alice.owner_candidates(group_id).await.unwrap().len(), 1);
        assert_eq!(bob.owner_candidates(group_id).await.unwrap().len(), 1);
        let removal_roster = vec![
            finalized.conversation.current_roster[0].clone(),
            finalized.conversation.current_roster[1].clone(),
        ];
        let removal = alice
            .prepare_membership_change(
                group_id,
                Uuid::from_u128(0xa3),
                &removal_roster,
                &[],
                now + 2,
            )
            .await
            .unwrap();
        assert!(removal.pending.welcome.is_none());
        assert_eq!(removal.control.transition.previous_member_count, 3);
        assert_eq!(removal.control.transition.next_member_count, 2);
        let removed_domain = removal
            .control
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "gamma.example")
            .unwrap();
        assert!(removed_domain.local_members_after.is_empty());
        assert!(removed_domain.envelopes.is_empty());
        let removal_block = &removal.control.vote_request.block;
        let removal_block_hash = removal_block.block_hash().unwrap();
        let authority = &removal.control.vote_request.authority_set.authorities[0];
        let mut removal_vote = kutup_chat_proto::MlsOrderingVoteV1 {
            conversation_id,
            incarnation: 1,
            authority_set_sequence: 1,
            height: 2,
            round: 0,
            vote_type: kutup_chat_proto::MlsOrderingVoteTypeV1::Precommit,
            block_hash: removal_block_hash.clone(),
            authority_domain: authority.domain.clone(),
            authority_key_id: authority.key_id.clone(),
            signature: String::new(),
        };
        let signature: ed25519_dalek::Signature =
            authority_key.sign(&removal_vote.signing_bytes().unwrap());
        removal_vote.signature = BASE64.encode(signature.to_bytes());
        let removal_request = alice
            .build_membership_commit_request(
                group_id,
                MlsOrderingQuorumCertificateV1 {
                    authority_set_sequence: 1,
                    height: 2,
                    round: 0,
                    block_hash: removal_block_hash.clone(),
                    votes: vec![removal_vote],
                },
            )
            .await
            .unwrap();
        let bob_envelope = removal
            .control
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "beta.example")
            .unwrap()
            .envelopes
            .first()
            .unwrap();
        assert_eq!(bob_envelope.kind, MlsMembershipEnvelopeKindV1::Commit);
        let bob_commit = BASE64.decode(&bob_envelope.opaque_message).unwrap();
        let acknowledgement = CommitMlsControlBlockResponseV1 {
            conversation_id,
            incarnation: 1,
            height: 2,
            epoch: 2,
            block_hash: removal_block_hash,
            idempotent: false,
        };
        let removed = alice
            .finalize_membership_change(group_id, &acknowledgement)
            .await
            .unwrap();
        assert!(alice.owner_candidates(group_id).await.unwrap().is_empty());
        let two_device_roster = vec![
            three_device_roster[0].clone(),
            three_device_roster[1].clone(),
        ];
        let commit_envelope = MlsControlEnvelopeContext {
            envelope_id: bob_envelope.envelope_id,
            cursor: "17".into(),
            send_id: bob_envelope.envelope_id,
        };
        let mut forged_request = removal_request.clone();
        forged_request.finalized.quorum_certificate.votes[0].signature = BASE64.encode([0; 64]);
        assert!(bob
            .apply_ordered_inbound_membership_commit(
                &commit_envelope,
                group_id,
                &bob_commit,
                &two_device_roster,
                &forged_request,
            )
            .await
            .is_err());
        assert_eq!(bob.group_state(group_id).await.unwrap().unwrap().epoch, 1);
        assert!(bob
            .processed_control_envelope(bob_envelope.envelope_id)
            .await
            .unwrap()
            .is_none());
        let applied = bob
            .apply_ordered_inbound_membership_commit(
                &commit_envelope,
                group_id,
                &bob_commit,
                &two_device_roster,
                &removal_request,
            )
            .await
            .unwrap();
        assert!(bob.owner_candidates(group_id).await.unwrap().is_empty());
        assert!(!applied.idempotent);
        assert_eq!(applied.group.epoch, 2);
        assert_eq!(applied.conversation, removed.conversation);
        assert_eq!(
            bob.processed_control_envelope(bob_envelope.envelope_id)
                .await
                .unwrap(),
            Some(applied.receipt.clone())
        );
        drop(bob);
        let bob = MlsClient::new(bob_db.clone());
        bob.initialize("bobby@beta.example#1").await.unwrap();
        let replay = bob
            .apply_ordered_inbound_membership_commit(
                &commit_envelope,
                group_id,
                &bob_commit,
                &two_device_roster,
                &removal_request,
            )
            .await
            .unwrap();
        assert!(replay.idempotent);
        assert_eq!(replay.conversation, applied.conversation);

        assert!(alice
            .prepare_membership_change(
                group_id,
                Uuid::from_u128(0xa6),
                &removed.conversation.current_roster,
                &[],
                now + 3,
            )
            .await
            .is_err());
        let mut administrator_roster = removed.conversation.current_roster.clone();
        administrator_roster
            .iter_mut()
            .find(|member| member.address.canonical() == "bobby@beta.example")
            .unwrap()
            .is_admin = true;
        let administrator = alice
            .prepare_membership_change(
                group_id,
                Uuid::from_u128(0xa7),
                &administrator_roster,
                &[],
                now + 3,
            )
            .await
            .unwrap();
        assert!(administrator.pending.welcome.is_none());
        assert_eq!(
            administrator
                .control
                .vote_request
                .block
                .proposal
                .action_type,
            MlsControlActionTypeV1::RoutineAdmin
        );
        assert_eq!(administrator.control.transition.previous_member_count, 2);
        assert_eq!(administrator.control.transition.next_member_count, 2);
        assert_eq!(
            administrator
                .control
                .transition
                .previous_participant_domains,
            administrator.control.transition.next_participant_domains
        );
        let administrator_block = &administrator.control.vote_request.block;
        let administrator_block_hash = administrator_block.block_hash().unwrap();
        let authority = &administrator.control.vote_request.authority_set.authorities[0];
        let mut administrator_vote = kutup_chat_proto::MlsOrderingVoteV1 {
            conversation_id,
            incarnation: 1,
            authority_set_sequence: 1,
            height: 3,
            round: 0,
            vote_type: kutup_chat_proto::MlsOrderingVoteTypeV1::Precommit,
            block_hash: administrator_block_hash.clone(),
            authority_domain: authority.domain.clone(),
            authority_key_id: authority.key_id.clone(),
            signature: String::new(),
        };
        let signature: ed25519_dalek::Signature =
            authority_key.sign(&administrator_vote.signing_bytes().unwrap());
        administrator_vote.signature = BASE64.encode(signature.to_bytes());
        let administrator_request = alice
            .build_membership_commit_request(
                group_id,
                MlsOrderingQuorumCertificateV1 {
                    authority_set_sequence: 1,
                    height: 3,
                    round: 0,
                    block_hash: administrator_block_hash.clone(),
                    votes: vec![administrator_vote],
                },
            )
            .await
            .unwrap();
        administrator_request.validate_shape().unwrap();
        let bob_administrator_envelope = administrator
            .control
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "beta.example")
            .unwrap()
            .envelopes
            .first()
            .unwrap();
        assert_eq!(
            bob_administrator_envelope.kind,
            MlsMembershipEnvelopeKindV1::Commit
        );
        let bob_administrator_commit = BASE64
            .decode(&bob_administrator_envelope.opaque_message)
            .unwrap();
        let promoted = alice
            .finalize_membership_change(
                group_id,
                &CommitMlsControlBlockResponseV1 {
                    conversation_id,
                    incarnation: 1,
                    height: 3,
                    epoch: 3,
                    block_hash: administrator_block_hash,
                    idempotent: false,
                },
            )
            .await
            .unwrap();
        let promoted_applied = bob
            .apply_ordered_inbound_membership_commit(
                &MlsControlEnvelopeContext {
                    envelope_id: bob_administrator_envelope.envelope_id,
                    cursor: "18".into(),
                    send_id: bob_administrator_envelope.envelope_id,
                },
                group_id,
                &bob_administrator_commit,
                &two_device_roster,
                &administrator_request,
            )
            .await
            .unwrap();
        assert_eq!(promoted.group.epoch, 3);
        assert_eq!(promoted_applied.conversation, promoted.conversation);
        assert!(promoted
            .conversation
            .current_roster
            .iter()
            .any(|member| member.address.canonical() == "bobby@beta.example" && member.is_admin));

        let alice_package = alice
            .generate_key_package(1, 1, now + 4, now + 86_400)
            .await
            .unwrap();
        let verified_alice = VerifiedMlsKeyPackage {
            wire: alice_package,
            credential: two_device_roster[0].clone(),
            anonymous_delivery_public_key: alice_public.anonymous_delivery_public_key.clone(),
        };
        let candidate_entry = bob
            .create_owner_candidate_message(group_id, now + 4)
            .await
            .unwrap()
            .unwrap();
        let candidate = bob
            .owner_candidates(group_id)
            .await
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.account.canonical() == "bobby@beta.example")
            .unwrap();
        let alice_address: AccountAddress = "alice@alpha.example".parse().unwrap();
        let candidate_capability = bob
            .derive_delivery_capability(group_id, conversation_id, 1, &alice_address)
            .await
            .unwrap();
        let staged_candidate = bob
            .stage_application_delivery(
                &candidate_entry.send_id,
                &alice_address,
                candidate_capability.capability,
                &[verified_alice],
                now + 4,
            )
            .await
            .unwrap();
        let candidate_context = MlsApplicationEnvelopeContext {
            envelope_id: Uuid::from_u128(0xa9),
            cursor: "19".into(),
            send_id: Uuid::parse_str(&candidate_entry.send_id).unwrap(),
            server_timestamp: now + 4,
        };
        alice
            .apply_anonymous_application_envelope(
                &candidate_context,
                &alice_address,
                &staged_candidate.submission.envelopes[0],
                &two_device_roster[1],
            )
            .await
            .unwrap();
        bob.mark_application_recipient_delivered(
            &candidate_entry.send_id,
            "alice@alpha.example",
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            alice.owner_candidates(group_id).await.unwrap(),
            vec![candidate.clone()]
        );

        let mut owner_roster = promoted.conversation.current_roster.clone();
        owner_roster
            .iter_mut()
            .find(|member| member.address.canonical() == "bobby@beta.example")
            .unwrap()
            .owner_id = Some(candidate.owner_id.clone());
        let mut owners = promoted.conversation.current_owner_set.owners.clone();
        owners.push(MlsOwnerV1 {
            owner_id: candidate.owner_id.clone(),
            public_key: candidate.public_key.clone(),
        });
        owners.sort_by(|left, right| left.owner_id.cmp(&right.owner_id));
        let next_owner_set = MlsOwnerSetV1 {
            sequence: 2,
            owners,
            required_quorum: 2,
        };
        let owner_change = alice
            .prepare_owner_change(
                group_id,
                Uuid::from_u128(0xaa),
                &owner_roster,
                next_owner_set,
                now + 5,
            )
            .await
            .unwrap();
        let owner_block = &owner_change.control.vote_request.block;
        let owner_block_hash = owner_block.block_hash().unwrap();
        let authority = &owner_change.control.vote_request.authority_set.authorities[0];
        let mut owner_vote = kutup_chat_proto::MlsOrderingVoteV1 {
            conversation_id,
            incarnation: 1,
            authority_set_sequence: 1,
            height: 4,
            round: 0,
            vote_type: kutup_chat_proto::MlsOrderingVoteTypeV1::Precommit,
            block_hash: owner_block_hash.clone(),
            authority_domain: authority.domain.clone(),
            authority_key_id: authority.key_id.clone(),
            signature: String::new(),
        };
        owner_vote.signature = BASE64.encode(
            authority_key
                .sign(&owner_vote.signing_bytes().unwrap())
                .to_bytes(),
        );
        let owner_request = alice
            .build_owner_commit_request(
                group_id,
                MlsOrderingQuorumCertificateV1 {
                    authority_set_sequence: 1,
                    height: 4,
                    round: 0,
                    block_hash: owner_block_hash.clone(),
                    votes: vec![owner_vote],
                },
            )
            .await
            .unwrap();
        let bob_owner_envelope = owner_change
            .control
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "beta.example")
            .unwrap()
            .envelopes
            .first()
            .unwrap();
        let bob_owner_commit = BASE64.decode(&bob_owner_envelope.opaque_message).unwrap();
        let owners_finalized = alice
            .finalize_owner_change(
                group_id,
                &CommitMlsControlBlockResponseV1 {
                    conversation_id,
                    incarnation: 1,
                    height: 4,
                    epoch: 4,
                    block_hash: owner_block_hash,
                    idempotent: false,
                },
            )
            .await
            .unwrap();
        let bob_owner_applied = bob
            .apply_ordered_inbound_membership_commit(
                &MlsControlEnvelopeContext {
                    envelope_id: bob_owner_envelope.envelope_id,
                    cursor: "20".into(),
                    send_id: bob_owner_envelope.envelope_id,
                },
                group_id,
                &bob_owner_commit,
                &two_device_roster,
                &owner_request,
            )
            .await
            .unwrap();
        assert_eq!(
            bob_owner_applied.conversation,
            owners_finalized.conversation
        );
        assert_eq!(
            bob.group_owner_credential(group_id).await.unwrap().owner_id,
            candidate.owner_id
        );

        drop(bob);
        let bob = MlsClient::new(bob_db.clone());
        bob.initialize("bobby@beta.example#1").await.unwrap();
        assert_eq!(
            bob.group_owner_credential(group_id).await.unwrap().owner_id,
            candidate.owner_id
        );
        let bob_approval_package = bob
            .generate_key_package(1, 1, now + 6, now + 86_400)
            .await
            .unwrap();
        let verified_bob_approval = VerifiedMlsKeyPackage {
            wire: bob_approval_package,
            credential: two_device_roster[1].clone(),
            anonymous_delivery_public_key: additions[0].anonymous_delivery_public_key.clone(),
        };
        let alice_approval_package = alice
            .generate_key_package(1, 1, now + 6, now + 86_400)
            .await
            .unwrap();
        let verified_alice_approval = VerifiedMlsKeyPackage {
            wire: alice_approval_package,
            credential: two_device_roster[0].clone(),
            anonymous_delivery_public_key: alice_public.anonymous_delivery_public_key.clone(),
        };
        let mut unilateral_roster = owners_finalized.conversation.current_roster.clone();
        unilateral_roster
            .iter_mut()
            .find(|member| member.address.canonical() == "bobby@beta.example")
            .unwrap()
            .owner_id = None;
        let alice_only_owner = owners_finalized
            .conversation
            .current_owner_set
            .owners
            .iter()
            .find(|owner| owner.owner_id != candidate.owner_id)
            .unwrap()
            .clone();
        let removal_owner_change = alice
            .prepare_owner_change(
                group_id,
                Uuid::from_u128(0xab),
                &unilateral_roster,
                MlsOwnerSetV1 {
                    sequence: 3,
                    owners: vec![alice_only_owner.clone()],
                    required_quorum: 1,
                },
                now + 6,
            )
            .await
            .unwrap();
        assert!(!alice.owner_change_has_quorum(group_id).await.unwrap());
        assert_eq!(alice.pending_owner_changes().await.unwrap().len(), 1);

        drop(alice);
        drop(reopened);
        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let alice = MlsClient::new(reopened.clone());
        alice.initialize("alice@alpha.example#1").await.unwrap();
        assert!(!alice.owner_change_has_quorum(group_id).await.unwrap());
        let approval_request_entry = alice
            .create_owner_approval_request_message(group_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            approval_request_entry.expected_recipients,
            vec!["bobby@beta.example"]
        );
        let bob_address: AccountAddress = "bobby@beta.example".parse().unwrap();
        let approval_request_capability = alice
            .derive_delivery_capability(group_id, conversation_id, 1, &bob_address)
            .await
            .unwrap();
        let staged_approval_request = alice
            .stage_application_delivery(
                &approval_request_entry.send_id,
                &bob_address,
                approval_request_capability.capability,
                &[verified_bob_approval],
                now + 7,
            )
            .await
            .unwrap();
        bob.apply_anonymous_application_envelope(
            &MlsApplicationEnvelopeContext {
                envelope_id: Uuid::from_u128(0xac),
                cursor: "21".into(),
                send_id: Uuid::parse_str(&approval_request_entry.send_id).unwrap(),
                server_timestamp: now + 7,
            },
            &bob_address,
            &staged_approval_request.submission.envelopes[0],
            &two_device_roster[0],
        )
        .await
        .unwrap();
        alice
            .mark_application_recipient_delivered(
                &approval_request_entry.send_id,
                "bobby@beta.example",
                false,
            )
            .await
            .unwrap();
        assert_eq!(
            bob.pending_owner_approval_requests().await.unwrap().len(),
            1
        );

        drop(bob);
        let bob = MlsClient::new(bob_db.clone());
        bob.initialize("bobby@beta.example#1").await.unwrap();
        assert_eq!(
            bob.pending_owner_approval_requests().await.unwrap().len(),
            1
        );
        let approval_response_entry = bob
            .approve_owner_approval_request(group_id, now + 8)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            approval_response_entry.expected_recipients,
            vec!["alice@alpha.example"]
        );
        assert!(bob
            .pending_owner_approval_requests()
            .await
            .unwrap()
            .is_empty());
        let approval_response_capability = bob
            .derive_delivery_capability(group_id, conversation_id, 1, &alice_address)
            .await
            .unwrap();
        let staged_approval_response = bob
            .stage_application_delivery(
                &approval_response_entry.send_id,
                &alice_address,
                approval_response_capability.capability,
                &[verified_alice_approval],
                now + 8,
            )
            .await
            .unwrap();
        alice
            .apply_anonymous_application_envelope(
                &MlsApplicationEnvelopeContext {
                    envelope_id: Uuid::from_u128(0xad),
                    cursor: "22".into(),
                    send_id: Uuid::parse_str(&approval_response_entry.send_id).unwrap(),
                    server_timestamp: now + 8,
                },
                &alice_address,
                &staged_approval_response.submission.envelopes[0],
                &two_device_roster[1],
            )
            .await
            .unwrap();
        bob.mark_application_recipient_delivered(
            &approval_response_entry.send_id,
            "alice@alpha.example",
            false,
        )
        .await
        .unwrap();
        assert!(alice.owner_change_has_quorum(group_id).await.unwrap());

        let removal_owner_block = &alice.pending_owner_changes().await.unwrap()[0]
            .vote_request
            .block;
        let removal_owner_block_hash = removal_owner_block.block_hash().unwrap();
        let authority = &removal_owner_change
            .control
            .vote_request
            .authority_set
            .authorities[0];
        let mut removal_owner_vote = kutup_chat_proto::MlsOrderingVoteV1 {
            conversation_id,
            incarnation: 1,
            authority_set_sequence: 1,
            height: 5,
            round: 0,
            vote_type: kutup_chat_proto::MlsOrderingVoteTypeV1::Precommit,
            block_hash: removal_owner_block_hash.clone(),
            authority_domain: authority.domain.clone(),
            authority_key_id: authority.key_id.clone(),
            signature: String::new(),
        };
        removal_owner_vote.signature = BASE64.encode(
            authority_key
                .sign(&removal_owner_vote.signing_bytes().unwrap())
                .to_bytes(),
        );
        let removal_owner_request = alice
            .build_owner_commit_request(
                group_id,
                MlsOrderingQuorumCertificateV1 {
                    authority_set_sequence: 1,
                    height: 5,
                    round: 0,
                    block_hash: removal_owner_block_hash.clone(),
                    votes: vec![removal_owner_vote],
                },
            )
            .await
            .unwrap();
        let bob_removal_envelope = removal_owner_change
            .control
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "beta.example")
            .unwrap()
            .envelopes
            .first()
            .unwrap();
        let bob_removal_commit = BASE64.decode(&bob_removal_envelope.opaque_message).unwrap();
        let removal_finalized = alice
            .finalize_owner_change(
                group_id,
                &CommitMlsControlBlockResponseV1 {
                    conversation_id,
                    incarnation: 1,
                    height: 5,
                    epoch: 5,
                    block_hash: removal_owner_block_hash,
                    idempotent: false,
                },
            )
            .await
            .unwrap();
        let bob_removal_applied = bob
            .apply_ordered_inbound_membership_commit(
                &MlsControlEnvelopeContext {
                    envelope_id: bob_removal_envelope.envelope_id,
                    cursor: "23".into(),
                    send_id: bob_removal_envelope.envelope_id,
                },
                group_id,
                &bob_removal_commit,
                &two_device_roster,
                &removal_owner_request,
            )
            .await
            .unwrap();
        assert_eq!(
            bob_removal_applied.conversation,
            removal_finalized.conversation
        );
        assert!(bob.group_owner_credential(group_id).await.is_err());
        assert_eq!(
            removal_finalized
                .conversation
                .current_owner_set
                .required_quorum,
            1
        );
        assert_eq!(
            removal_finalized.conversation.current_owner_set.owners,
            vec![alice_only_owner]
        );

        drop(alice);
        drop(reopened);
        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let alice = MlsClient::new(reopened.clone());
        alice.initialize("alice@alpha.example#1").await.unwrap();
        assert_eq!(
            alice.local_conversations().await.unwrap(),
            vec![removal_finalized.conversation.clone()]
        );

        let close = alice
            .prepare_close_conversation(group_id, Uuid::from_u128(0xae), now + 9)
            .await
            .unwrap();
        assert!(alice.close_has_owner_quorum(group_id).await.unwrap());
        assert_eq!(
            close.control.current_roster,
            removal_finalized.conversation.current_roster
        );
        assert_eq!(
            close.control.transition.previous_roster_commitment,
            close.control.transition.next_roster_commitment
        );
        assert_eq!(
            alice.pending_closes().await.unwrap(),
            vec![close.control.clone()]
        );

        drop(alice);
        drop(reopened);
        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let alice = MlsClient::new(reopened.clone());
        alice.initialize("alice@alpha.example#1").await.unwrap();
        assert_eq!(
            alice.pending_closes().await.unwrap(),
            vec![close.control.clone()]
        );
        assert!(alice
            .create_owner_approval_request_message(group_id)
            .await
            .unwrap()
            .is_none());

        let close_block = &close.control.vote_request.block;
        let close_block_hash = close_block.block_hash().unwrap();
        let authority = &close.control.vote_request.authority_set.authorities[0];
        let mut close_vote = kutup_chat_proto::MlsOrderingVoteV1 {
            conversation_id,
            incarnation: 1,
            authority_set_sequence: 1,
            height: 6,
            round: 0,
            vote_type: kutup_chat_proto::MlsOrderingVoteTypeV1::Precommit,
            block_hash: close_block_hash.clone(),
            authority_domain: authority.domain.clone(),
            authority_key_id: authority.key_id.clone(),
            signature: String::new(),
        };
        close_vote.signature = BASE64.encode(
            authority_key
                .sign(&close_vote.signing_bytes().unwrap())
                .to_bytes(),
        );
        let close_request = alice
            .build_close_commit_request(
                group_id,
                MlsOrderingQuorumCertificateV1 {
                    authority_set_sequence: 1,
                    height: 6,
                    round: 0,
                    block_hash: close_block_hash.clone(),
                    votes: vec![close_vote],
                },
            )
            .await
            .unwrap();
        close_request.validate_shape().unwrap();
        let bob_close_envelope = close
            .control
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "beta.example")
            .unwrap()
            .envelopes
            .first()
            .unwrap();
        let bob_close_commit = BASE64.decode(&bob_close_envelope.opaque_message).unwrap();
        let closed = alice
            .finalize_close(
                group_id,
                &CommitMlsControlBlockResponseV1 {
                    conversation_id,
                    incarnation: 1,
                    height: 6,
                    epoch: 6,
                    block_hash: close_block_hash,
                    idempotent: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            closed.conversation.status,
            LocalMlsConversationStatus::Closed
        );
        let bob_closed = bob
            .apply_ordered_inbound_membership_commit(
                &MlsControlEnvelopeContext {
                    envelope_id: bob_close_envelope.envelope_id,
                    cursor: "24".into(),
                    send_id: bob_close_envelope.envelope_id,
                },
                group_id,
                &bob_close_commit,
                &two_device_roster,
                &close_request,
            )
            .await
            .unwrap();
        assert_eq!(
            bob_closed.conversation.status,
            LocalMlsConversationStatus::Closed
        );
        assert!(alice
            .create_text_application_message(
                &Uuid::from_u128(0xaf).to_string(),
                conversation_id,
                1,
                group_id,
                "1700000010",
                "must not send after close",
                (now + 10) * 1000,
            )
            .await
            .is_err());

        drop(alice);
        drop(reopened);
        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let alice = MlsClient::new(reopened.clone());
        alice.initialize("alice@alpha.example#1").await.unwrap();
        assert_eq!(
            alice.local_conversations().await.unwrap()[0].status,
            LocalMlsConversationStatus::Closed
        );
        drop(alice);
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    });
}

#[test]
fn group_genesis_rejects_authority_downgrade_and_identity_collisions() {
    futures_executor::block_on(async {
        let path = std::env::temp_dir().join(format!(
            "kutup-openmls-genesis-reject-{}.db",
            crate::clock::unix_millis()
        ));
        let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(db.clone());
        client.initialize("alice@example.test#1").await.unwrap();
        let creator: AccountAddress = "alice@example.test".parse().unwrap();
        let mut rejected = ordering_policy("alpha.example", 21);
        rejected.accepts_group_ordering = false;
        assert!(client
            .prepare_group_genesis(
                Uuid::from_u128(0x91),
                b"group-rejected-id",
                creator.clone(),
                &[rejected],
                1_700_000_000,
            )
            .await
            .is_err());
        assert!(client.local_conversations().await.unwrap().is_empty());

        let policy = ordering_policy("alpha.example", 21);
        let prepared = client
            .prepare_group_genesis(
                Uuid::from_u128(0x92),
                b"group-accepted-id",
                creator.clone(),
                &[policy.clone()],
                1_700_000_000,
            )
            .await
            .unwrap();
        assert!(client
            .prepare_group_genesis(
                Uuid::from_u128(0x92),
                b"different-group!",
                creator.clone(),
                &[policy.clone()],
                1_700_000_000,
            )
            .await
            .is_err());
        assert!(client
            .prepare_group_genesis(
                Uuid::from_u128(0x93),
                b"group-accepted-id",
                creator,
                &[policy],
                1_700_000_000,
            )
            .await
            .is_err());
        assert_eq!(
            client.local_conversations().await.unwrap(),
            vec![prepared.conversation]
        );
        drop(client);
        drop(db);
        std::fs::remove_file(path).unwrap();
    });
}

#[test]
fn state_group_keypackage_and_ciphertext_survive_restart() {
    futures_executor::block_on(async {
        let path = std::env::temp_dir().join(format!(
            "kutup-openmls-restart-{}.db",
            crate::clock::unix_millis()
        ));
        let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(db.clone());
        let public = client.initialize("alice@example.test#1").await.unwrap();
        assert_eq!(public.credential_public_key.len(), 65);
        assert_eq!(public.anonymous_delivery_public_key.len(), 65);
        public.manifest_binding().validate().unwrap();

        let package = client
            .generate_key_package(1, 1, 1_700_000_000, 1_700_086_400)
            .await
            .unwrap();
        assert_eq!(
            u16::from(package.suite),
            MLS_CIPHERSUITE_P256_AES128GCM_SHA256_P256
        );
        assert!(!package.key_package.is_empty());
        let group_id = b"0123456789abcdef";
        assert_eq!(client.create_group(group_id).await.unwrap().epoch, 0);
        let proposal = client
            .sign_control_proposal(
                group_id,
                Uuid::from_u128(7),
                1,
                Uuid::from_u128(8),
                0,
                MlsControlActionTypeV1::MembershipChange,
                b"encrypted MLS commit",
                1_700_000_000,
            )
            .await
            .unwrap();
        proposal.verify().unwrap();
        let control = client.group_control_credential(group_id).await.unwrap();
        assert_eq!(
            proposal.proposer_id,
            hex::encode(Sha256::digest(&control.public_key))
        );
        assert_ne!(control.public_key, public.credential_public_key);
        let second_group_id = b"different-group!";
        client.create_group(second_group_id).await.unwrap();
        let second_control = client
            .group_control_credential(second_group_id)
            .await
            .unwrap();
        assert_ne!(control.public_key, second_control.public_key);
        drop(client);
        drop(db);

        let reopened: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(reopened.clone());
        let reopened_public = client.initialize("alice@example.test#1").await.unwrap();
        assert_eq!(reopened_public, public);
        assert_eq!(client.create_group(group_id).await.unwrap().epoch, 0);

        let send_id = "31fc6154-7886-49a8-9d64-735e901b7554";
        let entry = client
            .create_application_message(
                send_id,
                *b"conversation-id!",
                1,
                group_id,
                b"durable MLS message",
                1_700_000_000_000,
            )
            .await
            .unwrap();
        assert!(!entry.ciphertext.is_empty());
        let duplicate = client
            .create_application_message(
                send_id,
                *b"conversation-id!",
                1,
                group_id,
                b"durable MLS message",
                1_700_000_000_001,
            )
            .await
            .unwrap();
        assert_eq!(duplicate.ciphertext, entry.ciphertext);
        drop(client);
        drop(reopened);

        let restarted: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        assert_eq!(
            restarted
                .load_mls_outbox(send_id)
                .await
                .unwrap()
                .unwrap()
                .ciphertext,
            entry.ciphertext
        );
        let client = MlsClient::new(restarted.clone());
        assert_eq!(
            client
                .note_application_attempt(send_id)
                .await
                .unwrap()
                .attempts,
            1
        );
        client.mark_application_delivered(send_id).await.unwrap();
        assert!(restarted.load_mls_outbox(send_id).await.unwrap().is_none());
        drop(client);
        drop(restarted);

        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    });
}

#[test]
fn identity_change_and_send_id_reuse_fail_closed() {
    futures_executor::block_on(async {
        let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let client = MlsClient::new(db);
        client.initialize("alice@example.test#1").await.unwrap();
        assert!(matches!(
            client.initialize("mallory@example.test#1").await,
            Err(ChatError::Trust(_))
        ));
        let group_id = b"fed-group-id-001";
        client.create_group(group_id).await.unwrap();
        let send_id = "f3035928-4128-46d1-a5a4-12e80ce823aa";
        client
            .create_application_message(send_id, *b"conversation-id!", 1, group_id, b"first", 1)
            .await
            .unwrap();
        assert!(matches!(
            client
                .create_application_message(
                    send_id,
                    *b"conversation-id!",
                    1,
                    group_id,
                    b"different",
                    2,
                )
                .await,
            Err(ChatError::Trust(_))
        ));
    });
}

#[test]
fn welcome_commit_and_application_lifecycle_is_manifest_bound() {
    futures_executor::block_on(async {
        let alice_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let bob_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let charlie_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let alice = MlsClient::new(alice_db.clone());
        let bob = MlsClient::new(bob_db);
        let charlie = MlsClient::new(charlie_db);
        let alice_public = alice.initialize("alice@example.test#1").await.unwrap();
        let bob_public = bob.initialize("bob@example.test#1").await.unwrap();
        let charlie_public = charlie.initialize("charlie@example.test#1").await.unwrap();
        let now = crate::clock::unix_millis() / 1000;
        let bob_package = bob
            .generate_key_package(1, 1, now, now + 86_400)
            .await
            .unwrap();
        let charlie_package = charlie
            .generate_key_package(1, 1, now, now + 86_400)
            .await
            .unwrap();
        let alice_credential = VerifiedMlsCredential::new(
            "alice@example.test#1".into(),
            alice_public.credential_public_key,
        )
        .unwrap();
        let bob_credential = VerifiedMlsCredential::new(
            "bob@example.test#1".into(),
            bob_public.credential_public_key,
        )
        .unwrap();
        let charlie_credential = VerifiedMlsCredential::new(
            "charlie@example.test#1".into(),
            charlie_public.credential_public_key,
        )
        .unwrap();
        let group_id = b"manifest-mls-v1!";
        alice.create_group(group_id).await.unwrap();

        let pending = alice
            .prepare_add_members(
                group_id,
                &[VerifiedMlsKeyPackage {
                    wire: bob_package,
                    credential: bob_credential.clone(),
                    anonymous_delivery_public_key: bob_public.anonymous_delivery_public_key.clone(),
                }],
                now,
            )
            .await
            .unwrap();
        assert_eq!(pending.epoch_before, 0);
        assert_eq!(pending.epoch_after, 1);
        assert_eq!(
            alice.pending_commit(group_id).await.unwrap(),
            Some(pending.clone())
        );
        drop(alice);
        let alice = MlsClient::new(alice_db);
        assert_eq!(
            alice.pending_commit(group_id).await.unwrap(),
            Some(pending.clone())
        );

        let expected_roster = vec![alice_credential.clone(), bob_credential.clone()];
        let inspection = bob
            .inspect_welcome(group_id, pending.welcome.as_deref().unwrap())
            .await
            .unwrap();
        assert_eq!(inspection.epoch, 1);
        assert_eq!(inspection.claimed_members.len(), 2);
        assert!(bob.group_state(group_id).await.unwrap().is_none());
        assert_eq!(
            bob.join_from_welcome(
                group_id,
                pending.welcome.as_deref().unwrap(),
                &expected_roster,
            )
            .await
            .unwrap()
            .epoch,
            1
        );
        assert_eq!(
            alice
                .merge_pending_commit(group_id, &pending.commit_hash)
                .await
                .unwrap()
                .epoch,
            1
        );
        assert!(alice.pending_commit(group_id).await.unwrap().is_none());
        let bob_address: kutup_chat_proto::AccountAddress = "bob@example.test".parse().unwrap();
        let alice_epoch_one_capability = alice
            .derive_delivery_capability(group_id, Uuid::from_u128(77), 1, &bob_address)
            .await
            .unwrap();
        let bob_epoch_one_capability = bob
            .derive_delivery_capability(group_id, Uuid::from_u128(77), 1, &bob_address)
            .await
            .unwrap();
        assert_eq!(alice_epoch_one_capability, bob_epoch_one_capability);

        let second_commit = alice
            .prepare_add_members(
                group_id,
                &[VerifiedMlsKeyPackage {
                    wire: charlie_package,
                    credential: charlie_credential.clone(),
                    anonymous_delivery_public_key: charlie_public.anonymous_delivery_public_key,
                }],
                now,
            )
            .await
            .unwrap();
        let three_member_roster = vec![
            alice_credential.clone(),
            bob_credential.clone(),
            charlie_credential.clone(),
        ];
        assert_eq!(
            bob.apply_inbound_commit(group_id, &second_commit.commit, &three_member_roster,)
                .await
                .unwrap()
                .epoch,
            2
        );
        assert_eq!(
            charlie
                .join_from_welcome(
                    group_id,
                    second_commit.welcome.as_deref().unwrap(),
                    &three_member_roster,
                )
                .await
                .unwrap()
                .epoch,
            2
        );
        assert_eq!(
            alice
                .merge_pending_commit(group_id, &second_commit.commit_hash)
                .await
                .unwrap()
                .epoch,
            2
        );
        let bob_epoch_two_capability = bob
            .derive_delivery_capability(group_id, Uuid::from_u128(77), 1, &bob_address)
            .await
            .unwrap();
        assert_ne!(
            bob_epoch_two_capability.capability,
            bob_epoch_one_capability.capability
        );

        let removal = alice
            .prepare_remove_members(group_id, &["charlie@example.test#1".to_owned()])
            .await
            .unwrap();
        assert!(removal.welcome.is_none());
        assert_eq!(
            bob.apply_inbound_commit(
                group_id,
                &removal.commit,
                &[alice_credential.clone(), bob_credential.clone()],
            )
            .await
            .unwrap()
            .epoch,
            3
        );
        assert_eq!(
            alice
                .merge_pending_commit(group_id, &removal.commit_hash)
                .await
                .unwrap()
                .epoch,
            3
        );

        let outbound = alice
            .create_application_message(
                "16811fc6-27b8-4f32-81c4-c3888ca60f5e",
                *b"conversation-id!",
                1,
                group_id,
                b"hello from alice",
                1_700_000_000_000,
            )
            .await
            .unwrap();
        let decrypted = bob
            .decrypt_application_message(group_id, &outbound.ciphertext, &alice_credential)
            .await
            .unwrap();
        assert_eq!(decrypted.plaintext, b"hello from alice");
        assert_eq!(decrypted.epoch, 3);

        let forged = VerifiedMlsCredential::new(
            "alice@example.test#1".into(),
            bob_credential.credential_public_key.clone(),
        )
        .unwrap();
        let second = alice
            .create_application_message(
                "a7e832e9-bfc6-4560-ae65-9bce2e9c2294",
                *b"conversation-id!",
                1,
                group_id,
                b"manifest mismatch",
                1_700_000_000_001,
            )
            .await
            .unwrap();
        assert!(matches!(
            bob.decrypt_application_message(group_id, &second.ciphertext, &forged)
                .await,
            Err(ChatError::Trust(_))
        ));
    });
}
