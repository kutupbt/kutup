//! Focused restart and fail-closed tests for private MLS group policy.

use super::*;
use crate::SqliteChatDb;
use ed25519_dalek::SigningKey;

fn ordering_policy(domain: &str, signer: &SigningKey) -> MlsOrderingServicePolicyV1 {
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

fn certificate(
    vote_request: &FederatedMlsOrderingVoteRequestV1,
    signer: &SigningKey,
) -> MlsOrderingQuorumCertificateV1 {
    let block = &vote_request.block;
    let authority = &vote_request.authority_set.authorities[0];
    let block_hash = block.block_hash().unwrap();
    let mut vote = kutup_chat_proto::MlsOrderingVoteV1 {
        conversation_id: block.conversation_id,
        incarnation: block.incarnation,
        authority_set_sequence: vote_request.authority_set.sequence,
        height: block.height,
        round: 0,
        vote_type: kutup_chat_proto::MlsOrderingVoteTypeV1::Precommit,
        block_hash: block_hash.clone(),
        authority_domain: authority.domain.clone(),
        authority_key_id: authority.key_id.clone(),
        signature: String::new(),
    };
    vote.signature = BASE64.encode(signer.sign(&vote.signing_bytes().unwrap()).to_bytes());
    MlsOrderingQuorumCertificateV1 {
        authority_set_sequence: vote_request.authority_set.sequence,
        height: block.height,
        round: 0,
        block_hash,
        votes: vec![vote],
    }
}

#[test]
fn private_policy_changes_are_restart_safe_contiguous_and_enforced() {
    futures_executor::block_on(async {
        let path = std::env::temp_dir().join(format!(
            "kutup-openmls-policy-{}.db",
            crate::clock::unix_millis()
        ));
        let authority_signer = SigningKey::from_bytes(&[77; 32]);
        let now = crate::clock::unix_millis() / 1000;
        let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(db.clone());
        let alice_public = client.initialize("alice@alpha.example#1").await.unwrap();
        let conversation_id = Uuid::from_u128(0xc1);
        let group_id = b"policy-group-id!";
        let prepared = client
            .prepare_group_genesis(
                conversation_id,
                group_id,
                "alice@alpha.example".parse().unwrap(),
                &[ordering_policy("alpha.example", &authority_signer)],
                now,
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
        let active = client.local_conversations().await.unwrap().remove(0);
        let bob_db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open_in_memory().unwrap());
        let bob = MlsClient::new(bob_db);
        let bob_public = bob.initialize("bob@beta.example#1").await.unwrap();
        let bob_package = bob
            .generate_key_package(1, 1, now, now + 86_400)
            .await
            .unwrap();
        let bob_package = VerifiedMlsKeyPackage {
            wire: bob_package,
            credential: VerifiedMlsCredential::new(
                "bob@beta.example#1".into(),
                bob_public.credential_public_key.clone(),
            )
            .unwrap(),
            anonymous_delivery_public_key: bob_public.anonymous_delivery_public_key.clone(),
        };
        let bob_credential = bob_package.credential.clone();
        let next_roster = vec![
            active.current_roster[0].clone(),
            MlsConversationMemberV1 {
                address: "bob@beta.example".parse().unwrap(),
                is_admin: false,
                owner_id: None,
            },
        ];
        let membership = client
            .prepare_membership_change(
                group_id,
                Uuid::from_u128(0xc0),
                &next_roster,
                &[bob_package],
                now + 1,
            )
            .await
            .unwrap();
        let membership_request = client
            .build_membership_commit_request(
                group_id,
                certificate(&membership.control.vote_request, &authority_signer),
            )
            .await
            .unwrap();
        let membership_block = &membership_request.finalized.block;
        client
            .finalize_membership_change(
                group_id,
                &CommitMlsControlBlockResponseV1 {
                    conversation_id,
                    incarnation: 1,
                    height: membership_block.height,
                    epoch: membership_block.epoch_after,
                    block_hash: membership_block.block_hash().unwrap(),
                    idempotent: false,
                },
            )
            .await
            .unwrap();
        let welcome_envelope = membership
            .control
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "beta.example")
            .unwrap()
            .envelopes
            .first()
            .unwrap();
        let welcome = BASE64.decode(&welcome_envelope.opaque_message).unwrap();
        let expected_roster = vec![
            VerifiedMlsCredential::new(
                "alice@alpha.example#1".into(),
                alice_public.credential_public_key,
            )
            .unwrap(),
            bob_credential,
        ];
        let history = MlsClientControlHistoryPageV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            genesis: prepared.conversation.request.genesis.clone(),
            genesis_participant_domains: vec!["alpha.example".into()],
            after_height: "0".into(),
            commits: vec![membership_request],
            next_height: Some("1".into()),
        };
        bob.join_from_welcome_with_control_history(
            &MlsControlEnvelopeContext {
                envelope_id: welcome_envelope.envelope_id,
                cursor: "1".into(),
                send_id: welcome_envelope.envelope_id,
            },
            group_id,
            &welcome,
            &expected_roster,
            &[history.canonical_bytes().unwrap()],
        )
        .await
        .unwrap();

        let authorization = MlsGroupAuthorizationPolicyV1 {
            policy_version: 1,
            sequence: 2,
            application_senders: MlsApplicationSenderPolicyV1::Administrators,
        };
        let pending = client
            .prepare_authorization_policy_change(
                group_id,
                Uuid::from_u128(0xc2),
                authorization.clone(),
                now + 2,
            )
            .await
            .unwrap();
        assert!(client.policy_change_has_owner_quorum(group_id).await.unwrap());
        assert_eq!(
            client.pending_policy_changes().await.unwrap(),
            vec![pending.control.clone()]
        );

        drop(client);
        drop(db);
        let db: Rc<dyn ChatDb> = Rc::new(SqliteChatDb::open(&path).unwrap());
        let client = MlsClient::new(db.clone());
        client.initialize("alice@alpha.example#1").await.unwrap();
        assert_eq!(
            client.pending_policy_changes().await.unwrap(),
            vec![pending.control.clone()]
        );
        let request = client
            .build_policy_commit_request(
                group_id,
                certificate(&pending.control.vote_request, &authority_signer),
            )
            .await
            .unwrap();
        let block = &request.finalized.block;
        let bob_policy_envelope = pending
            .control
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "beta.example")
            .unwrap()
            .envelopes
            .first()
            .unwrap();
        let bob_policy_commit = BASE64
            .decode(&bob_policy_envelope.opaque_message)
            .unwrap();
        let acknowledgement = CommitMlsControlBlockResponseV1 {
            conversation_id,
            incarnation: 1,
            height: block.height,
            epoch: block.epoch_after,
            block_hash: block.block_hash().unwrap(),
            idempotent: false,
        };
        let finalized = client
            .finalize_policy_change(group_id, &acknowledgement)
            .await
            .unwrap();
        assert_eq!(
            finalized.conversation.current_authorization_policy,
            authorization
        );
        let replay = client
            .finalize_policy_change(group_id, &acknowledgement)
            .await
            .unwrap();
        assert_eq!(
            replay.conversation.current_authorization_policy,
            authorization
        );
        let bob_applied = bob
            .apply_ordered_inbound_membership_commit(
                &MlsControlEnvelopeContext {
                    envelope_id: bob_policy_envelope.envelope_id,
                    cursor: "2".into(),
                    send_id: bob_policy_envelope.envelope_id,
                },
                group_id,
                &bob_policy_commit,
                &expected_roster,
                &request,
            )
            .await
            .unwrap();
        assert_eq!(
            bob_applied.conversation.current_authorization_policy,
            authorization
        );
        assert!(matches!(
            bob.create_application_message(
                "ac770e49-80c5-4d90-81cf-73095c4af014",
                *conversation_id.as_bytes(),
                1,
                group_id,
                b"blocked non-admin message",
                (now + 3) * 1000,
            )
            .await,
            Err(ChatError::Trust(message))
                if message.contains("not permitted by group policy")
        ));
        assert!(client.pending_policy_changes().await.unwrap().is_empty());

        let cryptographic = MlsGroupCryptographicPolicyV1 {
            sequence: 2,
            maximum_application_plaintext_bytes: 1024,
            ..MlsGroupCryptographicPolicyV1::v1_default()
        };
        let pending = client
            .prepare_cryptographic_policy_change(
                group_id,
                Uuid::from_u128(0xc3),
                cryptographic.clone(),
                now + 3,
            )
            .await
            .unwrap();
        let request = client
            .build_policy_commit_request(
                group_id,
                certificate(&pending.control.vote_request, &authority_signer),
            )
            .await
            .unwrap();
        let block = &request.finalized.block;
        let finalized = client
            .finalize_policy_change(
                group_id,
                &CommitMlsControlBlockResponseV1 {
                    conversation_id,
                    incarnation: 1,
                    height: block.height,
                    epoch: block.epoch_after,
                    block_hash: block.block_hash().unwrap(),
                    idempotent: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            finalized.conversation.current_cryptographic_policy,
            cryptographic
        );

        let oversized = vec![b'x'; 1025];
        assert!(matches!(
            client
                .create_application_message(
                    "24dca878-9b75-4bc6-8767-d25d16689f34",
                    *conversation_id.as_bytes(),
                    1,
                    group_id,
                    &oversized,
                    (now + 4) * 1000,
                )
                .await,
            Err(ChatError::Invalid(message))
                if message.contains("authenticated group policy")
        ));
        let non_contiguous = MlsGroupAuthorizationPolicyV1 {
            policy_version: 1,
            sequence: 4,
            application_senders: MlsApplicationSenderPolicyV1::Members,
        };
        assert!(client
            .prepare_authorization_policy_change(
                group_id,
                Uuid::from_u128(0xc4),
                non_contiguous,
                now + 5,
            )
            .await
            .is_err());
    });
}
