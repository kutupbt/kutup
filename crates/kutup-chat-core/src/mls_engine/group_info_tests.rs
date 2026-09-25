//! The group's name, description and picture: set at creation, changed by
//! an administrator, delivered to members, refused to members unless the
//! group's private policy allows them.

use super::*;
use crate::SqliteChatDb;
use ed25519_dalek::SigningKey;
use kutup_chat_proto::{MlsGroupAvatarV1, MlsGroupInfoEditorsV1};

fn ordering_policy(domain: &str, signer: &SigningKey) -> MlsOrderingServicePolicyV1 {
    let public_key = signer.verifying_key().to_bytes();
    MlsOrderingServicePolicyV1 {
        policy_version: kutup_chat_proto::MLS_ORDERING_SERVICE_POLICY_VERSION,
        canonical_domain: domain.into(),
        suite: MlsCipherSuiteId::Mls128DhKemX25519ChaCha20Poly1305Sha256Ed25519,
        anonymous_delivery_suite:
            kutup_chat_proto::MlsAnonymousDeliverySuiteV1::DhKemX25519HkdfSha256ChaCha20Poly1305,
        control_signing_key_id: hex::encode(Sha256::digest(public_key)),
        control_signing_public_key: BASE64.encode(public_key),
        accepts_group_ordering: true,
        maximum_group_members: 256,
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

fn acknowledgement(
    conversation_id: Uuid,
    request: &CommitMlsControlBlockV1,
) -> CommitMlsControlBlockResponseV1 {
    let block = &request.finalized.block;
    CommitMlsControlBlockResponseV1 {
        conversation_id,
        incarnation: 1,
        height: block.height,
        epoch: block.epoch_after,
        block_hash: block.block_hash().unwrap(),
        idempotent: false,
    }
}

fn info(sequence: u64, name: &str) -> MlsGroupInfoV1 {
    MlsGroupInfoV1 {
        sequence,
        name: name.into(),
        description: String::new(),
        avatar: None,
    }
}

/// The Commit envelope one destination receives from a pending change.
fn envelope_for(
    control: &PendingMlsMembershipChange,
    destination: &str,
    cursor: u64,
) -> (MlsControlEnvelopeContext, Vec<u8>) {
    let envelope = control
        .deliveries
        .iter()
        .find(|delivery| delivery.destination == destination)
        .unwrap()
        .envelopes
        .first()
        .unwrap();
    (
        MlsControlEnvelopeContext {
            envelope_id: envelope.envelope_id,
            cursor: cursor.to_string(),
            send_id: envelope.envelope_id,
        },
        BASE64.decode(&envelope.opaque_message).unwrap(),
    )
}

#[test]
fn group_information_is_named_at_creation_changed_by_its_editors_and_delivered() {
    futures_executor::block_on(async {
        let authority_signer = SigningKey::from_bytes(&[91; 32]);
        let now = crate::clock::unix_millis() / 1000;
        let alice = MlsClient::new(Rc::new(SqliteChatDb::open_in_memory().unwrap()));
        let alice_public = alice.initialize("alice@alpha.example#1").await.unwrap();
        let conversation_id = Uuid::from_u128(0x91);
        let group_id = b"named-group-id!!";

        // An invalid name is refused before anything is staged.
        assert!(alice
            .prepare_group_genesis_with_info(
                conversation_id,
                group_id,
                "alice@alpha.example".parse().unwrap(),
                &[ordering_policy("alpha.example", &authority_signer)],
                now,
                Some(info(1, " spaced ")),
            )
            .await
            .is_err());
        let prepared = alice
            .prepare_group_genesis_with_info(
                conversation_id,
                group_id,
                "alice@alpha.example".parse().unwrap(),
                &[ordering_policy("alpha.example", &authority_signer)],
                now,
                Some(info(1, "Hikers")),
            )
            .await
            .unwrap();
        assert_eq!(
            prepared.conversation.current_group_info,
            Some(info(1, "Hikers"))
        );
        let genesis_hash = prepared
            .conversation
            .request
            .genesis
            .genesis_hash()
            .unwrap();
        alice
            .mark_group_genesis_published(conversation_id, &genesis_hash)
            .await
            .unwrap();
        let active = alice.local_conversations().await.unwrap().remove(0);

        // Bob joins and learns the name from his Welcome.
        let bob = MlsClient::new(Rc::new(SqliteChatDb::open_in_memory().unwrap()));
        let bob_public = bob.initialize("bob@beta.example#1").await.unwrap();
        let bob_package = VerifiedMlsKeyPackage {
            wire: bob
                .generate_key_package(1, 1, now, now + 86_400)
                .await
                .unwrap(),
            credential: VerifiedMlsCredential::new(
                "bob@beta.example#1".into(),
                bob_public.credential_public_key.clone(),
            )
            .unwrap(),
            anonymous_delivery_public_key: bob_public.anonymous_delivery_public_key.clone(),
        };
        let roster = vec![
            active.current_roster[0].clone(),
            MlsConversationMemberV1 {
                address: "bob@beta.example".parse().unwrap(),
                is_admin: false,
                owner_id: None,
            },
        ];
        let expected_roster = vec![
            VerifiedMlsCredential::new(
                "alice@alpha.example#1".into(),
                alice_public.credential_public_key,
            )
            .unwrap(),
            bob_package.credential.clone(),
        ];
        let membership = alice
            .prepare_membership_change(
                group_id,
                Uuid::from_u128(0x92),
                &roster,
                &[bob_package],
                now + 1,
            )
            .await
            .unwrap();
        let membership_request = alice
            .build_membership_commit_request(
                group_id,
                certificate(&membership.control.vote_request, &authority_signer),
            )
            .await
            .unwrap();
        alice
            .finalize_membership_change(
                group_id,
                &acknowledgement(conversation_id, &membership_request),
            )
            .await
            .unwrap();
        let (welcome_context, welcome) = envelope_for(&membership.control, "beta.example", 1);
        let history = MlsClientControlHistoryPageV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            genesis: prepared.conversation.request.genesis.clone(),
            genesis_participant_domains: vec!["alpha.example".into()],
            after_height: "0".into(),
            commits: vec![membership_request],
            next_height: Some("1".into()),
        };
        let joined = bob
            .join_from_welcome_with_control_history(
                &welcome_context,
                group_id,
                &welcome,
                &expected_roster,
                &[history.canonical_bytes().unwrap()],
            )
            .await
            .unwrap();
        assert_eq!(
            joined.conversation.current_group_info,
            Some(info(1, "Hikers"))
        );

        // Bob is not an administrator: by default he may not rename.
        assert!(matches!(
            bob.prepare_group_info_change(group_id, Uuid::from_u128(0x93), info(2, "Bob's"), now + 2)
                .await,
            Err(ChatError::Trust(message)) if message.contains("only administrators")
        ));

        // Alice renames, with a description and picture; Bob receives it.
        let renamed = MlsGroupInfoV1 {
            sequence: 2,
            name: "Hikers 2026".into(),
            description: "Saturday walks".into(),
            avatar: Some(MlsGroupAvatarV1 {
                content_type: "image/png".into(),
                data: BASE64.encode([1u8; 64]),
            }),
        };
        // Not the next sequence, or no actual change: refused.
        assert!(alice
            .prepare_group_info_change(
                group_id,
                Uuid::from_u128(0x94),
                MlsGroupInfoV1 {
                    sequence: 3,
                    ..renamed.clone()
                },
                now + 2
            )
            .await
            .is_err());
        assert!(alice
            .prepare_group_info_change(group_id, Uuid::from_u128(0x94), info(2, "Hikers"), now + 2)
            .await
            .is_err());
        let change = alice
            .prepare_group_info_change(group_id, Uuid::from_u128(0x95), renamed.clone(), now + 2)
            .await
            .unwrap();
        assert_eq!(
            change.control.vote_request.block.proposal.action_type,
            MlsControlActionTypeV1::GroupInfoChange
        );
        let request = alice
            .build_membership_commit_request(
                group_id,
                certificate(&change.control.vote_request, &authority_signer),
            )
            .await
            .unwrap();
        let finalized = alice
            .finalize_membership_change(group_id, &acknowledgement(conversation_id, &request))
            .await
            .unwrap();
        assert_eq!(
            finalized.conversation.current_group_info,
            Some(renamed.clone())
        );
        let (context, commit) = envelope_for(&change.control, "beta.example", 2);
        let applied = bob
            .apply_ordered_inbound_membership_commit(
                &context,
                group_id,
                &commit,
                &expected_roster,
                &request,
            )
            .await
            .unwrap();
        assert_eq!(
            applied.conversation.current_group_info,
            Some(renamed.clone())
        );

        // Alice (the only owner) opens editing to members.
        let open_policy = MlsGroupAuthorizationPolicyV1 {
            sequence: 2,
            group_info_editors: MlsGroupInfoEditorsV1::Members,
            ..MlsGroupAuthorizationPolicyV1::members_default()
        };
        let pending = alice
            .prepare_authorization_policy_change(
                group_id,
                Uuid::from_u128(0x96),
                open_policy.clone(),
                now + 3,
            )
            .await
            .unwrap();
        assert!(alice
            .policy_change_has_owner_quorum(group_id)
            .await
            .unwrap());
        let request = alice
            .build_policy_commit_request(
                group_id,
                certificate(&pending.control.vote_request, &authority_signer),
            )
            .await
            .unwrap();
        alice
            .finalize_policy_change(group_id, &acknowledgement(conversation_id, &request))
            .await
            .unwrap();
        let envelope = pending
            .control
            .deliveries
            .iter()
            .find(|delivery| delivery.destination == "beta.example")
            .unwrap()
            .envelopes
            .first()
            .unwrap();
        let applied = bob
            .apply_ordered_inbound_membership_commit(
                &MlsControlEnvelopeContext {
                    envelope_id: envelope.envelope_id,
                    cursor: "3".into(),
                    send_id: envelope.envelope_id,
                },
                group_id,
                &BASE64.decode(&envelope.opaque_message).unwrap(),
                &expected_roster,
                &request,
            )
            .await
            .unwrap();
        assert_eq!(
            applied.conversation.current_authorization_policy,
            open_policy
        );

        // Now Bob may rename; Alice accepts his change.
        let bobs = info(3, "Bob's walks");
        let change = bob
            .prepare_group_info_change(group_id, Uuid::from_u128(0x97), bobs.clone(), now + 4)
            .await
            .unwrap();
        let request = bob
            .build_membership_commit_request(
                group_id,
                certificate(&change.control.vote_request, &authority_signer),
            )
            .await
            .unwrap();
        bob.finalize_membership_change(group_id, &acknowledgement(conversation_id, &request))
            .await
            .unwrap();
        let (context, commit) = envelope_for(&change.control, "alpha.example", 1);
        let applied = alice
            .apply_ordered_inbound_membership_commit(
                &context,
                group_id,
                &commit,
                &expected_roster,
                &request,
            )
            .await
            .unwrap();
        assert_eq!(applied.conversation.current_group_info, Some(bobs));
    });
}
