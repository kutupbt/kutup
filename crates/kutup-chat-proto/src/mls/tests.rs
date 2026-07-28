//! Protocol vectors and adversarial validation tests.

use super::*;
use std::collections::BTreeMap;

fn authority(domain: &str, seed: u8) -> (MlsAuthorityV1, SigningKey) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes());
    (
        MlsAuthorityV1 {
            domain: domain.into(),
            key_id: hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
            public_key,
        },
        key,
    )
}

fn authority_set(count: usize) -> (MlsAuthoritySetV1, BTreeMap<String, SigningKey>) {
    let mut authorities = Vec::new();
    let mut keys = BTreeMap::new();
    for index in 0..count {
        let domain = format!("a{index}.example");
        let (authority, key) = authority(&domain, (index + 1) as u8);
        keys.insert(domain, key);
        authorities.push(authority);
    }
    (
        MlsAuthoritySetV1 {
            sequence: 1,
            required_quorum: MlsAuthoritySetV1::quorum_for(count).unwrap(),
            authorities,
        },
        keys,
    )
}

#[test]
fn suite_is_exactly_wire_suite_zero_x_two() {
    assert_eq!(
        serde_json::to_string(&MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256).unwrap(),
        "2"
    );
    assert!(
        serde_json::from_str::<MlsCipherSuiteId>("1").is_err(),
        "the old direct-chat suite must not be accepted as MLS"
    );
}

#[test]
fn invitation_feedback_has_one_canonical_vector() {
    let feedback = MlsInvitationFeedbackV1 {
        protocol_version: MLS_INVITATION_FEEDBACK_VERSION,
        conversation_id: Uuid::parse_str("4cc2114c-8015-4e78-9af8-2f5f71c18cf1").unwrap(),
        incarnation: 3,
        member: "bob@b.example".parse().unwrap(),
        invited_epoch: 9,
        decision: MlsInvitationFeedbackDecisionV1::Rejected,
        decided_at: 1_785_249_600,
    };
    let expected = br#"{"protocolVersion":1,"conversationId":"4cc2114c-8015-4e78-9af8-2f5f71c18cf1","incarnation":3,"member":{"username":"bob","server":"b.example"},"invitedEpoch":9,"decision":"rejected","decidedAt":1785249600}"#;
    assert_eq!(feedback.canonical_bytes().unwrap(), expected);
    assert_eq!(
        feedback.feedback_digest().unwrap(),
        "93a7802652346c4dacc3964ef7a123c82e2db750c1f2b1e6438e8595e592bbb0"
    );

    let mut malformed = feedback;
    malformed.member = "bob".parse().unwrap();
    assert!(malformed.validate().is_err());
}

#[test]
fn quorum_formula_covers_small_and_large_sets() {
    let expected = [(1, 1), (2, 2), (3, 3), (4, 3), (7, 5), (10, 7), (64, 43)];
    for (count, quorum) in expected {
        assert_eq!(MlsAuthoritySetV1::quorum_for(count).unwrap(), quorum);
    }
    assert!(MlsAuthoritySetV1::quorum_for(0).is_err());
    assert!(MlsAuthoritySetV1::quorum_for(65).is_err());
}

#[test]
fn owner_candidate_has_a_stable_signing_vector_and_sender_binding() {
    let signer = SigningKey::from_bytes(&[9; 32]);
    let public_key = signer.verifying_key().to_bytes();
    let mut candidate = MlsOwnerCandidateV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id: Uuid::from_u128(0x1234),
        incarnation: 7,
        account: "alice@alpha.example".parse().unwrap(),
        owner_id: hex::encode(Sha256::digest(public_key)),
        public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
        created_at: 1_700_000_000,
        signature: String::new(),
    };
    let signing_bytes = candidate.signing_bytes().unwrap();
    assert_eq!(
        hex::encode(&signing_bytes),
        "6b757475702d6d6c732d6f776e65722d63616e6469646174652d763100000100000000000000000000000000001234000000000000000700000013616c69636540616c7068612e6578616d706c6500000040646263323938323531633531333231623732363665373864316331353163326236326166663863623935623239333039366433343633303138353434666163650000002c2f52636b4f4671677831746b2b336a4e59432b68325a4839362f64724538574f31774c71794458703968673d000000006553f100"
    );
    candidate.signature =
        base64::engine::general_purpose::STANDARD.encode(signer.sign(&signing_bytes).to_bytes());
    candidate.verify().unwrap();

    let body = MlsGroupControlBodyV1::OwnerCandidate {
        candidate: candidate.clone(),
    };
    assert_eq!(
        serde_json::from_slice::<MlsGroupControlBodyV1>(&serde_json::to_vec(&body).unwrap())
            .unwrap(),
        body
    );
    candidate.account = "mallory@alpha.example".parse().unwrap();
    assert!(candidate.verify().is_err());
}

#[test]
fn owner_approval_cannot_be_replayed_for_a_substituted_transition() {
    use p256::ecdsa::signature::Signer as _;

    let conversation_id = Uuid::from_u128(0x2234);
    let proposer_key = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let proposer_public = proposer_key.verifying_key().to_encoded_point(false);
    let payload = b"encrypted owner transition";
    let mut proposal = MlsControlProposalV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 3,
        proposal_id: Uuid::from_u128(0x2235),
        base_epoch: 8,
        action_type: MlsControlActionTypeV1::OwnerSetChange,
        proposer_id: hex::encode(Sha256::digest(proposer_public.as_bytes())),
        proposer_credential_public_key: base64::engine::general_purpose::STANDARD
            .encode(proposer_public.as_bytes()),
        encrypted_payload: base64::engine::general_purpose::STANDARD.encode(payload),
        payload_digest: hex::encode(Sha256::digest(payload)),
        created_at: 1_700_000_001,
        proposer_signature: String::new(),
    };
    let signature: p256::ecdsa::Signature = proposer_key.sign(&proposal.signing_bytes().unwrap());
    proposal.proposer_signature =
        base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());

    let owner_key = SigningKey::from_bytes(&[11; 32]);
    let owner = MlsOwnerV1 {
        owner_id: hex::encode(Sha256::digest(owner_key.verifying_key().as_bytes())),
        public_key: base64::engine::general_purpose::STANDARD
            .encode(owner_key.verifying_key().as_bytes()),
    };
    let second_owner_key = SigningKey::from_bytes(&[12; 32]);
    let second_owner = MlsOwnerV1 {
        owner_id: hex::encode(Sha256::digest(second_owner_key.verifying_key().as_bytes())),
        public_key: base64::engine::general_purpose::STANDARD
            .encode(second_owner_key.verifying_key().as_bytes()),
    };
    let mut declared_owners = vec![owner.clone(), second_owner.clone()];
    declared_owners.sort_by(|left, right| left.owner_id.cmp(&right.owner_id));
    let owners = MlsOwnerSetV1 {
        sequence: 4,
        owners: declared_owners,
        required_quorum: 2,
    };
    let transition_digest = "aa".repeat(32);
    let proposal_hash = proposal.proposal_hash().unwrap();
    let mut approval = MlsOwnerApprovalV1 {
        conversation_id,
        incarnation: 3,
        owner_set_sequence: owners.sequence,
        proposal_hash: proposal_hash.clone(),
        transition_digest: Some(transition_digest.clone()),
        owner_id: owner.owner_id,
        approved_at: 1_700_000_002,
        signature: String::new(),
    };
    approval.signature = base64::engine::general_purpose::STANDARD.encode(
        owner_key
            .sign(&approval.signing_bytes().unwrap())
            .to_bytes(),
    );
    let mut certificate = MlsOwnerApprovalCertificateV1 {
        owner_set_sequence: owners.sequence,
        proposal_hash,
        transition_digest: Some(transition_digest.clone()),
        approvals: vec![approval],
    };
    certificate
        .verify_partial(&proposal, Some(&transition_digest), &owners)
        .unwrap();
    assert_eq!(
        certificate
            .verify(&proposal, Some(&transition_digest), &owners)
            .unwrap_err(),
        "MLS owner certificate does not meet quorum"
    );
    let mut second_approval = MlsOwnerApprovalV1 {
        conversation_id,
        incarnation: 3,
        owner_set_sequence: owners.sequence,
        proposal_hash: certificate.proposal_hash.clone(),
        transition_digest: Some(transition_digest.clone()),
        owner_id: second_owner.owner_id,
        approved_at: 1_700_000_003,
        signature: String::new(),
    };
    second_approval.signature = base64::engine::general_purpose::STANDARD.encode(
        second_owner_key
            .sign(&second_approval.signing_bytes().unwrap())
            .to_bytes(),
    );
    certificate.approvals.push(second_approval);
    certificate
        .approvals
        .sort_by(|left, right| left.owner_id.cmp(&right.owner_id));
    certificate
        .verify(&proposal, Some(&transition_digest), &owners)
        .unwrap();
    assert!(certificate
        .verify(&proposal, Some(&"bb".repeat(32)), &owners)
        .is_err());
    let mut substituted = certificate;
    substituted.transition_digest = Some("bb".repeat(32));
    assert!(substituted
        .verify(&proposal, substituted.transition_digest.as_deref(), &owners)
        .is_err());
}

#[test]
fn owner_approval_request_has_one_exact_private_transition_vector() {
    use p256::ecdsa::signature::Signer as _;

    let conversation_id = Uuid::from_u128(0x3234);
    let proposal_id = Uuid::from_u128(0x3235);
    let owner_key = SigningKey::from_bytes(&[21; 32]);
    let owner = MlsOwnerV1 {
        owner_id: hex::encode(Sha256::digest(owner_key.verifying_key().as_bytes())),
        public_key: base64::engine::general_purpose::STANDARD
            .encode(owner_key.verifying_key().as_bytes()),
    };
    let next_roster = vec![
        MlsConversationMemberV1 {
            address: "alice@a0.example".parse().unwrap(),
            is_admin: true,
            owner_id: Some(owner.owner_id.clone()),
        },
        MlsConversationMemberV1 {
            address: "bobby@a1.example".parse().unwrap(),
            is_admin: false,
            owner_id: None,
        },
    ];
    let transition = MlsMembershipTransitionV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 2,
        proposal_id,
        previous_roster_commitment: "01".repeat(32),
        next_roster_commitment: roster_commitment(&next_roster).unwrap(),
        previous_member_count: 2,
        next_member_count: 2,
        previous_participant_domains: vec!["a0.example".into(), "a1.example".into()],
        next_participant_domains: vec!["a0.example".into(), "a1.example".into()],
        deliveries: vec![
            MlsMembershipDeliveryCommitmentV1 {
                destination: "a0.example".into(),
                delivery_digest: "02".repeat(32),
            },
            MlsMembershipDeliveryCommitmentV1 {
                destination: "a1.example".into(),
                delivery_digest: "03".repeat(32),
            },
        ],
    };
    let owner_change = MlsOwnerChangeV1 {
        next_owner_set: MlsOwnerSetV1 {
            sequence: 5,
            owners: vec![owner],
            required_quorum: 1,
        },
        delivery_transition: transition,
    };
    let proposer_key = p256::ecdsa::SigningKey::from_bytes((&[22u8; 32]).into()).unwrap();
    let proposer_public = proposer_key.verifying_key().to_encoded_point(false);
    let payload = b"encrypted exact owner transition";
    let mut proposal = MlsControlProposalV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 2,
        proposal_id,
        base_epoch: 9,
        action_type: MlsControlActionTypeV1::OwnerSetChange,
        proposer_id: hex::encode(Sha256::digest(proposer_public.as_bytes())),
        proposer_credential_public_key: base64::engine::general_purpose::STANDARD
            .encode(proposer_public.as_bytes()),
        encrypted_payload: base64::engine::general_purpose::STANDARD.encode(payload),
        payload_digest: hex::encode(Sha256::digest(payload)),
        created_at: 1_700_000_100,
        proposer_signature: String::new(),
    };
    let signature: p256::ecdsa::Signature = proposer_key.sign(&proposal.signing_bytes().unwrap());
    proposal.proposer_signature =
        base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
    let request = MlsOwnerApprovalRequestV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        owner_set_sequence: 4,
        proposal,
        transition_digest: owner_change.transition_digest().unwrap(),
        owner_change: Some(owner_change),
        membership_transition: None,
        incarnation_recovery: None,
        next_authorization_policy: None,
        next_cryptographic_policy: None,
        next_roster,
        requested_at: 1_700_000_100,
        expires_at: 1_700_086_500,
    };
    request.validate().unwrap();
    assert_eq!(
        request.request_hash().unwrap(),
        "10b612e60ba0e5214a464b6d39b61019c30b5ef1273df12935d5d26d8e92c7a0"
    );
    let encoded = serde_json::to_vec(&request).unwrap();
    let decoded: MlsOwnerApprovalRequestV1 = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, request);

    let mut close_transition = request
        .owner_change
        .as_ref()
        .unwrap()
        .delivery_transition
        .clone();
    close_transition.previous_roster_commitment = close_transition.next_roster_commitment.clone();
    let mut close_proposal = request.proposal.clone();
    close_proposal.action_type = MlsControlActionTypeV1::CloseConversation;
    close_proposal.proposer_signature.clear();
    let signature: p256::ecdsa::Signature =
        proposer_key.sign(&close_proposal.signing_bytes().unwrap());
    close_proposal.proposer_signature =
        base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
    let close_request = MlsOwnerApprovalRequestV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        owner_set_sequence: 4,
        proposal: close_proposal.clone(),
        transition_digest: close_transition.transition_digest().unwrap(),
        owner_change: None,
        membership_transition: Some(close_transition.clone()),
        incarnation_recovery: None,
        next_authorization_policy: None,
        next_cryptographic_policy: None,
        next_roster: request.next_roster.clone(),
        requested_at: 1_700_000_100,
        expires_at: 1_700_086_500,
    };
    close_request.validate().unwrap();
    let close_block = MlsControlBlockV1 {
        conversation_id,
        incarnation: 2,
        height: 10,
        previous_block_hash: Some("04".repeat(32)),
        epoch_before: 9,
        epoch_after: 10,
        proposal: close_proposal,
        transition_digest: Some(close_transition.transition_digest().unwrap()),
        owner_approval: None,
        finalized_at: 1_700_000_101,
    };
    CommitMlsControlBlockV1 {
        finalized: MlsFinalizedControlBlockV1 {
            block: close_block,
            quorum_certificate: MlsOrderingQuorumCertificateV1 {
                authority_set_sequence: 1,
                height: 10,
                round: 0,
                block_hash: "05".repeat(32),
                votes: vec![],
            },
        },
        membership_transition: Some(close_transition),
        authority_change: None,
        authority_transition: None,
        owner_change: None,
    }
    .validate_shape()
    .unwrap();

    let mut substituted = request;
    substituted.next_roster[1].is_admin = true;
    assert!(substituted.validate().is_err());
}

#[test]
fn incarnation_recovery_is_owner_bound_append_only_and_destination_private() {
    use p256::ecdsa::signature::Signer as _;

    let conversation_id = Uuid::from_u128(0x7331);
    let proposal_id = Uuid::from_u128(0x7332);
    let owner_key = SigningKey::from_bytes(&[31; 32]);
    let owner = MlsOwnerV1 {
        owner_id: hex::encode(Sha256::digest(owner_key.verifying_key().as_bytes())),
        public_key: base64::engine::general_purpose::STANDARD
            .encode(owner_key.verifying_key().as_bytes()),
    };
    let owners = MlsOwnerSetV1 {
        sequence: 7,
        owners: vec![owner.clone()],
        required_quorum: 1,
    };
    let members = vec![
        MlsConversationMemberV1 {
            address: "alice@a0.example".parse().unwrap(),
            is_admin: true,
            owner_id: Some(owner.owner_id.clone()),
        },
        MlsConversationMemberV1 {
            address: "bob@a1.example".parse().unwrap(),
            is_admin: false,
            owner_id: None,
        },
    ];
    let roster_hash = roster_commitment(&members).unwrap();
    let (authorities, _) = authority_set(3);
    let new_genesis = MlsConversationGenesisV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 4,
        mls_group_id: base64::engine::general_purpose::STANDARD.encode([44; 32]),
        kind: MlsConversationKindV1::Group,
        suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
        roster_commitment: roster_hash.clone(),
        member_count: 2,
        authority_set: authorities,
        owner_set: Some(owners.clone()),
        initial_epoch: 1,
        created_at: 1_700_001_000,
    };
    let make_delivery = |destination: &str,
                         recipient: &str,
                         device_id: u32,
                         envelope_id: u128|
     -> MlsMembershipDeliveryV1 {
        MlsMembershipDeliveryV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 4,
            proposal_id,
            destination: destination.into(),
            epoch_after: 1,
            next_roster_commitment: roster_hash.clone(),
            next_participant_domains: vec!["a0.example".into(), "a1.example".into()],
            local_members_after: members
                .iter()
                .filter(|member| member.address.server.as_deref() == Some(destination))
                .cloned()
                .collect(),
            envelopes: vec![MlsMembershipEnvelopeV1 {
                envelope_id: Uuid::from_u128(envelope_id),
                recipient: recipient.parse().unwrap(),
                device_id,
                kind: MlsMembershipEnvelopeKindV1::Welcome,
                opaque_message: base64::engine::general_purpose::STANDARD.encode(b"welcome"),
            }],
        }
    };
    let mut creator_delivery = make_delivery("a0.example", "alice@a0.example", 1, 0x7333);
    creator_delivery.envelopes.clear();
    let deliveries = vec![
        creator_delivery,
        make_delivery("a1.example", "bob@a1.example", 2, 0x7334),
    ];
    let plan = MlsIncarnationRecoveryPlanV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        previous_incarnation: 3,
        proposal_id,
        previous_genesis_hash: "11".repeat(32),
        previous_height: 9,
        previous_epoch: 9,
        previous_block_hash: Some("12".repeat(32)),
        previous_roster_commitment: roster_hash,
        participant_domains: vec!["a0.example".into(), "a1.example".into()],
        new_genesis,
        deliveries: deliveries
            .iter()
            .map(|delivery| MlsMembershipDeliveryCommitmentV1 {
                destination: delivery.destination.clone(),
                delivery_digest: delivery.delivery_digest().unwrap(),
            })
            .collect(),
    };
    let recovery_digest = plan.transition_digest().unwrap();
    let proposer_key = p256::ecdsa::SigningKey::from_bytes((&[32u8; 32]).into()).unwrap();
    let proposer_public = proposer_key.verifying_key().to_encoded_point(false);
    let payload = b"encrypted recovery approval context";
    let mut proposal = MlsControlProposalV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 3,
        proposal_id,
        base_epoch: 9,
        action_type: MlsControlActionTypeV1::RecoverIncarnation,
        proposer_id: hex::encode(Sha256::digest(proposer_public.as_bytes())),
        proposer_credential_public_key: base64::engine::general_purpose::STANDARD
            .encode(proposer_public.as_bytes()),
        encrypted_payload: base64::engine::general_purpose::STANDARD.encode(payload),
        payload_digest: hex::encode(Sha256::digest(payload)),
        created_at: 1_700_000_999,
        proposer_signature: String::new(),
    };
    let signature: p256::ecdsa::Signature = proposer_key.sign(&proposal.signing_bytes().unwrap());
    proposal.proposer_signature =
        base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
    let proposal_hash = proposal.proposal_hash().unwrap();
    let mut approval = MlsOwnerApprovalV1 {
        conversation_id,
        incarnation: 3,
        owner_set_sequence: owners.sequence,
        proposal_hash: proposal_hash.clone(),
        transition_digest: Some(recovery_digest.clone()),
        owner_id: owner.owner_id,
        approved_at: 1_700_001_001,
        signature: String::new(),
    };
    approval.signature = base64::engine::general_purpose::STANDARD.encode(
        owner_key
            .sign(&approval.signing_bytes().unwrap())
            .to_bytes(),
    );
    let recovery = MlsIncarnationRecoveryV1 {
        plan,
        proposal,
        owner_approval: MlsOwnerApprovalCertificateV1 {
            owner_set_sequence: owners.sequence,
            proposal_hash,
            transition_digest: Some(recovery_digest.clone()),
            approvals: vec![approval],
        },
    };
    recovery.verify(&owners).unwrap();
    let request = RecoverMlsConversationRequestV1 {
        recovery: recovery.clone(),
        creator: "alice@a0.example".parse().unwrap(),
        creator_device_id: 1,
        members,
        deliveries,
    };
    request.validate_shape().unwrap();
    assert_eq!(
        recovery_digest,
        "ba02112a3c75c9ea2a9e904dd8d4be028e2e5517df32fa06d18827f1945adce8"
    );

    let mut substituted = request.clone();
    substituted.deliveries[1].envelopes[0].device_id = 3;
    assert!(substituted.validate_shape().is_err());
    let mut rollback = recovery.clone();
    rollback.plan.new_genesis.incarnation = 3;
    assert!(rollback.verify(&owners).is_err());
    let mut replaced_owner = owners;
    replaced_owner.sequence += 1;
    assert!(recovery.verify(&replaced_owner).is_err());
    let mut ordinary = CreateMlsConversationRequestV1 {
        genesis: request.recovery.plan.new_genesis,
        members: request.members,
    };
    assert!(ordinary.validate().is_err());
    ordinary.genesis.incarnation = 1;
    ordinary.genesis.initial_epoch = 0;
    assert!(
        ordinary.validate().is_err(),
        "group creation stays creator-only"
    );
}

#[test]
fn direct_roster_requires_exact_participant_authorities() {
    let (authorities, _) = authority_set(2);
    let members = vec![
        MlsConversationMemberV1 {
            address: "alice@a0.example".parse().unwrap(),
            is_admin: false,
            owner_id: None,
        },
        MlsConversationMemberV1 {
            address: "bobby@a1.example".parse().unwrap(),
            is_admin: false,
            owner_id: None,
        },
    ];
    let request = CreateMlsConversationRequestV1 {
        genesis: MlsConversationGenesisV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id: Uuid::from_u128(11),
            incarnation: 1,
            mls_group_id: base64::engine::general_purpose::STANDARD.encode([7u8; 16]),
            kind: MlsConversationKindV1::Direct,
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            roster_commitment: roster_commitment(&members).unwrap(),
            member_count: 2,
            authority_set: authorities,
            owner_set: None,
            initial_epoch: 0,
            created_at: 1,
        },
        members,
    };
    request.validate().unwrap();

    let replica = FederatedMlsGenesisReplicaV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        genesis: request.genesis.clone(),
        participant_domains: vec!["a0.example".into(), "a1.example".into()],
        members: vec![request.members[0].clone()],
    };
    replica.validate().unwrap();
    let encoded = serde_json::to_string(&replica).unwrap();
    assert!(!encoded.contains("bobby"));

    let mut mixed_destination = replica;
    mixed_destination.members.push(request.members[1].clone());
    assert!(mixed_destination.validate().is_err());

    let mut wrong = request.clone();
    wrong.genesis.authority_set.authorities[1].domain = "other.example".into();
    assert!(wrong.validate().is_err());
}

#[test]
fn membership_transition_commits_destination_private_snapshots() {
    let conversation_id = Uuid::from_u128(71);
    let alice = MlsConversationMemberV1 {
        address: "alice@a0.example".parse().unwrap(),
        is_admin: true,
        owner_id: None,
    };
    let bob = MlsConversationMemberV1 {
        address: "bobby@a1.example".parse().unwrap(),
        is_admin: false,
        owner_id: None,
    };
    let previous = roster_commitment(std::slice::from_ref(&alice)).unwrap();
    let next = roster_commitment(&[alice.clone(), bob.clone()]).unwrap();
    let delivery_a = MlsMembershipDeliveryV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 1,
        proposal_id: Uuid::from_u128(72),
        destination: "a0.example".into(),
        epoch_after: 1,
        next_roster_commitment: next.clone(),
        next_participant_domains: vec!["a0.example".into(), "a1.example".into()],
        local_members_after: vec![alice],
        envelopes: Vec::new(),
    };
    let delivery_b = MlsMembershipDeliveryV1 {
        destination: "a1.example".into(),
        local_members_after: vec![bob],
        ..delivery_a.clone()
    };
    let transition = MlsMembershipTransitionV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 1,
        proposal_id: delivery_a.proposal_id,
        previous_roster_commitment: previous,
        next_roster_commitment: next,
        previous_member_count: 1,
        next_member_count: 2,
        previous_participant_domains: vec!["a0.example".into()],
        next_participant_domains: vec!["a0.example".into(), "a1.example".into()],
        deliveries: vec![
            MlsMembershipDeliveryCommitmentV1 {
                destination: "a0.example".into(),
                delivery_digest: delivery_a.delivery_digest().unwrap(),
            },
            MlsMembershipDeliveryCommitmentV1 {
                destination: "a1.example".into(),
                delivery_digest: delivery_b.delivery_digest().unwrap(),
            },
        ],
    };
    transition.validate().unwrap();
    delivery_a.verify_transition(&transition).unwrap();
    delivery_b.verify_transition(&transition).unwrap();

    let public_json = serde_json::to_string(&transition).unwrap();
    assert!(!public_json.contains("alice"));
    assert!(!public_json.contains("bobby"));

    let mut tampered = delivery_b;
    tampered.local_members_after[0].is_admin = true;
    assert!(tampered.verify_transition(&transition).is_err());
    let mut missing = transition;
    missing.deliveries.pop();
    assert!(missing.validate().is_err());
}

#[test]
fn authority_change_has_a_stable_composite_digest_and_rejects_roster_changes() {
    let conversation_id = Uuid::from_u128(73);
    let (mut next_authority_set, _) = authority_set(1);
    next_authority_set.sequence = 2;
    let transition = MlsMembershipTransitionV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 1,
        proposal_id: Uuid::from_u128(74),
        previous_roster_commitment: "aa".repeat(32),
        next_roster_commitment: "aa".repeat(32),
        previous_member_count: 2,
        next_member_count: 2,
        previous_participant_domains: vec!["a0.example".into()],
        next_participant_domains: vec!["a0.example".into()],
        deliveries: vec![MlsMembershipDeliveryCommitmentV1 {
            destination: "a0.example".into(),
            delivery_digest: "bb".repeat(32),
        }],
    };
    let change = MlsAuthorityChangeV1 {
        next_authority_set,
        delivery_transition: transition,
    };
    change.validate().unwrap();
    assert_eq!(
        change.transition_digest().unwrap(),
        "5f3cbf3bdb82c84c825c74fdee376ca018f060a07d1b44fa402fba35cddc9d9d"
    );
    let encoded = serde_json::to_vec(&change).unwrap();
    assert_eq!(
        serde_json::to_vec(&serde_json::from_slice::<MlsAuthorityChangeV1>(&encoded).unwrap())
            .unwrap(),
        encoded
    );

    let mut changed_roster = change;
    changed_roster.delivery_transition.next_roster_commitment = "cc".repeat(32);
    assert!(changed_roster.validate().is_err());
}

#[test]
fn new_participant_bootstrap_requires_complete_qc_history_and_private_digest() {
    use p256::ecdsa::signature::Signer as _;

    let conversation_id = Uuid::from_u128(81);
    let proposal_id = Uuid::from_u128(82);
    let (authorities, authority_keys) = authority_set(2);
    let alice = MlsConversationMemberV1 {
        address: "alice@a0.example".parse().unwrap(),
        is_admin: true,
        owner_id: None,
    };
    let bob = MlsConversationMemberV1 {
        address: "bobby@a1.example".parse().unwrap(),
        is_admin: false,
        owner_id: None,
    };
    let carol = MlsConversationMemberV1 {
        address: "carol@a2.example".parse().unwrap(),
        is_admin: false,
        owner_id: None,
    };
    let previous_roster = roster_commitment(&[alice.clone(), bob.clone()]).unwrap();
    let next_roster = roster_commitment(&[alice.clone(), bob.clone(), carol.clone()]).unwrap();
    let delivery_a0 = MlsMembershipDeliveryV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 1,
        proposal_id,
        destination: "a0.example".into(),
        epoch_after: 1,
        next_roster_commitment: next_roster.clone(),
        next_participant_domains: vec![
            "a0.example".into(),
            "a1.example".into(),
            "a2.example".into(),
        ],
        local_members_after: vec![alice],
        envelopes: Vec::new(),
    };
    let delivery_a1 = MlsMembershipDeliveryV1 {
        destination: "a1.example".into(),
        local_members_after: vec![bob],
        ..delivery_a0.clone()
    };
    let delivery_a2 = MlsMembershipDeliveryV1 {
        destination: "a2.example".into(),
        local_members_after: vec![carol],
        ..delivery_a0.clone()
    };
    let transition = MlsMembershipTransitionV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 1,
        proposal_id,
        previous_roster_commitment: previous_roster.clone(),
        next_roster_commitment: next_roster,
        previous_member_count: 2,
        next_member_count: 3,
        previous_participant_domains: vec!["a0.example".into(), "a1.example".into()],
        next_participant_domains: vec![
            "a0.example".into(),
            "a1.example".into(),
            "a2.example".into(),
        ],
        deliveries: vec![
            MlsMembershipDeliveryCommitmentV1 {
                destination: "a0.example".into(),
                delivery_digest: delivery_a0.delivery_digest().unwrap(),
            },
            MlsMembershipDeliveryCommitmentV1 {
                destination: "a1.example".into(),
                delivery_digest: delivery_a1.delivery_digest().unwrap(),
            },
            MlsMembershipDeliveryCommitmentV1 {
                destination: "a2.example".into(),
                delivery_digest: delivery_a2.delivery_digest().unwrap(),
            },
        ],
    };
    let proposer_key = p256::ecdsa::SigningKey::from_bytes((&[19u8; 32]).into()).unwrap();
    let proposer_public = proposer_key.verifying_key().to_encoded_point(false);
    let payload = b"encrypted membership change";
    let mut proposal = MlsControlProposalV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 1,
        proposal_id,
        base_epoch: 0,
        action_type: MlsControlActionTypeV1::MembershipChange,
        proposer_id: hex::encode(Sha256::digest(proposer_public.as_bytes())),
        proposer_credential_public_key: base64::engine::general_purpose::STANDARD
            .encode(proposer_public.as_bytes()),
        encrypted_payload: base64::engine::general_purpose::STANDARD.encode(payload),
        payload_digest: hex::encode(Sha256::digest(payload)),
        created_at: 1,
        proposer_signature: String::new(),
    };
    let signature: p256::ecdsa::Signature = proposer_key.sign(&proposal.signing_bytes().unwrap());
    proposal.proposer_signature =
        base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
    let block = MlsControlBlockV1 {
        conversation_id,
        incarnation: 1,
        height: 1,
        previous_block_hash: None,
        epoch_before: 0,
        epoch_after: 1,
        proposal,
        transition_digest: Some(transition.transition_digest().unwrap()),
        owner_approval: None,
        finalized_at: 2,
    };
    let block_hash = block.block_hash().unwrap();
    let mut votes = Vec::new();
    for authority in &authorities.authorities {
        let mut vote = MlsOrderingVoteV1 {
            conversation_id,
            incarnation: 1,
            authority_set_sequence: authorities.sequence,
            height: 1,
            round: 0,
            vote_type: MlsOrderingVoteTypeV1::Precommit,
            block_hash: block_hash.clone(),
            authority_domain: authority.domain.clone(),
            authority_key_id: authority.key_id.clone(),
            signature: String::new(),
        };
        vote.signature = base64::engine::general_purpose::STANDARD.encode(
            authority_keys[&authority.domain]
                .sign(&vote.signing_bytes().unwrap())
                .to_bytes(),
        );
        votes.push(vote);
    }
    let request = CommitMlsControlBlockV1 {
        finalized: MlsFinalizedControlBlockV1 {
            block,
            quorum_certificate: MlsOrderingQuorumCertificateV1 {
                authority_set_sequence: authorities.sequence,
                height: 1,
                round: 0,
                block_hash,
                votes,
            },
        },
        membership_transition: Some(transition),
        authority_change: None,
        authority_transition: None,
        owner_change: None,
    };
    let history = Vec::new();
    let descriptor = MlsParticipantBootstrapDescriptorV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        genesis: MlsConversationGenesisV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            mls_group_id: base64::engine::general_purpose::STANDARD.encode([9u8; 16]),
            kind: MlsConversationKindV1::Direct,
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            roster_commitment: previous_roster,
            member_count: 2,
            authority_set: authorities,
            owner_set: None,
            initial_epoch: 0,
            created_at: 1,
        },
        genesis_participant_domains: vec!["a0.example".into(), "a1.example".into()],
        destination: "a2.example".into(),
        transition_request: request,
        delivery_digest: delivery_a2.delivery_digest().unwrap(),
        history_block_count: 0,
        history_digest: mls_authority_history_digest(&history).unwrap(),
    };
    verify_mls_participant_bootstrap_history(&descriptor, &history, &delivery_a2).unwrap();
    let page = FederatedMlsParticipantBootstrapPageV1 {
        bootstrap_id: descriptor.bootstrap_id().unwrap(),
        descriptor: descriptor.clone(),
        page_index: 0,
        page_count: 1,
        start_height: 1,
        previous_page_hash: None,
        commits: history,
        membership_delivery: Some(delivery_a2.clone()),
    };
    page.validate().unwrap();

    let mut tampered = delivery_a2;
    tampered.local_members_after[0].is_admin = true;
    assert!(verify_mls_participant_bootstrap_history(&descriptor, &[], &tampered).is_err());
    let mut wrong_destination = descriptor;
    wrong_destination.destination = "a1.example".into();
    assert!(wrong_destination.validate().is_err());
}

#[test]
fn ordering_certificate_requires_distinct_matching_precommits() {
    let conversation_id = Uuid::from_u128(1);
    let (authorities, keys) = authority_set(4);
    let block_hash = "ab".repeat(32);
    let mut votes = Vec::new();
    for authority in authorities.authorities.iter().take(3) {
        let mut vote = MlsOrderingVoteV1 {
            conversation_id,
            incarnation: 1,
            authority_set_sequence: 1,
            height: 1,
            round: 0,
            vote_type: MlsOrderingVoteTypeV1::Precommit,
            block_hash: block_hash.clone(),
            authority_domain: authority.domain.clone(),
            authority_key_id: authority.key_id.clone(),
            signature: String::new(),
        };
        vote.signature = base64::engine::general_purpose::STANDARD.encode(
            keys[&authority.domain]
                .sign(&vote.signing_bytes().unwrap())
                .to_bytes(),
        );
        votes.push(vote);
    }
    let certificate = MlsOrderingQuorumCertificateV1 {
        authority_set_sequence: 1,
        height: 1,
        round: 0,
        block_hash,
        votes,
    };
    certificate.verify(&authorities).unwrap();

    let mut insufficient = certificate.clone();
    insufficient.votes.pop();
    assert!(insufficient.verify(&authorities).is_err());
}

#[test]
fn new_authority_bootstrap_requires_old_quorum_and_exact_history() {
    use p256::ecdsa::signature::Signer as _;

    let conversation_id = Uuid::from_u128(31);
    let (current, current_keys) = authority_set(2);
    let (new_authority, _) = authority("a2.example", 9);
    let mut next = current.clone();
    next.sequence = 2;
    next.authorities.push(new_authority);
    next.required_quorum = MlsAuthoritySetV1::quorum_for(next.authorities.len()).unwrap();
    let delivery_transition = MlsMembershipTransitionV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 1,
        proposal_id: Uuid::from_u128(32),
        previous_roster_commitment: "ab".repeat(32),
        next_roster_commitment: "ab".repeat(32),
        previous_member_count: 2,
        next_member_count: 2,
        previous_participant_domains: vec!["a0.example".into(), "a1.example".into()],
        next_participant_domains: vec!["a0.example".into(), "a1.example".into()],
        deliveries: vec![
            MlsMembershipDeliveryCommitmentV1 {
                destination: "a0.example".into(),
                delivery_digest: "cd".repeat(32),
            },
            MlsMembershipDeliveryCommitmentV1 {
                destination: "a1.example".into(),
                delivery_digest: "ef".repeat(32),
            },
        ],
    };
    let authority_change = MlsAuthorityChangeV1 {
        next_authority_set: next,
        delivery_transition,
    };

    let proposer_key = p256::ecdsa::SigningKey::from_bytes((&[17u8; 32]).into()).unwrap();
    let proposer_public = proposer_key.verifying_key().to_encoded_point(false);
    let payload = b"encrypted authority transition";
    let mut proposal = MlsControlProposalV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 1,
        proposal_id: Uuid::from_u128(32),
        base_epoch: 0,
        action_type: MlsControlActionTypeV1::AuthoritySetChange,
        proposer_id: hex::encode(Sha256::digest(proposer_public.as_bytes())),
        proposer_credential_public_key: base64::engine::general_purpose::STANDARD
            .encode(proposer_public.as_bytes()),
        encrypted_payload: base64::engine::general_purpose::STANDARD.encode(payload),
        payload_digest: hex::encode(Sha256::digest(payload)),
        created_at: 1,
        proposer_signature: String::new(),
    };
    let signature: p256::ecdsa::Signature = proposer_key.sign(&proposal.signing_bytes().unwrap());
    proposal.proposer_signature =
        base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
    let block = MlsControlBlockV1 {
        conversation_id,
        incarnation: 1,
        height: 1,
        previous_block_hash: None,
        epoch_before: 0,
        epoch_after: 1,
        proposal,
        transition_digest: Some(authority_change.transition_digest().unwrap()),
        owner_approval: None,
        finalized_at: 2,
    };
    let block_hash = block.block_hash().unwrap();
    let mut votes = Vec::new();
    for authority in &current.authorities {
        let mut vote = MlsOrderingVoteV1 {
            conversation_id,
            incarnation: 1,
            authority_set_sequence: current.sequence,
            height: 1,
            round: 0,
            vote_type: MlsOrderingVoteTypeV1::Precommit,
            block_hash: block_hash.clone(),
            authority_domain: authority.domain.clone(),
            authority_key_id: authority.key_id.clone(),
            signature: String::new(),
        };
        vote.signature = base64::engine::general_purpose::STANDARD.encode(
            current_keys[&authority.domain]
                .sign(&vote.signing_bytes().unwrap())
                .to_bytes(),
        );
        votes.push(vote);
    }
    let previous_set_certificate = MlsOrderingQuorumCertificateV1 {
        authority_set_sequence: current.sequence,
        height: 1,
        round: 0,
        block_hash,
        votes,
    };
    let history = Vec::new();
    let descriptor = MlsAuthorityBootstrapDescriptorV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        genesis: MlsConversationGenesisV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            mls_group_id: base64::engine::general_purpose::STANDARD.encode([3u8; 16]),
            kind: MlsConversationKindV1::Direct,
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            roster_commitment: "ab".repeat(32),
            member_count: 2,
            authority_set: current.clone(),
            owner_set: None,
            initial_epoch: 0,
            created_at: 1,
        },
        genesis_participant_domains: vec!["a0.example".into(), "a1.example".into()],
        participant_domains: vec!["a0.example".into(), "a1.example".into()],
        transition_block: block,
        previous_set_certificate,
        authority_change,
        history_block_count: 0,
        history_digest: mls_authority_history_digest(&history).unwrap(),
    };
    assert_eq!(
        verify_mls_authority_bootstrap_history(&descriptor, &history).unwrap(),
        current
    );
    let page = FederatedMlsAuthorityBootstrapPageV1 {
        bootstrap_id: descriptor.bootstrap_id().unwrap(),
        descriptor: descriptor.clone(),
        page_index: 0,
        page_count: 1,
        start_height: 1,
        previous_page_hash: None,
        commits: history,
    };
    page.validate().unwrap();

    let mut tampered = descriptor;
    tampered.history_digest = "00".repeat(32);
    assert!(verify_mls_authority_bootstrap_history(&tampered, &[]).is_err());
}

#[test]
fn control_proposal_is_bound_to_the_pseudonymous_mls_credential() {
    use p256::ecdsa::signature::Signer as _;

    let signing_key = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let public_key = public_key.as_bytes();
    let mut proposal = MlsControlProposalV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id: Uuid::from_u128(21),
        incarnation: 1,
        proposal_id: Uuid::from_u128(22),
        base_epoch: 3,
        action_type: MlsControlActionTypeV1::MembershipChange,
        proposer_id: hex::encode(Sha256::digest(public_key)),
        proposer_credential_public_key: base64::engine::general_purpose::STANDARD
            .encode(public_key),
        encrypted_payload: base64::engine::general_purpose::STANDARD.encode(b"opaque commit"),
        payload_digest: hex::encode(Sha256::digest(b"opaque commit")),
        created_at: 1,
        proposer_signature: String::new(),
    };
    let signature: p256::ecdsa::Signature = signing_key.sign(&proposal.signing_bytes().unwrap());
    proposal.proposer_signature =
        base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
    proposal.verify().unwrap();

    let mut replaced = proposal.clone();
    replaced.proposer_credential_public_key = base64::engine::general_purpose::STANDARD.encode(
        p256::ecdsa::SigningKey::from_bytes((&[8u8; 32]).into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    assert!(replaced.verify().is_err());
}

#[test]
fn pending_policy_is_bounded_and_strictest_wins() {
    let default = PendingMessageRequestPolicyV1::default();
    default.validate().unwrap();
    let strict = PendingMessageRequestPolicyV1 {
        maximum_messages: 5,
        maximum_ciphertext_bytes: 256 * 1024,
        expiry_seconds: 7 * 24 * 60 * 60,
    };
    assert_eq!(default.clone().strictest(strict.clone()), strict);
    assert!(PendingMessageRequestPolicyV1 {
        maximum_messages: 129,
        ..default
    }
    .validate()
    .is_err());
}

#[test]
fn anonymous_submission_has_stable_aad_and_hides_conversation_id() {
    let submission = AnonymousMlsSubmissionV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        recipient: "alice@example.org".parse().unwrap(),
        send_id: Uuid::from_u128(9),
        capability: base64::engine::general_purpose::STANDARD.encode([7u8; 16]),
        suite: MlsAnonymousDeliverySuiteV1::DhKemP256HkdfSha256Aes128Gcm,
        envelopes: vec![AnonymousMlsDeviceEnvelopeV1 {
            device_id: 1,
            encapsulated_key: base64::engine::general_purpose::STANDARD.encode([4u8; 65]),
            ciphertext: base64::engine::general_purpose::STANDARD.encode([5u8; 17]),
        }],
    };
    submission.validate().unwrap();
    let aad = submission.aad_for_device(1).unwrap();
    assert!(aad.starts_with(ANONYMOUS_MLS_DELIVERY_CONTEXT));
    let json = serde_json::to_value(&submission).unwrap();
    assert!(json.get("conversationId").is_none());
    assert!(json.get("sender").is_none());
    assert!(json.get("epoch").is_none());
}

#[test]
fn anonymous_key_package_checkpoint_cursor_is_lossless_and_canonical() {
    let mut request = AnonymousMlsKeyPackageRequestV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        recipient: "alice@example.org".parse().unwrap(),
        capability: base64::engine::general_purpose::STANDARD.encode([7u8; 16]),
        transparency_tree_size: u64::MAX.to_string(),
    };
    request.validate().unwrap();
    assert_eq!(request.known_tree_size().unwrap(), u64::MAX);
    assert_eq!(
        serde_json::to_value(&request).unwrap()["transparencyTreeSize"],
        u64::MAX.to_string()
    );
    request.transparency_tree_size = "01".into();
    assert!(request.validate().is_err());
}

#[test]
fn mailbox_structurally_hides_anonymous_conversation_metadata() {
    let mut envelope = MlsMailboxEnvelopeV1 {
        id: Uuid::from_u128(1),
        cursor: "9007199254740993".into(),
        delivery_kind: MlsMailboxDeliveryKindV1::Anonymous,
        conversation_id: None,
        incarnation: None,
        send_id: Uuid::from_u128(2),
        opaque_envelope: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        server_timestamp: 10,
    };
    envelope.validate().unwrap();
    let json = serde_json::to_value(&envelope).unwrap();
    assert_eq!(json["cursor"], "9007199254740993");
    assert!(json.get("conversationId").is_none());
    assert!(json.get("incarnation").is_none());

    envelope.conversation_id = Some(Uuid::from_u128(3));
    assert!(envelope.validate().is_err());
    envelope.delivery_kind = MlsMailboxDeliveryKindV1::MembershipControl;
    envelope.incarnation = Some(1);
    envelope.validate().unwrap();
}

#[test]
fn group_capability_binds_epoch_and_recipient() {
    let conversation_id = Uuid::from_u128(3);
    let alice: AccountAddress = "alice@example.org".parse().unwrap();
    let first = derive_group_delivery_capability(&[9; 32], conversation_id, 1, 5, &alice).unwrap();
    let second = derive_group_delivery_capability(&[9; 32], conversation_id, 1, 6, &alice).unwrap();
    assert_ne!(first, second);
    assert_eq!(first.len(), 16);
}

#[test]
fn ordering_policy_requires_production_group_capacity() {
    let (authority, _) = authority("orderer.example", 42);
    let policy = MlsOrderingServicePolicyV1 {
        policy_version: MLS_ORDERING_SERVICE_POLICY_VERSION,
        canonical_domain: "orderer.example".into(),
        suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
        anonymous_delivery_suite: MlsAnonymousDeliverySuiteV1::DhKemP256HkdfSha256Aes128Gcm,
        control_signing_key_id: authority.key_id,
        control_signing_public_key: authority.public_key,
        accepts_group_ordering: true,
        maximum_group_members: 1000,
        maximum_authorities: 64,
        maximum_control_payload_bytes: 1024 * 1024,
        pending_message_requests: PendingMessageRequestPolicyV1::default(),
        abuse_limits: MlsAbuseLimitsV1::default(),
    };
    let bytes = policy.canonical_bytes().unwrap();
    assert_eq!(
        MlsOrderingServicePolicyV1::from_canonical_bytes(&bytes).unwrap(),
        policy
    );
    let pretty = serde_json::to_vec_pretty(&policy).unwrap();
    assert!(MlsOrderingServicePolicyV1::from_canonical_bytes(&pretty).is_err());
}

#[test]
fn private_control_and_client_history_have_stable_canonical_vectors() {
    let (authorities, _) = authority_set(1);
    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
    let owner_public = owner_key.verifying_key().to_bytes();
    let owner_id = hex::encode(Sha256::digest(owner_public));
    let owners = MlsOwnerSetV1 {
        sequence: 1,
        owners: vec![MlsOwnerV1 {
            owner_id: owner_id.clone(),
            public_key: base64::engine::general_purpose::STANDARD.encode(owner_public),
        }],
        required_quorum: 1,
    };
    let roster = vec![MlsConversationMemberV1 {
        address: "alice@a0.example".parse().unwrap(),
        is_admin: true,
        owner_id: Some(owner_id),
    }];
    let private = MlsPrivateControlStateV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id: Uuid::from_u128(0x101),
        incarnation: 1,
        proposal_id: None,
        height: 0,
        initial_epoch: 0,
        epoch: 0,
        previous_block_hash: None,
        genesis_roster: roster.clone(),
        genesis_authority_set: authorities.clone(),
        genesis_owner_set: owners.clone(),
        genesis_authorization_policy: MlsGroupAuthorizationPolicyV1::members_default(),
        genesis_cryptographic_policy: MlsGroupCryptographicPolicyV1::v1_default(),
        roster: roster.clone(),
        authority_set: authorities.clone(),
        owner_set: owners.clone(),
        authorization_policy: MlsGroupAuthorizationPolicyV1::members_default(),
        cryptographic_policy: MlsGroupCryptographicPolicyV1::v1_default(),
    };
    let private_bytes = private.canonical_bytes().unwrap();
    assert_eq!(
        MlsPrivateControlStateV1::from_canonical_bytes(&private_bytes).unwrap(),
        private
    );
    let genesis = MlsConversationGenesisV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id: private.conversation_id,
        incarnation: 1,
        mls_group_id: base64::engine::general_purpose::STANDARD.encode([6; 16]),
        kind: MlsConversationKindV1::Group,
        suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
        roster_commitment: roster_commitment(&roster).unwrap(),
        member_count: 1,
        authority_set: authorities,
        owner_set: Some(owners),
        initial_epoch: 0,
        created_at: 1_700_000_000,
    };
    let page = MlsClientControlHistoryPageV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        genesis,
        genesis_participant_domains: vec!["a0.example".into()],
        after_height: "0".into(),
        commits: Vec::new(),
        next_height: None,
    };
    let page_bytes = page.canonical_bytes().unwrap();
    assert_eq!(
        MlsClientControlHistoryPageV1::from_canonical_bytes(&page_bytes).unwrap(),
        page
    );
    assert_eq!(
        hex::encode(Sha256::digest(&private_bytes)),
        "247a283bfb4cf3b2bb3d65f2a48ee3f0f5b4a43ab5ac791598161edb80dfdd66"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&page_bytes)),
        "8c9cc89d2276c5a1b4e73e399ec7755b5c36a1d473d6c3493238ed3211f505c4"
    );
    let pretty = serde_json::to_vec_pretty(&page).unwrap();
    assert!(MlsClientControlHistoryPageV1::from_canonical_bytes(&pretty).is_err());
    let mut unknown = serde_json::to_value(&private).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("downgrade".into(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<MlsPrivateControlStateV1>(unknown).is_err());
    assert!(verify_mls_client_control_history(&[], &private).is_err());
}

#[test]
fn private_group_policies_have_stable_canonical_vectors() {
    let authorization = MlsGroupAuthorizationPolicyV1::members_default();
    let authorization_bytes = authorization.canonical_bytes().unwrap();
    assert_eq!(
        MlsGroupAuthorizationPolicyV1::from_canonical_bytes(&authorization_bytes).unwrap(),
        authorization
    );
    assert_eq!(
        authorization.policy_digest().unwrap(),
        "9428a5e307c99b64c9cc1fd5b0efb76567cd5845ca422a33ba25875664545bf7"
    );

    let cryptographic = MlsGroupCryptographicPolicyV1::v1_default();
    let cryptographic_bytes = cryptographic.canonical_bytes().unwrap();
    assert_eq!(
        MlsGroupCryptographicPolicyV1::from_canonical_bytes(&cryptographic_bytes).unwrap(),
        cryptographic
    );
    assert_eq!(
        cryptographic.policy_digest().unwrap(),
        "af88bc6a47502751ad485059e6373d99352d225b68a9cef177f0969c641a73a4"
    );
}

#[test]
fn client_control_history_replays_exactly_across_page_boundaries() {
    use p256::ecdsa::signature::Signer as _;

    let (authorities, authority_keys) = authority_set(1);
    let authority = &authorities.authorities[0];
    let authority_key = &authority_keys[&authority.domain];
    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[45; 32]);
    let owner_public = owner_key.verifying_key().to_bytes();
    let owner_id = hex::encode(Sha256::digest(owner_public));
    let owners = MlsOwnerSetV1 {
        sequence: 1,
        owners: vec![MlsOwnerV1 {
            owner_id: owner_id.clone(),
            public_key: base64::engine::general_purpose::STANDARD.encode(owner_public),
        }],
        required_quorum: 1,
    };
    let roster = vec![MlsConversationMemberV1 {
        address: "alice@a0.example".parse().unwrap(),
        is_admin: true,
        owner_id: Some(owner_id),
    }];
    let conversation_id = Uuid::from_u128(0x202);
    let genesis = MlsConversationGenesisV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 1,
        mls_group_id: base64::engine::general_purpose::STANDARD.encode([7; 16]),
        kind: MlsConversationKindV1::Group,
        suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
        roster_commitment: roster_commitment(&roster).unwrap(),
        member_count: 1,
        authority_set: authorities.clone(),
        owner_set: Some(owners.clone()),
        initial_epoch: 0,
        created_at: 1_700_000_000,
    };
    let proposer_key = p256::ecdsa::SigningKey::from_bytes((&[46; 32]).into()).unwrap();
    let proposer_public = proposer_key.verifying_key().to_encoded_point(false);
    let proposer_id = hex::encode(Sha256::digest(proposer_public.as_bytes()));
    let proposer_public =
        base64::engine::general_purpose::STANDARD.encode(proposer_public.as_bytes());
    let mut commits = Vec::new();
    let mut previous_block_hash = None;
    for height in 1..=65 {
        let payload = format!("opaque routine-admin commit {height}");
        let mut proposal = MlsControlProposalV1 {
            protocol_version: MLS_PROTOCOL_VERSION,
            conversation_id,
            incarnation: 1,
            proposal_id: Uuid::from_u128(0x1_000 + u128::from(height)),
            base_epoch: height - 1,
            action_type: MlsControlActionTypeV1::RoutineAdmin,
            proposer_id: proposer_id.clone(),
            proposer_credential_public_key: proposer_public.clone(),
            encrypted_payload: base64::engine::general_purpose::STANDARD.encode(payload.as_bytes()),
            payload_digest: hex::encode(Sha256::digest(payload.as_bytes())),
            created_at: 1_700_000_000 + height as i64,
            proposer_signature: String::new(),
        };
        let signature: p256::ecdsa::Signature =
            proposer_key.sign(&proposal.signing_bytes().unwrap());
        proposal.proposer_signature =
            base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
        let block = MlsControlBlockV1 {
            conversation_id,
            incarnation: 1,
            height,
            previous_block_hash: previous_block_hash.clone(),
            epoch_before: height - 1,
            epoch_after: height,
            proposal,
            transition_digest: None,
            owner_approval: None,
            finalized_at: 1_700_000_100 + height as i64,
        };
        let block_hash = block.block_hash().unwrap();
        let mut vote = MlsOrderingVoteV1 {
            conversation_id,
            incarnation: 1,
            authority_set_sequence: authorities.sequence,
            height,
            round: 0,
            vote_type: MlsOrderingVoteTypeV1::Precommit,
            block_hash: block_hash.clone(),
            authority_domain: authority.domain.clone(),
            authority_key_id: authority.key_id.clone(),
            signature: String::new(),
        };
        vote.signature = base64::engine::general_purpose::STANDARD.encode(
            authority_key
                .sign(&vote.signing_bytes().unwrap())
                .to_bytes(),
        );
        commits.push(CommitMlsControlBlockV1 {
            finalized: MlsFinalizedControlBlockV1 {
                block,
                quorum_certificate: MlsOrderingQuorumCertificateV1 {
                    authority_set_sequence: authorities.sequence,
                    height,
                    round: 0,
                    block_hash: block_hash.clone(),
                    votes: vec![vote],
                },
            },
            membership_transition: None,
            authority_change: None,
            authority_transition: None,
            owner_change: None,
        });
        previous_block_hash = Some(block_hash);
    }
    let final_block = &commits.last().unwrap().finalized.block;
    let private = MlsPrivateControlStateV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        conversation_id,
        incarnation: 1,
        proposal_id: Some(final_block.proposal.proposal_id),
        height: 65,
        initial_epoch: 0,
        epoch: 65,
        previous_block_hash: final_block.previous_block_hash.clone(),
        genesis_roster: roster.clone(),
        genesis_authority_set: authorities.clone(),
        genesis_owner_set: owners.clone(),
        genesis_authorization_policy: MlsGroupAuthorizationPolicyV1::members_default(),
        genesis_cryptographic_policy: MlsGroupCryptographicPolicyV1::v1_default(),
        roster,
        authority_set: authorities,
        owner_set: owners,
        authorization_policy: MlsGroupAuthorizationPolicyV1::members_default(),
        cryptographic_policy: MlsGroupCryptographicPolicyV1::v1_default(),
    };
    let first = MlsClientControlHistoryPageV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        genesis: genesis.clone(),
        genesis_participant_domains: vec!["a0.example".into()],
        after_height: "0".into(),
        commits: commits[..64].to_vec(),
        next_height: Some("64".into()),
    };
    let second = MlsClientControlHistoryPageV1 {
        protocol_version: MLS_PROTOCOL_VERSION,
        genesis,
        genesis_participant_domains: vec!["a0.example".into()],
        after_height: "64".into(),
        commits: commits[64..].to_vec(),
        next_height: Some("65".into()),
    };

    assert_eq!(
        verify_mls_client_control_history(&[first.clone(), second.clone()], &private).unwrap(),
        previous_block_hash
    );
    assert!(verify_mls_client_control_history(std::slice::from_ref(&first), &private).is_err());
    assert!(verify_mls_client_control_history(&[second.clone(), first.clone()], &private).is_err());
    assert!(verify_mls_client_control_history(&[first.clone(), first], &private).is_err());
    assert!(MlsClientControlHistoryPageV1::from_canonical_bytes(
        &second.canonical_bytes().unwrap()
    )
    .is_ok());
}
