-- MLS groups are gone (docs/plans/pairwise-groups.md §9): they were never
-- on in the beta, so their tables hold nothing worth keeping. Pairwise
-- groups replace them.
DROP TABLE IF EXISTS
    chat_invite_links,
    chat_invite_requests,
    chat_mls_admin_audit_events,
    chat_mls_anonymous_send_ids,
    chat_mls_authority_bootstrap_pages,
    chat_mls_authority_bootstraps,
    chat_mls_consensus_evidence,
    chat_mls_control_blocks,
    chat_mls_control_outbox,
    chat_mls_conversations,
    chat_mls_delivery_capabilities,
    chat_mls_devices,
    chat_mls_federation_inbound_state,
    chat_mls_federation_inbound_transactions,
    chat_mls_federation_outbox,
    chat_mls_federation_sequences,
    chat_mls_incarnation_recoveries,
    chat_mls_incarnations,
    chat_mls_invitation_feedback,
    chat_mls_invitation_feedback_outbox,
    chat_mls_key_packages,
    chat_mls_local_member_devices,
    chat_mls_local_members,
    chat_mls_mailbox,
    chat_mls_membership_deliveries,
    chat_mls_ordering_votes,
    chat_mls_owner_approvals,
    chat_mls_participant_bootstrap_pages,
    chat_mls_participant_bootstraps,
    chat_mls_pending_requests,
    chat_mls_rate_counters,
    chat_mls_recovery_outbox
    CASCADE;
DROP FUNCTION IF EXISTS reject_chat_mls_append_only_mutation();

-- The MLS ordering service's feature policies (type 2), its generated
-- control key and the invite links' rate-limit overrides.
DELETE FROM federation_feature_policy_failures WHERE feature_type = 2;
DELETE FROM federation_feature_policy_documents WHERE feature_type = 2;
ALTER TABLE federation_feature_policy_documents
    DROP CONSTRAINT federation_feature_policy_documents_feature_type_check,
    ADD CONSTRAINT federation_feature_policy_documents_feature_type_check
        CHECK (feature_type = 1);
DELETE FROM server_generated_keys WHERE purpose = 'mls-control';
ALTER TABLE server_generated_keys
    DROP CONSTRAINT server_generated_keys_purpose_check,
    ADD CONSTRAINT server_generated_keys_purpose_check
        CHECK (purpose = ANY (ARRAY['federation-identity', 'fake-accounts', 'registration-codes']));
DELETE FROM user_rate_limit_overrides
 WHERE key IN ('invite_link_account_calls', 'invite_link_account_requests',
               'invite_link_origin_calls');
