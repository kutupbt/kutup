-- The MLS tables as the baseline made them (empty).
ALTER TABLE federation_feature_policy_documents
    DROP CONSTRAINT federation_feature_policy_documents_feature_type_check,
    ADD CONSTRAINT federation_feature_policy_documents_feature_type_check
        CHECK (feature_type = ANY (ARRAY[1, 2]));
ALTER TABLE server_generated_keys
    DROP CONSTRAINT server_generated_keys_purpose_check,
    ADD CONSTRAINT server_generated_keys_purpose_check
        CHECK (purpose = ANY (ARRAY['federation-identity', 'mls-control', 'fake-accounts', 'registration-codes']));

CREATE FUNCTION public.reject_chat_mls_append_only_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'MLS security history is append-only';
END
$$;

CREATE TABLE public.chat_invite_links (
    link_id text NOT NULL,
    manage_hash bytea NOT NULL,
    preview text NOT NULL,
    origin_domain text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    touched_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_invite_links_link_id_check CHECK ((length(link_id) = 44)),
    CONSTRAINT chat_invite_links_manage_hash_check CHECK ((octet_length(manage_hash) = 32))
);

CREATE TABLE public.chat_invite_requests (
    id uuid NOT NULL,
    link_id text NOT NULL,
    origin_domain text NOT NULL,
    request text NOT NULL,
    status_hash bytea NOT NULL,
    status smallint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_at timestamp with time zone,
    CONSTRAINT chat_invite_requests_status_check CHECK ((status = ANY (ARRAY[0, 1, 2]))),
    CONSTRAINT chat_invite_requests_status_hash_check CHECK ((octet_length(status_hash) = 32))
);

CREATE TABLE public.chat_mls_admin_audit_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_type text NOT NULL,
    conversation_id uuid,
    incarnation bigint,
    evidence_digest character(64),
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_admin_audit_events_details_check CHECK ((jsonb_typeof(details) = 'object'::text)),
    CONSTRAINT chat_mls_admin_audit_events_event_type_check CHECK ((event_type = ANY (ARRAY['genesis'::text, 'owner_change'::text, 'authority_change'::text, 'policy_change'::text, 'incarnation_recovery'::text, 'conversation_close'::text, 'quarantine'::text, 'cryptographic_failure'::text, 'invitation_accept'::text, 'invitation_reject'::text]))),
    CONSTRAINT chat_mls_admin_audit_events_evidence_digest_check CHECK (((evidence_digest IS NULL) OR (evidence_digest ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chat_mls_admin_audit_events_incarnation_check CHECK (((incarnation IS NULL) OR (incarnation > 0)))
);

CREATE TABLE public.chat_mls_anonymous_send_ids (
    recipient_user_id uuid NOT NULL,
    capability_hash bytea NOT NULL,
    send_id uuid NOT NULL,
    stored_count integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_anonymous_send_ids_capability_hash_check CHECK ((octet_length(capability_hash) = 32)),
    CONSTRAINT chat_mls_anonymous_send_ids_stored_count_check CHECK (((stored_count >= 1) AND (stored_count <= 32)))
);

CREATE TABLE public.chat_mls_authority_bootstrap_pages (
    bootstrap_id character(64) NOT NULL,
    page_index integer NOT NULL,
    start_height bigint NOT NULL,
    page_hash character(64) NOT NULL,
    page jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_authority_bootstrap_pages_page_check CHECK ((jsonb_typeof(page) = 'object'::text)),
    CONSTRAINT chat_mls_authority_bootstrap_pages_page_hash_check CHECK ((page_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_authority_bootstrap_pages_page_index_check CHECK ((page_index >= 0)),
    CONSTRAINT chat_mls_authority_bootstrap_pages_start_height_check CHECK ((start_height > 0))
);

CREATE TABLE public.chat_mls_authority_bootstraps (
    bootstrap_id character(64) NOT NULL,
    origin_domain text NOT NULL,
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    descriptor jsonb NOT NULL,
    page_count integer NOT NULL,
    next_page integer DEFAULT 0 NOT NULL,
    last_page_hash character(64),
    state text DEFAULT 'receiving'::text NOT NULL,
    failure_class text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_authority_bootstraps_bootstrap_id_check CHECK ((bootstrap_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_authority_bootstraps_check CHECK ((next_page <= page_count)),
    CONSTRAINT chat_mls_authority_bootstraps_check1 CHECK (((next_page = 0) = (last_page_hash IS NULL))),
    CONSTRAINT chat_mls_authority_bootstraps_descriptor_check CHECK ((jsonb_typeof(descriptor) = 'object'::text)),
    CONSTRAINT chat_mls_authority_bootstraps_incarnation_check CHECK ((incarnation > 0)),
    CONSTRAINT chat_mls_authority_bootstraps_last_page_hash_check CHECK (((last_page_hash IS NULL) OR (last_page_hash ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chat_mls_authority_bootstraps_next_page_check CHECK ((next_page >= 0)),
    CONSTRAINT chat_mls_authority_bootstraps_origin_domain_check CHECK ((origin_domain = lower(origin_domain))),
    CONSTRAINT chat_mls_authority_bootstraps_page_count_check CHECK ((page_count > 0)),
    CONSTRAINT chat_mls_authority_bootstraps_state_check CHECK ((state = ANY (ARRAY['receiving'::text, 'verified'::text, 'materialized'::text, 'rejected'::text])))
);

CREATE TABLE public.chat_mls_consensus_evidence (
    evidence_digest character(64) NOT NULL,
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    failure_class text NOT NULL,
    evidence jsonb NOT NULL,
    detected_at timestamp with time zone NOT NULL,
    acknowledged_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_consensus_evidence_evidence_check CHECK ((jsonb_typeof(evidence) = 'object'::text)),
    CONSTRAINT chat_mls_consensus_evidence_evidence_digest_check CHECK ((evidence_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_consensus_evidence_failure_class_check CHECK ((failure_class = ANY (ARRAY['authority_equivocation'::text, 'invalid_vote'::text, 'invalid_quorum'::text, 'control_fork'::text, 'owner_equivocation'::text, 'invalid_owner_approval'::text, 'authority_set_regression'::text, 'epoch_regression'::text]))),
    CONSTRAINT chat_mls_consensus_evidence_incarnation_check CHECK ((incarnation > 0))
);

CREATE TABLE public.chat_mls_control_blocks (
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    height bigint NOT NULL,
    block_hash character(64) NOT NULL,
    previous_hash character(64),
    epoch_before bigint NOT NULL,
    epoch_after bigint NOT NULL,
    block jsonb NOT NULL,
    quorum_certificate jsonb NOT NULL,
    commit_request jsonb NOT NULL,
    finalized_at timestamp with time zone NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_control_blocks_block_check CHECK ((jsonb_typeof(block) = 'object'::text)),
    CONSTRAINT chat_mls_control_blocks_block_hash_check CHECK ((block_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_control_blocks_check CHECK ((epoch_after > epoch_before)),
    CONSTRAINT chat_mls_control_blocks_check1 CHECK ((((height = 1) AND (previous_hash IS NULL)) OR ((height > 1) AND (previous_hash IS NOT NULL)))),
    CONSTRAINT chat_mls_control_blocks_commit_request_check CHECK ((jsonb_typeof(commit_request) = 'object'::text)),
    CONSTRAINT chat_mls_control_blocks_epoch_before_check CHECK ((epoch_before >= 0)),
    CONSTRAINT chat_mls_control_blocks_height_check CHECK ((height > 0)),
    CONSTRAINT chat_mls_control_blocks_previous_hash_check CHECK (((previous_hash IS NULL) OR (previous_hash ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chat_mls_control_blocks_quorum_certificate_check CHECK ((jsonb_typeof(quorum_certificate) = 'object'::text))
);

CREATE TABLE public.chat_mls_control_outbox (
    destination text NOT NULL,
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    height bigint NOT NULL,
    block_hash character(64) NOT NULL,
    commit_request jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error_class text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_control_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT chat_mls_control_outbox_block_hash_check CHECK ((block_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_control_outbox_commit_request_check CHECK ((jsonb_typeof(commit_request) = 'object'::text)),
    CONSTRAINT chat_mls_control_outbox_destination_check CHECK ((destination = lower(destination))),
    CONSTRAINT chat_mls_control_outbox_height_check CHECK ((height > 0)),
    CONSTRAINT chat_mls_control_outbox_incarnation_check CHECK ((incarnation > 0)),
    CONSTRAINT chat_mls_control_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'delivered'::text])))
);

CREATE TABLE public.chat_mls_conversations (
    conversation_id uuid NOT NULL,
    kind smallint NOT NULL,
    current_incarnation bigint NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_conversations_current_incarnation_check CHECK ((current_incarnation > 0)),
    CONSTRAINT chat_mls_conversations_kind_check CHECK ((kind = ANY (ARRAY[1, 2, 3]))),
    CONSTRAINT chat_mls_conversations_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'blocked'::text, 'closed'::text])))
);

CREATE TABLE public.chat_mls_delivery_capabilities (
    recipient_user_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    epoch bigint NOT NULL,
    capability_kind text NOT NULL,
    capability_hash bytea NOT NULL,
    policy_sequence bigint NOT NULL,
    published_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_delivery_capabilities_capability_hash_check CHECK ((octet_length(capability_hash) = 32)),
    CONSTRAINT chat_mls_delivery_capabilities_capability_kind_check CHECK ((capability_kind = ANY (ARRAY['direct'::text, 'group'::text]))),
    CONSTRAINT chat_mls_delivery_capabilities_epoch_check CHECK ((epoch >= 0)),
    CONSTRAINT chat_mls_delivery_capabilities_incarnation_check CHECK ((incarnation > 0)),
    CONSTRAINT chat_mls_delivery_capabilities_policy_sequence_check CHECK ((policy_sequence > 0))
);

CREATE TABLE public.chat_mls_devices (
    user_id uuid NOT NULL,
    device_id integer NOT NULL,
    manifest_version bigint NOT NULL,
    suite smallint NOT NULL,
    credential_public_key bytea NOT NULL,
    anonymous_delivery_public_key bytea NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone,
    CONSTRAINT chat_mls_devices_anonymous_delivery_public_key_check CHECK ((octet_length(anonymous_delivery_public_key) = 32)),
    CONSTRAINT chat_mls_devices_credential_public_key_check CHECK ((octet_length(credential_public_key) = 32)),
    CONSTRAINT chat_mls_devices_device_id_check CHECK (((device_id >= 1) AND (device_id <= 127))),
    CONSTRAINT chat_mls_devices_manifest_version_check CHECK ((manifest_version > 0)),
    CONSTRAINT chat_mls_devices_suite_check CHECK ((suite = 3))
);

CREATE TABLE public.chat_mls_federation_inbound_state (
    origin text NOT NULL,
    last_sequence bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_federation_inbound_state_last_sequence_check CHECK ((last_sequence >= 0)),
    CONSTRAINT chat_mls_federation_inbound_state_origin_check CHECK ((origin = lower(origin)))
);

CREATE TABLE public.chat_mls_federation_inbound_transactions (
    origin text NOT NULL,
    sequence bigint NOT NULL,
    send_id uuid NOT NULL,
    transaction_digest character(64) NOT NULL,
    response_status smallint NOT NULL,
    response jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_federation_inbound_transactio_transaction_digest_check CHECK ((transaction_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_federation_inbound_transactions_response_check CHECK ((jsonb_typeof(response) = 'object'::text)),
    CONSTRAINT chat_mls_federation_inbound_transactions_response_status_check CHECK (((response_status >= 200) AND (response_status <= 599))),
    CONSTRAINT chat_mls_federation_inbound_transactions_sequence_check CHECK ((sequence > 0))
);

CREATE TABLE public.chat_mls_federation_outbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    destination text NOT NULL,
    sequence bigint NOT NULL,
    sender_user_id uuid,
    sender_device_id integer,
    send_id uuid NOT NULL,
    transaction jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error_class text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    recipient_account_id uuid NOT NULL,
    CONSTRAINT chat_mls_federation_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT chat_mls_federation_outbox_destination_check CHECK ((destination = lower(destination))),
    CONSTRAINT chat_mls_federation_outbox_sender_device_id_check CHECK (((sender_device_id IS NULL) OR ((sender_device_id >= 1) AND (sender_device_id <= 127)))),
    CONSTRAINT chat_mls_federation_outbox_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT chat_mls_federation_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'delivered'::text, 'rejected'::text]))),
    CONSTRAINT chat_mls_federation_outbox_transaction_check CHECK ((jsonb_typeof(transaction) = 'object'::text)),
    CONSTRAINT chat_mls_federation_outbox_transaction_check1 CHECK ((NOT (transaction ?| ARRAY['sender'::text, 'senderDeviceId'::text, 'conversationId'::text, 'groupId'::text, 'epoch'::text])))
);

CREATE TABLE public.chat_mls_federation_sequences (
    destination text NOT NULL,
    next_sequence bigint NOT NULL,
    CONSTRAINT chat_mls_federation_sequences_destination_check CHECK ((destination = lower(destination))),
    CONSTRAINT chat_mls_federation_sequences_next_sequence_check CHECK ((next_sequence > 0))
);

CREATE TABLE public.chat_mls_incarnation_recoveries (
    recovery_digest character(64) NOT NULL,
    conversation_id uuid NOT NULL,
    previous_incarnation bigint NOT NULL,
    new_incarnation bigint NOT NULL,
    proposal_id uuid NOT NULL,
    origin_domain text NOT NULL,
    initiated_by uuid,
    recovery jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_incarnation_recoveries_check CHECK ((new_incarnation > previous_incarnation)),
    CONSTRAINT chat_mls_incarnation_recoveries_check1 CHECK ((new_incarnation = (previous_incarnation + 1))),
    CONSTRAINT chat_mls_incarnation_recoveries_origin_domain_check CHECK ((origin_domain = lower(origin_domain))),
    CONSTRAINT chat_mls_incarnation_recoveries_previous_incarnation_check CHECK ((previous_incarnation > 0)),
    CONSTRAINT chat_mls_incarnation_recoveries_recovery_check CHECK ((jsonb_typeof(recovery) = 'object'::text)),
    CONSTRAINT chat_mls_incarnation_recoveries_recovery_digest_check CHECK ((recovery_digest ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.chat_mls_incarnations (
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    mls_group_id bytea NOT NULL,
    suite smallint NOT NULL,
    roster_commitment character(64) NOT NULL,
    member_count integer NOT NULL,
    genesis_participant_domains jsonb NOT NULL,
    participant_domains jsonb NOT NULL,
    authority_set_sequence bigint NOT NULL,
    authority_set jsonb NOT NULL,
    owner_set_sequence bigint,
    owner_set jsonb,
    genesis jsonb NOT NULL,
    genesis_hash character(64) NOT NULL,
    last_finalized_height bigint DEFAULT 0 NOT NULL,
    last_finalized_epoch bigint DEFAULT 0 NOT NULL,
    last_block_hash character(64),
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_incarnations_authority_set_check CHECK ((jsonb_typeof(authority_set) = 'object'::text)),
    CONSTRAINT chat_mls_incarnations_authority_set_sequence_check CHECK ((authority_set_sequence > 0)),
    CONSTRAINT chat_mls_incarnations_check CHECK (((owner_set_sequence IS NULL) = (owner_set IS NULL))),
    CONSTRAINT chat_mls_incarnations_genesis_check CHECK ((jsonb_typeof(genesis) = 'object'::text)),
    CONSTRAINT chat_mls_incarnations_genesis_hash_check CHECK ((genesis_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_incarnations_genesis_participant_domains_check CHECK ((jsonb_typeof(genesis_participant_domains) = 'array'::text)),
    CONSTRAINT chat_mls_incarnations_incarnation_check CHECK ((incarnation > 0)),
    CONSTRAINT chat_mls_incarnations_last_block_hash_check CHECK (((last_block_hash IS NULL) OR (last_block_hash ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chat_mls_incarnations_last_finalized_epoch_check CHECK ((last_finalized_epoch >= 0)),
    CONSTRAINT chat_mls_incarnations_last_finalized_height_check CHECK ((last_finalized_height >= 0)),
    CONSTRAINT chat_mls_incarnations_member_count_check CHECK (((member_count >= 1) AND (member_count <= 256))),
    CONSTRAINT chat_mls_incarnations_mls_group_id_check CHECK (((octet_length(mls_group_id) >= 16) AND (octet_length(mls_group_id) <= 255))),
    CONSTRAINT chat_mls_incarnations_owner_set_check CHECK (((owner_set IS NULL) OR (jsonb_typeof(owner_set) = 'object'::text))),
    CONSTRAINT chat_mls_incarnations_participant_domains_check CHECK ((jsonb_typeof(participant_domains) = 'array'::text)),
    CONSTRAINT chat_mls_incarnations_roster_commitment_check CHECK ((roster_commitment ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_incarnations_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'read_only'::text, 'closed'::text]))),
    CONSTRAINT chat_mls_incarnations_suite_check CHECK ((suite = 3))
);

CREATE TABLE public.chat_mls_invitation_feedback (
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    invited_epoch bigint NOT NULL,
    source_domain text NOT NULL,
    decision text NOT NULL,
    decided_at timestamp with time zone NOT NULL,
    feedback_digest character(64) NOT NULL,
    feedback jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    member_account text NOT NULL,
    CONSTRAINT chat_mls_invitation_feedback_decision_check CHECK ((decision = ANY (ARRAY['accepted'::text, 'rejected'::text, 'expired'::text]))),
    CONSTRAINT chat_mls_invitation_feedback_feedback_check CHECK ((jsonb_typeof(feedback) = 'object'::text)),
    CONSTRAINT chat_mls_invitation_feedback_feedback_digest_check CHECK ((feedback_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_invitation_feedback_incarnation_check CHECK ((incarnation > 0)),
    CONSTRAINT chat_mls_invitation_feedback_invited_epoch_check CHECK ((invited_epoch > 0)),
    CONSTRAINT chat_mls_invitation_feedback_member_account_check CHECK ((member_account ~ '^aci:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@[a-z0-9.-]+$'::text)),
    CONSTRAINT chat_mls_invitation_feedback_source_domain_check CHECK ((source_domain = lower(source_domain)))
);

CREATE TABLE public.chat_mls_invitation_feedback_outbox (
    destination text NOT NULL,
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    invited_epoch bigint NOT NULL,
    feedback_digest character(64) NOT NULL,
    feedback jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error_class text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    member_account text NOT NULL,
    CONSTRAINT chat_mls_invitation_feedback_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT chat_mls_invitation_feedback_outbox_destination_check CHECK ((destination = lower(destination))),
    CONSTRAINT chat_mls_invitation_feedback_outbox_feedback_check CHECK ((jsonb_typeof(feedback) = 'object'::text)),
    CONSTRAINT chat_mls_invitation_feedback_outbox_feedback_digest_check CHECK ((feedback_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_invitation_feedback_outbox_incarnation_check CHECK ((incarnation > 0)),
    CONSTRAINT chat_mls_invitation_feedback_outbox_invited_epoch_check CHECK ((invited_epoch > 0)),
    CONSTRAINT chat_mls_invitation_feedback_outbox_member_account_check CHECK ((member_account ~ '^aci:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@[a-z0-9.-]+$'::text)),
    CONSTRAINT chat_mls_invitation_feedback_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'delivered'::text])))
);

CREATE TABLE public.chat_mls_key_packages (
    user_id uuid NOT NULL,
    device_id integer NOT NULL,
    key_package_ref character(64) NOT NULL,
    manifest_version bigint NOT NULL,
    suite smallint NOT NULL,
    key_package bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    claimed_at timestamp with time zone,
    claimed_conversation uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_key_packages_check CHECK (((claimed_at IS NULL) = (claimed_conversation IS NULL))),
    CONSTRAINT chat_mls_key_packages_key_package_check CHECK (((octet_length(key_package) >= 1) AND (octet_length(key_package) <= 65536))),
    CONSTRAINT chat_mls_key_packages_key_package_ref_check CHECK ((key_package_ref ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_key_packages_manifest_version_check CHECK ((manifest_version > 0)),
    CONSTRAINT chat_mls_key_packages_suite_check CHECK ((suite = 3))
);

CREATE TABLE public.chat_mls_local_member_devices (
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    user_id uuid NOT NULL,
    device_id integer NOT NULL,
    joined_epoch bigint NOT NULL,
    removed_epoch bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_local_member_devices_check CHECK (((removed_epoch IS NULL) OR (removed_epoch > joined_epoch))),
    CONSTRAINT chat_mls_local_member_devices_device_id_check CHECK (((device_id >= 1) AND (device_id <= 127))),
    CONSTRAINT chat_mls_local_member_devices_joined_epoch_check CHECK ((joined_epoch >= 0))
);

CREATE TABLE public.chat_mls_local_members (
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    user_id uuid NOT NULL,
    is_admin boolean DEFAULT false NOT NULL,
    is_owner boolean DEFAULT false NOT NULL,
    owner_id character(64),
    membership_status text DEFAULT 'active'::text NOT NULL,
    invitation_expires_at timestamp with time zone,
    invited_by_domain text,
    joined_epoch bigint NOT NULL,
    removed_epoch bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_local_members_check CHECK ((is_owner = (owner_id IS NOT NULL))),
    CONSTRAINT chat_mls_local_members_check1 CHECK ((((membership_status = 'pending'::text) AND (invitation_expires_at IS NOT NULL) AND (invited_by_domain IS NOT NULL)) OR ((membership_status <> 'pending'::text) AND (invitation_expires_at IS NULL)))),
    CONSTRAINT chat_mls_local_members_check2 CHECK (((removed_epoch IS NULL) OR (removed_epoch > joined_epoch))),
    CONSTRAINT chat_mls_local_members_invited_by_domain_check CHECK (((invited_by_domain IS NULL) OR (invited_by_domain = lower(invited_by_domain)))),
    CONSTRAINT chat_mls_local_members_joined_epoch_check CHECK ((joined_epoch >= 0)),
    CONSTRAINT chat_mls_local_members_membership_status_check CHECK ((membership_status = ANY (ARRAY['pending'::text, 'active'::text, 'rejected'::text]))),
    CONSTRAINT chat_mls_local_members_owner_id_check CHECK (((owner_id IS NULL) OR (owner_id ~ '^[0-9a-f]{64}$'::text)))
);

CREATE TABLE public.chat_mls_mailbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    cursor bigint NOT NULL,
    recipient_user_id uuid NOT NULL,
    recipient_device_id integer NOT NULL,
    delivery_kind text NOT NULL,
    request_id uuid,
    conversation_id uuid,
    incarnation bigint,
    send_id uuid NOT NULL,
    opaque_envelope bytea NOT NULL,
    server_ts timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_mailbox_delivery_kind_check CHECK ((delivery_kind = ANY (ARRAY['identified_request'::text, 'anonymous'::text, 'self_sync'::text, 'membership_control'::text]))),
    CONSTRAINT chat_mls_mailbox_metadata_shape_check CHECK ((((delivery_kind = 'identified_request'::text) AND (request_id IS NOT NULL) AND (conversation_id IS NOT NULL) AND (incarnation IS NULL)) OR ((delivery_kind = 'anonymous'::text) AND (request_id IS NULL) AND (conversation_id IS NULL) AND (incarnation IS NULL)) OR ((delivery_kind = 'self_sync'::text) AND (request_id IS NULL) AND (conversation_id IS NOT NULL) AND (incarnation IS NULL)) OR ((delivery_kind = 'membership_control'::text) AND (request_id IS NULL) AND (conversation_id IS NOT NULL) AND (incarnation IS NOT NULL) AND (incarnation > 0)))),
    CONSTRAINT chat_mls_mailbox_opaque_envelope_check CHECK (((octet_length(opaque_envelope) >= 1) AND (octet_length(opaque_envelope) <= 1048576)))
);

ALTER TABLE public.chat_mls_mailbox ALTER COLUMN cursor ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.chat_mls_mailbox_cursor_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.chat_mls_membership_deliveries (
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    proposal_id uuid NOT NULL,
    destination text NOT NULL,
    delivery_digest character(64) NOT NULL,
    delivery jsonb NOT NULL,
    submitted_by uuid,
    state text DEFAULT 'staged'::text NOT NULL,
    block_height bigint,
    block_hash character(64),
    expires_at timestamp with time zone DEFAULT (now() + '24:00:00'::interval) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    finalized_at timestamp with time zone,
    CONSTRAINT chat_mls_membership_deliveries_block_hash_check CHECK (((block_hash IS NULL) OR (block_hash ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chat_mls_membership_deliveries_check CHECK ((((state = 'staged'::text) AND (block_height IS NULL) AND (block_hash IS NULL) AND (finalized_at IS NULL)) OR ((state = 'finalized'::text) AND (block_height > 0) AND (block_hash IS NOT NULL) AND (finalized_at IS NOT NULL)))),
    CONSTRAINT chat_mls_membership_deliveries_delivery_check CHECK ((jsonb_typeof(delivery) = 'object'::text)),
    CONSTRAINT chat_mls_membership_deliveries_delivery_digest_check CHECK ((delivery_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_membership_deliveries_destination_check CHECK ((destination = lower(destination))),
    CONSTRAINT chat_mls_membership_deliveries_incarnation_check CHECK ((incarnation > 0)),
    CONSTRAINT chat_mls_membership_deliveries_state_check CHECK ((state = ANY (ARRAY['staged'::text, 'finalized'::text])))
);

CREATE TABLE public.chat_mls_ordering_votes (
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    authority_set_sequence bigint NOT NULL,
    height bigint NOT NULL,
    round integer NOT NULL,
    vote_type smallint NOT NULL,
    block_hash character(64) NOT NULL,
    authority_domain text NOT NULL,
    authority_key_id character(64) NOT NULL,
    vote jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_ordering_votes_authority_domain_check CHECK ((authority_domain = lower(authority_domain))),
    CONSTRAINT chat_mls_ordering_votes_authority_key_id_check CHECK ((authority_key_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_ordering_votes_authority_set_sequence_check CHECK ((authority_set_sequence > 0)),
    CONSTRAINT chat_mls_ordering_votes_block_hash_check CHECK ((block_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_ordering_votes_height_check CHECK ((height > 0)),
    CONSTRAINT chat_mls_ordering_votes_round_check CHECK ((round >= 0)),
    CONSTRAINT chat_mls_ordering_votes_vote_check CHECK ((jsonb_typeof(vote) = 'object'::text)),
    CONSTRAINT chat_mls_ordering_votes_vote_type_check CHECK ((vote_type = ANY (ARRAY[1, 2])))
);

CREATE TABLE public.chat_mls_owner_approvals (
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    owner_set_sequence bigint NOT NULL,
    proposal_hash character(64) NOT NULL,
    owner_id character(64) NOT NULL,
    approval jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_owner_approvals_approval_check CHECK ((jsonb_typeof(approval) = 'object'::text)),
    CONSTRAINT chat_mls_owner_approvals_owner_id_check CHECK ((owner_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_owner_approvals_owner_set_sequence_check CHECK ((owner_set_sequence > 0)),
    CONSTRAINT chat_mls_owner_approvals_proposal_hash_check CHECK ((proposal_hash ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.chat_mls_participant_bootstrap_pages (
    bootstrap_id character(64) NOT NULL,
    page_index integer NOT NULL,
    start_height bigint NOT NULL,
    page_hash character(64) NOT NULL,
    page jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_participant_bootstrap_pages_page_check CHECK ((jsonb_typeof(page) = 'object'::text)),
    CONSTRAINT chat_mls_participant_bootstrap_pages_page_hash_check CHECK ((page_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_participant_bootstrap_pages_page_index_check CHECK ((page_index >= 0)),
    CONSTRAINT chat_mls_participant_bootstrap_pages_start_height_check CHECK ((start_height > 0))
);

CREATE TABLE public.chat_mls_participant_bootstraps (
    bootstrap_id character(64) NOT NULL,
    origin_domain text NOT NULL,
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    descriptor jsonb NOT NULL,
    page_count integer NOT NULL,
    next_page integer DEFAULT 0 NOT NULL,
    last_page_hash character(64),
    state text DEFAULT 'receiving'::text NOT NULL,
    failure_class text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_participant_bootstraps_bootstrap_id_check CHECK ((bootstrap_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_participant_bootstraps_check CHECK ((next_page <= page_count)),
    CONSTRAINT chat_mls_participant_bootstraps_check1 CHECK (((next_page = 0) = (last_page_hash IS NULL))),
    CONSTRAINT chat_mls_participant_bootstraps_descriptor_check CHECK ((jsonb_typeof(descriptor) = 'object'::text)),
    CONSTRAINT chat_mls_participant_bootstraps_incarnation_check CHECK ((incarnation > 0)),
    CONSTRAINT chat_mls_participant_bootstraps_last_page_hash_check CHECK (((last_page_hash IS NULL) OR (last_page_hash ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chat_mls_participant_bootstraps_next_page_check CHECK ((next_page >= 0)),
    CONSTRAINT chat_mls_participant_bootstraps_origin_domain_check CHECK ((origin_domain = lower(origin_domain))),
    CONSTRAINT chat_mls_participant_bootstraps_page_count_check CHECK ((page_count > 0)),
    CONSTRAINT chat_mls_participant_bootstraps_state_check CHECK ((state = ANY (ARRAY['receiving'::text, 'verified'::text, 'materialized'::text, 'rejected'::text])))
);

CREATE TABLE public.chat_mls_pending_requests (
    request_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    sender_address text NOT NULL,
    sender_origin text NOT NULL,
    recipient_user_id uuid NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    maximum_messages integer NOT NULL,
    maximum_ciphertext_bytes bigint NOT NULL,
    message_count integer DEFAULT 0 NOT NULL,
    ciphertext_bytes bigint DEFAULT 0 NOT NULL,
    genesis jsonb NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_pending_requests_check CHECK ((message_count <= maximum_messages)),
    CONSTRAINT chat_mls_pending_requests_check1 CHECK ((ciphertext_bytes <= maximum_ciphertext_bytes)),
    CONSTRAINT chat_mls_pending_requests_ciphertext_bytes_check CHECK ((ciphertext_bytes >= 0)),
    CONSTRAINT chat_mls_pending_requests_genesis_check CHECK ((jsonb_typeof(genesis) = 'object'::text)),
    CONSTRAINT chat_mls_pending_requests_incarnation_check CHECK ((incarnation > 0)),
    CONSTRAINT chat_mls_pending_requests_maximum_ciphertext_bytes_check CHECK (((maximum_ciphertext_bytes >= 65536) AND (maximum_ciphertext_bytes <= 16777216))),
    CONSTRAINT chat_mls_pending_requests_maximum_messages_check CHECK (((maximum_messages >= 1) AND (maximum_messages <= 128))),
    CONSTRAINT chat_mls_pending_requests_message_count_check CHECK ((message_count >= 0)),
    CONSTRAINT chat_mls_pending_requests_sender_origin_check CHECK ((sender_origin = lower(sender_origin))),
    CONSTRAINT chat_mls_pending_requests_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'accepted'::text, 'rejected'::text, 'blocked'::text, 'expired'::text])))
);

CREATE TABLE public.chat_mls_rate_counters (
    scope_type text NOT NULL,
    scope_digest bytea NOT NULL,
    window_start timestamp with time zone NOT NULL,
    count bigint NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT chat_mls_rate_counters_count_check CHECK ((count >= 0)),
    CONSTRAINT chat_mls_rate_counters_scope_digest_check CHECK ((octet_length(scope_digest) = 32)),
    CONSTRAINT chat_mls_rate_counters_scope_type_check CHECK ((scope_type = ANY (ARRAY['capability_bundle'::text, 'identified_bundle'::text, 'capability_minute'::text, 'capability_day'::text, 'recipient'::text, 'federation_origin'::text])))
);

CREATE TABLE public.chat_mls_recovery_outbox (
    destination text NOT NULL,
    recovery_digest character(64) NOT NULL,
    conversation_id uuid NOT NULL,
    previous_incarnation bigint NOT NULL,
    replica jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error_class text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_recovery_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT chat_mls_recovery_outbox_destination_check CHECK ((destination = lower(destination))),
    CONSTRAINT chat_mls_recovery_outbox_previous_incarnation_check CHECK ((previous_incarnation > 0)),
    CONSTRAINT chat_mls_recovery_outbox_replica_check CHECK ((jsonb_typeof(replica) = 'object'::text)),
    CONSTRAINT chat_mls_recovery_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'delivered'::text])))
);

ALTER TABLE ONLY public.chat_invite_links
    ADD CONSTRAINT chat_invite_links_pkey PRIMARY KEY (link_id);

ALTER TABLE ONLY public.chat_invite_requests
    ADD CONSTRAINT chat_invite_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.chat_mls_admin_audit_events
    ADD CONSTRAINT chat_mls_admin_audit_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.chat_mls_anonymous_send_ids
    ADD CONSTRAINT chat_mls_anonymous_send_ids_pkey PRIMARY KEY (recipient_user_id, capability_hash, send_id);

ALTER TABLE ONLY public.chat_mls_authority_bootstrap_pages
    ADD CONSTRAINT chat_mls_authority_bootstrap_pages_pkey PRIMARY KEY (bootstrap_id, page_index);

ALTER TABLE ONLY public.chat_mls_authority_bootstraps
    ADD CONSTRAINT chat_mls_authority_bootstraps_pkey PRIMARY KEY (bootstrap_id);

ALTER TABLE ONLY public.chat_mls_consensus_evidence
    ADD CONSTRAINT chat_mls_consensus_evidence_pkey PRIMARY KEY (evidence_digest);

ALTER TABLE ONLY public.chat_mls_control_blocks
    ADD CONSTRAINT chat_mls_control_blocks_conversation_id_incarnation_block_h_key UNIQUE (conversation_id, incarnation, block_hash);

ALTER TABLE ONLY public.chat_mls_control_blocks
    ADD CONSTRAINT chat_mls_control_blocks_pkey PRIMARY KEY (conversation_id, incarnation, height);

ALTER TABLE ONLY public.chat_mls_control_outbox
    ADD CONSTRAINT chat_mls_control_outbox_pkey PRIMARY KEY (destination, conversation_id, incarnation, height);

ALTER TABLE ONLY public.chat_mls_conversations
    ADD CONSTRAINT chat_mls_conversations_pkey PRIMARY KEY (conversation_id);

ALTER TABLE ONLY public.chat_mls_delivery_capabilities
    ADD CONSTRAINT chat_mls_delivery_capabilities_pkey PRIMARY KEY (recipient_user_id, conversation_id, incarnation, epoch);

ALTER TABLE ONLY public.chat_mls_devices
    ADD CONSTRAINT chat_mls_devices_pkey PRIMARY KEY (user_id, device_id);

ALTER TABLE ONLY public.chat_mls_federation_inbound_state
    ADD CONSTRAINT chat_mls_federation_inbound_state_pkey PRIMARY KEY (origin);

ALTER TABLE ONLY public.chat_mls_federation_inbound_transactions
    ADD CONSTRAINT chat_mls_federation_inbound_transactions_pkey PRIMARY KEY (origin, sequence);

ALTER TABLE ONLY public.chat_mls_federation_outbox
    ADD CONSTRAINT chat_mls_federation_outbox_destination_recipient_send_id_key UNIQUE (destination, recipient_account_id, send_id);

ALTER TABLE ONLY public.chat_mls_federation_outbox
    ADD CONSTRAINT chat_mls_federation_outbox_destination_sequence_key UNIQUE (destination, sequence);

ALTER TABLE ONLY public.chat_mls_federation_outbox
    ADD CONSTRAINT chat_mls_federation_outbox_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.chat_mls_federation_sequences
    ADD CONSTRAINT chat_mls_federation_sequences_pkey PRIMARY KEY (destination);

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveri_conversation_id_new_incarnati_key UNIQUE (conversation_id, new_incarnation);

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveri_conversation_id_previous_inc_key1 UNIQUE (conversation_id, previous_incarnation, proposal_id);

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveri_conversation_id_previous_inca_key UNIQUE (conversation_id, previous_incarnation);

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveries_pkey PRIMARY KEY (recovery_digest);

ALTER TABLE ONLY public.chat_mls_incarnations
    ADD CONSTRAINT chat_mls_incarnations_mls_group_id_key UNIQUE (mls_group_id);

ALTER TABLE ONLY public.chat_mls_incarnations
    ADD CONSTRAINT chat_mls_incarnations_pkey PRIMARY KEY (conversation_id, incarnation);

ALTER TABLE ONLY public.chat_mls_invitation_feedback_outbox
    ADD CONSTRAINT chat_mls_invitation_feedback_outbox_pkey PRIMARY KEY (destination, conversation_id, incarnation, member_account, invited_epoch);

ALTER TABLE ONLY public.chat_mls_invitation_feedback
    ADD CONSTRAINT chat_mls_invitation_feedback_pkey PRIMARY KEY (conversation_id, incarnation, member_account, invited_epoch);

ALTER TABLE ONLY public.chat_mls_key_packages
    ADD CONSTRAINT chat_mls_key_packages_pkey PRIMARY KEY (user_id, device_id, key_package_ref);

ALTER TABLE ONLY public.chat_mls_local_member_devices
    ADD CONSTRAINT chat_mls_local_member_devices_pkey PRIMARY KEY (conversation_id, incarnation, user_id, device_id, joined_epoch);

ALTER TABLE ONLY public.chat_mls_local_members
    ADD CONSTRAINT chat_mls_local_members_pkey PRIMARY KEY (conversation_id, incarnation, user_id, joined_epoch);

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_recipient_user_id_recipient_device_id_send_key UNIQUE (recipient_user_id, recipient_device_id, send_id);

ALTER TABLE ONLY public.chat_mls_membership_deliveries
    ADD CONSTRAINT chat_mls_membership_deliveries_pkey PRIMARY KEY (conversation_id, incarnation, proposal_id, destination);

ALTER TABLE ONLY public.chat_mls_ordering_votes
    ADD CONSTRAINT chat_mls_ordering_votes_pkey PRIMARY KEY (conversation_id, incarnation, authority_set_sequence, height, round, vote_type, authority_domain);

ALTER TABLE ONLY public.chat_mls_owner_approvals
    ADD CONSTRAINT chat_mls_owner_approvals_pkey PRIMARY KEY (conversation_id, incarnation, owner_set_sequence, proposal_hash, owner_id);

ALTER TABLE ONLY public.chat_mls_participant_bootstrap_pages
    ADD CONSTRAINT chat_mls_participant_bootstrap_pages_pkey PRIMARY KEY (bootstrap_id, page_index);

ALTER TABLE ONLY public.chat_mls_participant_bootstraps
    ADD CONSTRAINT chat_mls_participant_bootstraps_pkey PRIMARY KEY (bootstrap_id);

ALTER TABLE ONLY public.chat_mls_pending_requests
    ADD CONSTRAINT chat_mls_pending_requests_pkey PRIMARY KEY (request_id);

ALTER TABLE ONLY public.chat_mls_rate_counters
    ADD CONSTRAINT chat_mls_rate_counters_pkey PRIMARY KEY (scope_type, scope_digest, window_start);

ALTER TABLE ONLY public.chat_mls_recovery_outbox
    ADD CONSTRAINT chat_mls_recovery_outbox_pkey PRIMARY KEY (destination, recovery_digest);

CREATE INDEX chat_invite_links_origin ON public.chat_invite_links USING btree (origin_domain);

CREATE INDEX chat_invite_links_touched ON public.chat_invite_links USING btree (touched_at);

CREATE INDEX chat_invite_requests_link ON public.chat_invite_requests USING btree (link_id, created_at);

CREATE INDEX chat_mls_control_outbox_due_idx ON public.chat_mls_control_outbox USING btree (state, next_attempt_at, destination, conversation_id, incarnation, height);

CREATE UNIQUE INDEX chat_mls_delivery_capability_current_idx ON public.chat_mls_delivery_capabilities USING btree (recipient_user_id, conversation_id, incarnation, capability_hash);

CREATE INDEX chat_mls_federation_outbox_due_idx ON public.chat_mls_federation_outbox USING btree (state, next_attempt_at, destination, sequence);

CREATE INDEX chat_mls_invitation_feedback_outbox_due_idx ON public.chat_mls_invitation_feedback_outbox USING btree (state, next_attempt_at, destination, conversation_id, incarnation);

CREATE INDEX chat_mls_key_packages_available_idx ON public.chat_mls_key_packages USING btree (user_id, device_id, expires_at, created_at) WHERE (claimed_at IS NULL);

CREATE INDEX chat_mls_mailbox_recipient_idx ON public.chat_mls_mailbox USING btree (recipient_user_id, recipient_device_id, cursor);

CREATE INDEX chat_mls_membership_deliveries_expiry_idx ON public.chat_mls_membership_deliveries USING btree (state, expires_at);

CREATE UNIQUE INDEX chat_mls_one_active_local_member_device_idx ON public.chat_mls_local_member_devices USING btree (conversation_id, incarnation, user_id, device_id) WHERE (removed_epoch IS NULL);

CREATE UNIQUE INDEX chat_mls_one_active_local_membership_idx ON public.chat_mls_local_members USING btree (conversation_id, incarnation, user_id) WHERE (removed_epoch IS NULL);

CREATE UNIQUE INDEX chat_mls_one_pending_request_per_sender_idx ON public.chat_mls_pending_requests USING btree (recipient_user_id, sender_address) WHERE (status = 'pending'::text);

CREATE INDEX chat_mls_pending_requests_recipient_idx ON public.chat_mls_pending_requests USING btree (recipient_user_id, status, created_at);

CREATE INDEX chat_mls_rate_counters_expiry_idx ON public.chat_mls_rate_counters USING btree (expires_at);

CREATE INDEX chat_mls_recovery_outbox_due_idx ON public.chat_mls_recovery_outbox USING btree (state, next_attempt_at, destination, recovery_digest);

CREATE TRIGGER chat_mls_authority_bootstrap_pages_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_authority_bootstrap_pages FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();

CREATE TRIGGER chat_mls_consensus_evidence_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_consensus_evidence FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();

CREATE TRIGGER chat_mls_control_blocks_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_control_blocks FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();

CREATE TRIGGER chat_mls_incarnation_recoveries_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_incarnation_recoveries FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();

CREATE TRIGGER chat_mls_invitation_feedback_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_invitation_feedback FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();

CREATE TRIGGER chat_mls_ordering_votes_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_ordering_votes FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();

CREATE TRIGGER chat_mls_owner_approvals_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_owner_approvals FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();

CREATE TRIGGER chat_mls_participant_bootstrap_pages_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_participant_bootstrap_pages FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();

ALTER TABLE ONLY public.chat_invite_requests
    ADD CONSTRAINT chat_invite_requests_link_id_fkey FOREIGN KEY (link_id) REFERENCES public.chat_invite_links(link_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_admin_audit_events
    ADD CONSTRAINT chat_mls_admin_audit_events_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE SET NULL;

ALTER TABLE ONLY public.chat_mls_anonymous_send_ids
    ADD CONSTRAINT chat_mls_anonymous_send_ids_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_authority_bootstrap_pages
    ADD CONSTRAINT chat_mls_authority_bootstrap_pages_bootstrap_id_fkey FOREIGN KEY (bootstrap_id) REFERENCES public.chat_mls_authority_bootstraps(bootstrap_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_consensus_evidence
    ADD CONSTRAINT chat_mls_consensus_evidence_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_control_blocks
    ADD CONSTRAINT chat_mls_control_blocks_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_control_outbox
    ADD CONSTRAINT chat_mls_control_outbox_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_conversations
    ADD CONSTRAINT chat_mls_conversations_current_incarnation_fk FOREIGN KEY (conversation_id, current_incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.chat_mls_delivery_capabilities
    ADD CONSTRAINT chat_mls_delivery_capabilities_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_delivery_capabilities
    ADD CONSTRAINT chat_mls_delivery_capabilities_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_delivery_capabilities
    ADD CONSTRAINT chat_mls_delivery_capabilities_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_devices
    ADD CONSTRAINT chat_mls_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_federation_inbound_transactions
    ADD CONSTRAINT chat_mls_federation_inbound_transactions_origin_fkey FOREIGN KEY (origin) REFERENCES public.chat_mls_federation_inbound_state(origin) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_federation_outbox
    ADD CONSTRAINT chat_mls_federation_outbox_sender_user_id_fkey FOREIGN KEY (sender_user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveri_conversation_id_new_incarnat_fkey FOREIGN KEY (conversation_id, new_incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveri_conversation_id_previous_inc_fkey FOREIGN KEY (conversation_id, previous_incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveries_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveries_initiated_by_fkey FOREIGN KEY (initiated_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.chat_mls_incarnations
    ADD CONSTRAINT chat_mls_incarnations_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_invitation_feedback
    ADD CONSTRAINT chat_mls_invitation_feedback_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_invitation_feedback_outbox
    ADD CONSTRAINT chat_mls_invitation_feedback_o_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_key_packages
    ADD CONSTRAINT chat_mls_key_packages_user_id_device_id_fkey FOREIGN KEY (user_id, device_id) REFERENCES public.chat_mls_devices(user_id, device_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_local_member_devices
    ADD CONSTRAINT chat_mls_local_member_devices_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_local_member_devices
    ADD CONSTRAINT chat_mls_local_member_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_local_members
    ADD CONSTRAINT chat_mls_local_members_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_local_members
    ADD CONSTRAINT chat_mls_local_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_recipient_user_id_recipient_device_id_fkey FOREIGN KEY (recipient_user_id, recipient_device_id) REFERENCES public.chat_mls_devices(user_id, device_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.chat_mls_pending_requests(request_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_membership_deliveries
    ADD CONSTRAINT chat_mls_membership_deliveries_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_membership_deliveries
    ADD CONSTRAINT chat_mls_membership_deliveries_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.chat_mls_ordering_votes
    ADD CONSTRAINT chat_mls_ordering_votes_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_owner_approvals
    ADD CONSTRAINT chat_mls_owner_approvals_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_participant_bootstrap_pages
    ADD CONSTRAINT chat_mls_participant_bootstrap_pages_bootstrap_id_fkey FOREIGN KEY (bootstrap_id) REFERENCES public.chat_mls_participant_bootstraps(bootstrap_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_pending_requests
    ADD CONSTRAINT chat_mls_pending_requests_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_pending_requests
    ADD CONSTRAINT chat_mls_pending_requests_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_pending_requests
    ADD CONSTRAINT chat_mls_pending_requests_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.chat_mls_recovery_outbox
    ADD CONSTRAINT chat_mls_recovery_outbox_recovery_digest_fkey FOREIGN KEY (recovery_digest) REFERENCES public.chat_mls_incarnation_recoveries(recovery_digest) ON DELETE CASCADE;
