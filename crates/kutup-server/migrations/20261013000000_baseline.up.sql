-- The schema every migration up to the clean-slate release built, squashed
-- (scripts/check-migration-baseline.sh proves it equal). Never edit:
-- a change is a new timestamped migration (docs/contributing.md).
--
-- Refuses a database that already holds the old chain's tables.
DO $$ BEGIN
  IF to_regclass('public.users') IS NOT NULL THEN
    RAISE EXCEPTION 'this database predates the baseline: start from an empty one';
  END IF;
END $$;

--
-- PostgreSQL database dump
--


-- Dumped from database version 16.15
-- Dumped by pg_dump version 16.15


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: kutup_no_files_in_albums(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.kutup_no_files_in_albums() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM collections WHERE id = NEW.collection_id AND kind = 'album') THEN
        RAISE EXCEPTION 'albums hold references, not files' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: kutup_no_folders_in_albums(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.kutup_no_folders_in_albums() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.parent_collection_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM collections WHERE id = NEW.parent_collection_id AND kind = 'album'
    ) THEN
        RAISE EXCEPTION 'albums hold no folders' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: mail_message_labels_mark_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mail_message_labels_mark_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE mail_messages SET change_xid = -1
     WHERE id = CASE WHEN TG_OP = 'DELETE' THEN OLD.message_id ELSE NEW.message_id END;
    RETURN NULL;
END
$$;


--
-- Name: mail_messages_folder_changed(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mail_messages_folder_changed() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.folder IS DISTINCT FROM OLD.folder THEN
        NEW.folder_changed_at := now();
    END IF;
    RETURN NEW;
END
$$;


--
-- Name: mail_messages_mark_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mail_messages_mark_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.change_xid := pg_current_xact_id()::text::bigint;
    RETURN NEW;
END
$$;


--
-- Name: mail_messages_tombstone(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mail_messages_tombstone() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.owner = OLD.user_id THEN
        INSERT INTO mail_message_tombstones (owner, id, received_at, change_xid)
        VALUES (OLD.owner, OLD.id, OLD.received_at, pg_current_xact_id()::text::bigint)
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NULL;
END
$$;


--
-- Name: reject_chat_mls_append_only_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reject_chat_mls_append_only_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'MLS security history is append-only';
END
$$;




--
-- Name: admin_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_audit_log (
    id bigint NOT NULL,
    admin_user_id uuid NOT NULL,
    action text NOT NULL,
    target_user_id uuid,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: admin_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.admin_audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: admin_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.admin_audit_log_id_seq OWNED BY public.admin_audit_log.id;


--
-- Name: album_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.album_items (
    album_id uuid NOT NULL,
    file_id uuid NOT NULL,
    file_key_envelope text NOT NULL,
    key_generation integer NOT NULL,
    album_epoch integer NOT NULL,
    added_by uuid,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT album_items_album_epoch_check CHECK ((album_epoch > 0)),
    CONSTRAINT album_items_key_generation_check CHECK ((key_generation > 0))
);


--
-- Name: auth_session_forks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_session_forks (
    selector_hash bytea NOT NULL,
    parent_session_id uuid NOT NULL,
    child_client_type text NOT NULL,
    payload bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT auth_session_forks_child_client_type_check CHECK ((child_client_type = ANY (ARRAY['web-drive'::text, 'web-chat'::text, 'web-maps'::text, 'web-photos'::text, 'web-office'::text, 'web-contacts'::text, 'web-mail'::text, 'web-pass'::text]))),
    CONSTRAINT auth_session_forks_payload_check CHECK (((octet_length(payload) >= 1) AND (octet_length(payload) <= 16384))),
    CONSTRAINT auth_session_forks_selector_hash_check CHECK ((octet_length(selector_hash) = 32))
);


--
-- Name: auth_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_sessions (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    client_type text NOT NULL,
    parent_session_id uuid,
    refresh_token_hash bytea NOT NULL,
    previous_refresh_token_hash bytea,
    rotated_at timestamp with time zone,
    local_key bytea,
    user_agent text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT auth_sessions_check CHECK (((parent_session_id IS NULL) OR (client_type = ANY (ARRAY['web-drive'::text, 'web-chat'::text, 'web-maps'::text, 'web-photos'::text, 'web-office'::text, 'web-contacts'::text, 'web-mail'::text, 'web-pass'::text])))),
    CONSTRAINT auth_sessions_client_type_check CHECK ((client_type = ANY (ARRAY['web-account'::text, 'web-drive'::text, 'web-chat'::text, 'web-maps'::text, 'web-photos'::text, 'web-office'::text, 'web-contacts'::text, 'web-mail'::text, 'web-pass'::text, 'cli'::text, 'android-drive'::text, 'android-chat'::text, 'android-maps'::text, 'android-photos'::text, 'ios-drive'::text, 'ios-chat'::text, 'ios-maps'::text, 'ios-photos'::text]))),
    CONSTRAINT auth_sessions_local_key_check CHECK ((octet_length(local_key) = 32)),
    CONSTRAINT auth_sessions_previous_refresh_token_hash_check CHECK ((octet_length(previous_refresh_token_hash) = 32)),
    CONSTRAINT auth_sessions_refresh_token_hash_check CHECK ((octet_length(refresh_token_hash) = 32)),
    CONSTRAINT auth_sessions_user_agent_check CHECK ((char_length(user_agent) <= 512))
);


--
-- Name: chat_anonymous_rate_counters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_anonymous_rate_counters (
    scope_type text NOT NULL,
    scope_digest bytea NOT NULL,
    window_start timestamp with time zone NOT NULL,
    count bigint NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT chat_anonymous_rate_counters_count_check CHECK ((count >= 0)),
    CONSTRAINT chat_anonymous_rate_counters_scope_digest_check CHECK ((octet_length(scope_digest) = 32)),
    CONSTRAINT chat_anonymous_rate_counters_scope_type_check CHECK ((scope_type = ANY (ARRAY['capability_bundle'::text, 'capability_minute'::text, 'capability_day'::text, 'recipient'::text, 'federation_origin'::text])))
);


--
-- Name: chat_anonymous_send_ids; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_anonymous_send_ids (
    recipient_user_id uuid NOT NULL,
    capability_hash bytea NOT NULL,
    send_id uuid NOT NULL,
    stored_count integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_anonymous_send_ids_capability_hash_check CHECK ((octet_length(capability_hash) = 32)),
    CONSTRAINT chat_anonymous_send_ids_stored_count_check CHECK (((stored_count >= 1) AND (stored_count <= 32)))
);


--
-- Name: chat_attachment_ledger_cursor_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_attachment_ledger_cursor_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_attachment_ledger_entities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_attachment_ledger_entities (
    user_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    revision bigint NOT NULL,
    envelope_digest character(64) NOT NULL,
    cursor bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_attachment_ledger_entities_envelope_digest_check CHECK ((envelope_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_attachment_ledger_entities_revision_check CHECK ((revision > 0))
);


--
-- Name: chat_attachment_ledger_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_attachment_ledger_history (
    user_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    revision bigint NOT NULL,
    envelope_digest character(64) NOT NULL,
    envelope text NOT NULL,
    cursor bigint DEFAULT nextval('public.chat_attachment_ledger_cursor_seq'::regclass) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_attachment_ledger_history_envelope_digest_check CHECK ((envelope_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_attachment_ledger_history_revision_check CHECK ((revision > 0))
);


--
-- Name: chat_attachment_ledger_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_attachment_ledger_operations (
    user_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    revision bigint NOT NULL,
    envelope_digest character(64) NOT NULL,
    cursor bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_attachment_ledger_operations_envelope_digest_check CHECK ((envelope_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_attachment_ledger_operations_revision_check CHECK ((revision > 0))
);


--
-- Name: chat_backup_bases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_bases (
    user_id uuid NOT NULL,
    object_id uuid NOT NULL,
    generation bigint NOT NULL,
    covered_cursor bigint NOT NULL,
    ciphertext_bytes bigint NOT NULL,
    ciphertext_sha256 character(64) NOT NULL,
    storage_path text NOT NULL,
    state text DEFAULT 'staged'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '24:00:00'::interval) NOT NULL,
    committed_at timestamp with time zone,
    CONSTRAINT chat_backup_bases_ciphertext_bytes_check CHECK (((ciphertext_bytes > 0) AND (ciphertext_bytes <= 134218752))),
    CONSTRAINT chat_backup_bases_ciphertext_sha256_check CHECK ((ciphertext_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_backup_bases_covered_cursor_check CHECK ((covered_cursor >= 0)),
    CONSTRAINT chat_backup_bases_generation_check CHECK ((generation > 0)),
    CONSTRAINT chat_backup_bases_state_check CHECK ((state = ANY (ARRAY['staged'::text, 'committed'::text])))
);


--
-- Name: chat_backup_device_heads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_device_heads (
    user_id uuid NOT NULL,
    source_device_id integer NOT NULL,
    last_device_sequence bigint NOT NULL,
    last_segment_digest character(64) NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_device_heads_last_device_sequence_check CHECK ((last_device_sequence > 0)),
    CONSTRAINT chat_backup_device_heads_last_segment_digest_check CHECK ((last_segment_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_backup_device_heads_source_device_id_check CHECK ((source_device_id > 0))
);


--
-- Name: chat_backup_media_objects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_objects (
    user_id uuid NOT NULL,
    media_id bytea NOT NULL,
    ciphertext_bytes bigint NOT NULL,
    ciphertext_sha256 character(64) NOT NULL,
    storage_path text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_media_objects_ciphertext_bytes_check CHECK ((ciphertext_bytes > 0)),
    CONSTRAINT chat_backup_media_objects_ciphertext_sha256_check CHECK ((ciphertext_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_backup_media_objects_media_id_check CHECK ((octet_length(media_id) = 32))
);


--
-- Name: chat_backup_media_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_operations (
    user_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    request_digest character(64) NOT NULL,
    media_id bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_media_operations_media_id_check CHECK ((octet_length(media_id) = 32)),
    CONSTRAINT chat_backup_media_operations_request_digest_check CHECK ((request_digest ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: chat_backup_media_reconciliation_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_reconciliation_entries (
    user_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    reference_id uuid NOT NULL,
    media_id bytea NOT NULL,
    CONSTRAINT chat_backup_media_reconciliation_entries_media_id_check CHECK ((octet_length(media_id) = 32))
);


--
-- Name: chat_backup_media_reconciliation_pages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_reconciliation_pages (
    user_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    page_index integer NOT NULL,
    request_digest character(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_media_reconciliation_pages_page_index_check CHECK ((page_index >= 0)),
    CONSTRAINT chat_backup_media_reconciliation_pages_request_digest_check CHECK ((request_digest ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: chat_backup_media_reconciliations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_reconciliations (
    user_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    target_generation bigint NOT NULL,
    reference_set_digest character(64) NOT NULL,
    next_page integer DEFAULT 0 NOT NULL,
    completed boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_media_reconciliations_next_page_check CHECK ((next_page >= 0)),
    CONSTRAINT chat_backup_media_reconciliations_reference_set_digest_check CHECK ((reference_set_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_backup_media_reconciliations_target_generation_check CHECK ((target_generation > 0))
);


--
-- Name: chat_backup_media_references; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_references (
    user_id uuid NOT NULL,
    media_id bytea NOT NULL,
    reference_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_backup_provision_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_provision_operations (
    user_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    request_digest character(64) NOT NULL,
    backup_incarnation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_provision_operations_request_digest_check CHECK ((request_digest ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: chat_backup_segments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_segments (
    user_id uuid NOT NULL,
    cursor bigint NOT NULL,
    operation_id uuid NOT NULL,
    source_device_id integer NOT NULL,
    device_sequence bigint NOT NULL,
    previous_segment_digest character(64) NOT NULL,
    account_manifest_sequence bigint NOT NULL,
    ciphertext_bytes integer NOT NULL,
    ciphertext_sha256 character(64) NOT NULL,
    ciphertext bytea NOT NULL,
    acknowledged_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_segments_account_manifest_sequence_check CHECK ((account_manifest_sequence > 0)),
    CONSTRAINT chat_backup_segments_check CHECK ((octet_length(ciphertext) = ciphertext_bytes)),
    CONSTRAINT chat_backup_segments_ciphertext_bytes_check CHECK (((ciphertext_bytes > 0) AND (ciphertext_bytes <= 263168))),
    CONSTRAINT chat_backup_segments_ciphertext_sha256_check CHECK ((ciphertext_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_backup_segments_cursor_check CHECK ((cursor > 0)),
    CONSTRAINT chat_backup_segments_device_sequence_check CHECK ((device_sequence > 0)),
    CONSTRAINT chat_backup_segments_previous_segment_digest_check CHECK ((previous_segment_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_backup_segments_source_device_id_check CHECK ((source_device_id > 0))
);


--
-- Name: chat_backups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backups (
    user_id uuid NOT NULL,
    backup_incarnation_id uuid NOT NULL,
    suite smallint NOT NULL,
    protection_domain smallint NOT NULL,
    root_envelope text NOT NULL,
    signer_authorization jsonb NOT NULL,
    signer_authorization_digest character(64) NOT NULL,
    current_cursor bigint DEFAULT 0 NOT NULL,
    current_generation bigint DEFAULT 0 NOT NULL,
    current_manifest_digest character(64) DEFAULT repeat('0'::text, 64) NOT NULL,
    current_manifest jsonb,
    current_base_object_id uuid,
    latest_protected_at timestamp with time zone,
    provisioned_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backups_check CHECK ((((current_generation = 0) AND (current_manifest IS NULL) AND (current_base_object_id IS NULL)) OR ((current_generation > 0) AND (current_manifest IS NOT NULL) AND (current_base_object_id IS NOT NULL)))),
    CONSTRAINT chat_backups_current_cursor_check CHECK ((current_cursor >= 0)),
    CONSTRAINT chat_backups_current_generation_check CHECK ((current_generation >= 0)),
    CONSTRAINT chat_backups_current_manifest_check CHECK (((current_manifest IS NULL) OR (jsonb_typeof(current_manifest) = 'object'::text))),
    CONSTRAINT chat_backups_current_manifest_digest_check CHECK ((current_manifest_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_backups_protection_domain_check CHECK ((protection_domain = 1)),
    CONSTRAINT chat_backups_signer_authorization_check CHECK ((jsonb_typeof(signer_authorization) = 'object'::text)),
    CONSTRAINT chat_backups_signer_authorization_digest_check CHECK ((signer_authorization_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_backups_suite_check CHECK ((suite = 1))
);


--
-- Name: chat_call_link_knocks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_call_link_knocks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    room_id text NOT NULL,
    participant_id text NOT NULL,
    label bytea NOT NULL,
    ticket_hash bytea NOT NULL,
    status smallint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    seat_hash bytea NOT NULL,
    account text,
    CONSTRAINT chat_call_link_knocks_label_check CHECK ((octet_length(label) = 168)),
    CONSTRAINT chat_call_link_knocks_participant_id_check CHECK ((participant_id ~ '^[0-9a-f]{32}$'::text)),
    CONSTRAINT chat_call_link_knocks_seat_hash_check CHECK ((octet_length(seat_hash) = 32)),
    CONSTRAINT chat_call_link_knocks_status_check CHECK ((status = ANY (ARRAY[0, 1, 2]))),
    CONSTRAINT chat_call_link_knocks_ticket_hash_check CHECK ((octet_length(ticket_hash) = 32))
);


--
-- Name: chat_call_link_seats; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_call_link_seats (
    room_id text NOT NULL,
    participant_id text NOT NULL,
    seat_hash bytea NOT NULL,
    role smallint,
    account text,
    no_screen boolean DEFAULT false NOT NULL,
    removed_at timestamp with time zone,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    last_minted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_call_link_seats_participant_id_check CHECK ((participant_id ~ '^[0-9a-f]{32}$'::text)),
    CONSTRAINT chat_call_link_seats_role_check CHECK ((role = ANY (ARRAY[1, 2]))),
    CONSTRAINT chat_call_link_seats_seat_hash_check CHECK ((octet_length(seat_hash) = 32))
);


--
-- Name: chat_call_links; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_call_links (
    room_id text NOT NULL,
    owner_user_id uuid NOT NULL,
    nonce text NOT NULL,
    access_token_hash bytea NOT NULL,
    info bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    waiting_room boolean DEFAULT false NOT NULL,
    host_token_hash bytea NOT NULL,
    sitting bigint DEFAULT 0 NOT NULL,
    locked boolean DEFAULT false NOT NULL,
    hostless_since timestamp with time zone,
    CONSTRAINT chat_call_links_access_token_hash_check CHECK ((octet_length(access_token_hash) = 32)),
    CONSTRAINT chat_call_links_host_token_hash_check CHECK (((host_token_hash IS NULL) OR (octet_length(host_token_hash) = 32))),
    CONSTRAINT chat_call_links_info_check CHECK ((octet_length(info) = 552)),
    CONSTRAINT chat_call_links_nonce_check CHECK ((nonce ~ '^[0-9a-f]{32}$'::text)),
    CONSTRAINT chat_call_links_room_id_check CHECK ((room_id ~ '^[0-9a-f]{32}$'::text))
);


--
-- Name: chat_delivery_capabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_delivery_capabilities (
    user_id uuid NOT NULL,
    profile_version character(64) NOT NULL,
    profile_revision bigint NOT NULL,
    capability_hash bytea NOT NULL,
    rotated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_delivery_capabilities_capability_hash_check CHECK ((octet_length(capability_hash) = 32)),
    CONSTRAINT chat_delivery_capabilities_profile_revision_check CHECK ((profile_revision > 0))
);


--
-- Name: chat_device_manifest_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_device_manifest_history (
    user_id uuid NOT NULL,
    incarnation_id character(64) NOT NULL,
    version bigint NOT NULL,
    manifest_hash character(64) NOT NULL,
    authority_key_id character(64) NOT NULL,
    manifest jsonb NOT NULL,
    accepted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_device_manifest_history_authority_key_id_check CHECK ((authority_key_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_device_manifest_history_incarnation_id_check CHECK ((incarnation_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_device_manifest_history_manifest_check CHECK ((jsonb_typeof(manifest) = 'object'::text)),
    CONSTRAINT chat_device_manifest_history_manifest_hash_check CHECK ((manifest_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_device_manifest_history_version_check CHECK ((version > 0))
);


--
-- Name: chat_device_manifests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_device_manifests (
    user_id uuid NOT NULL,
    version bigint NOT NULL,
    manifest_hash text NOT NULL,
    authority_key_id text NOT NULL,
    manifest jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_device_manifests_authority_key_id_check CHECK ((length(authority_key_id) = 64)),
    CONSTRAINT chat_device_manifests_manifest_hash_check CHECK ((length(manifest_hash) = 64)),
    CONSTRAINT chat_device_manifests_version_check CHECK ((version > 0))
);


--
-- Name: chat_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_devices (
    user_id uuid NOT NULL,
    device_id integer NOT NULL,
    suite smallint NOT NULL,
    registration_id bigint NOT NULL,
    identity_key text NOT NULL,
    signed_pre_key_id bigint NOT NULL,
    signed_pre_key text NOT NULL,
    signed_pre_key_signature text NOT NULL,
    last_resort_kyber_pre_key_id bigint NOT NULL,
    last_resort_kyber_pre_key text NOT NULL,
    last_resort_kyber_pre_key_signature text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone,
    CONSTRAINT chat_devices_device_id_check CHECK (((device_id >= 1) AND (device_id <= 127))),
    CONSTRAINT chat_devices_suite_known CHECK ((suite = 1))
);


--
-- Name: chat_federation_inbound_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_federation_inbound_state (
    origin text NOT NULL,
    last_sequence bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_federation_inbound_state_last_sequence_check CHECK ((last_sequence >= 0))
);


--
-- Name: chat_federation_inbound_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_federation_inbound_transactions (
    origin text NOT NULL,
    sequence bigint NOT NULL,
    transaction_id text NOT NULL,
    response jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_federation_inbound_transactions_sequence_check CHECK ((sequence > 0))
);


--
-- Name: chat_federation_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_federation_outbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    destination text NOT NULL,
    sequence bigint NOT NULL,
    sender_user_id uuid NOT NULL,
    sender_device_id integer NOT NULL,
    send_id text NOT NULL,
    recipient text NOT NULL,
    sender text NOT NULL,
    request jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    response jsonb,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_federation_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT chat_federation_outbox_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT chat_federation_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'mismatch'::text, 'delivered'::text])))
);


--
-- Name: chat_federation_sequences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_federation_sequences (
    destination text NOT NULL,
    next_sequence bigint NOT NULL,
    CONSTRAINT chat_federation_sequences_next_sequence_check CHECK ((next_sequence > 0))
);


--
-- Name: chat_invite_links; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_invite_requests; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_joined_meetings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_joined_meetings (
    user_id uuid NOT NULL,
    id text NOT NULL,
    entry bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_joined_meetings_entry_check CHECK ((octet_length(entry) = 1064)),
    CONSTRAINT chat_joined_meetings_id_check CHECK ((id ~ '^[0-9a-f]{32}$'::text))
);


--
-- Name: chat_mailbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_mailbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    cursor bigint NOT NULL,
    recipient_user_id uuid NOT NULL,
    recipient_device_id integer NOT NULL,
    sender text,
    sender_device_id integer NOT NULL,
    envelope_type smallint NOT NULL,
    suite smallint NOT NULL,
    content text NOT NULL,
    server_ts timestamp with time zone DEFAULT now() NOT NULL,
    sealed_sender boolean DEFAULT false NOT NULL,
    send_id text,
    CONSTRAINT chat_mailbox_sender_qualified CHECK (((sender IS NULL) OR (sender ~ '^[a-z0-9_-]{3,32}@([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text))),
    CONSTRAINT chat_mailbox_suite_known CHECK ((suite = 1))
);


--
-- Name: chat_mailbox_cursor_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.chat_mailbox ALTER COLUMN cursor ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.chat_mailbox_cursor_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: chat_media_federation_inbound_pending; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_federation_inbound_pending (
    origin text NOT NULL,
    sequence bigint NOT NULL,
    operation_id uuid NOT NULL,
    transaction_digest character(64) NOT NULL,
    recipient_user_id uuid NOT NULL,
    attachment_id uuid NOT NULL,
    ciphertext_bytes bigint NOT NULL,
    lease_id uuid NOT NULL,
    lease_until timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_media_federation_inbound_pending_ciphertext_bytes_check CHECK ((ciphertext_bytes > 0)),
    CONSTRAINT chat_media_federation_inbound_pending_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT chat_media_federation_inbound_pending_transaction_digest_check CHECK ((transaction_digest ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: chat_media_federation_inbound_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_federation_inbound_state (
    origin text NOT NULL,
    last_sequence bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_media_federation_inbound_state_last_sequence_check CHECK ((last_sequence >= 0))
);


--
-- Name: chat_media_federation_inbound_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_federation_inbound_transactions (
    origin text NOT NULL,
    sequence bigint NOT NULL,
    operation_id uuid NOT NULL,
    transaction_digest character(64) NOT NULL,
    response_status smallint NOT NULL,
    response jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_media_federation_inbound_transact_transaction_digest_check CHECK ((transaction_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_media_federation_inbound_transactions_sequence_check CHECK ((sequence > 0))
);


--
-- Name: chat_media_federation_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_federation_outbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    destination text NOT NULL,
    sequence bigint NOT NULL,
    origin_user_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    transaction jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error_class text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_media_federation_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT chat_media_federation_outbox_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT chat_media_federation_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'delivered'::text, 'rejected'::text])))
);


--
-- Name: chat_media_federation_pull_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_federation_pull_grants (
    origin_user_id uuid NOT NULL,
    destination text NOT NULL,
    recipient text NOT NULL,
    operation_id uuid NOT NULL,
    attachment_id uuid NOT NULL,
    retrieval_token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_media_federation_pull_grants_retrieval_token_hash_check CHECK ((octet_length(retrieval_token_hash) = 32))
);


--
-- Name: chat_media_federation_sequences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_federation_sequences (
    destination text NOT NULL,
    next_sequence bigint DEFAULT 1 NOT NULL,
    CONSTRAINT chat_media_federation_sequences_next_sequence_check CHECK ((next_sequence > 0))
);


--
-- Name: chat_media_objects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_objects (
    attachment_id uuid NOT NULL,
    origin_user_id uuid,
    origin_domain text NOT NULL,
    suite smallint NOT NULL,
    ciphertext_bytes bigint NOT NULL,
    ciphertext_sha256 character(64) NOT NULL,
    retrieval_token_hash bytea NOT NULL,
    storage_path text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_media_objects_ciphertext_bytes_check CHECK ((ciphertext_bytes > 0)),
    CONSTRAINT chat_media_objects_ciphertext_sha256_check CHECK ((ciphertext_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_media_objects_retrieval_token_hash_check CHECK ((octet_length(retrieval_token_hash) = 32)),
    CONSTRAINT chat_media_objects_suite_check CHECK ((suite = 1))
);


--
-- Name: chat_media_origin_delivery_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_origin_delivery_operations (
    origin_user_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    recipient_user_id uuid NOT NULL,
    attachment_id uuid NOT NULL,
    ciphertext_bytes bigint NOT NULL,
    ciphertext_sha256 character(64) NOT NULL,
    offer_digest character(64) NOT NULL,
    storage_reference_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_media_origin_delivery_operations_ciphertext_bytes_check CHECK ((ciphertext_bytes > 0)),
    CONSTRAINT chat_media_origin_delivery_operations_ciphertext_sha256_check CHECK ((ciphertext_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_media_origin_delivery_operations_offer_digest_check CHECK ((offer_digest ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: chat_media_rate_counters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_rate_counters (
    scope_type text NOT NULL,
    scope_digest bytea NOT NULL,
    window_start timestamp with time zone NOT NULL,
    count bigint NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT chat_media_rate_counters_count_check CHECK ((count >= 0)),
    CONSTRAINT chat_media_rate_counters_scope_digest_check CHECK ((octet_length(scope_digest) = 32)),
    CONSTRAINT chat_media_rate_counters_scope_type_check CHECK ((scope_type = ANY (ARRAY['capability_minute'::text, 'capability_day'::text, 'recipient'::text, 'federation_origin'::text])))
);


--
-- Name: chat_media_references; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_references (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    attachment_id uuid NOT NULL,
    logical_bytes bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_media_references_logical_bytes_check CHECK ((logical_bytes > 0))
);


--
-- Name: chat_media_uploads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_uploads (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    attachment_id uuid NOT NULL,
    suite smallint NOT NULL,
    total_bytes bigint NOT NULL,
    received_bytes bigint DEFAULT 0 NOT NULL,
    retrieval_token_hash bytea NOT NULL,
    storage_path text NOT NULL,
    s3_upload_id text NOT NULL,
    s3_part_etags jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    pending_bytes bytea DEFAULT '\x'::bytea NOT NULL,
    CONSTRAINT chat_media_uploads_check CHECK ((received_bytes <= total_bytes)),
    CONSTRAINT chat_media_uploads_received_bytes_check CHECK ((received_bytes >= 0)),
    CONSTRAINT chat_media_uploads_retrieval_token_hash_check CHECK ((octet_length(retrieval_token_hash) = 32)),
    CONSTRAINT chat_media_uploads_suite_check CHECK ((suite = 1)),
    CONSTRAINT chat_media_uploads_total_bytes_check CHECK ((total_bytes > 0))
);


--
-- Name: chat_mls_admin_audit_events; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_anonymous_send_ids; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_mls_anonymous_send_ids (
    recipient_user_id uuid NOT NULL,
    capability_hash bytea NOT NULL,
    send_id uuid NOT NULL,
    stored_count integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_anonymous_send_ids_capability_hash_check CHECK ((octet_length(capability_hash) = 32)),
    CONSTRAINT chat_mls_anonymous_send_ids_stored_count_check CHECK (((stored_count >= 1) AND (stored_count <= 32)))
);


--
-- Name: chat_mls_authority_bootstrap_pages; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_authority_bootstraps; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_consensus_evidence; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_control_blocks; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_control_outbox; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_conversations; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_delivery_capabilities; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_devices; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_federation_inbound_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_mls_federation_inbound_state (
    origin text NOT NULL,
    last_sequence bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_federation_inbound_state_last_sequence_check CHECK ((last_sequence >= 0)),
    CONSTRAINT chat_mls_federation_inbound_state_origin_check CHECK ((origin = lower(origin)))
);


--
-- Name: chat_mls_federation_inbound_transactions; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_federation_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_mls_federation_outbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    destination text NOT NULL,
    sequence bigint NOT NULL,
    sender_user_id uuid,
    sender_device_id integer,
    recipient text NOT NULL,
    send_id uuid NOT NULL,
    transaction jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error_class text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_federation_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT chat_mls_federation_outbox_destination_check CHECK ((destination = lower(destination))),
    CONSTRAINT chat_mls_federation_outbox_sender_device_id_check CHECK (((sender_device_id IS NULL) OR ((sender_device_id >= 1) AND (sender_device_id <= 127)))),
    CONSTRAINT chat_mls_federation_outbox_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT chat_mls_federation_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'delivered'::text, 'rejected'::text]))),
    CONSTRAINT chat_mls_federation_outbox_transaction_check CHECK ((jsonb_typeof(transaction) = 'object'::text)),
    CONSTRAINT chat_mls_federation_outbox_transaction_check1 CHECK ((NOT (transaction ?| ARRAY['sender'::text, 'senderDeviceId'::text, 'conversationId'::text, 'groupId'::text, 'epoch'::text])))
);


--
-- Name: chat_mls_federation_sequences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_mls_federation_sequences (
    destination text NOT NULL,
    next_sequence bigint NOT NULL,
    CONSTRAINT chat_mls_federation_sequences_destination_check CHECK ((destination = lower(destination))),
    CONSTRAINT chat_mls_federation_sequences_next_sequence_check CHECK ((next_sequence > 0))
);


--
-- Name: chat_mls_incarnation_recoveries; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_incarnations; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_invitation_feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_mls_invitation_feedback (
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    member_address text NOT NULL,
    invited_epoch bigint NOT NULL,
    source_domain text NOT NULL,
    decision text NOT NULL,
    decided_at timestamp with time zone NOT NULL,
    feedback_digest character(64) NOT NULL,
    feedback jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_invitation_feedback_decision_check CHECK ((decision = ANY (ARRAY['accepted'::text, 'rejected'::text, 'expired'::text]))),
    CONSTRAINT chat_mls_invitation_feedback_feedback_check CHECK ((jsonb_typeof(feedback) = 'object'::text)),
    CONSTRAINT chat_mls_invitation_feedback_feedback_digest_check CHECK ((feedback_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_invitation_feedback_incarnation_check CHECK ((incarnation > 0)),
    CONSTRAINT chat_mls_invitation_feedback_invited_epoch_check CHECK ((invited_epoch > 0)),
    CONSTRAINT chat_mls_invitation_feedback_source_domain_check CHECK ((source_domain = lower(source_domain)))
);


--
-- Name: chat_mls_invitation_feedback_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_mls_invitation_feedback_outbox (
    destination text NOT NULL,
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL,
    member_address text NOT NULL,
    invited_epoch bigint NOT NULL,
    feedback_digest character(64) NOT NULL,
    feedback jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error_class text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_mls_invitation_feedback_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT chat_mls_invitation_feedback_outbox_destination_check CHECK ((destination = lower(destination))),
    CONSTRAINT chat_mls_invitation_feedback_outbox_feedback_check CHECK ((jsonb_typeof(feedback) = 'object'::text)),
    CONSTRAINT chat_mls_invitation_feedback_outbox_feedback_digest_check CHECK ((feedback_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_mls_invitation_feedback_outbox_incarnation_check CHECK ((incarnation > 0)),
    CONSTRAINT chat_mls_invitation_feedback_outbox_invited_epoch_check CHECK ((invited_epoch > 0)),
    CONSTRAINT chat_mls_invitation_feedback_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'delivered'::text])))
);


--
-- Name: chat_mls_key_packages; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_local_member_devices; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_local_members; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_mailbox; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_mailbox_cursor_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.chat_mls_mailbox ALTER COLUMN cursor ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.chat_mls_mailbox_cursor_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: chat_mls_membership_deliveries; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_ordering_votes; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_owner_approvals; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_participant_bootstrap_pages; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_participant_bootstraps; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_pending_requests; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_rate_counters; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_mls_recovery_outbox; Type: TABLE; Schema: public; Owner: -
--

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


--
-- Name: chat_one_time_kyber_pre_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_one_time_kyber_pre_keys (
    user_id uuid NOT NULL,
    device_id integer NOT NULL,
    key_id bigint NOT NULL,
    public_key text NOT NULL,
    signature text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_one_time_pre_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_one_time_pre_keys (
    user_id uuid NOT NULL,
    device_id integer NOT NULL,
    key_id bigint NOT NULL,
    public_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_profiles (
    user_id uuid NOT NULL,
    suite smallint NOT NULL,
    version character(64) NOT NULL,
    revision bigint NOT NULL,
    source_device_id integer NOT NULL,
    name_ciphertext text NOT NULL,
    avatar_ciphertext text,
    wrapped_key text NOT NULL,
    access_key_verifier bytea NOT NULL,
    is_current boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    about_ciphertext text,
    CONSTRAINT chat_profiles_access_key_verifier_check CHECK ((octet_length(access_key_verifier) = 32)),
    CONSTRAINT chat_profiles_revision_check CHECK ((revision > 0)),
    CONSTRAINT chat_profiles_source_device_id_check CHECK ((((source_device_id >= 1) AND (source_device_id <= 127)) OR (source_device_id = 128))),
    CONSTRAINT chat_profiles_suite_check CHECK ((suite = 1))
);


--
-- Name: chat_push_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_push_subscriptions (
    user_id uuid NOT NULL,
    device_id integer NOT NULL,
    endpoint text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_push_subscriptions_endpoint_check CHECK ((length(endpoint) <= 2048))
);


--
-- Name: chat_sealed_federation_inbound; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_sealed_federation_inbound (
    origin text NOT NULL,
    sequence bigint NOT NULL,
    send_id uuid NOT NULL,
    response_status smallint NOT NULL,
    response jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_sealed_federation_inbound_response_check CHECK ((jsonb_typeof(response) = 'object'::text)),
    CONSTRAINT chat_sealed_federation_inbound_response_status_check CHECK (((response_status >= 200) AND (response_status <= 599))),
    CONSTRAINT chat_sealed_federation_inbound_sequence_check CHECK ((sequence > 0))
);


--
-- Name: chat_sealed_federation_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_sealed_federation_outbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    destination text NOT NULL,
    sequence bigint NOT NULL,
    sender_user_id uuid,
    sender_device_id integer,
    recipient text NOT NULL,
    send_id uuid NOT NULL,
    transaction jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error_class text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_sealed_federation_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT chat_sealed_federation_outbox_sender_device_id_check CHECK (((sender_device_id IS NULL) OR ((sender_device_id >= 1) AND (sender_device_id <= 127)))),
    CONSTRAINT chat_sealed_federation_outbox_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT chat_sealed_federation_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'delivered'::text, 'rejected'::text]))),
    CONSTRAINT chat_sealed_federation_outbox_transaction_check CHECK ((jsonb_typeof(transaction) = 'object'::text))
);


--
-- Name: chat_sealed_federation_sequences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_sealed_federation_sequences (
    destination text NOT NULL,
    next_sequence bigint NOT NULL,
    CONSTRAINT chat_sealed_federation_sequences_next_sequence_check CHECK ((next_sequence > 0))
);


--
-- Name: chat_sends; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_sends (
    sender_user_id uuid NOT NULL,
    sender_device_id integer NOT NULL,
    send_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    delivery_scope text DEFAULT 'direct'::text NOT NULL,
    CONSTRAINT chat_sends_delivery_scope_check CHECK ((delivery_scope = ANY (ARRAY['direct'::text, 'sync'::text])))
);


--
-- Name: chat_web_push_key; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_web_push_key (
    id smallint NOT NULL,
    private_key bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_web_push_key_id_check CHECK ((id = 1)),
    CONSTRAINT chat_web_push_key_private_key_check CHECK ((octet_length(private_key) = 32))
);


--
-- Name: chat_ws_tickets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_ws_tickets (
    token_hash text NOT NULL,
    user_id uuid NOT NULL,
    device_id integer NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_ws_tickets_token_hash_check CHECK ((length(token_hash) = 64))
);


--
-- Name: collection_key_epoch_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collection_key_epoch_history (
    collection_id uuid NOT NULL,
    epoch integer NOT NULL,
    owner_key_envelope text NOT NULL,
    epoch_statement text NOT NULL,
    epoch_statement_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    previous_key_envelope text,
    CONSTRAINT collection_key_epoch_history_epoch_check CHECK ((epoch > 0)),
    CONSTRAINT collection_key_epoch_history_epoch_statement_hash_check CHECK ((epoch_statement_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT collection_key_epoch_history_previous_key CHECK (((epoch = 1) = (previous_key_envelope IS NULL)))
);


--
-- Name: collection_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collection_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    collection_id uuid NOT NULL,
    sharer_user_id uuid NOT NULL,
    recipient_user_id uuid NOT NULL,
    named_share_envelope text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    can_upload boolean DEFAULT false NOT NULL,
    can_delete boolean DEFAULT false NOT NULL,
    upload_quota_bytes bigint
);


--
-- Name: collections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collections (
    id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    name_envelope text NOT NULL,
    owner_key_envelope text NOT NULL,
    key_epoch integer NOT NULL,
    name_revision bigint NOT NULL,
    epoch_statement text NOT NULL,
    epoch_statement_hash text NOT NULL,
    parent_collection_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    color text,
    deleted_at timestamp with time zone,
    trash_root_id uuid,
    kind text DEFAULT 'folder'::text NOT NULL,
    name_hash text,
    CONSTRAINT collections_album_top_level CHECK (((kind = 'folder'::text) OR (parent_collection_id IS NULL))),
    CONSTRAINT collections_epoch_statement_hash_check CHECK ((epoch_statement_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT collections_key_epoch_check CHECK ((key_epoch > 0)),
    CONSTRAINT collections_kind_check CHECK ((kind = ANY (ARRAY['folder'::text, 'album'::text]))),
    CONSTRAINT collections_name_hash_check CHECK ((name_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT collections_name_revision_check CHECK ((name_revision > 0))
);


--
-- Name: contact_emails; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contact_emails (
    contact_id uuid NOT NULL,
    user_id uuid NOT NULL,
    address text NOT NULL,
    label text,
    "position" integer NOT NULL,
    last_used_at timestamp with time zone,
    CONSTRAINT contact_emails_address_check CHECK (((address = lower(address)) AND ((length(address) >= 3) AND (length(address) <= 320)))),
    CONSTRAINT contact_emails_position_check CHECK (("position" >= 0))
);


--
-- Name: contact_group_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contact_group_members (
    contact_id uuid NOT NULL,
    group_id uuid NOT NULL
);


--
-- Name: contact_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contact_groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    color text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT contact_groups_color_check CHECK ((color ~ '^#[0-9a-f]{6}$'::text)),
    CONSTRAINT contact_groups_name_check CHECK (((length(name) >= 1) AND (length(name) <= 100)))
);


--
-- Name: contacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contacts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    uid text NOT NULL,
    name text NOT NULL,
    summary text NOT NULL,
    signature bytea NOT NULL,
    card bytea NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT contacts_card_check CHECK (((octet_length(card) >= 1) AND (octet_length(card) <= 600000))),
    CONSTRAINT contacts_name_check CHECK (((length(name) >= 1) AND (length(name) <= 800))),
    CONSTRAINT contacts_revision_check CHECK ((revision >= 1)),
    CONSTRAINT contacts_signature_check CHECK ((octet_length(signature) = 64)),
    CONSTRAINT contacts_summary_check CHECK (((octet_length(summary) >= 1) AND (octet_length(summary) <= 32768))),
    CONSTRAINT contacts_uid_check CHECK (((length(uid) >= 1) AND (length(uid) <= 800)))
);


--
-- Name: drive_federation_mutations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_federation_mutations (
    origin text NOT NULL,
    request_id text NOT NULL,
    request_hash text NOT NULL,
    share_id uuid NOT NULL,
    operation text NOT NULL,
    response_status smallint NOT NULL,
    response_content_type text NOT NULL,
    response_body bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT drive_federation_mutations_operation_check CHECK ((operation = ANY (ARRAY['upload'::text, 'delete'::text]))),
    CONSTRAINT drive_federation_mutations_origin_check CHECK ((origin = lower(origin))),
    CONSTRAINT drive_federation_mutations_origin_check1 CHECK (((length(origin) >= 3) AND (length(origin) <= 253))),
    CONSTRAINT drive_federation_mutations_origin_check2 CHECK ((origin ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT drive_federation_mutations_request_hash_check CHECK ((request_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT drive_federation_mutations_request_id_check CHECK (((length(request_id) >= 1) AND (length(request_id) <= 128))),
    CONSTRAINT drive_federation_mutations_request_id_check1 CHECK ((request_id ~ '^[A-Za-z0-9._~-]+$'::text)),
    CONSTRAINT drive_federation_mutations_response_status_check CHECK (((response_status >= 100) AND (response_status <= 599)))
);


--
-- Name: drive_profile_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_profile_keys (
    user_id uuid NOT NULL,
    direction text NOT NULL,
    peer_account text NOT NULL,
    envelope text NOT NULL,
    profile_version text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT drive_profile_keys_direction_check CHECK ((direction = ANY (ARRAY['sent'::text, 'received'::text]))),
    CONSTRAINT drive_profile_keys_envelope_check CHECK ((length(envelope) <= 2048)),
    CONSTRAINT drive_profile_keys_peer_account_check CHECK (((length(peer_account) >= 3) AND (length(peer_account) <= 320))),
    CONSTRAINT drive_profile_keys_profile_version_check CHECK ((profile_version ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: federated_incoming_file_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federated_incoming_file_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    remote_domain text NOT NULL,
    remote_capability text NOT NULL,
    capability_hash text NOT NULL,
    remote_file_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    owner_account text NOT NULL,
    owner_incarnation_id text NOT NULL,
    owner_signing_public_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federated_incoming_file_shares_capability_hash_check CHECK ((capability_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federated_incoming_file_shares_owner_incarnation_id_check CHECK ((owner_incarnation_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federated_incoming_file_shares_remote_capability_check CHECK (((length(remote_capability) >= 32) AND (length(remote_capability) <= 256))),
    CONSTRAINT federated_incoming_file_shares_remote_capability_check1 CHECK ((remote_capability ~ '^[A-Za-z0-9._~-]+$'::text)),
    CONSTRAINT federated_incoming_file_shares_remote_domain_check CHECK ((remote_domain = lower(remote_domain)))
);


--
-- Name: federated_incoming_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federated_incoming_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    remote_domain text NOT NULL,
    remote_capability text NOT NULL,
    capability_hash text NOT NULL,
    remote_collection_id uuid NOT NULL,
    named_share_envelope text NOT NULL,
    name_envelope text NOT NULL,
    key_epoch integer NOT NULL,
    name_revision bigint NOT NULL,
    epoch_statement text NOT NULL,
    epoch_statement_hash text NOT NULL,
    owner_user_id uuid NOT NULL,
    owner_account text NOT NULL,
    owner_incarnation_id text NOT NULL,
    owner_signing_public_key text NOT NULL,
    owner_authority_public_key text NOT NULL,
    can_upload boolean DEFAULT false NOT NULL,
    can_delete boolean DEFAULT false NOT NULL,
    upload_quota_bytes bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    collection_kind text DEFAULT 'folder'::text NOT NULL,
    CONSTRAINT federated_incoming_shares_capability_hash_check CHECK ((capability_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federated_incoming_shares_collection_kind_check CHECK ((collection_kind = ANY (ARRAY['folder'::text, 'album'::text]))),
    CONSTRAINT federated_incoming_shares_epoch_statement_hash_check CHECK ((epoch_statement_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federated_incoming_shares_key_epoch_check CHECK ((key_epoch > 0)),
    CONSTRAINT federated_incoming_shares_name_revision_check CHECK ((name_revision > 0)),
    CONSTRAINT federated_incoming_shares_owner_incarnation_id_check CHECK ((owner_incarnation_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federated_incoming_shares_remote_capability_check CHECK (((length(remote_capability) >= 32) AND (length(remote_capability) <= 256))),
    CONSTRAINT federated_incoming_shares_remote_capability_check1 CHECK ((remote_capability ~ '^[A-Za-z0-9._~-]+$'::text)),
    CONSTRAINT federated_incoming_shares_remote_domain_check CHECK ((remote_domain = lower(remote_domain))),
    CONSTRAINT federated_incoming_shares_remote_domain_check1 CHECK (((length(remote_domain) >= 3) AND (length(remote_domain) <= 253))),
    CONSTRAINT federated_incoming_shares_remote_domain_check2 CHECK ((remote_domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT federated_incoming_shares_upload_quota_bytes_check CHECK (((upload_quota_bytes IS NULL) OR (upload_quota_bytes >= 0)))
);


--
-- Name: federated_outgoing_file_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federated_outgoing_file_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    file_id uuid NOT NULL,
    sharer_user_id uuid NOT NULL,
    recipient_username text NOT NULL,
    recipient_domain text NOT NULL,
    recipient_incarnation_id text NOT NULL,
    share_envelope text NOT NULL,
    key_generation integer NOT NULL,
    capability_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    can_edit boolean DEFAULT false NOT NULL,
    CONSTRAINT federated_outgoing_file_shares_capability_hash_check CHECK ((capability_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federated_outgoing_file_shares_key_generation_check CHECK ((key_generation > 0)),
    CONSTRAINT federated_outgoing_file_shares_recipient_domain_check CHECK ((recipient_domain = lower(recipient_domain))),
    CONSTRAINT federated_outgoing_file_shares_recipient_domain_check1 CHECK (((length(recipient_domain) >= 3) AND (length(recipient_domain) <= 253))),
    CONSTRAINT federated_outgoing_file_shares_recipient_incarnation_id_check CHECK ((recipient_incarnation_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federated_outgoing_file_shares_recipient_username_check CHECK ((recipient_username ~ '^[a-z0-9][a-z0-9._-]{0,63}$'::text)),
    CONSTRAINT federated_outgoing_file_shares_share_envelope_check CHECK ((length(share_envelope) <= 2048))
);


--
-- Name: federated_outgoing_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federated_outgoing_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    collection_id uuid NOT NULL,
    sharer_user_id uuid NOT NULL,
    recipient_username text NOT NULL,
    recipient_domain text NOT NULL,
    named_share_envelope text NOT NULL,
    capability_hash text NOT NULL,
    can_upload boolean DEFAULT false NOT NULL,
    can_delete boolean DEFAULT false NOT NULL,
    upload_quota_bytes bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federated_outgoing_shares_capability_hash_check CHECK ((capability_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federated_outgoing_shares_recipient_domain_check CHECK ((recipient_domain = lower(recipient_domain))),
    CONSTRAINT federated_outgoing_shares_recipient_domain_check1 CHECK (((length(recipient_domain) >= 3) AND (length(recipient_domain) <= 253))),
    CONSTRAINT federated_outgoing_shares_recipient_domain_check2 CHECK ((recipient_domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT federated_outgoing_shares_recipient_username_check CHECK ((recipient_username ~ '^[a-z0-9][a-z0-9._-]{0,63}$'::text)),
    CONSTRAINT federated_outgoing_shares_upload_quota_bytes_check CHECK (((upload_quota_bytes IS NULL) OR (upload_quota_bytes >= 0)))
);


--
-- Name: federation_domain_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_domain_rules (
    domain text NOT NULL,
    feature text NOT NULL,
    inbound_action text DEFAULT 'inherit'::text NOT NULL,
    outbound_action text DEFAULT 'inherit'::text NOT NULL,
    trust_requirement text DEFAULT 'inherit'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_domain_rules_domain_check CHECK ((domain = lower(domain))),
    CONSTRAINT federation_domain_rules_domain_check1 CHECK (((length(domain) >= 3) AND (length(domain) <= 253))),
    CONSTRAINT federation_domain_rules_domain_check2 CHECK ((domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT federation_domain_rules_inbound_action_check CHECK ((inbound_action = ANY (ARRAY['inherit'::text, 'allow'::text, 'block'::text]))),
    CONSTRAINT federation_domain_rules_outbound_action_check CHECK ((outbound_action = ANY (ARRAY['inherit'::text, 'allow'::text, 'block'::text]))),
    CONSTRAINT federation_domain_rules_trust_requirement_check CHECK ((trust_requirement = ANY (ARRAY['inherit'::text, 'tofu'::text, 'verified'::text])))
);


--
-- Name: federation_feature_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_feature_policies (
    feature text NOT NULL,
    mode text DEFAULT 'allowlist'::text NOT NULL,
    minimum_trust text DEFAULT 'verified'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_feature_policies_feature_check CHECK ((feature = ANY (ARRAY['chat'::text, 'drive'::text]))),
    CONSTRAINT federation_feature_policies_minimum_trust_check CHECK ((minimum_trust = ANY (ARRAY['tofu'::text, 'verified'::text]))),
    CONSTRAINT federation_feature_policies_mode_check CHECK ((mode = ANY (ARRAY['disabled'::text, 'allowlist'::text, 'blocklist'::text, 'open'::text])))
);


--
-- Name: federation_feature_policy_documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_feature_policy_documents (
    domain text NOT NULL,
    feature_type smallint NOT NULL,
    sequence bigint NOT NULL,
    policy_hash character(64) NOT NULL,
    federation_identity_generation bigint NOT NULL,
    envelope jsonb NOT NULL,
    is_local boolean NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_feature_policy_do_federation_identity_generati_check CHECK ((federation_identity_generation >= 0)),
    CONSTRAINT federation_feature_policy_documents_domain_check CHECK ((domain = lower(domain))),
    CONSTRAINT federation_feature_policy_documents_envelope_check CHECK ((jsonb_typeof(envelope) = 'object'::text)),
    CONSTRAINT federation_feature_policy_documents_feature_type_check CHECK ((feature_type = ANY (ARRAY[1, 2]))),
    CONSTRAINT federation_feature_policy_documents_policy_hash_check CHECK ((policy_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federation_feature_policy_documents_sequence_check CHECK ((sequence > 0))
);


--
-- Name: federation_feature_policy_failures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_feature_policy_failures (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    domain text NOT NULL,
    feature_type smallint NOT NULL,
    failure_class text NOT NULL,
    evidence_digest character(64) NOT NULL,
    received_value jsonb,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_feature_policy_failures_evidence_digest_check CHECK ((evidence_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federation_feature_policy_failures_failure_class_check CHECK ((failure_class = ANY (ARRAY['rollback'::text, 'gap'::text, 'wrong_domain'::text, 'unknown_type'::text, 'malformed'::text, 'signature'::text, 'identity_chain'::text, 'configuration_replacement'::text])))
);


--
-- Name: federation_local_identity_documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_local_identity_documents (
    sequence bigint NOT NULL,
    document_hash text NOT NULL,
    key_id text NOT NULL,
    document jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_local_identity_documents_document_check CHECK ((jsonb_typeof(document) = 'object'::text)),
    CONSTRAINT federation_local_identity_documents_document_hash_check CHECK ((document_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federation_local_identity_documents_key_id_check CHECK ((key_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federation_local_identity_documents_sequence_check CHECK ((sequence >= 0))
);


--
-- Name: federation_peer_identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_peer_identities (
    domain text NOT NULL,
    trust_state text NOT NULL,
    current_sequence bigint NOT NULL,
    current_document_hash text NOT NULL,
    current_key_id text NOT NULL,
    current_public_key text NOT NULL,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    verified_at timestamp with time zone,
    quarantine_reason text,
    pending_document jsonb,
    pending_identity_chain jsonb,
    pending_document_hash text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    current_api_base text,
    capabilities jsonb DEFAULT '[]'::jsonb NOT NULL,
    discovery_expires_at timestamp with time zone,
    last_discovery_error text,
    CONSTRAINT federation_peer_identities_capabilities_check CHECK ((jsonb_typeof(capabilities) = 'array'::text)),
    CONSTRAINT federation_peer_identities_check CHECK ((((trust_state = 'quarantined'::text) AND (quarantine_reason IS NOT NULL) AND (pending_document IS NOT NULL) AND (jsonb_typeof(pending_document) = 'object'::text) AND (pending_identity_chain IS NOT NULL) AND (jsonb_typeof(pending_identity_chain) = 'array'::text) AND (jsonb_array_length(pending_identity_chain) > 0) AND (pending_document_hash IS NOT NULL)) OR ((trust_state <> 'quarantined'::text) AND (quarantine_reason IS NULL) AND (pending_document IS NULL) AND (pending_identity_chain IS NULL) AND (pending_document_hash IS NULL)))),
    CONSTRAINT federation_peer_identities_current_document_hash_check CHECK ((current_document_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federation_peer_identities_current_key_id_check CHECK ((current_key_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federation_peer_identities_current_public_key_check CHECK ((current_public_key ~ '^[A-Za-z0-9+/]{43}=$'::text)),
    CONSTRAINT federation_peer_identities_current_sequence_check CHECK ((current_sequence >= 0)),
    CONSTRAINT federation_peer_identities_domain_check CHECK ((domain = lower(domain))),
    CONSTRAINT federation_peer_identities_domain_check1 CHECK (((length(domain) >= 3) AND (length(domain) <= 253))),
    CONSTRAINT federation_peer_identities_domain_check2 CHECK ((domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT federation_peer_identities_pending_document_hash_check CHECK (((pending_document_hash IS NULL) OR (pending_document_hash ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT federation_peer_identities_trust_state_check CHECK ((trust_state = ANY (ARRAY['tofu'::text, 'verified'::text, 'quarantined'::text])))
);


--
-- Name: federation_peer_identity_documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_peer_identity_documents (
    domain text NOT NULL,
    sequence bigint NOT NULL,
    document_hash text NOT NULL,
    key_id text NOT NULL,
    document jsonb NOT NULL,
    acceptance text NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_peer_identity_documents_acceptance_check CHECK ((acceptance = ANY (ARRAY['accepted'::text, 'quarantined'::text, 'superseded'::text]))),
    CONSTRAINT federation_peer_identity_documents_document_check CHECK ((jsonb_typeof(document) = 'object'::text)),
    CONSTRAINT federation_peer_identity_documents_document_hash_check CHECK ((document_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federation_peer_identity_documents_key_id_check CHECK ((key_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federation_peer_identity_documents_sequence_check CHECK ((sequence >= 0))
);


--
-- Name: federation_policy; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_policy (
    singleton boolean DEFAULT true NOT NULL,
    global_enabled boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_policy_singleton_check CHECK (singleton)
);


--
-- Name: federation_request_replays; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_request_replays (
    origin text NOT NULL,
    request_id text NOT NULL,
    request_hash text NOT NULL,
    first_seen_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT federation_request_replays_check CHECK ((expires_at > first_seen_at)),
    CONSTRAINT federation_request_replays_origin_check CHECK ((origin = lower(origin))),
    CONSTRAINT federation_request_replays_origin_check1 CHECK (((length(origin) >= 3) AND (length(origin) <= 253))),
    CONSTRAINT federation_request_replays_origin_check2 CHECK ((origin ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT federation_request_replays_request_hash_check CHECK ((request_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT federation_request_replays_request_id_check CHECK (((length(request_id) >= 1) AND (length(request_id) <= 128))),
    CONSTRAINT federation_request_replays_request_id_check1 CHECK ((request_id ~ '^[A-Za-z0-9._~-]+$'::text))
);


--
-- Name: feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feedback (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    kind text NOT NULL,
    app text NOT NULL,
    message text NOT NULL,
    details jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by uuid,
    resolution text,
    github_url text,
    CONSTRAINT feedback_app_check CHECK ((char_length(app) <= 32)),
    CONSTRAINT feedback_check CHECK (((resolved_at IS NULL) = (resolution IS NULL))),
    CONSTRAINT feedback_check1 CHECK (((github_url IS NULL) OR (resolution = 'forwarded'::text))),
    CONSTRAINT feedback_github_url_check CHECK (((github_url IS NULL) OR (char_length(github_url) <= 512))),
    CONSTRAINT feedback_kind_check CHECK ((kind = ANY (ARRAY['bug'::text, 'feature'::text, 'other'::text]))),
    CONSTRAINT feedback_message_check CHECK (((char_length(message) >= 1) AND (char_length(message) <= 5000))),
    CONSTRAINT feedback_resolution_check CHECK ((resolution = ANY (ARRAY['done'::text, 'dismissed'::text, 'forwarded'::text])))
);


--
-- Name: file_assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_assets (
    file_id uuid NOT NULL,
    asset_id text NOT NULL,
    size_bytes bigint NOT NULL,
    uploader_user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    key_generation integer NOT NULL,
    CONSTRAINT file_assets_size_bytes_check CHECK ((size_bytes >= 0))
);


--
-- Name: file_key_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_key_history (
    file_id uuid NOT NULL,
    generation integer NOT NULL,
    previous_key_envelope text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    previous_metadata_envelope text,
    previous_metadata_revision bigint,
    CONSTRAINT file_key_history_generation_check CHECK ((generation > 1))
);


--
-- Name: file_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    file_id uuid NOT NULL,
    sharer_user_id uuid NOT NULL,
    recipient_user_id uuid NOT NULL,
    share_envelope text NOT NULL,
    key_generation integer NOT NULL,
    can_edit boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT file_shares_check CHECK ((sharer_user_id <> recipient_user_id)),
    CONSTRAINT file_shares_key_generation_check CHECK ((key_generation > 0)),
    CONSTRAINT file_shares_share_envelope_check CHECK ((length(share_envelope) <= 2048))
);


--
-- Name: file_thumbnails; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_thumbnails (
    file_id uuid NOT NULL,
    variant text NOT NULL,
    size_bytes bigint NOT NULL,
    s3_version_id text DEFAULT ''::text NOT NULL,
    source_version uuid,
    uploader_user_id uuid NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    key_generation integer NOT NULL,
    CONSTRAINT file_thumbnails_size_bytes_check CHECK ((size_bytes > 0)),
    CONSTRAINT file_thumbnails_variant_check CHECK ((variant = ANY (ARRAY['sm'::text, 'lg'::text])))
);


--
-- Name: file_update_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_update_log (
    file_id uuid NOT NULL,
    seq bigint NOT NULL,
    sender_device bigint,
    doc_key_id bigint NOT NULL,
    kind smallint NOT NULL,
    frame bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sender_seq bigint DEFAULT 0 NOT NULL,
    remote_domain text,
    remote_device bigint,
    CONSTRAINT file_update_log_remote_sender CHECK (((remote_domain IS NULL) = (remote_device IS NULL)))
);


--
-- Name: file_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    file_id uuid NOT NULL,
    storage_path text NOT NULL,
    seq_at_snapshot bigint NOT NULL,
    doc_key_id bigint NOT NULL,
    author_user_id uuid NOT NULL,
    size_bytes bigint NOT NULL,
    label text,
    keep_forever boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    kind text NOT NULL,
    ciphertext_sha256 text,
    key_generation integer NOT NULL,
    remote_author text,
    parent_version_id uuid,
    CONSTRAINT file_versions_kind_check CHECK ((kind = ANY (ARRAY['file'::text, 'yjs'::text]))),
    CONSTRAINT file_versions_remote_author_check CHECK ((length(remote_author) <= 320))
);


--
-- Name: files; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.files (
    id uuid NOT NULL,
    collection_id uuid NOT NULL,
    uploader_user_id uuid NOT NULL,
    metadata_envelope text NOT NULL,
    file_key_envelope text NOT NULL,
    key_epoch integer NOT NULL,
    metadata_revision bigint DEFAULT 1 NOT NULL,
    storage_path text NOT NULL,
    encrypted_size_bytes bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    current_doc_key_id bigint DEFAULT 1 NOT NULL,
    seed_committed boolean DEFAULT false NOT NULL,
    deleted_at timestamp with time zone,
    trash_root_id uuid,
    ciphertext_sha256 text,
    original_pruned boolean DEFAULT false NOT NULL,
    fed_share_id uuid,
    original_key_generation integer NOT NULL,
    key_generation integer NOT NULL,
    collab_log_floor bigint DEFAULT 0 NOT NULL,
    editors_can_share boolean DEFAULT false NOT NULL,
    name_hash text,
    content_hash text,
    CONSTRAINT files_ciphertext_sha256_check CHECK (((ciphertext_sha256 IS NULL) OR (ciphertext_sha256 ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT files_collab_log_floor_check CHECK ((collab_log_floor >= 0)),
    CONSTRAINT files_content_hash_check CHECK ((content_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT files_key_epoch_check CHECK ((key_epoch > 0)),
    CONSTRAINT files_key_generation CHECK ((key_generation > 0)),
    CONSTRAINT files_metadata_revision_check CHECK ((metadata_revision > 0)),
    CONSTRAINT files_name_hash_check CHECK ((name_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT files_original_key_generation CHECK ((original_key_generation > 0))
);


--
-- Name: identity_pins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_pins (
    user_id uuid NOT NULL,
    revision bigint NOT NULL,
    envelope bytea NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT identity_pins_revision_check CHECK ((revision > 0))
);


--
-- Name: live_location_streams; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.live_location_streams (
    stream_id bytea NOT NULL,
    write_verifier bytea NOT NULL,
    read_verifier bytea NOT NULL,
    update_bytes bytea,
    counter bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT live_location_streams_counter_check CHECK ((counter >= 0)),
    CONSTRAINT live_location_streams_read_verifier_check CHECK ((octet_length(read_verifier) = 32)),
    CONSTRAINT live_location_streams_stream_id_check CHECK ((octet_length(stream_id) = 16)),
    CONSTRAINT live_location_streams_update_bytes_check CHECK (((update_bytes IS NULL) OR (octet_length(update_bytes) = 88))),
    CONSTRAINT live_location_streams_write_verifier_check CHECK ((octet_length(write_verifier) = 32))
);


--
-- Name: mail_address_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_address_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    address_id uuid NOT NULL,
    fingerprint character(40) NOT NULL,
    sha256_fingerprint character(64) NOT NULL,
    public_key bytea NOT NULL,
    private_key_envelope bytea NOT NULL,
    is_primary boolean NOT NULL,
    flags integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_address_keys_fingerprint_check CHECK ((fingerprint ~ '^[0-9a-f]{40}$'::text)),
    CONSTRAINT mail_address_keys_flags_check CHECK (((flags >= 0) AND (flags <= 15))),
    CONSTRAINT mail_address_keys_private_key_envelope_check CHECK (((octet_length(private_key_envelope) >= 1) AND (octet_length(private_key_envelope) <= 8192))),
    CONSTRAINT mail_address_keys_public_key_check CHECK (((octet_length(public_key) >= 1) AND (octet_length(public_key) <= 16384))),
    CONSTRAINT mail_address_keys_sha256_fingerprint_check CHECK ((sha256_fingerprint ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: mail_addresses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_addresses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    address text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    group_id uuid,
    CONSTRAINT mail_addresses_address_check CHECK (((address = lower(address)) AND ((length(address) >= 3) AND (length(address) <= 320)))),
    CONSTRAINT mail_addresses_owner CHECK (((user_id IS NULL) <> (group_id IS NULL)))
);


--
-- Name: mail_auto_replies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_auto_replies (
    user_id uuid NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    repeat text NOT NULL,
    zone text NOT NULL,
    start_local timestamp without time zone,
    end_local timestamp without time zone,
    days smallint[] DEFAULT '{}'::smallint[] NOT NULL,
    start_day smallint,
    end_day smallint,
    start_minute smallint,
    end_minute smallint,
    message_html text NOT NULL,
    message_text text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_auto_replies_end_minute_check CHECK (((end_minute >= 0) AND (end_minute <= 1439))),
    CONSTRAINT mail_auto_replies_message_html_check CHECK ((octet_length(message_html) <= 10000)),
    CONSTRAINT mail_auto_replies_message_text_check CHECK ((octet_length(message_text) <= 10000)),
    CONSTRAINT mail_auto_replies_repeat_check CHECK ((repeat = ANY (ARRAY['fixed'::text, 'daily'::text, 'weekly'::text, 'monthly'::text, 'permanent'::text]))),
    CONSTRAINT mail_auto_replies_start_minute_check CHECK (((start_minute >= 0) AND (start_minute <= 1439)))
);


--
-- Name: mail_auto_reply_sent; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_auto_reply_sent (
    user_id uuid NOT NULL,
    sender text NOT NULL,
    sent_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: mail_change_floors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_change_floors (
    owner uuid NOT NULL,
    floor_xid bigint NOT NULL
);


--
-- Name: mail_draft_attachments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_draft_attachments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    message_id uuid NOT NULL,
    user_id uuid NOT NULL,
    object_key text NOT NULL,
    size_bytes bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_draft_attachments_size_bytes_check CHECK ((size_bytes > 0))
);


--
-- Name: mail_filter_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_filter_runs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    filter_ids uuid[] NOT NULL,
    total integer DEFAULT 0 NOT NULL,
    done integer DEFAULT 0 NOT NULL,
    changed integer DEFAULT 0 NOT NULL,
    failed boolean DEFAULT false NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone
);


--
-- Name: mail_filters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_filters (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    name_sealed text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    "position" integer DEFAULT 0 NOT NULL,
    match text NOT NULL,
    conditions jsonb NOT NULL,
    actions jsonb NOT NULL,
    source text DEFAULT 'manual'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_filters_actions_check CHECK ((jsonb_typeof(actions) = 'object'::text)),
    CONSTRAINT mail_filters_conditions_check CHECK ((jsonb_typeof(conditions) = 'array'::text)),
    CONSTRAINT mail_filters_match_check CHECK ((match = ANY (ARRAY['all'::text, 'any'::text]))),
    CONSTRAINT mail_filters_name_sealed_check CHECK (((length(name_sealed) >= 1) AND (length(name_sealed) <= 1000))),
    CONSTRAINT mail_filters_source_check CHECK ((source = ANY (ARRAY['manual'::text, 'sender'::text])))
);


--
-- Name: mail_folders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_folders (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    parent_id uuid,
    name_sealed text NOT NULL,
    color text NOT NULL,
    "position" integer DEFAULT 0 NOT NULL,
    expanded boolean DEFAULT true NOT NULL,
    notify boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_folders_check CHECK (((parent_id IS NULL) OR (parent_id <> id))),
    CONSTRAINT mail_folders_color_check CHECK ((color ~ '^#[0-9a-f]{6}$'::text)),
    CONSTRAINT mail_folders_name_sealed_check CHECK (((length(name_sealed) >= 1) AND (length(name_sealed) <= 1000)))
);


--
-- Name: mail_group_key_lists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_group_key_lists (
    group_id uuid NOT NULL,
    sequence bigint NOT NULL,
    data bytea NOT NULL,
    signature bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_group_key_lists_sequence_check CHECK ((sequence >= 1)),
    CONSTRAINT mail_group_key_lists_signature_check CHECK ((octet_length(signature) = 64))
);


--
-- Name: mail_group_key_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_group_key_shares (
    group_key_id uuid NOT NULL,
    user_id uuid NOT NULL,
    share bytea NOT NULL,
    member_fingerprint character(40) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_group_key_shares_member_fingerprint_check CHECK ((member_fingerprint ~ '^[0-9a-f]{40}$'::text)),
    CONSTRAINT mail_group_key_shares_share_check CHECK (((octet_length(share) >= 1) AND (octet_length(share) <= 16384)))
);


--
-- Name: mail_group_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_group_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id uuid NOT NULL,
    fingerprint character(40) NOT NULL,
    sha256_fingerprint character(64) NOT NULL,
    public_key bytea NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    flags integer DEFAULT 3 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_group_keys_fingerprint_check CHECK ((fingerprint ~ '^[0-9a-f]{40}$'::text)),
    CONSTRAINT mail_group_keys_flags_check CHECK (((flags >= 0) AND (flags <= 15))),
    CONSTRAINT mail_group_keys_public_key_check CHECK (((octet_length(public_key) >= 1) AND (octet_length(public_key) <= 16384))),
    CONSTRAINT mail_group_keys_sha256_fingerprint_check CHECK ((sha256_fingerprint ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: mail_group_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_group_members (
    group_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL,
    can_send_as boolean DEFAULT false NOT NULL,
    added_by uuid,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_group_members_role_check CHECK ((role = ANY (ARRAY['owner'::text, 'manager'::text, 'member'::text])))
);


--
-- Name: mail_group_objects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_group_objects (
    object_key text NOT NULL,
    object_version text DEFAULT ''::text NOT NULL,
    group_id uuid NOT NULL,
    size_bytes bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_group_objects_size_bytes_check CHECK ((size_bytes > 0))
);


--
-- Name: mail_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    address text NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    kind text NOT NULL,
    post_policy text DEFAULT 'members'::text NOT NULL,
    system_role text,
    storage_quota_bytes bigint NOT NULL,
    storage_used_bytes bigint DEFAULT 0 NOT NULL,
    storage_owner text DEFAULT 'server'::text NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_groups_address_check CHECK (((address = lower(address)) AND ((length(address) >= 3) AND (length(address) <= 320)))),
    CONSTRAINT mail_groups_check CHECK (((system_role IS NULL) OR (post_policy = 'anyone'::text))),
    CONSTRAINT mail_groups_description_check CHECK ((length(description) <= 1000)),
    CONSTRAINT mail_groups_display_name_check CHECK ((length(display_name) <= 200)),
    CONSTRAINT mail_groups_kind_check CHECK ((kind = ANY (ARRAY['list'::text, 'shared'::text]))),
    CONSTRAINT mail_groups_post_policy_check CHECK ((post_policy = ANY (ARRAY['anyone'::text, 'local'::text, 'members'::text, 'managers'::text]))),
    CONSTRAINT mail_groups_storage_owner_check CHECK ((storage_owner = 'server'::text)),
    CONSTRAINT mail_groups_storage_quota_bytes_check CHECK ((storage_quota_bytes > 0)),
    CONSTRAINT mail_groups_storage_used_bytes_check CHECK ((storage_used_bytes >= 0)),
    CONSTRAINT mail_groups_system_role_check CHECK ((system_role = ANY (ARRAY['postmaster'::text, 'abuse'::text, 'security'::text, 'hostmaster'::text])))
);


--
-- Name: mail_identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_identities (
    address_id uuid NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    signature text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_identities_display_name_check CHECK ((length(display_name) <= 100)),
    CONSTRAINT mail_identities_signature_check CHECK ((length(signature) <= 10000))
);


--
-- Name: mail_image_senders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_image_senders (
    user_id uuid NOT NULL,
    address text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_image_senders_address_check CHECK ((((length(address) >= 3) AND (length(address) <= 320)) AND (address = lower(address))))
);


--
-- Name: mail_key_lists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_key_lists (
    address_id uuid NOT NULL,
    sequence bigint NOT NULL,
    data bytea NOT NULL,
    signature bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_key_lists_data_check CHECK (((octet_length(data) >= 1) AND (octet_length(data) <= 8192))),
    CONSTRAINT mail_key_lists_sequence_check CHECK ((sequence >= 1)),
    CONSTRAINT mail_key_lists_signature_check CHECK ((octet_length(signature) = 64))
);


--
-- Name: mail_labels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_labels (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    name_sealed text NOT NULL,
    color text NOT NULL,
    "position" integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_labels_color_check CHECK ((color ~ '^#[0-9a-f]{6}$'::text)),
    CONSTRAINT mail_labels_name_sealed_check CHECK (((length(name_sealed) >= 1) AND (length(name_sealed) <= 1000)))
);


--
-- Name: mail_message_labels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_message_labels (
    message_id uuid NOT NULL,
    label_id uuid NOT NULL
);


--
-- Name: mail_message_tombstones; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_message_tombstones (
    owner uuid NOT NULL,
    id uuid NOT NULL,
    received_at timestamp with time zone NOT NULL,
    change_xid bigint NOT NULL,
    deleted_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: mail_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_messages (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    address_id uuid NOT NULL,
    thread_id uuid NOT NULL,
    direction text NOT NULL,
    folder text NOT NULL,
    seen boolean DEFAULT false NOT NULL,
    starred boolean DEFAULT false NOT NULL,
    protection text NOT NULL,
    object_key text NOT NULL,
    object_version text DEFAULT ''::text NOT NULL,
    size_bytes bigint NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    subject text DEFAULT ''::text NOT NULL,
    from_address text DEFAULT ''::text NOT NULL,
    from_name text DEFAULT ''::text NOT NULL,
    to_list jsonb DEFAULT '[]'::jsonb NOT NULL,
    cc_list jsonb DEFAULT '[]'::jsonb NOT NULL,
    reply_to jsonb DEFAULT '[]'::jsonb NOT NULL,
    bcc_list jsonb DEFAULT '[]'::jsonb NOT NULL,
    external_recipients integer DEFAULT 0 NOT NULL,
    message_id text,
    in_reply_to text,
    references_list text[] DEFAULT '{}'::text[] NOT NULL,
    attachment_count integer DEFAULT 0 NOT NULL,
    group_id uuid,
    key_packet bytea,
    owner uuid GENERATED ALWAYS AS (COALESCE(user_id, group_id)) STORED,
    sent_by uuid,
    sender_account uuid GENERATED ALWAYS AS (COALESCE(sent_by, user_id)) STORED,
    custom_folder uuid,
    folder_changed_at timestamp with time zone DEFAULT now() NOT NULL,
    unsubscribed boolean DEFAULT false NOT NULL,
    unsubscribable boolean DEFAULT false NOT NULL,
    receipt_sent boolean DEFAULT false NOT NULL,
    attachments jsonb DEFAULT '[]'::jsonb NOT NULL,
    snoozed_until timestamp with time zone,
    expires_at timestamp with time zone,
    notify_at timestamp with time zone,
    change_xid bigint DEFAULT 0 NOT NULL,
    CONSTRAINT mail_messages_attachment_count_check CHECK ((attachment_count >= 0)),
    CONSTRAINT mail_messages_bcc_list_check CHECK (((jsonb_typeof(bcc_list) = 'array'::text) AND (jsonb_array_length(bcc_list) <= 100))),
    CONSTRAINT mail_messages_cc_list_check CHECK (((jsonb_typeof(cc_list) = 'array'::text) AND (jsonb_array_length(cc_list) <= 100))),
    CONSTRAINT mail_messages_custom_folder_check CHECK (((folder = 'custom'::text) = (custom_folder IS NOT NULL))),
    CONSTRAINT mail_messages_direction_check CHECK ((direction = ANY (ARRAY['inbound'::text, 'outbound'::text]))),
    CONSTRAINT mail_messages_external_recipients_check CHECK (((external_recipients >= 0) AND (external_recipients <= 100))),
    CONSTRAINT mail_messages_folder_check CHECK ((folder = ANY (ARRAY['inbox'::text, 'drafts'::text, 'scheduled'::text, 'snoozed'::text, 'sent'::text, 'archive'::text, 'spam'::text, 'trash'::text, 'custom'::text]))),
    CONSTRAINT mail_messages_from_address_check CHECK ((length(from_address) <= 320)),
    CONSTRAINT mail_messages_from_name_check CHECK ((length(from_name) <= 400)),
    CONSTRAINT mail_messages_in_reply_to_check CHECK (((length(in_reply_to) >= 1) AND (length(in_reply_to) <= 998))),
    CONSTRAINT mail_messages_key_packet_check CHECK (((octet_length(key_packet) >= 1) AND (octet_length(key_packet) <= 4096))),
    CONSTRAINT mail_messages_message_id_check CHECK (((length(message_id) >= 1) AND (length(message_id) <= 998))),
    CONSTRAINT mail_messages_owner CHECK (((user_id IS NOT NULL) OR (group_id IS NOT NULL))),
    CONSTRAINT mail_messages_protection_check CHECK ((protection = ANY (ARRAY['zero_access'::text, 'end_to_end'::text]))),
    CONSTRAINT mail_messages_references_list_check CHECK ((cardinality(references_list) <= 50)),
    CONSTRAINT mail_messages_reply_to_check CHECK (((jsonb_typeof(reply_to) = 'array'::text) AND (jsonb_array_length(reply_to) <= 100))),
    CONSTRAINT mail_messages_size_bytes_check CHECK ((size_bytes > 0)),
    CONSTRAINT mail_messages_subject_check CHECK ((length(subject) <= 1000)),
    CONSTRAINT mail_messages_to_list_check CHECK (((jsonb_typeof(to_list) = 'array'::text) AND (jsonb_array_length(to_list) <= 100)))
);


--
-- Name: mail_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_outbox (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    draft_id uuid NOT NULL,
    is_admin boolean NOT NULL,
    deliver_at timestamp with time zone NOT NULL,
    parts_key text NOT NULL,
    parts_version text NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    result jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    scheduled boolean DEFAULT false NOT NULL,
    CONSTRAINT mail_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'sending'::text, 'sent'::text, 'cancelled'::text, 'failed'::text])))
);


--
-- Name: mail_sender_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_sender_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    pattern text NOT NULL,
    kind text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_sender_rules_kind_check CHECK ((kind = ANY (ARRAY['spam'::text, 'block'::text, 'allow'::text]))),
    CONSTRAINT mail_sender_rules_pattern_check CHECK ((((length(pattern) >= 3) AND (length(pattern) <= 320)) AND (pattern = lower(pattern))))
);


--
-- Name: mail_sending_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_sending_events (
    id bigint NOT NULL,
    user_id uuid NOT NULL,
    kind text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_sending_events_kind_check CHECK ((kind = ANY (ARRAY['bounce'::text, 'spam_refused'::text])))
);


--
-- Name: mail_sending_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mail_sending_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mail_sending_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mail_sending_events_id_seq OWNED BY public.mail_sending_events.id;


--
-- Name: mail_sending_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_sending_policies (
    user_id uuid NOT NULL,
    per_hour integer,
    per_day integer,
    paused_at timestamp with time zone,
    paused_reason text,
    flagged_at timestamp with time zone,
    flag_reason text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_sending_policies_flag_reason_check CHECK ((flag_reason = ANY (ARRAY['bounces'::text, 'spam'::text]))),
    CONSTRAINT mail_sending_policies_paused_reason_check CHECK ((paused_reason = ANY (ARRAY['admin'::text, 'bounces'::text, 'spam'::text]))),
    CONSTRAINT mail_sending_policies_per_day_check CHECK (((per_day >= 0) AND (per_day <= 100000))),
    CONSTRAINT mail_sending_policies_per_hour_check CHECK (((per_hour >= 0) AND (per_hour <= 100000)))
);


--
-- Name: mail_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_settings (
    user_id uuid NOT NULL,
    auto_delete_days integer DEFAULT 0 NOT NULL,
    almost_all_mail boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    sign_outside boolean DEFAULT true NOT NULL,
    view_layout text DEFAULT 'column'::text NOT NULL,
    density text DEFAULT 'comfortable'::text NOT NULL,
    composer_mode text DEFAULT 'popup'::text NOT NULL,
    view_mode text DEFAULT 'conversation'::text NOT NULL,
    attach_public_key boolean DEFAULT false NOT NULL,
    pgp_scheme text DEFAULT 'pgp_mime'::text NOT NULL,
    confirm_link boolean DEFAULT true NOT NULL,
    page_size integer DEFAULT 50 NOT NULL,
    spam_action text DEFAULT 'ask'::text NOT NULL,
    remote_images text DEFAULT 'ask'::text NOT NULL,
    delay_send_seconds integer DEFAULT 10 NOT NULL,
    draft_type text DEFAULT 'html'::text NOT NULL,
    text_direction text DEFAULT 'ltr'::text NOT NULL,
    font_face text DEFAULT 'arial'::text NOT NULL,
    font_size integer DEFAULT 14 NOT NULL,
    image_proxy boolean DEFAULT true NOT NULL,
    embedded_images boolean DEFAULT true NOT NULL,
    remove_image_metadata boolean DEFAULT true NOT NULL,
    CONSTRAINT mail_settings_auto_delete_days_check CHECK ((auto_delete_days = ANY (ARRAY[0, 30]))),
    CONSTRAINT mail_settings_composer_mode_check CHECK ((composer_mode = ANY (ARRAY['popup'::text, 'maximized'::text]))),
    CONSTRAINT mail_settings_delay_send_seconds_check CHECK ((delay_send_seconds = ANY (ARRAY[0, 5, 10, 20]))),
    CONSTRAINT mail_settings_density_check CHECK ((density = ANY (ARRAY['comfortable'::text, 'compact'::text]))),
    CONSTRAINT mail_settings_draft_type_check CHECK ((draft_type = ANY (ARRAY['html'::text, 'plain'::text]))),
    CONSTRAINT mail_settings_font_face_check CHECK ((font_face = ANY (ARRAY['sans-serif'::text, 'serif'::text, 'georgia'::text, 'arial'::text, 'helvetica'::text, 'monospace'::text, 'tahoma'::text, 'verdana'::text, 'times'::text, 'trebuchet'::text]))),
    CONSTRAINT mail_settings_font_size_check CHECK ((font_size = ANY (ARRAY[10, 12, 14, 16, 18, 20, 22, 24, 26]))),
    CONSTRAINT mail_settings_page_size_check CHECK ((page_size = ANY (ARRAY[50, 100, 200]))),
    CONSTRAINT mail_settings_pgp_scheme_check CHECK ((pgp_scheme = ANY (ARRAY['pgp_mime'::text, 'inline'::text]))),
    CONSTRAINT mail_settings_remote_images_check CHECK ((remote_images = ANY (ARRAY['ask'::text, 'always'::text]))),
    CONSTRAINT mail_settings_spam_action_check CHECK ((spam_action = ANY (ARRAY['ask'::text, 'just_spam'::text, 'spam_and_unsubscribe'::text]))),
    CONSTRAINT mail_settings_text_direction_check CHECK ((text_direction = ANY (ARRAY['ltr'::text, 'rtl'::text]))),
    CONSTRAINT mail_settings_view_layout_check CHECK ((view_layout = ANY (ARRAY['column'::text, 'row'::text]))),
    CONSTRAINT mail_settings_view_mode_check CHECK ((view_mode = ANY (ARRAY['conversation'::text, 'message'::text])))
);


--
-- Name: pass_pin_failures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pass_pin_failures (
    sign_in_id uuid NOT NULL,
    user_id uuid NOT NULL,
    failures smallint NOT NULL
);


--
-- Name: pass_pins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pass_pins (
    user_id uuid NOT NULL,
    pin_hash text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: pass_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pass_settings (
    user_id uuid NOT NULL,
    site_icons text DEFAULT 'kutup'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pass_settings_site_icons_check CHECK ((site_icons = ANY (ARRAY['kutup'::text, 'off'::text])))
);


--
-- Name: pass_vault_secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pass_vault_secrets (
    user_id uuid NOT NULL,
    file_id uuid NOT NULL,
    envelope bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: photos_library; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.photos_library (
    user_id uuid NOT NULL,
    revision bigint NOT NULL,
    envelope_digest text NOT NULL,
    envelope bytea NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT photos_library_revision_check CHECK ((revision > 0))
);


--
-- Name: photos_library_folders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.photos_library_folders (
    user_id uuid NOT NULL,
    collection_id uuid NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: photos_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.photos_preferences (
    user_id uuid NOT NULL,
    upload_folder_id uuid,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: public_link_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.public_link_reports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    share_id uuid NOT NULL,
    reason text NOT NULL,
    details text DEFAULT ''::text NOT NULL,
    link text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by uuid,
    resolution text,
    CONSTRAINT public_link_reports_check CHECK (((resolved_at IS NULL) = (resolution IS NULL))),
    CONSTRAINT public_link_reports_check1 CHECK (((resolved_at IS NULL) OR (link IS NULL))),
    CONSTRAINT public_link_reports_details_check CHECK ((char_length(details) <= 2000)),
    CONSTRAINT public_link_reports_link_check CHECK (((link IS NULL) OR (char_length(link) <= 2048))),
    CONSTRAINT public_link_reports_reason_check CHECK ((reason = ANY (ARRAY['phishing'::text, 'malware'::text, 'illegal'::text, 'abuse'::text, 'other'::text]))),
    CONSTRAINT public_link_reports_resolution_check CHECK ((resolution = ANY (ARRAY['dismissed'::text, 'removed'::text, 'disabled'::text])))
);


--
-- Name: public_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.public_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    share_type text NOT NULL,
    target_id uuid NOT NULL,
    token text NOT NULL,
    collection_key_envelope text NOT NULL,
    collection_key_epoch integer NOT NULL,
    owner_user_id uuid NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    owner_link_key_envelope text NOT NULL,
    removed_at timestamp with time zone,
    CONSTRAINT public_shares_collection_key_epoch_check CHECK ((collection_key_epoch > 0)),
    CONSTRAINT public_shares_share_type_check CHECK ((share_type = ANY (ARRAY['collection'::text, 'file'::text])))
);


--
-- Name: sealed_sender_generated_certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sealed_sender_generated_certificates (
    certificate_id bigint NOT NULL,
    root_id text NOT NULL,
    root_public_key text NOT NULL,
    certificate text NOT NULL,
    online_private_key bytea,
    published_at bigint NOT NULL,
    activates_at bigint NOT NULL,
    expires_at bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sealed_sender_generated_certificates_certificate_id_check CHECK (((certificate_id > 0) AND (certificate_id <= '4294967295'::bigint))),
    CONSTRAINT sealed_sender_generated_certificates_check CHECK ((activates_at >= published_at)),
    CONSTRAINT sealed_sender_generated_certificates_check1 CHECK ((expires_at > activates_at)),
    CONSTRAINT sealed_sender_generated_certificates_online_private_key_check CHECK ((octet_length(online_private_key) = 32)),
    CONSTRAINT sealed_sender_generated_certificates_root_id_check CHECK ((root_id ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: server_generated_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.server_generated_keys (
    purpose text NOT NULL,
    private_key bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT server_generated_keys_private_key_check CHECK ((octet_length(private_key) = 32)),
    CONSTRAINT server_generated_keys_purpose_check CHECK ((purpose = ANY (ARRAY['federation-identity'::text, 'mls-control'::text, 'mail-group-authority'::text, 'fake-accounts'::text])))
);


--
-- Name: site_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.site_settings (
    key text NOT NULL,
    value text NOT NULL
);


--
-- Name: uploads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.uploads (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    collection_id uuid NOT NULL,
    file_id uuid NOT NULL,
    total_bytes bigint NOT NULL,
    received_bytes bigint DEFAULT 0 NOT NULL,
    metadata_envelope text NOT NULL,
    file_key_envelope text NOT NULL,
    key_epoch integer NOT NULL,
    metadata_revision bigint DEFAULT 1 NOT NULL,
    storage_path text NOT NULL,
    s3_upload_id text NOT NULL,
    s3_part_etags jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    pending_bytes bytea DEFAULT '\x'::bytea NOT NULL,
    name_hash text,
    CONSTRAINT uploads_key_epoch_check CHECK ((key_epoch > 0)),
    CONSTRAINT uploads_metadata_revision_check CHECK ((metadata_revision > 0)),
    CONSTRAINT uploads_name_hash_check CHECK ((name_hash ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: user_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_devices (
    id bigint NOT NULL,
    user_id uuid NOT NULL,
    public_signing bytea NOT NULL,
    label text,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone
);


--
-- Name: user_devices_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_devices_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_devices_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_devices_id_seq OWNED BY public.user_devices.id;


--
-- Name: user_map_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_map_preferences (
    user_id uuid NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    provider text,
    via_proxy boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    save_folder_id uuid,
    CONSTRAINT user_map_preferences_provider_check CHECK ((provider = ANY (ARRAY['openfreemap'::text, 'openstreetmap'::text, 'custom'::text])))
);


--
-- Name: user_ui_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_ui_preferences (
    user_id uuid NOT NULL,
    theme text,
    language text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_ui_preferences_language_check CHECK ((language = ANY (ARRAY['en'::text, 'tr'::text]))),
    CONSTRAINT user_ui_preferences_theme_check CHECK ((theme = ANY (ARRAY['light'::text, 'dark'::text, 'system'::text])))
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    master_key_envelope text NOT NULL,
    recovery_key_envelope text NOT NULL,
    drive_private_key_envelope text NOT NULL,
    public_key text NOT NULL,
    account_authority_public_key text NOT NULL,
    account_authority_key_id character(64) NOT NULL,
    account_incarnation_id character(64) NOT NULL,
    drive_signing_public_key text NOT NULL,
    account_protection_suite smallint NOT NULL,
    account_protection_salt text NOT NULL,
    argon_memory_kib integer NOT NULL,
    argon_iterations integer NOT NULL,
    argon_parallelism integer NOT NULL,
    login_key_hash text NOT NULL,
    totp_secret text,
    totp_enabled boolean DEFAULT false NOT NULL,
    storage_quota_bytes bigint DEFAULT '10737418240'::bigint NOT NULL,
    storage_used_bytes bigint DEFAULT 0 NOT NULL,
    is_admin boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_first_login boolean DEFAULT false NOT NULL,
    username text NOT NULL,
    recovery_key_verifier text DEFAULT ''::text NOT NULL,
    color text,
    version_retention_days integer DEFAULT 30 NOT NULL,
    drive_key_binding text,
    key_binding text,
    CONSTRAINT users_account_authority_key_id_check CHECK (((account_authority_key_id = ''::bpchar) OR (account_authority_key_id ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT users_account_incarnation_id_check CHECK (((account_incarnation_id = ''::bpchar) OR (account_incarnation_id ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT users_account_protection_suite_check CHECK ((account_protection_suite = ANY (ARRAY[0, 1]))),
    CONSTRAINT users_argon_iterations_check CHECK ((argon_iterations >= 0)),
    CONSTRAINT users_argon_memory_kib_check CHECK ((argon_memory_kib >= 0)),
    CONSTRAINT users_argon_parallelism_check CHECK ((argon_parallelism >= 0)),
    CONSTRAINT users_color_format CHECK (((color IS NULL) OR (color ~ '^#[0-9a-fA-F]{6}$'::text))),
    CONSTRAINT users_key_binding_check CHECK ((key_binding ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text)),
    CONSTRAINT users_username_format CHECK ((username ~ '^[a-z0-9_-]{3,32}$'::text)),
    CONSTRAINT users_version_retention_days_check CHECK ((version_retention_days = ANY (ARRAY[7, 30, 90, 180, 365, 3650])))
);


--
-- Name: admin_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit_log ALTER COLUMN id SET DEFAULT nextval('public.admin_audit_log_id_seq'::regclass);


--
-- Name: mail_sending_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sending_events ALTER COLUMN id SET DEFAULT nextval('public.mail_sending_events_id_seq'::regclass);


--
-- Name: user_devices id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_devices ALTER COLUMN id SET DEFAULT nextval('public.user_devices_id_seq'::regclass);


--
-- Name: admin_audit_log admin_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit_log
    ADD CONSTRAINT admin_audit_log_pkey PRIMARY KEY (id);


--
-- Name: album_items album_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.album_items
    ADD CONSTRAINT album_items_pkey PRIMARY KEY (album_id, file_id);


--
-- Name: auth_session_forks auth_session_forks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_session_forks
    ADD CONSTRAINT auth_session_forks_pkey PRIMARY KEY (selector_hash);


--
-- Name: auth_sessions auth_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_pkey PRIMARY KEY (id);


--
-- Name: auth_sessions auth_sessions_refresh_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_refresh_token_hash_key UNIQUE (refresh_token_hash);


--
-- Name: chat_anonymous_rate_counters chat_anonymous_rate_counters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_anonymous_rate_counters
    ADD CONSTRAINT chat_anonymous_rate_counters_pkey PRIMARY KEY (scope_type, scope_digest, window_start);


--
-- Name: chat_anonymous_send_ids chat_anonymous_send_ids_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_anonymous_send_ids
    ADD CONSTRAINT chat_anonymous_send_ids_pkey PRIMARY KEY (recipient_user_id, capability_hash, send_id);


--
-- Name: chat_attachment_ledger_entities chat_attachment_ledger_entities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_attachment_ledger_entities
    ADD CONSTRAINT chat_attachment_ledger_entities_pkey PRIMARY KEY (user_id, entity_id);


--
-- Name: chat_attachment_ledger_entities chat_attachment_ledger_entities_user_id_cursor_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_attachment_ledger_entities
    ADD CONSTRAINT chat_attachment_ledger_entities_user_id_cursor_key UNIQUE (user_id, cursor);


--
-- Name: chat_attachment_ledger_history chat_attachment_ledger_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_attachment_ledger_history
    ADD CONSTRAINT chat_attachment_ledger_history_pkey PRIMARY KEY (user_id, entity_id, revision);


--
-- Name: chat_attachment_ledger_history chat_attachment_ledger_history_user_id_cursor_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_attachment_ledger_history
    ADD CONSTRAINT chat_attachment_ledger_history_user_id_cursor_key UNIQUE (user_id, cursor);


--
-- Name: chat_attachment_ledger_operations chat_attachment_ledger_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_attachment_ledger_operations
    ADD CONSTRAINT chat_attachment_ledger_operations_pkey PRIMARY KEY (user_id, operation_id);


--
-- Name: chat_backup_bases chat_backup_bases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_bases
    ADD CONSTRAINT chat_backup_bases_pkey PRIMARY KEY (user_id, object_id);


--
-- Name: chat_backup_bases chat_backup_bases_storage_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_bases
    ADD CONSTRAINT chat_backup_bases_storage_path_key UNIQUE (storage_path);


--
-- Name: chat_backup_bases chat_backup_bases_user_id_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_bases
    ADD CONSTRAINT chat_backup_bases_user_id_generation_key UNIQUE (user_id, generation);


--
-- Name: chat_backup_device_heads chat_backup_device_heads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_device_heads
    ADD CONSTRAINT chat_backup_device_heads_pkey PRIMARY KEY (user_id, source_device_id);


--
-- Name: chat_backup_media_objects chat_backup_media_objects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_objects
    ADD CONSTRAINT chat_backup_media_objects_pkey PRIMARY KEY (user_id, media_id);


--
-- Name: chat_backup_media_objects chat_backup_media_objects_storage_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_objects
    ADD CONSTRAINT chat_backup_media_objects_storage_path_key UNIQUE (storage_path);


--
-- Name: chat_backup_media_operations chat_backup_media_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_operations
    ADD CONSTRAINT chat_backup_media_operations_pkey PRIMARY KEY (user_id, operation_id);


--
-- Name: chat_backup_media_reconciliation_entries chat_backup_media_reconciliation_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliation_entries
    ADD CONSTRAINT chat_backup_media_reconciliation_entries_pkey PRIMARY KEY (user_id, operation_id, reference_id);


--
-- Name: chat_backup_media_reconciliation_pages chat_backup_media_reconciliation_pages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliation_pages
    ADD CONSTRAINT chat_backup_media_reconciliation_pages_pkey PRIMARY KEY (user_id, operation_id, page_index);


--
-- Name: chat_backup_media_reconciliations chat_backup_media_reconciliations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliations
    ADD CONSTRAINT chat_backup_media_reconciliations_pkey PRIMARY KEY (user_id, operation_id);


--
-- Name: chat_backup_media_reconciliations chat_backup_media_reconciliations_user_id_target_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliations
    ADD CONSTRAINT chat_backup_media_reconciliations_user_id_target_generation_key UNIQUE (user_id, target_generation);


--
-- Name: chat_backup_media_references chat_backup_media_references_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_references
    ADD CONSTRAINT chat_backup_media_references_pkey PRIMARY KEY (user_id, reference_id);


--
-- Name: chat_backup_provision_operations chat_backup_provision_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_provision_operations
    ADD CONSTRAINT chat_backup_provision_operations_pkey PRIMARY KEY (user_id, operation_id);


--
-- Name: chat_backup_segments chat_backup_segments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_segments
    ADD CONSTRAINT chat_backup_segments_pkey PRIMARY KEY (user_id, cursor);


--
-- Name: chat_backup_segments chat_backup_segments_user_id_operation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_segments
    ADD CONSTRAINT chat_backup_segments_user_id_operation_id_key UNIQUE (user_id, operation_id);


--
-- Name: chat_backup_segments chat_backup_segments_user_id_source_device_id_device_sequen_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_segments
    ADD CONSTRAINT chat_backup_segments_user_id_source_device_id_device_sequen_key UNIQUE (user_id, source_device_id, device_sequence);


--
-- Name: chat_backups chat_backups_backup_incarnation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backups
    ADD CONSTRAINT chat_backups_backup_incarnation_id_key UNIQUE (backup_incarnation_id);


--
-- Name: chat_backups chat_backups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backups
    ADD CONSTRAINT chat_backups_pkey PRIMARY KEY (user_id);


--
-- Name: chat_call_link_knocks chat_call_link_knocks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_link_knocks
    ADD CONSTRAINT chat_call_link_knocks_pkey PRIMARY KEY (id);


--
-- Name: chat_call_link_seats chat_call_link_seats_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_link_seats
    ADD CONSTRAINT chat_call_link_seats_pkey PRIMARY KEY (room_id, participant_id);


--
-- Name: chat_call_links chat_call_links_owner_user_id_nonce_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_links
    ADD CONSTRAINT chat_call_links_owner_user_id_nonce_key UNIQUE (owner_user_id, nonce);


--
-- Name: chat_call_links chat_call_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_links
    ADD CONSTRAINT chat_call_links_pkey PRIMARY KEY (room_id);


--
-- Name: chat_delivery_capabilities chat_delivery_capabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_delivery_capabilities
    ADD CONSTRAINT chat_delivery_capabilities_pkey PRIMARY KEY (user_id);


--
-- Name: chat_device_manifest_history chat_device_manifest_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_device_manifest_history
    ADD CONSTRAINT chat_device_manifest_history_pkey PRIMARY KEY (user_id, incarnation_id, version);


--
-- Name: chat_device_manifests chat_device_manifests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_device_manifests
    ADD CONSTRAINT chat_device_manifests_pkey PRIMARY KEY (user_id);


--
-- Name: chat_devices chat_devices_identity_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_devices
    ADD CONSTRAINT chat_devices_identity_unique UNIQUE (user_id, identity_key);


--
-- Name: chat_devices chat_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_devices
    ADD CONSTRAINT chat_devices_pkey PRIMARY KEY (user_id, device_id);


--
-- Name: chat_federation_inbound_state chat_federation_inbound_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_federation_inbound_state
    ADD CONSTRAINT chat_federation_inbound_state_pkey PRIMARY KEY (origin);


--
-- Name: chat_federation_inbound_transactions chat_federation_inbound_transactions_origin_transaction_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_federation_inbound_transactions
    ADD CONSTRAINT chat_federation_inbound_transactions_origin_transaction_id_key UNIQUE (origin, transaction_id);


--
-- Name: chat_federation_inbound_transactions chat_federation_inbound_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_federation_inbound_transactions
    ADD CONSTRAINT chat_federation_inbound_transactions_pkey PRIMARY KEY (origin, sequence);


--
-- Name: chat_federation_outbox chat_federation_outbox_destination_sequence_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_federation_outbox
    ADD CONSTRAINT chat_federation_outbox_destination_sequence_key UNIQUE (destination, sequence);


--
-- Name: chat_federation_outbox chat_federation_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_federation_outbox
    ADD CONSTRAINT chat_federation_outbox_pkey PRIMARY KEY (id);


--
-- Name: chat_federation_outbox chat_federation_outbox_sender_user_id_sender_device_id_send_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_federation_outbox
    ADD CONSTRAINT chat_federation_outbox_sender_user_id_sender_device_id_send_key UNIQUE (sender_user_id, sender_device_id, send_id);


--
-- Name: chat_federation_sequences chat_federation_sequences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_federation_sequences
    ADD CONSTRAINT chat_federation_sequences_pkey PRIMARY KEY (destination);


--
-- Name: chat_invite_links chat_invite_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_invite_links
    ADD CONSTRAINT chat_invite_links_pkey PRIMARY KEY (link_id);


--
-- Name: chat_invite_requests chat_invite_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_invite_requests
    ADD CONSTRAINT chat_invite_requests_pkey PRIMARY KEY (id);


--
-- Name: chat_joined_meetings chat_joined_meetings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_joined_meetings
    ADD CONSTRAINT chat_joined_meetings_pkey PRIMARY KEY (user_id, id);


--
-- Name: chat_mailbox chat_mailbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mailbox
    ADD CONSTRAINT chat_mailbox_pkey PRIMARY KEY (id);


--
-- Name: chat_media_federation_inbound_pending chat_media_federation_inbound_pending_origin_operation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_inbound_pending
    ADD CONSTRAINT chat_media_federation_inbound_pending_origin_operation_id_key UNIQUE (origin, operation_id);


--
-- Name: chat_media_federation_inbound_pending chat_media_federation_inbound_pending_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_inbound_pending
    ADD CONSTRAINT chat_media_federation_inbound_pending_pkey PRIMARY KEY (origin, sequence);


--
-- Name: chat_media_federation_inbound_state chat_media_federation_inbound_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_inbound_state
    ADD CONSTRAINT chat_media_federation_inbound_state_pkey PRIMARY KEY (origin);


--
-- Name: chat_media_federation_inbound_transactions chat_media_federation_inbound_transacti_origin_operation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_inbound_transactions
    ADD CONSTRAINT chat_media_federation_inbound_transacti_origin_operation_id_key UNIQUE (origin, operation_id);


--
-- Name: chat_media_federation_inbound_transactions chat_media_federation_inbound_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_inbound_transactions
    ADD CONSTRAINT chat_media_federation_inbound_transactions_pkey PRIMARY KEY (origin, sequence);


--
-- Name: chat_media_federation_outbox chat_media_federation_outbox_destination_sequence_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_outbox
    ADD CONSTRAINT chat_media_federation_outbox_destination_sequence_key UNIQUE (destination, sequence);


--
-- Name: chat_media_federation_outbox chat_media_federation_outbox_origin_user_id_operation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_outbox
    ADD CONSTRAINT chat_media_federation_outbox_origin_user_id_operation_id_key UNIQUE (origin_user_id, operation_id);


--
-- Name: chat_media_federation_outbox chat_media_federation_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_outbox
    ADD CONSTRAINT chat_media_federation_outbox_pkey PRIMARY KEY (id);


--
-- Name: chat_media_federation_pull_grants chat_media_federation_pull_gr_destination_recipient_attachm_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_pull_grants
    ADD CONSTRAINT chat_media_federation_pull_gr_destination_recipient_attachm_key UNIQUE (destination, recipient, attachment_id);


--
-- Name: chat_media_federation_pull_grants chat_media_federation_pull_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_pull_grants
    ADD CONSTRAINT chat_media_federation_pull_grants_pkey PRIMARY KEY (destination, operation_id);


--
-- Name: chat_media_federation_sequences chat_media_federation_sequences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_sequences
    ADD CONSTRAINT chat_media_federation_sequences_pkey PRIMARY KEY (destination);


--
-- Name: chat_media_objects chat_media_objects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_objects
    ADD CONSTRAINT chat_media_objects_pkey PRIMARY KEY (attachment_id);


--
-- Name: chat_media_objects chat_media_objects_storage_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_objects
    ADD CONSTRAINT chat_media_objects_storage_path_key UNIQUE (storage_path);


--
-- Name: chat_media_origin_delivery_operations chat_media_origin_delivery_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_origin_delivery_operations
    ADD CONSTRAINT chat_media_origin_delivery_operations_pkey PRIMARY KEY (origin_user_id, operation_id);


--
-- Name: chat_media_rate_counters chat_media_rate_counters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_rate_counters
    ADD CONSTRAINT chat_media_rate_counters_pkey PRIMARY KEY (scope_type, scope_digest, window_start);


--
-- Name: chat_media_references chat_media_references_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_references
    ADD CONSTRAINT chat_media_references_pkey PRIMARY KEY (id);


--
-- Name: chat_media_references chat_media_references_user_id_attachment_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_references
    ADD CONSTRAINT chat_media_references_user_id_attachment_id_key UNIQUE (user_id, attachment_id);


--
-- Name: chat_media_uploads chat_media_uploads_attachment_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_uploads
    ADD CONSTRAINT chat_media_uploads_attachment_id_key UNIQUE (attachment_id);


--
-- Name: chat_media_uploads chat_media_uploads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_uploads
    ADD CONSTRAINT chat_media_uploads_pkey PRIMARY KEY (id);


--
-- Name: chat_media_uploads chat_media_uploads_storage_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_uploads
    ADD CONSTRAINT chat_media_uploads_storage_path_key UNIQUE (storage_path);


--
-- Name: chat_mls_admin_audit_events chat_mls_admin_audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_admin_audit_events
    ADD CONSTRAINT chat_mls_admin_audit_events_pkey PRIMARY KEY (id);


--
-- Name: chat_mls_anonymous_send_ids chat_mls_anonymous_send_ids_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_anonymous_send_ids
    ADD CONSTRAINT chat_mls_anonymous_send_ids_pkey PRIMARY KEY (recipient_user_id, capability_hash, send_id);


--
-- Name: chat_mls_authority_bootstrap_pages chat_mls_authority_bootstrap_pages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_authority_bootstrap_pages
    ADD CONSTRAINT chat_mls_authority_bootstrap_pages_pkey PRIMARY KEY (bootstrap_id, page_index);


--
-- Name: chat_mls_authority_bootstraps chat_mls_authority_bootstraps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_authority_bootstraps
    ADD CONSTRAINT chat_mls_authority_bootstraps_pkey PRIMARY KEY (bootstrap_id);


--
-- Name: chat_mls_consensus_evidence chat_mls_consensus_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_consensus_evidence
    ADD CONSTRAINT chat_mls_consensus_evidence_pkey PRIMARY KEY (evidence_digest);


--
-- Name: chat_mls_control_blocks chat_mls_control_blocks_conversation_id_incarnation_block_h_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_control_blocks
    ADD CONSTRAINT chat_mls_control_blocks_conversation_id_incarnation_block_h_key UNIQUE (conversation_id, incarnation, block_hash);


--
-- Name: chat_mls_control_blocks chat_mls_control_blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_control_blocks
    ADD CONSTRAINT chat_mls_control_blocks_pkey PRIMARY KEY (conversation_id, incarnation, height);


--
-- Name: chat_mls_control_outbox chat_mls_control_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_control_outbox
    ADD CONSTRAINT chat_mls_control_outbox_pkey PRIMARY KEY (destination, conversation_id, incarnation, height);


--
-- Name: chat_mls_conversations chat_mls_conversations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_conversations
    ADD CONSTRAINT chat_mls_conversations_pkey PRIMARY KEY (conversation_id);


--
-- Name: chat_mls_delivery_capabilities chat_mls_delivery_capabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_delivery_capabilities
    ADD CONSTRAINT chat_mls_delivery_capabilities_pkey PRIMARY KEY (recipient_user_id, conversation_id, incarnation, epoch);


--
-- Name: chat_mls_devices chat_mls_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_devices
    ADD CONSTRAINT chat_mls_devices_pkey PRIMARY KEY (user_id, device_id);


--
-- Name: chat_mls_federation_inbound_state chat_mls_federation_inbound_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_federation_inbound_state
    ADD CONSTRAINT chat_mls_federation_inbound_state_pkey PRIMARY KEY (origin);


--
-- Name: chat_mls_federation_inbound_transactions chat_mls_federation_inbound_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_federation_inbound_transactions
    ADD CONSTRAINT chat_mls_federation_inbound_transactions_pkey PRIMARY KEY (origin, sequence);


--
-- Name: chat_mls_federation_outbox chat_mls_federation_outbox_destination_recipient_send_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_federation_outbox
    ADD CONSTRAINT chat_mls_federation_outbox_destination_recipient_send_id_key UNIQUE (destination, recipient, send_id);


--
-- Name: chat_mls_federation_outbox chat_mls_federation_outbox_destination_sequence_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_federation_outbox
    ADD CONSTRAINT chat_mls_federation_outbox_destination_sequence_key UNIQUE (destination, sequence);


--
-- Name: chat_mls_federation_outbox chat_mls_federation_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_federation_outbox
    ADD CONSTRAINT chat_mls_federation_outbox_pkey PRIMARY KEY (id);


--
-- Name: chat_mls_federation_sequences chat_mls_federation_sequences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_federation_sequences
    ADD CONSTRAINT chat_mls_federation_sequences_pkey PRIMARY KEY (destination);


--
-- Name: chat_mls_incarnation_recoveries chat_mls_incarnation_recoveri_conversation_id_new_incarnati_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveri_conversation_id_new_incarnati_key UNIQUE (conversation_id, new_incarnation);


--
-- Name: chat_mls_incarnation_recoveries chat_mls_incarnation_recoveri_conversation_id_previous_inc_key1; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveri_conversation_id_previous_inc_key1 UNIQUE (conversation_id, previous_incarnation, proposal_id);


--
-- Name: chat_mls_incarnation_recoveries chat_mls_incarnation_recoveri_conversation_id_previous_inca_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveri_conversation_id_previous_inca_key UNIQUE (conversation_id, previous_incarnation);


--
-- Name: chat_mls_incarnation_recoveries chat_mls_incarnation_recoveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveries_pkey PRIMARY KEY (recovery_digest);


--
-- Name: chat_mls_incarnations chat_mls_incarnations_mls_group_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_incarnations
    ADD CONSTRAINT chat_mls_incarnations_mls_group_id_key UNIQUE (mls_group_id);


--
-- Name: chat_mls_incarnations chat_mls_incarnations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_incarnations
    ADD CONSTRAINT chat_mls_incarnations_pkey PRIMARY KEY (conversation_id, incarnation);


--
-- Name: chat_mls_invitation_feedback_outbox chat_mls_invitation_feedback_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_invitation_feedback_outbox
    ADD CONSTRAINT chat_mls_invitation_feedback_outbox_pkey PRIMARY KEY (destination, conversation_id, incarnation, member_address, invited_epoch);


--
-- Name: chat_mls_invitation_feedback chat_mls_invitation_feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_invitation_feedback
    ADD CONSTRAINT chat_mls_invitation_feedback_pkey PRIMARY KEY (conversation_id, incarnation, member_address, invited_epoch);


--
-- Name: chat_mls_key_packages chat_mls_key_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_key_packages
    ADD CONSTRAINT chat_mls_key_packages_pkey PRIMARY KEY (user_id, device_id, key_package_ref);


--
-- Name: chat_mls_local_member_devices chat_mls_local_member_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_local_member_devices
    ADD CONSTRAINT chat_mls_local_member_devices_pkey PRIMARY KEY (conversation_id, incarnation, user_id, device_id, joined_epoch);


--
-- Name: chat_mls_local_members chat_mls_local_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_local_members
    ADD CONSTRAINT chat_mls_local_members_pkey PRIMARY KEY (conversation_id, incarnation, user_id, joined_epoch);


--
-- Name: chat_mls_mailbox chat_mls_mailbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_pkey PRIMARY KEY (id);


--
-- Name: chat_mls_mailbox chat_mls_mailbox_recipient_user_id_recipient_device_id_send_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_recipient_user_id_recipient_device_id_send_key UNIQUE (recipient_user_id, recipient_device_id, send_id);


--
-- Name: chat_mls_membership_deliveries chat_mls_membership_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_membership_deliveries
    ADD CONSTRAINT chat_mls_membership_deliveries_pkey PRIMARY KEY (conversation_id, incarnation, proposal_id, destination);


--
-- Name: chat_mls_ordering_votes chat_mls_ordering_votes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_ordering_votes
    ADD CONSTRAINT chat_mls_ordering_votes_pkey PRIMARY KEY (conversation_id, incarnation, authority_set_sequence, height, round, vote_type, authority_domain);


--
-- Name: chat_mls_owner_approvals chat_mls_owner_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_owner_approvals
    ADD CONSTRAINT chat_mls_owner_approvals_pkey PRIMARY KEY (conversation_id, incarnation, owner_set_sequence, proposal_hash, owner_id);


--
-- Name: chat_mls_participant_bootstrap_pages chat_mls_participant_bootstrap_pages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_participant_bootstrap_pages
    ADD CONSTRAINT chat_mls_participant_bootstrap_pages_pkey PRIMARY KEY (bootstrap_id, page_index);


--
-- Name: chat_mls_participant_bootstraps chat_mls_participant_bootstraps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_participant_bootstraps
    ADD CONSTRAINT chat_mls_participant_bootstraps_pkey PRIMARY KEY (bootstrap_id);


--
-- Name: chat_mls_pending_requests chat_mls_pending_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_pending_requests
    ADD CONSTRAINT chat_mls_pending_requests_pkey PRIMARY KEY (request_id);


--
-- Name: chat_mls_rate_counters chat_mls_rate_counters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_rate_counters
    ADD CONSTRAINT chat_mls_rate_counters_pkey PRIMARY KEY (scope_type, scope_digest, window_start);


--
-- Name: chat_mls_recovery_outbox chat_mls_recovery_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_recovery_outbox
    ADD CONSTRAINT chat_mls_recovery_outbox_pkey PRIMARY KEY (destination, recovery_digest);


--
-- Name: chat_one_time_kyber_pre_keys chat_one_time_kyber_pre_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_one_time_kyber_pre_keys
    ADD CONSTRAINT chat_one_time_kyber_pre_keys_pkey PRIMARY KEY (user_id, device_id, key_id);


--
-- Name: chat_one_time_pre_keys chat_one_time_pre_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_one_time_pre_keys
    ADD CONSTRAINT chat_one_time_pre_keys_pkey PRIMARY KEY (user_id, device_id, key_id);


--
-- Name: chat_profiles chat_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_profiles
    ADD CONSTRAINT chat_profiles_pkey PRIMARY KEY (user_id, version);


--
-- Name: chat_push_subscriptions chat_push_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_push_subscriptions
    ADD CONSTRAINT chat_push_subscriptions_pkey PRIMARY KEY (user_id, device_id);


--
-- Name: chat_sealed_federation_inbound chat_sealed_federation_inbound_origin_send_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sealed_federation_inbound
    ADD CONSTRAINT chat_sealed_federation_inbound_origin_send_id_key UNIQUE (origin, send_id);


--
-- Name: chat_sealed_federation_inbound chat_sealed_federation_inbound_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sealed_federation_inbound
    ADD CONSTRAINT chat_sealed_federation_inbound_pkey PRIMARY KEY (origin, sequence);


--
-- Name: chat_sealed_federation_outbox chat_sealed_federation_outbox_destination_recipient_send_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sealed_federation_outbox
    ADD CONSTRAINT chat_sealed_federation_outbox_destination_recipient_send_id_key UNIQUE (destination, recipient, send_id);


--
-- Name: chat_sealed_federation_outbox chat_sealed_federation_outbox_destination_sequence_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sealed_federation_outbox
    ADD CONSTRAINT chat_sealed_federation_outbox_destination_sequence_key UNIQUE (destination, sequence);


--
-- Name: chat_sealed_federation_outbox chat_sealed_federation_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sealed_federation_outbox
    ADD CONSTRAINT chat_sealed_federation_outbox_pkey PRIMARY KEY (id);


--
-- Name: chat_sealed_federation_sequences chat_sealed_federation_sequences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sealed_federation_sequences
    ADD CONSTRAINT chat_sealed_federation_sequences_pkey PRIMARY KEY (destination);


--
-- Name: chat_sends chat_sends_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sends
    ADD CONSTRAINT chat_sends_pkey PRIMARY KEY (sender_user_id, sender_device_id, send_id, delivery_scope);


--
-- Name: chat_web_push_key chat_web_push_key_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_web_push_key
    ADD CONSTRAINT chat_web_push_key_pkey PRIMARY KEY (id);


--
-- Name: chat_ws_tickets chat_ws_tickets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_ws_tickets
    ADD CONSTRAINT chat_ws_tickets_pkey PRIMARY KEY (token_hash);


--
-- Name: collection_key_epoch_history collection_key_epoch_history_collection_id_epoch_statement__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_key_epoch_history
    ADD CONSTRAINT collection_key_epoch_history_collection_id_epoch_statement__key UNIQUE (collection_id, epoch_statement_hash);


--
-- Name: collection_key_epoch_history collection_key_epoch_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_key_epoch_history
    ADD CONSTRAINT collection_key_epoch_history_pkey PRIMARY KEY (collection_id, epoch);


--
-- Name: collection_shares collection_shares_collection_id_recipient_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_shares
    ADD CONSTRAINT collection_shares_collection_id_recipient_user_id_key UNIQUE (collection_id, recipient_user_id);


--
-- Name: collection_shares collection_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_shares
    ADD CONSTRAINT collection_shares_pkey PRIMARY KEY (id);


--
-- Name: collections collections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collections
    ADD CONSTRAINT collections_pkey PRIMARY KEY (id);


--
-- Name: contact_emails contact_emails_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_emails
    ADD CONSTRAINT contact_emails_pkey PRIMARY KEY (contact_id, address);


--
-- Name: contact_group_members contact_group_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_group_members
    ADD CONSTRAINT contact_group_members_pkey PRIMARY KEY (contact_id, group_id);


--
-- Name: contact_groups contact_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_groups
    ADD CONSTRAINT contact_groups_pkey PRIMARY KEY (id);


--
-- Name: contacts contacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts
    ADD CONSTRAINT contacts_pkey PRIMARY KEY (id);


--
-- Name: contacts contacts_user_id_uid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts
    ADD CONSTRAINT contacts_user_id_uid_key UNIQUE (user_id, uid);


--
-- Name: drive_federation_mutations drive_federation_mutations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federation_mutations
    ADD CONSTRAINT drive_federation_mutations_pkey PRIMARY KEY (origin, request_id);


--
-- Name: drive_profile_keys drive_profile_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_profile_keys
    ADD CONSTRAINT drive_profile_keys_pkey PRIMARY KEY (user_id, direction, peer_account);


--
-- Name: federated_incoming_file_shares federated_incoming_file_share_user_id_remote_domain_capabil_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_incoming_file_shares
    ADD CONSTRAINT federated_incoming_file_share_user_id_remote_domain_capabil_key UNIQUE (user_id, remote_domain, capability_hash);


--
-- Name: federated_incoming_file_shares federated_incoming_file_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_incoming_file_shares
    ADD CONSTRAINT federated_incoming_file_shares_pkey PRIMARY KEY (id);


--
-- Name: federated_incoming_shares federated_incoming_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_incoming_shares
    ADD CONSTRAINT federated_incoming_shares_pkey PRIMARY KEY (id);


--
-- Name: federated_incoming_shares federated_incoming_shares_user_id_remote_domain_capability__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_incoming_shares
    ADD CONSTRAINT federated_incoming_shares_user_id_remote_domain_capability__key UNIQUE (user_id, remote_domain, capability_hash);


--
-- Name: federated_outgoing_file_shares federated_outgoing_file_shares_capability_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_outgoing_file_shares
    ADD CONSTRAINT federated_outgoing_file_shares_capability_hash_key UNIQUE (capability_hash);


--
-- Name: federated_outgoing_file_shares federated_outgoing_file_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_outgoing_file_shares
    ADD CONSTRAINT federated_outgoing_file_shares_pkey PRIMARY KEY (id);


--
-- Name: federated_outgoing_shares federated_outgoing_shares_capability_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_outgoing_shares
    ADD CONSTRAINT federated_outgoing_shares_capability_hash_key UNIQUE (capability_hash);


--
-- Name: federated_outgoing_shares federated_outgoing_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_outgoing_shares
    ADD CONSTRAINT federated_outgoing_shares_pkey PRIMARY KEY (id);


--
-- Name: federation_domain_rules federation_domain_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_domain_rules
    ADD CONSTRAINT federation_domain_rules_pkey PRIMARY KEY (domain, feature);


--
-- Name: federation_feature_policies federation_feature_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_feature_policies
    ADD CONSTRAINT federation_feature_policies_pkey PRIMARY KEY (feature);


--
-- Name: federation_feature_policy_documents federation_feature_policy_doc_domain_feature_type_policy_ha_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_feature_policy_documents
    ADD CONSTRAINT federation_feature_policy_doc_domain_feature_type_policy_ha_key UNIQUE (domain, feature_type, policy_hash);


--
-- Name: federation_feature_policy_documents federation_feature_policy_documents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_feature_policy_documents
    ADD CONSTRAINT federation_feature_policy_documents_pkey PRIMARY KEY (domain, feature_type, sequence);


--
-- Name: federation_feature_policy_failures federation_feature_policy_failures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_feature_policy_failures
    ADD CONSTRAINT federation_feature_policy_failures_pkey PRIMARY KEY (id);


--
-- Name: federation_local_identity_documents federation_local_identity_documents_document_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_local_identity_documents
    ADD CONSTRAINT federation_local_identity_documents_document_hash_key UNIQUE (document_hash);


--
-- Name: federation_local_identity_documents federation_local_identity_documents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_local_identity_documents
    ADD CONSTRAINT federation_local_identity_documents_pkey PRIMARY KEY (sequence);


--
-- Name: federation_peer_identities federation_peer_identities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_identities
    ADD CONSTRAINT federation_peer_identities_pkey PRIMARY KEY (domain);


--
-- Name: federation_peer_identity_documents federation_peer_identity_documents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_identity_documents
    ADD CONSTRAINT federation_peer_identity_documents_pkey PRIMARY KEY (domain, sequence, document_hash);


--
-- Name: federation_policy federation_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_policy
    ADD CONSTRAINT federation_policy_pkey PRIMARY KEY (singleton);


--
-- Name: federation_request_replays federation_request_replays_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_request_replays
    ADD CONSTRAINT federation_request_replays_pkey PRIMARY KEY (origin, request_id);


--
-- Name: feedback feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback
    ADD CONSTRAINT feedback_pkey PRIMARY KEY (id);


--
-- Name: file_assets file_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_assets
    ADD CONSTRAINT file_assets_pkey PRIMARY KEY (file_id, asset_id);


--
-- Name: file_key_history file_key_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_key_history
    ADD CONSTRAINT file_key_history_pkey PRIMARY KEY (file_id, generation);


--
-- Name: file_shares file_shares_file_id_recipient_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_shares
    ADD CONSTRAINT file_shares_file_id_recipient_user_id_key UNIQUE (file_id, recipient_user_id);


--
-- Name: file_shares file_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_shares
    ADD CONSTRAINT file_shares_pkey PRIMARY KEY (id);


--
-- Name: file_thumbnails file_thumbnails_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_thumbnails
    ADD CONSTRAINT file_thumbnails_pkey PRIMARY KEY (file_id, variant);


--
-- Name: file_update_log file_update_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_update_log
    ADD CONSTRAINT file_update_log_pkey PRIMARY KEY (file_id, seq);


--
-- Name: file_versions file_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_versions
    ADD CONSTRAINT file_versions_pkey PRIMARY KEY (id);


--
-- Name: files files_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.files
    ADD CONSTRAINT files_pkey PRIMARY KEY (id);


--
-- Name: identity_pins identity_pins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_pins
    ADD CONSTRAINT identity_pins_pkey PRIMARY KEY (user_id);


--
-- Name: live_location_streams live_location_streams_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.live_location_streams
    ADD CONSTRAINT live_location_streams_pkey PRIMARY KEY (stream_id);


--
-- Name: mail_address_keys mail_address_keys_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_address_keys
    ADD CONSTRAINT mail_address_keys_fingerprint_key UNIQUE (fingerprint);


--
-- Name: mail_address_keys mail_address_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_address_keys
    ADD CONSTRAINT mail_address_keys_pkey PRIMARY KEY (id);


--
-- Name: mail_addresses mail_addresses_address_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_addresses
    ADD CONSTRAINT mail_addresses_address_key UNIQUE (address);


--
-- Name: mail_addresses mail_addresses_group_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_addresses
    ADD CONSTRAINT mail_addresses_group_id_key UNIQUE (group_id);


--
-- Name: mail_addresses mail_addresses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_addresses
    ADD CONSTRAINT mail_addresses_pkey PRIMARY KEY (id);


--
-- Name: mail_auto_replies mail_auto_replies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_auto_replies
    ADD CONSTRAINT mail_auto_replies_pkey PRIMARY KEY (user_id);


--
-- Name: mail_auto_reply_sent mail_auto_reply_sent_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_auto_reply_sent
    ADD CONSTRAINT mail_auto_reply_sent_pkey PRIMARY KEY (user_id, sender);


--
-- Name: mail_change_floors mail_change_floors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_change_floors
    ADD CONSTRAINT mail_change_floors_pkey PRIMARY KEY (owner);


--
-- Name: mail_draft_attachments mail_draft_attachments_object_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_draft_attachments
    ADD CONSTRAINT mail_draft_attachments_object_key_key UNIQUE (object_key);


--
-- Name: mail_draft_attachments mail_draft_attachments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_draft_attachments
    ADD CONSTRAINT mail_draft_attachments_pkey PRIMARY KEY (id);


--
-- Name: mail_filter_runs mail_filter_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_filter_runs
    ADD CONSTRAINT mail_filter_runs_pkey PRIMARY KEY (id);


--
-- Name: mail_filters mail_filters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_filters
    ADD CONSTRAINT mail_filters_pkey PRIMARY KEY (id);


--
-- Name: mail_folders mail_folders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_folders
    ADD CONSTRAINT mail_folders_pkey PRIMARY KEY (id);


--
-- Name: mail_folders mail_folders_user_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_folders
    ADD CONSTRAINT mail_folders_user_id_id_key UNIQUE (user_id, id);


--
-- Name: mail_group_key_lists mail_group_key_lists_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_key_lists
    ADD CONSTRAINT mail_group_key_lists_pkey PRIMARY KEY (group_id, sequence);


--
-- Name: mail_group_key_shares mail_group_key_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_key_shares
    ADD CONSTRAINT mail_group_key_shares_pkey PRIMARY KEY (group_key_id, user_id);


--
-- Name: mail_group_keys mail_group_keys_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_keys
    ADD CONSTRAINT mail_group_keys_fingerprint_key UNIQUE (fingerprint);


--
-- Name: mail_group_keys mail_group_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_keys
    ADD CONSTRAINT mail_group_keys_pkey PRIMARY KEY (id);


--
-- Name: mail_group_members mail_group_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_members
    ADD CONSTRAINT mail_group_members_pkey PRIMARY KEY (group_id, user_id);


--
-- Name: mail_group_objects mail_group_objects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_objects
    ADD CONSTRAINT mail_group_objects_pkey PRIMARY KEY (object_key);


--
-- Name: mail_groups mail_groups_address_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_groups
    ADD CONSTRAINT mail_groups_address_key UNIQUE (address);


--
-- Name: mail_groups mail_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_groups
    ADD CONSTRAINT mail_groups_pkey PRIMARY KEY (id);


--
-- Name: mail_groups mail_groups_system_role_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_groups
    ADD CONSTRAINT mail_groups_system_role_key UNIQUE (system_role);


--
-- Name: mail_identities mail_identities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_identities
    ADD CONSTRAINT mail_identities_pkey PRIMARY KEY (address_id);


--
-- Name: mail_image_senders mail_image_senders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_image_senders
    ADD CONSTRAINT mail_image_senders_pkey PRIMARY KEY (user_id, address);


--
-- Name: mail_key_lists mail_key_lists_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_key_lists
    ADD CONSTRAINT mail_key_lists_pkey PRIMARY KEY (address_id, sequence);


--
-- Name: mail_labels mail_labels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_labels
    ADD CONSTRAINT mail_labels_pkey PRIMARY KEY (id);


--
-- Name: mail_labels mail_labels_user_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_labels
    ADD CONSTRAINT mail_labels_user_id_id_key UNIQUE (user_id, id);


--
-- Name: mail_message_labels mail_message_labels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_message_labels
    ADD CONSTRAINT mail_message_labels_pkey PRIMARY KEY (message_id, label_id);


--
-- Name: mail_message_tombstones mail_message_tombstones_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_message_tombstones
    ADD CONSTRAINT mail_message_tombstones_pkey PRIMARY KEY (owner, change_xid, id);


--
-- Name: mail_messages mail_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_messages
    ADD CONSTRAINT mail_messages_pkey PRIMARY KEY (id);


--
-- Name: mail_outbox mail_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_outbox
    ADD CONSTRAINT mail_outbox_pkey PRIMARY KEY (id);


--
-- Name: mail_sender_rules mail_sender_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sender_rules
    ADD CONSTRAINT mail_sender_rules_pkey PRIMARY KEY (id);


--
-- Name: mail_sender_rules mail_sender_rules_user_id_pattern_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sender_rules
    ADD CONSTRAINT mail_sender_rules_user_id_pattern_key UNIQUE (user_id, pattern);


--
-- Name: mail_sending_events mail_sending_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sending_events
    ADD CONSTRAINT mail_sending_events_pkey PRIMARY KEY (id);


--
-- Name: mail_sending_policies mail_sending_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sending_policies
    ADD CONSTRAINT mail_sending_policies_pkey PRIMARY KEY (user_id);


--
-- Name: mail_settings mail_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_settings
    ADD CONSTRAINT mail_settings_pkey PRIMARY KEY (user_id);


--
-- Name: pass_pin_failures pass_pin_failures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_pin_failures
    ADD CONSTRAINT pass_pin_failures_pkey PRIMARY KEY (sign_in_id);


--
-- Name: pass_pins pass_pins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_pins
    ADD CONSTRAINT pass_pins_pkey PRIMARY KEY (user_id);


--
-- Name: pass_settings pass_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_settings
    ADD CONSTRAINT pass_settings_pkey PRIMARY KEY (user_id);


--
-- Name: pass_vault_secrets pass_vault_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_vault_secrets
    ADD CONSTRAINT pass_vault_secrets_pkey PRIMARY KEY (user_id, file_id);


--
-- Name: photos_library_folders photos_library_folders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_library_folders
    ADD CONSTRAINT photos_library_folders_pkey PRIMARY KEY (user_id, collection_id);


--
-- Name: photos_library photos_library_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_library
    ADD CONSTRAINT photos_library_pkey PRIMARY KEY (user_id);


--
-- Name: photos_preferences photos_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_preferences
    ADD CONSTRAINT photos_preferences_pkey PRIMARY KEY (user_id);


--
-- Name: public_link_reports public_link_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_link_reports
    ADD CONSTRAINT public_link_reports_pkey PRIMARY KEY (id);


--
-- Name: public_shares public_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_shares
    ADD CONSTRAINT public_shares_pkey PRIMARY KEY (id);


--
-- Name: public_shares public_shares_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_shares
    ADD CONSTRAINT public_shares_token_key UNIQUE (token);


--
-- Name: sealed_sender_generated_certificates sealed_sender_generated_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sealed_sender_generated_certificates
    ADD CONSTRAINT sealed_sender_generated_certificates_pkey PRIMARY KEY (certificate_id);


--
-- Name: sealed_sender_generated_certificates sealed_sender_generated_certificates_root_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sealed_sender_generated_certificates
    ADD CONSTRAINT sealed_sender_generated_certificates_root_id_key UNIQUE (root_id);


--
-- Name: server_generated_keys server_generated_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.server_generated_keys
    ADD CONSTRAINT server_generated_keys_pkey PRIMARY KEY (purpose);


--
-- Name: site_settings site_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.site_settings
    ADD CONSTRAINT site_settings_pkey PRIMARY KEY (key);


--
-- Name: uploads uploads_file_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.uploads
    ADD CONSTRAINT uploads_file_id_key UNIQUE (file_id);


--
-- Name: uploads uploads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.uploads
    ADD CONSTRAINT uploads_pkey PRIMARY KEY (id);


--
-- Name: user_devices user_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_devices
    ADD CONSTRAINT user_devices_pkey PRIMARY KEY (id);


--
-- Name: user_map_preferences user_map_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_map_preferences
    ADD CONSTRAINT user_map_preferences_pkey PRIMARY KEY (user_id);


--
-- Name: user_ui_preferences user_ui_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_ui_preferences
    ADD CONSTRAINT user_ui_preferences_pkey PRIMARY KEY (user_id);


--
-- Name: users users_key_binding_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_key_binding_key UNIQUE (key_binding);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_unique UNIQUE (username);


--
-- Name: auth_session_forks_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_session_forks_expiry_idx ON public.auth_session_forks USING btree (expires_at);


--
-- Name: auth_sessions_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_sessions_parent_idx ON public.auth_sessions USING btree (parent_session_id);


--
-- Name: auth_sessions_previous_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_sessions_previous_hash_idx ON public.auth_sessions USING btree (previous_refresh_token_hash) WHERE (previous_refresh_token_hash IS NOT NULL);


--
-- Name: auth_sessions_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_sessions_user_idx ON public.auth_sessions USING btree (user_id) WHERE (revoked_at IS NULL);


--
-- Name: chat_anonymous_rate_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_anonymous_rate_expiry_idx ON public.chat_anonymous_rate_counters USING btree (expires_at);


--
-- Name: chat_backup_bases_staging_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_backup_bases_staging_idx ON public.chat_backup_bases USING btree (state, created_at);


--
-- Name: chat_backup_media_reconciliation_entries_order_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_backup_media_reconciliation_entries_order_idx ON public.chat_backup_media_reconciliation_entries USING btree (user_id, operation_id, reference_id);


--
-- Name: chat_backup_media_references_media_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_backup_media_references_media_idx ON public.chat_backup_media_references USING btree (user_id, media_id);


--
-- Name: chat_backup_segments_restore_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_backup_segments_restore_idx ON public.chat_backup_segments USING btree (user_id, cursor);


--
-- Name: chat_federation_outbox_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_federation_outbox_due_idx ON public.chat_federation_outbox USING btree (state, next_attempt_at, destination, sequence);


--
-- Name: chat_invite_links_origin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_invite_links_origin ON public.chat_invite_links USING btree (origin_domain);


--
-- Name: chat_invite_links_touched; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_invite_links_touched ON public.chat_invite_links USING btree (touched_at);


--
-- Name: chat_invite_requests_link; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_invite_requests_link ON public.chat_invite_requests USING btree (link_id, created_at);


--
-- Name: chat_mailbox_recipient_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mailbox_recipient_idx ON public.chat_mailbox USING btree (recipient_user_id, recipient_device_id, cursor);


--
-- Name: chat_mls_control_outbox_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mls_control_outbox_due_idx ON public.chat_mls_control_outbox USING btree (state, next_attempt_at, destination, conversation_id, incarnation, height);


--
-- Name: chat_mls_delivery_capability_current_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_mls_delivery_capability_current_idx ON public.chat_mls_delivery_capabilities USING btree (recipient_user_id, conversation_id, incarnation, capability_hash);


--
-- Name: chat_mls_federation_outbox_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mls_federation_outbox_due_idx ON public.chat_mls_federation_outbox USING btree (state, next_attempt_at, destination, sequence);


--
-- Name: chat_mls_invitation_feedback_outbox_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mls_invitation_feedback_outbox_due_idx ON public.chat_mls_invitation_feedback_outbox USING btree (state, next_attempt_at, destination, conversation_id, incarnation);


--
-- Name: chat_mls_key_packages_available_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mls_key_packages_available_idx ON public.chat_mls_key_packages USING btree (user_id, device_id, expires_at, created_at) WHERE (claimed_at IS NULL);


--
-- Name: chat_mls_mailbox_recipient_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mls_mailbox_recipient_idx ON public.chat_mls_mailbox USING btree (recipient_user_id, recipient_device_id, cursor);


--
-- Name: chat_mls_membership_deliveries_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mls_membership_deliveries_expiry_idx ON public.chat_mls_membership_deliveries USING btree (state, expires_at);


--
-- Name: chat_mls_one_active_local_member_device_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_mls_one_active_local_member_device_idx ON public.chat_mls_local_member_devices USING btree (conversation_id, incarnation, user_id, device_id) WHERE (removed_epoch IS NULL);


--
-- Name: chat_mls_one_active_local_membership_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_mls_one_active_local_membership_idx ON public.chat_mls_local_members USING btree (conversation_id, incarnation, user_id) WHERE (removed_epoch IS NULL);


--
-- Name: chat_mls_one_pending_request_per_sender_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_mls_one_pending_request_per_sender_idx ON public.chat_mls_pending_requests USING btree (recipient_user_id, sender_address) WHERE (status = 'pending'::text);


--
-- Name: chat_mls_pending_requests_recipient_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mls_pending_requests_recipient_idx ON public.chat_mls_pending_requests USING btree (recipient_user_id, status, created_at);


--
-- Name: chat_mls_rate_counters_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mls_rate_counters_expiry_idx ON public.chat_mls_rate_counters USING btree (expires_at);


--
-- Name: chat_mls_recovery_outbox_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mls_recovery_outbox_due_idx ON public.chat_mls_recovery_outbox USING btree (state, next_attempt_at, destination, recovery_digest);


--
-- Name: chat_profiles_one_current; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_profiles_one_current ON public.chat_profiles USING btree (user_id) WHERE is_current;


--
-- Name: chat_ws_tickets_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_ws_tickets_expiry_idx ON public.chat_ws_tickets USING btree (expires_at);


--
-- Name: collections_unique_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX collections_unique_name ON public.collections USING btree (parent_collection_id, name_hash) WHERE ((deleted_at IS NULL) AND (name_hash IS NOT NULL) AND (parent_collection_id IS NOT NULL));


--
-- Name: collections_unique_top_level_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX collections_unique_top_level_name ON public.collections USING btree (owner_user_id, name_hash) WHERE ((deleted_at IS NULL) AND (name_hash IS NOT NULL) AND (parent_collection_id IS NULL) AND (kind = 'folder'::text));


--
-- Name: drive_federation_mutations_share_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_federation_mutations_share_created_idx ON public.drive_federation_mutations USING btree (share_id, created_at DESC);


--
-- Name: federated_incoming_shares_remote_domain_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federated_incoming_shares_remote_domain_idx ON public.federated_incoming_shares USING btree (remote_domain, created_at DESC);


--
-- Name: federated_outgoing_file_shares_file_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federated_outgoing_file_shares_file_idx ON public.federated_outgoing_file_shares USING btree (file_id);


--
-- Name: federated_outgoing_shares_recipient_domain_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federated_outgoing_shares_recipient_domain_idx ON public.federated_outgoing_shares USING btree (recipient_domain, created_at DESC);


--
-- Name: federation_domain_rules_updated_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_domain_rules_updated_idx ON public.federation_domain_rules USING btree (updated_at DESC, domain, feature);


--
-- Name: federation_feature_policy_current_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_feature_policy_current_idx ON public.federation_feature_policy_documents USING btree (domain, feature_type, sequence DESC);


--
-- Name: federation_peer_identities_state_updated_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_peer_identities_state_updated_idx ON public.federation_peer_identities USING btree (trust_state, updated_at DESC);


--
-- Name: federation_peer_identity_documents_history_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_peer_identity_documents_history_idx ON public.federation_peer_identity_documents USING btree (domain, sequence DESC, recorded_at DESC);


--
-- Name: federation_peer_identity_one_accepted_sequence_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX federation_peer_identity_one_accepted_sequence_idx ON public.federation_peer_identity_documents USING btree (domain, sequence) WHERE (acceptance = 'accepted'::text);


--
-- Name: federation_request_replays_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_request_replays_expiry_idx ON public.federation_request_replays USING btree (expires_at);


--
-- Name: feedback_open; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX feedback_open ON public.feedback USING btree (created_at) WHERE (resolved_at IS NULL);


--
-- Name: feedback_resolved; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX feedback_resolved ON public.feedback USING btree (resolved_at DESC) WHERE (resolved_at IS NOT NULL);


--
-- Name: file_assets_uploader_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX file_assets_uploader_idx ON public.file_assets USING btree (uploader_user_id);


--
-- Name: file_shares_recipient_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX file_shares_recipient_idx ON public.file_shares USING btree (recipient_user_id);


--
-- Name: file_thumbnails_uploader_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX file_thumbnails_uploader_idx ON public.file_thumbnails USING btree (uploader_user_id);


--
-- Name: file_update_log_remote_sender_seq_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX file_update_log_remote_sender_seq_unique ON public.file_update_log USING btree (file_id, remote_domain, remote_device, sender_seq) WHERE (remote_domain IS NOT NULL);


--
-- Name: file_update_log_sender_seq_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX file_update_log_sender_seq_unique ON public.file_update_log USING btree (file_id, sender_device, sender_seq);


--
-- Name: file_versions_timeline; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX file_versions_timeline ON public.file_versions USING btree (file_id, created_at DESC);


--
-- Name: files_ciphertext_digest_backfill_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX files_ciphertext_digest_backfill_idx ON public.files USING btree (created_at, id) WHERE ((ciphertext_sha256 IS NULL) AND (deleted_at IS NULL) AND (NOT original_pruned));


--
-- Name: files_fed_share_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX files_fed_share_idx ON public.files USING btree (fed_share_id) WHERE (fed_share_id IS NOT NULL);


--
-- Name: files_unique_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX files_unique_name ON public.files USING btree (collection_id, name_hash) WHERE ((deleted_at IS NULL) AND (name_hash IS NOT NULL));


--
-- Name: idx_admin_audit_log_id_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_admin_audit_log_id_desc ON public.admin_audit_log USING btree (id DESC);


--
-- Name: idx_album_items_file; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_album_items_file ON public.album_items USING btree (file_id);


--
-- Name: idx_chat_attachment_ledger_cursor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_attachment_ledger_cursor ON public.chat_attachment_ledger_entities USING btree (user_id, cursor);


--
-- Name: idx_chat_attachment_ledger_history_cursor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_attachment_ledger_history_cursor ON public.chat_attachment_ledger_history USING btree (user_id, cursor);


--
-- Name: idx_chat_call_link_knocks_room; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_call_link_knocks_room ON public.chat_call_link_knocks USING btree (room_id, status, created_at);


--
-- Name: idx_chat_call_links_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_call_links_owner ON public.chat_call_links USING btree (owner_user_id, created_at DESC);


--
-- Name: idx_chat_joined_meetings_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_joined_meetings_user ON public.chat_joined_meetings USING btree (user_id, created_at DESC);


--
-- Name: idx_chat_media_federation_outbox_retry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_media_federation_outbox_retry ON public.chat_media_federation_outbox USING btree (state, next_attempt_at, destination, sequence);


--
-- Name: idx_chat_media_inbound_pending_recipient; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_media_inbound_pending_recipient ON public.chat_media_federation_inbound_pending USING btree (recipient_user_id);


--
-- Name: idx_chat_media_rate_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_media_rate_expiry ON public.chat_media_rate_counters USING btree (expires_at);


--
-- Name: idx_chat_media_references_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_media_references_user ON public.chat_media_references USING btree (user_id);


--
-- Name: idx_chat_media_uploads_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_media_uploads_updated ON public.chat_media_uploads USING btree (updated_at);


--
-- Name: idx_chat_media_uploads_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_media_uploads_user ON public.chat_media_uploads USING btree (user_id);


--
-- Name: idx_collections_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collections_deleted_at ON public.collections USING btree (deleted_at) WHERE (deleted_at IS NOT NULL);


--
-- Name: idx_collections_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collections_owner ON public.collections USING btree (owner_user_id);


--
-- Name: idx_collections_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collections_parent ON public.collections USING btree (parent_collection_id);


--
-- Name: idx_collections_trash_root; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collections_trash_root ON public.collections USING btree (trash_root_id) WHERE (trash_root_id IS NOT NULL);


--
-- Name: idx_contact_emails_user_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_contact_emails_user_address ON public.contact_emails USING btree (user_id, address text_pattern_ops);


--
-- Name: idx_contact_group_members_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_contact_group_members_group ON public.contact_group_members USING btree (group_id);


--
-- Name: idx_contact_groups_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_contact_groups_user ON public.contact_groups USING btree (user_id);


--
-- Name: idx_contacts_user_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_contacts_user_name ON public.contacts USING btree (user_id, lower(name), id);


--
-- Name: idx_files_collection; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_files_collection ON public.files USING btree (collection_id);


--
-- Name: idx_files_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_files_deleted_at ON public.files USING btree (deleted_at) WHERE (deleted_at IS NOT NULL);


--
-- Name: idx_files_trash_root; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_files_trash_root ON public.files USING btree (trash_root_id) WHERE (trash_root_id IS NOT NULL);


--
-- Name: idx_files_uploader; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_files_uploader ON public.files USING btree (uploader_user_id);


--
-- Name: idx_mail_address_keys_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_address_keys_address ON public.mail_address_keys USING btree (address_id);


--
-- Name: idx_mail_address_keys_one_primary; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mail_address_keys_one_primary ON public.mail_address_keys USING btree (address_id) WHERE is_primary;


--
-- Name: idx_mail_addresses_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_addresses_user ON public.mail_addresses USING btree (user_id);


--
-- Name: idx_mail_auto_reply_sent_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_auto_reply_sent_at ON public.mail_auto_reply_sent USING btree (sent_at);


--
-- Name: idx_mail_draft_attachments_message; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_draft_attachments_message ON public.mail_draft_attachments USING btree (message_id, created_at);


--
-- Name: idx_mail_filter_runs_one; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mail_filter_runs_one ON public.mail_filter_runs USING btree (user_id) WHERE (finished_at IS NULL);


--
-- Name: idx_mail_filters_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_filters_user ON public.mail_filters USING btree (user_id, "position") WHERE enabled;


--
-- Name: idx_mail_folders_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_folders_user ON public.mail_folders USING btree (user_id, parent_id, "position");


--
-- Name: idx_mail_group_key_shares_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_group_key_shares_user ON public.mail_group_key_shares USING btree (user_id);


--
-- Name: idx_mail_group_keys_primary; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mail_group_keys_primary ON public.mail_group_keys USING btree (group_id) WHERE is_primary;


--
-- Name: idx_mail_group_members_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_group_members_user ON public.mail_group_members USING btree (user_id);


--
-- Name: idx_mail_group_objects_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_group_objects_group ON public.mail_group_objects USING btree (group_id);


--
-- Name: idx_mail_labels_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_labels_user ON public.mail_labels USING btree (user_id, "position");


--
-- Name: idx_mail_message_labels_label; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_message_labels_label ON public.mail_message_labels USING btree (label_id);


--
-- Name: idx_mail_message_tombstones_age; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_message_tombstones_age ON public.mail_message_tombstones USING btree (deleted_at);


--
-- Name: idx_mail_messages_changes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_changes ON public.mail_messages USING btree (owner, change_xid, id);


--
-- Name: idx_mail_messages_custom_folder; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_custom_folder ON public.mail_messages USING btree (user_id, custom_folder, received_at DESC, id) WHERE (custom_folder IS NOT NULL);


--
-- Name: idx_mail_messages_folder; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_folder ON public.mail_messages USING btree (user_id, folder, received_at DESC, id);


--
-- Name: idx_mail_messages_inbound_once; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mail_messages_inbound_once ON public.mail_messages USING btree (address_id, message_id) WHERE ((direction = 'inbound'::text) AND (message_id IS NOT NULL));


--
-- Name: idx_mail_messages_message_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_message_id ON public.mail_messages USING btree (user_id, message_id) WHERE (message_id IS NOT NULL);


--
-- Name: idx_mail_messages_notify; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_notify ON public.mail_messages USING btree (owner, notify_at) WHERE (notify_at IS NOT NULL);


--
-- Name: idx_mail_messages_object_once; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mail_messages_object_once ON public.mail_messages USING btree (object_key) WHERE (key_packet IS NULL);


--
-- Name: idx_mail_messages_owner_folder; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_owner_folder ON public.mail_messages USING btree (owner, folder, received_at DESC, id);


--
-- Name: idx_mail_messages_owner_received; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_owner_received ON public.mail_messages USING btree (owner, received_at DESC, id DESC);


--
-- Name: idx_mail_messages_owner_thread; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_owner_thread ON public.mail_messages USING btree (owner, thread_id, received_at);


--
-- Name: idx_mail_messages_sender_recently; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_sender_recently ON public.mail_messages USING btree (sender_account, received_at) WHERE (external_recipients > 0);


--
-- Name: idx_mail_messages_sent_recently; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_sent_recently ON public.mail_messages USING btree (user_id, received_at) WHERE (external_recipients > 0);


--
-- Name: idx_mail_messages_shared_object; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_shared_object ON public.mail_messages USING btree (object_key) WHERE (key_packet IS NOT NULL);


--
-- Name: idx_mail_messages_thread; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_thread ON public.mail_messages USING btree (thread_id, received_at);


--
-- Name: idx_mail_messages_unwanted; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_unwanted ON public.mail_messages USING btree (owner, folder_changed_at) WHERE (folder = ANY (ARRAY['trash'::text, 'spam'::text]));


--
-- Name: idx_mail_sending_events_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_sending_events_user ON public.mail_sending_events USING btree (user_id, kind, created_at);


--
-- Name: idx_mail_sending_policies_attention; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_sending_policies_attention ON public.mail_sending_policies USING btree (updated_at) WHERE ((paused_at IS NOT NULL) OR (flagged_at IS NOT NULL));


--
-- Name: idx_public_shares_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_public_shares_token ON public.public_shares USING btree (token);


--
-- Name: idx_shares_collection; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shares_collection ON public.collection_shares USING btree (collection_id);


--
-- Name: idx_shares_recipient; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shares_recipient ON public.collection_shares USING btree (recipient_user_id);


--
-- Name: idx_uploads_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_uploads_updated_at ON public.uploads USING btree (updated_at);


--
-- Name: idx_uploads_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_uploads_user_id ON public.uploads USING btree (user_id);


--
-- Name: idx_users_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_username ON public.users USING btree (username);


--
-- Name: live_location_streams_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX live_location_streams_expires_idx ON public.live_location_streams USING btree (expires_at);


--
-- Name: mail_messages_expiring; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_messages_expiring ON public.mail_messages USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: mail_messages_snoozed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_messages_snoozed ON public.mail_messages USING btree (snoozed_until) WHERE (folder = 'snoozed'::text);


--
-- Name: mail_outbox_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_outbox_due ON public.mail_outbox USING btree (deliver_at) WHERE (state = 'pending'::text);


--
-- Name: mail_outbox_one_per_draft; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mail_outbox_one_per_draft ON public.mail_outbox USING btree (draft_id) WHERE (state = ANY (ARRAY['pending'::text, 'sending'::text]));


--
-- Name: pass_pin_failures_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX pass_pin_failures_user ON public.pass_pin_failures USING btree (user_id);


--
-- Name: pass_vault_secrets_file; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX pass_vault_secrets_file ON public.pass_vault_secrets USING btree (file_id);


--
-- Name: public_link_reports_open; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX public_link_reports_open ON public.public_link_reports USING btree (created_at) WHERE (resolved_at IS NULL);


--
-- Name: public_link_reports_share; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX public_link_reports_share ON public.public_link_reports USING btree (share_id);


--
-- Name: public_shares_file_target_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX public_shares_file_target_idx ON public.public_shares USING btree (target_id) WHERE (share_type = 'file'::text);


--
-- Name: user_devices_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_devices_active ON public.user_devices USING btree (user_id) WHERE is_active;


--
-- Name: chat_mls_authority_bootstrap_pages chat_mls_authority_bootstrap_pages_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER chat_mls_authority_bootstrap_pages_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_authority_bootstrap_pages FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();


--
-- Name: chat_mls_consensus_evidence chat_mls_consensus_evidence_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER chat_mls_consensus_evidence_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_consensus_evidence FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();


--
-- Name: chat_mls_control_blocks chat_mls_control_blocks_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER chat_mls_control_blocks_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_control_blocks FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();


--
-- Name: chat_mls_incarnation_recoveries chat_mls_incarnation_recoveries_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER chat_mls_incarnation_recoveries_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_incarnation_recoveries FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();


--
-- Name: chat_mls_invitation_feedback chat_mls_invitation_feedback_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER chat_mls_invitation_feedback_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_invitation_feedback FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();


--
-- Name: chat_mls_ordering_votes chat_mls_ordering_votes_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER chat_mls_ordering_votes_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_ordering_votes FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();


--
-- Name: chat_mls_owner_approvals chat_mls_owner_approvals_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER chat_mls_owner_approvals_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_owner_approvals FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();


--
-- Name: chat_mls_participant_bootstrap_pages chat_mls_participant_bootstrap_pages_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER chat_mls_participant_bootstrap_pages_append_only BEFORE DELETE OR UPDATE ON public.chat_mls_participant_bootstrap_pages FOR EACH ROW EXECUTE FUNCTION public.reject_chat_mls_append_only_mutation();


--
-- Name: collections collections_not_in_albums; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER collections_not_in_albums BEFORE INSERT OR UPDATE OF parent_collection_id ON public.collections FOR EACH ROW EXECUTE FUNCTION public.kutup_no_folders_in_albums();


--
-- Name: files files_not_in_albums; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER files_not_in_albums BEFORE INSERT OR UPDATE OF collection_id ON public.files FOR EACH ROW EXECUTE FUNCTION public.kutup_no_files_in_albums();


--
-- Name: mail_message_labels mail_message_labels_changed; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mail_message_labels_changed AFTER INSERT OR DELETE ON public.mail_message_labels FOR EACH ROW EXECUTE FUNCTION public.mail_message_labels_mark_change();


--
-- Name: mail_messages mail_messages_deleted; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mail_messages_deleted AFTER DELETE ON public.mail_messages FOR EACH ROW EXECUTE FUNCTION public.mail_messages_tombstone();


--
-- Name: mail_messages mail_messages_folder_changed; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mail_messages_folder_changed BEFORE UPDATE OF folder ON public.mail_messages FOR EACH ROW EXECUTE FUNCTION public.mail_messages_folder_changed();


--
-- Name: mail_messages mail_messages_inserted; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mail_messages_inserted BEFORE INSERT ON public.mail_messages FOR EACH ROW EXECUTE FUNCTION public.mail_messages_mark_change();


--
-- Name: mail_messages mail_messages_updated; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mail_messages_updated BEFORE UPDATE ON public.mail_messages FOR EACH ROW EXECUTE FUNCTION public.mail_messages_mark_change();


--
-- Name: album_items album_items_added_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.album_items
    ADD CONSTRAINT album_items_added_by_fkey FOREIGN KEY (added_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: album_items album_items_album_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.album_items
    ADD CONSTRAINT album_items_album_id_fkey FOREIGN KEY (album_id) REFERENCES public.collections(id) ON DELETE CASCADE;


--
-- Name: album_items album_items_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.album_items
    ADD CONSTRAINT album_items_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.files(id) ON DELETE CASCADE;


--
-- Name: auth_session_forks auth_session_forks_parent_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_session_forks
    ADD CONSTRAINT auth_session_forks_parent_session_id_fkey FOREIGN KEY (parent_session_id) REFERENCES public.auth_sessions(id) ON DELETE CASCADE;


--
-- Name: auth_sessions auth_sessions_parent_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_parent_session_id_fkey FOREIGN KEY (parent_session_id) REFERENCES public.auth_sessions(id) ON DELETE CASCADE;


--
-- Name: auth_sessions auth_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_anonymous_send_ids chat_anonymous_send_ids_recipient_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_anonymous_send_ids
    ADD CONSTRAINT chat_anonymous_send_ids_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_attachment_ledger_entities chat_attachment_ledger_entities_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_attachment_ledger_entities
    ADD CONSTRAINT chat_attachment_ledger_entities_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_attachment_ledger_history chat_attachment_ledger_history_user_id_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_attachment_ledger_history
    ADD CONSTRAINT chat_attachment_ledger_history_user_id_entity_id_fkey FOREIGN KEY (user_id, entity_id) REFERENCES public.chat_attachment_ledger_entities(user_id, entity_id) ON DELETE CASCADE;


--
-- Name: chat_attachment_ledger_history chat_attachment_ledger_history_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_attachment_ledger_history
    ADD CONSTRAINT chat_attachment_ledger_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_attachment_ledger_operations chat_attachment_ledger_operations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_attachment_ledger_operations
    ADD CONSTRAINT chat_attachment_ledger_operations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_backup_bases chat_backup_bases_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_bases
    ADD CONSTRAINT chat_backup_bases_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.chat_backups(user_id) ON DELETE CASCADE;


--
-- Name: chat_backup_device_heads chat_backup_device_heads_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_device_heads
    ADD CONSTRAINT chat_backup_device_heads_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.chat_backups(user_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_objects chat_backup_media_objects_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_objects
    ADD CONSTRAINT chat_backup_media_objects_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.chat_backups(user_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_operations chat_backup_media_operations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_operations
    ADD CONSTRAINT chat_backup_media_operations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.chat_backups(user_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_operations chat_backup_media_operations_user_id_media_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_operations
    ADD CONSTRAINT chat_backup_media_operations_user_id_media_id_fkey FOREIGN KEY (user_id, media_id) REFERENCES public.chat_backup_media_objects(user_id, media_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_reconciliation_entries chat_backup_media_reconciliation_entr_user_id_operation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliation_entries
    ADD CONSTRAINT chat_backup_media_reconciliation_entr_user_id_operation_id_fkey FOREIGN KEY (user_id, operation_id) REFERENCES public.chat_backup_media_reconciliations(user_id, operation_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_reconciliation_entries chat_backup_media_reconciliation_entries_user_id_media_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliation_entries
    ADD CONSTRAINT chat_backup_media_reconciliation_entries_user_id_media_id_fkey FOREIGN KEY (user_id, media_id) REFERENCES public.chat_backup_media_objects(user_id, media_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_reconciliation_pages chat_backup_media_reconciliation_page_user_id_operation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliation_pages
    ADD CONSTRAINT chat_backup_media_reconciliation_page_user_id_operation_id_fkey FOREIGN KEY (user_id, operation_id) REFERENCES public.chat_backup_media_reconciliations(user_id, operation_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_reconciliations chat_backup_media_reconciliations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliations
    ADD CONSTRAINT chat_backup_media_reconciliations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.chat_backups(user_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_references chat_backup_media_references_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_references
    ADD CONSTRAINT chat_backup_media_references_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.chat_backups(user_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_references chat_backup_media_references_user_id_media_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_references
    ADD CONSTRAINT chat_backup_media_references_user_id_media_id_fkey FOREIGN KEY (user_id, media_id) REFERENCES public.chat_backup_media_objects(user_id, media_id) ON DELETE CASCADE;


--
-- Name: chat_backup_provision_operations chat_backup_provision_operations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_provision_operations
    ADD CONSTRAINT chat_backup_provision_operations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_backup_segments chat_backup_segments_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_segments
    ADD CONSTRAINT chat_backup_segments_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.chat_backups(user_id) ON DELETE CASCADE;


--
-- Name: chat_backups chat_backups_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backups
    ADD CONSTRAINT chat_backups_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_call_link_knocks chat_call_link_knocks_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_link_knocks
    ADD CONSTRAINT chat_call_link_knocks_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.chat_call_links(room_id) ON DELETE CASCADE;


--
-- Name: chat_call_link_seats chat_call_link_seats_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_link_seats
    ADD CONSTRAINT chat_call_link_seats_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.chat_call_links(room_id) ON DELETE CASCADE;


--
-- Name: chat_call_links chat_call_links_owner_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_links
    ADD CONSTRAINT chat_call_links_owner_user_id_fkey FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_delivery_capabilities chat_delivery_capabilities_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_delivery_capabilities
    ADD CONSTRAINT chat_delivery_capabilities_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_device_manifest_history chat_device_manifest_history_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_device_manifest_history
    ADD CONSTRAINT chat_device_manifest_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_device_manifests chat_device_manifests_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_device_manifests
    ADD CONSTRAINT chat_device_manifests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_devices chat_devices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_devices
    ADD CONSTRAINT chat_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_federation_inbound_transactions chat_federation_inbound_transactions_origin_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_federation_inbound_transactions
    ADD CONSTRAINT chat_federation_inbound_transactions_origin_fkey FOREIGN KEY (origin) REFERENCES public.chat_federation_inbound_state(origin) ON DELETE CASCADE;


--
-- Name: chat_federation_outbox chat_federation_outbox_sender_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_federation_outbox
    ADD CONSTRAINT chat_federation_outbox_sender_user_id_fkey FOREIGN KEY (sender_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_invite_requests chat_invite_requests_link_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_invite_requests
    ADD CONSTRAINT chat_invite_requests_link_id_fkey FOREIGN KEY (link_id) REFERENCES public.chat_invite_links(link_id) ON DELETE CASCADE;


--
-- Name: chat_joined_meetings chat_joined_meetings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_joined_meetings
    ADD CONSTRAINT chat_joined_meetings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_mailbox chat_mailbox_recipient_user_id_recipient_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mailbox
    ADD CONSTRAINT chat_mailbox_recipient_user_id_recipient_device_id_fkey FOREIGN KEY (recipient_user_id, recipient_device_id) REFERENCES public.chat_devices(user_id, device_id) ON DELETE CASCADE;


--
-- Name: chat_media_federation_inbound_pending chat_media_federation_inbound_pending_recipient_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_inbound_pending
    ADD CONSTRAINT chat_media_federation_inbound_pending_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_media_federation_outbox chat_media_federation_outbox_origin_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_outbox
    ADD CONSTRAINT chat_media_federation_outbox_origin_user_id_fkey FOREIGN KEY (origin_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_media_federation_pull_grants chat_media_federation_pull_grants_attachment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_pull_grants
    ADD CONSTRAINT chat_media_federation_pull_grants_attachment_id_fkey FOREIGN KEY (attachment_id) REFERENCES public.chat_media_objects(attachment_id) ON DELETE CASCADE;


--
-- Name: chat_media_federation_pull_grants chat_media_federation_pull_grants_origin_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_pull_grants
    ADD CONSTRAINT chat_media_federation_pull_grants_origin_user_id_fkey FOREIGN KEY (origin_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_media_objects chat_media_objects_origin_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_objects
    ADD CONSTRAINT chat_media_objects_origin_user_id_fkey FOREIGN KEY (origin_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_media_origin_delivery_operations chat_media_origin_delivery_operations_attachment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_origin_delivery_operations
    ADD CONSTRAINT chat_media_origin_delivery_operations_attachment_id_fkey FOREIGN KEY (attachment_id) REFERENCES public.chat_media_objects(attachment_id) ON DELETE CASCADE;


--
-- Name: chat_media_origin_delivery_operations chat_media_origin_delivery_operations_origin_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_origin_delivery_operations
    ADD CONSTRAINT chat_media_origin_delivery_operations_origin_user_id_fkey FOREIGN KEY (origin_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_media_origin_delivery_operations chat_media_origin_delivery_operations_recipient_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_origin_delivery_operations
    ADD CONSTRAINT chat_media_origin_delivery_operations_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_media_references chat_media_references_attachment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_references
    ADD CONSTRAINT chat_media_references_attachment_id_fkey FOREIGN KEY (attachment_id) REFERENCES public.chat_media_objects(attachment_id) ON DELETE CASCADE;


--
-- Name: chat_media_references chat_media_references_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_references
    ADD CONSTRAINT chat_media_references_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_media_uploads chat_media_uploads_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_uploads
    ADD CONSTRAINT chat_media_uploads_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_mls_admin_audit_events chat_mls_admin_audit_events_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_admin_audit_events
    ADD CONSTRAINT chat_mls_admin_audit_events_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE SET NULL;


--
-- Name: chat_mls_anonymous_send_ids chat_mls_anonymous_send_ids_recipient_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_anonymous_send_ids
    ADD CONSTRAINT chat_mls_anonymous_send_ids_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_mls_authority_bootstrap_pages chat_mls_authority_bootstrap_pages_bootstrap_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_authority_bootstrap_pages
    ADD CONSTRAINT chat_mls_authority_bootstrap_pages_bootstrap_id_fkey FOREIGN KEY (bootstrap_id) REFERENCES public.chat_mls_authority_bootstraps(bootstrap_id) ON DELETE CASCADE;


--
-- Name: chat_mls_consensus_evidence chat_mls_consensus_evidence_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_consensus_evidence
    ADD CONSTRAINT chat_mls_consensus_evidence_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;


--
-- Name: chat_mls_control_blocks chat_mls_control_blocks_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_control_blocks
    ADD CONSTRAINT chat_mls_control_blocks_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_control_outbox chat_mls_control_outbox_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_control_outbox
    ADD CONSTRAINT chat_mls_control_outbox_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_conversations chat_mls_conversations_current_incarnation_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_conversations
    ADD CONSTRAINT chat_mls_conversations_current_incarnation_fk FOREIGN KEY (conversation_id, current_incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: chat_mls_delivery_capabilities chat_mls_delivery_capabilities_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_delivery_capabilities
    ADD CONSTRAINT chat_mls_delivery_capabilities_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;


--
-- Name: chat_mls_delivery_capabilities chat_mls_delivery_capabilities_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_delivery_capabilities
    ADD CONSTRAINT chat_mls_delivery_capabilities_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_delivery_capabilities chat_mls_delivery_capabilities_recipient_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_delivery_capabilities
    ADD CONSTRAINT chat_mls_delivery_capabilities_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_mls_devices chat_mls_devices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_devices
    ADD CONSTRAINT chat_mls_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_mls_federation_inbound_transactions chat_mls_federation_inbound_transactions_origin_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_federation_inbound_transactions
    ADD CONSTRAINT chat_mls_federation_inbound_transactions_origin_fkey FOREIGN KEY (origin) REFERENCES public.chat_mls_federation_inbound_state(origin) ON DELETE CASCADE;


--
-- Name: chat_mls_federation_outbox chat_mls_federation_outbox_sender_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_federation_outbox
    ADD CONSTRAINT chat_mls_federation_outbox_sender_user_id_fkey FOREIGN KEY (sender_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: chat_mls_incarnation_recoveries chat_mls_incarnation_recoveri_conversation_id_new_incarnat_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveri_conversation_id_new_incarnat_fkey FOREIGN KEY (conversation_id, new_incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_incarnation_recoveries chat_mls_incarnation_recoveri_conversation_id_previous_inc_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveri_conversation_id_previous_inc_fkey FOREIGN KEY (conversation_id, previous_incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_incarnation_recoveries chat_mls_incarnation_recoveries_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveries_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;


--
-- Name: chat_mls_incarnation_recoveries chat_mls_incarnation_recoveries_initiated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_incarnation_recoveries
    ADD CONSTRAINT chat_mls_incarnation_recoveries_initiated_by_fkey FOREIGN KEY (initiated_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: chat_mls_incarnations chat_mls_incarnations_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_incarnations
    ADD CONSTRAINT chat_mls_incarnations_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;


--
-- Name: chat_mls_invitation_feedback chat_mls_invitation_feedback_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_invitation_feedback
    ADD CONSTRAINT chat_mls_invitation_feedback_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_invitation_feedback_outbox chat_mls_invitation_feedback_o_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_invitation_feedback_outbox
    ADD CONSTRAINT chat_mls_invitation_feedback_o_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_key_packages chat_mls_key_packages_user_id_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_key_packages
    ADD CONSTRAINT chat_mls_key_packages_user_id_device_id_fkey FOREIGN KEY (user_id, device_id) REFERENCES public.chat_mls_devices(user_id, device_id) ON DELETE CASCADE;


--
-- Name: chat_mls_local_member_devices chat_mls_local_member_devices_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_local_member_devices
    ADD CONSTRAINT chat_mls_local_member_devices_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_local_member_devices chat_mls_local_member_devices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_local_member_devices
    ADD CONSTRAINT chat_mls_local_member_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_mls_local_members chat_mls_local_members_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_local_members
    ADD CONSTRAINT chat_mls_local_members_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_local_members chat_mls_local_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_local_members
    ADD CONSTRAINT chat_mls_local_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_mls_mailbox chat_mls_mailbox_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;


--
-- Name: chat_mls_mailbox chat_mls_mailbox_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_mailbox chat_mls_mailbox_recipient_user_id_recipient_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_recipient_user_id_recipient_device_id_fkey FOREIGN KEY (recipient_user_id, recipient_device_id) REFERENCES public.chat_mls_devices(user_id, device_id) ON DELETE CASCADE;


--
-- Name: chat_mls_mailbox chat_mls_mailbox_request_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.chat_mls_pending_requests(request_id) ON DELETE CASCADE;


--
-- Name: chat_mls_membership_deliveries chat_mls_membership_deliveries_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_membership_deliveries
    ADD CONSTRAINT chat_mls_membership_deliveries_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_membership_deliveries chat_mls_membership_deliveries_submitted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_membership_deliveries
    ADD CONSTRAINT chat_mls_membership_deliveries_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: chat_mls_ordering_votes chat_mls_ordering_votes_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_ordering_votes
    ADD CONSTRAINT chat_mls_ordering_votes_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_owner_approvals chat_mls_owner_approvals_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_owner_approvals
    ADD CONSTRAINT chat_mls_owner_approvals_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_participant_bootstrap_pages chat_mls_participant_bootstrap_pages_bootstrap_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_participant_bootstrap_pages
    ADD CONSTRAINT chat_mls_participant_bootstrap_pages_bootstrap_id_fkey FOREIGN KEY (bootstrap_id) REFERENCES public.chat_mls_participant_bootstraps(bootstrap_id) ON DELETE CASCADE;


--
-- Name: chat_mls_pending_requests chat_mls_pending_requests_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_pending_requests
    ADD CONSTRAINT chat_mls_pending_requests_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.chat_mls_conversations(conversation_id) ON DELETE CASCADE;


--
-- Name: chat_mls_pending_requests chat_mls_pending_requests_conversation_id_incarnation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_pending_requests
    ADD CONSTRAINT chat_mls_pending_requests_conversation_id_incarnation_fkey FOREIGN KEY (conversation_id, incarnation) REFERENCES public.chat_mls_incarnations(conversation_id, incarnation) ON DELETE CASCADE;


--
-- Name: chat_mls_pending_requests chat_mls_pending_requests_recipient_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_pending_requests
    ADD CONSTRAINT chat_mls_pending_requests_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_mls_recovery_outbox chat_mls_recovery_outbox_recovery_digest_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mls_recovery_outbox
    ADD CONSTRAINT chat_mls_recovery_outbox_recovery_digest_fkey FOREIGN KEY (recovery_digest) REFERENCES public.chat_mls_incarnation_recoveries(recovery_digest) ON DELETE CASCADE;


--
-- Name: chat_one_time_kyber_pre_keys chat_one_time_kyber_pre_keys_user_id_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_one_time_kyber_pre_keys
    ADD CONSTRAINT chat_one_time_kyber_pre_keys_user_id_device_id_fkey FOREIGN KEY (user_id, device_id) REFERENCES public.chat_devices(user_id, device_id) ON DELETE CASCADE;


--
-- Name: chat_one_time_pre_keys chat_one_time_pre_keys_user_id_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_one_time_pre_keys
    ADD CONSTRAINT chat_one_time_pre_keys_user_id_device_id_fkey FOREIGN KEY (user_id, device_id) REFERENCES public.chat_devices(user_id, device_id) ON DELETE CASCADE;


--
-- Name: chat_profiles chat_profiles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_profiles
    ADD CONSTRAINT chat_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_push_subscriptions chat_push_subscriptions_user_id_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_push_subscriptions
    ADD CONSTRAINT chat_push_subscriptions_user_id_device_id_fkey FOREIGN KEY (user_id, device_id) REFERENCES public.chat_devices(user_id, device_id) ON DELETE CASCADE;


--
-- Name: chat_sealed_federation_outbox chat_sealed_federation_outbox_sender_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sealed_federation_outbox
    ADD CONSTRAINT chat_sealed_federation_outbox_sender_user_id_fkey FOREIGN KEY (sender_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: chat_sends chat_sends_sender_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sends
    ADD CONSTRAINT chat_sends_sender_user_id_fkey FOREIGN KEY (sender_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: chat_ws_tickets chat_ws_tickets_user_id_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_ws_tickets
    ADD CONSTRAINT chat_ws_tickets_user_id_device_id_fkey FOREIGN KEY (user_id, device_id) REFERENCES public.chat_devices(user_id, device_id) ON DELETE CASCADE;


--
-- Name: collection_key_epoch_history collection_key_epoch_history_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_key_epoch_history
    ADD CONSTRAINT collection_key_epoch_history_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.collections(id) ON DELETE CASCADE;


--
-- Name: collection_shares collection_shares_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_shares
    ADD CONSTRAINT collection_shares_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.collections(id) ON DELETE CASCADE;


--
-- Name: collection_shares collection_shares_recipient_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_shares
    ADD CONSTRAINT collection_shares_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: collection_shares collection_shares_sharer_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collection_shares
    ADD CONSTRAINT collection_shares_sharer_user_id_fkey FOREIGN KEY (sharer_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: collections collections_owner_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collections
    ADD CONSTRAINT collections_owner_user_id_fkey FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: collections collections_parent_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collections
    ADD CONSTRAINT collections_parent_collection_id_fkey FOREIGN KEY (parent_collection_id) REFERENCES public.collections(id) ON DELETE SET NULL;


--
-- Name: contact_emails contact_emails_contact_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_emails
    ADD CONSTRAINT contact_emails_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.contacts(id) ON DELETE CASCADE;


--
-- Name: contact_emails contact_emails_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_emails
    ADD CONSTRAINT contact_emails_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: contact_group_members contact_group_members_contact_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_group_members
    ADD CONSTRAINT contact_group_members_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.contacts(id) ON DELETE CASCADE;


--
-- Name: contact_group_members contact_group_members_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_group_members
    ADD CONSTRAINT contact_group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.contact_groups(id) ON DELETE CASCADE;


--
-- Name: contact_groups contact_groups_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_groups
    ADD CONSTRAINT contact_groups_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: contacts contacts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts
    ADD CONSTRAINT contacts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: drive_federation_mutations drive_federation_mutations_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federation_mutations
    ADD CONSTRAINT drive_federation_mutations_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.federated_outgoing_shares(id) ON DELETE CASCADE;


--
-- Name: drive_profile_keys drive_profile_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_profile_keys
    ADD CONSTRAINT drive_profile_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: federated_incoming_file_shares federated_incoming_file_shares_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_incoming_file_shares
    ADD CONSTRAINT federated_incoming_file_shares_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: federated_incoming_shares federated_incoming_shares_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_incoming_shares
    ADD CONSTRAINT federated_incoming_shares_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: federated_outgoing_file_shares federated_outgoing_file_shares_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_outgoing_file_shares
    ADD CONSTRAINT federated_outgoing_file_shares_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.files(id) ON DELETE CASCADE;


--
-- Name: federated_outgoing_file_shares federated_outgoing_file_shares_sharer_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_outgoing_file_shares
    ADD CONSTRAINT federated_outgoing_file_shares_sharer_user_id_fkey FOREIGN KEY (sharer_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: federated_outgoing_shares federated_outgoing_shares_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_outgoing_shares
    ADD CONSTRAINT federated_outgoing_shares_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.collections(id) ON DELETE CASCADE;


--
-- Name: federated_outgoing_shares federated_outgoing_shares_sharer_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federated_outgoing_shares
    ADD CONSTRAINT federated_outgoing_shares_sharer_user_id_fkey FOREIGN KEY (sharer_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: federation_domain_rules federation_domain_rules_feature_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_domain_rules
    ADD CONSTRAINT federation_domain_rules_feature_fkey FOREIGN KEY (feature) REFERENCES public.federation_feature_policies(feature) ON DELETE CASCADE;


--
-- Name: federation_peer_identity_documents federation_peer_identity_documents_domain_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_identity_documents
    ADD CONSTRAINT federation_peer_identity_documents_domain_fkey FOREIGN KEY (domain) REFERENCES public.federation_peer_identities(domain) ON DELETE CASCADE;


--
-- Name: feedback feedback_resolved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback
    ADD CONSTRAINT feedback_resolved_by_fkey FOREIGN KEY (resolved_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: feedback feedback_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback
    ADD CONSTRAINT feedback_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: file_assets file_assets_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_assets
    ADD CONSTRAINT file_assets_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.files(id) ON DELETE CASCADE;


--
-- Name: file_assets file_assets_uploader_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_assets
    ADD CONSTRAINT file_assets_uploader_user_id_fkey FOREIGN KEY (uploader_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: file_key_history file_key_history_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_key_history
    ADD CONSTRAINT file_key_history_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.files(id) ON DELETE CASCADE;


--
-- Name: file_shares file_shares_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_shares
    ADD CONSTRAINT file_shares_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.files(id) ON DELETE CASCADE;


--
-- Name: file_shares file_shares_recipient_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_shares
    ADD CONSTRAINT file_shares_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: file_shares file_shares_sharer_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_shares
    ADD CONSTRAINT file_shares_sharer_user_id_fkey FOREIGN KEY (sharer_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: file_thumbnails file_thumbnails_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_thumbnails
    ADD CONSTRAINT file_thumbnails_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.files(id) ON DELETE CASCADE;


--
-- Name: file_thumbnails file_thumbnails_source_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_thumbnails
    ADD CONSTRAINT file_thumbnails_source_version_fkey FOREIGN KEY (source_version) REFERENCES public.file_versions(id) ON DELETE SET NULL;


--
-- Name: file_thumbnails file_thumbnails_uploader_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_thumbnails
    ADD CONSTRAINT file_thumbnails_uploader_user_id_fkey FOREIGN KEY (uploader_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: file_update_log file_update_log_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_update_log
    ADD CONSTRAINT file_update_log_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.files(id) ON DELETE CASCADE;


--
-- Name: file_update_log file_update_log_sender_device_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_update_log
    ADD CONSTRAINT file_update_log_sender_device_fkey FOREIGN KEY (sender_device) REFERENCES public.user_devices(id) ON DELETE SET NULL;


--
-- Name: file_versions file_versions_author_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_versions
    ADD CONSTRAINT file_versions_author_user_id_fkey FOREIGN KEY (author_user_id) REFERENCES public.users(id);


--
-- Name: file_versions file_versions_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_versions
    ADD CONSTRAINT file_versions_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.files(id) ON DELETE CASCADE;


--
-- Name: files files_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.files
    ADD CONSTRAINT files_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.collections(id) ON DELETE CASCADE;


--
-- Name: files files_fed_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.files
    ADD CONSTRAINT files_fed_share_id_fkey FOREIGN KEY (fed_share_id) REFERENCES public.federated_outgoing_shares(id) ON DELETE SET NULL;


--
-- Name: files files_uploader_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.files
    ADD CONSTRAINT files_uploader_user_id_fkey FOREIGN KEY (uploader_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: identity_pins identity_pins_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_pins
    ADD CONSTRAINT identity_pins_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_address_keys mail_address_keys_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_address_keys
    ADD CONSTRAINT mail_address_keys_address_id_fkey FOREIGN KEY (address_id) REFERENCES public.mail_addresses(id) ON DELETE CASCADE;


--
-- Name: mail_addresses mail_addresses_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_addresses
    ADD CONSTRAINT mail_addresses_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: mail_addresses mail_addresses_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_addresses
    ADD CONSTRAINT mail_addresses_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_auto_replies mail_auto_replies_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_auto_replies
    ADD CONSTRAINT mail_auto_replies_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_auto_reply_sent mail_auto_reply_sent_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_auto_reply_sent
    ADD CONSTRAINT mail_auto_reply_sent_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_draft_attachments mail_draft_attachments_message_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_draft_attachments
    ADD CONSTRAINT mail_draft_attachments_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.mail_messages(id) ON DELETE CASCADE;


--
-- Name: mail_draft_attachments mail_draft_attachments_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_draft_attachments
    ADD CONSTRAINT mail_draft_attachments_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_filter_runs mail_filter_runs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_filter_runs
    ADD CONSTRAINT mail_filter_runs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_filters mail_filters_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_filters
    ADD CONSTRAINT mail_filters_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_folders mail_folders_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_folders
    ADD CONSTRAINT mail_folders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_folders mail_folders_user_id_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_folders
    ADD CONSTRAINT mail_folders_user_id_parent_id_fkey FOREIGN KEY (user_id, parent_id) REFERENCES public.mail_folders(user_id, id) ON DELETE CASCADE;


--
-- Name: mail_group_key_lists mail_group_key_lists_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_key_lists
    ADD CONSTRAINT mail_group_key_lists_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: mail_group_key_shares mail_group_key_shares_group_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_key_shares
    ADD CONSTRAINT mail_group_key_shares_group_key_id_fkey FOREIGN KEY (group_key_id) REFERENCES public.mail_group_keys(id) ON DELETE CASCADE;


--
-- Name: mail_group_key_shares mail_group_key_shares_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_key_shares
    ADD CONSTRAINT mail_group_key_shares_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_group_keys mail_group_keys_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_keys
    ADD CONSTRAINT mail_group_keys_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: mail_group_members mail_group_members_added_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_members
    ADD CONSTRAINT mail_group_members_added_by_fkey FOREIGN KEY (added_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: mail_group_members mail_group_members_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_members
    ADD CONSTRAINT mail_group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: mail_group_members mail_group_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_members
    ADD CONSTRAINT mail_group_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_group_objects mail_group_objects_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_objects
    ADD CONSTRAINT mail_group_objects_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: mail_groups mail_groups_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_groups
    ADD CONSTRAINT mail_groups_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: mail_identities mail_identities_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_identities
    ADD CONSTRAINT mail_identities_address_id_fkey FOREIGN KEY (address_id) REFERENCES public.mail_addresses(id) ON DELETE CASCADE;


--
-- Name: mail_image_senders mail_image_senders_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_image_senders
    ADD CONSTRAINT mail_image_senders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_key_lists mail_key_lists_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_key_lists
    ADD CONSTRAINT mail_key_lists_address_id_fkey FOREIGN KEY (address_id) REFERENCES public.mail_addresses(id) ON DELETE CASCADE;


--
-- Name: mail_labels mail_labels_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_labels
    ADD CONSTRAINT mail_labels_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_message_labels mail_message_labels_label_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_message_labels
    ADD CONSTRAINT mail_message_labels_label_id_fkey FOREIGN KEY (label_id) REFERENCES public.mail_labels(id) ON DELETE CASCADE;


--
-- Name: mail_message_labels mail_message_labels_message_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_message_labels
    ADD CONSTRAINT mail_message_labels_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.mail_messages(id) ON DELETE CASCADE;


--
-- Name: mail_messages mail_messages_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_messages
    ADD CONSTRAINT mail_messages_address_id_fkey FOREIGN KEY (address_id) REFERENCES public.mail_addresses(id) ON DELETE CASCADE;


--
-- Name: mail_messages mail_messages_custom_folder_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_messages
    ADD CONSTRAINT mail_messages_custom_folder_fk FOREIGN KEY (user_id, custom_folder) REFERENCES public.mail_folders(user_id, id);


--
-- Name: mail_messages mail_messages_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_messages
    ADD CONSTRAINT mail_messages_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE SET NULL;


--
-- Name: mail_messages mail_messages_sent_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_messages
    ADD CONSTRAINT mail_messages_sent_by_fkey FOREIGN KEY (sent_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: mail_messages mail_messages_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_messages
    ADD CONSTRAINT mail_messages_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_outbox mail_outbox_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_outbox
    ADD CONSTRAINT mail_outbox_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_sender_rules mail_sender_rules_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sender_rules
    ADD CONSTRAINT mail_sender_rules_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_sending_events mail_sending_events_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sending_events
    ADD CONSTRAINT mail_sending_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_sending_policies mail_sending_policies_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sending_policies
    ADD CONSTRAINT mail_sending_policies_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mail_settings mail_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_settings
    ADD CONSTRAINT mail_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: pass_pin_failures pass_pin_failures_sign_in_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_pin_failures
    ADD CONSTRAINT pass_pin_failures_sign_in_id_fkey FOREIGN KEY (sign_in_id) REFERENCES public.auth_sessions(id) ON DELETE CASCADE;


--
-- Name: pass_pin_failures pass_pin_failures_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_pin_failures
    ADD CONSTRAINT pass_pin_failures_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: pass_pins pass_pins_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_pins
    ADD CONSTRAINT pass_pins_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: pass_settings pass_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_settings
    ADD CONSTRAINT pass_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: pass_vault_secrets pass_vault_secrets_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_vault_secrets
    ADD CONSTRAINT pass_vault_secrets_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.files(id) ON DELETE CASCADE;


--
-- Name: pass_vault_secrets pass_vault_secrets_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_vault_secrets
    ADD CONSTRAINT pass_vault_secrets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: photos_library_folders photos_library_folders_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_library_folders
    ADD CONSTRAINT photos_library_folders_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.collections(id) ON DELETE CASCADE;


--
-- Name: photos_library_folders photos_library_folders_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_library_folders
    ADD CONSTRAINT photos_library_folders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: photos_library photos_library_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_library
    ADD CONSTRAINT photos_library_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: photos_preferences photos_preferences_upload_folder_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_preferences
    ADD CONSTRAINT photos_preferences_upload_folder_id_fkey FOREIGN KEY (upload_folder_id) REFERENCES public.collections(id) ON DELETE SET NULL;


--
-- Name: photos_preferences photos_preferences_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_preferences
    ADD CONSTRAINT photos_preferences_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: public_link_reports public_link_reports_resolved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_link_reports
    ADD CONSTRAINT public_link_reports_resolved_by_fkey FOREIGN KEY (resolved_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: public_link_reports public_link_reports_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_link_reports
    ADD CONSTRAINT public_link_reports_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.public_shares(id) ON DELETE CASCADE;


--
-- Name: public_shares public_shares_owner_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_shares
    ADD CONSTRAINT public_shares_owner_user_id_fkey FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: uploads uploads_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.uploads
    ADD CONSTRAINT uploads_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.collections(id) ON DELETE CASCADE;


--
-- Name: uploads uploads_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.uploads
    ADD CONSTRAINT uploads_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_devices user_devices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_devices
    ADD CONSTRAINT user_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_map_preferences user_map_preferences_save_folder_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_map_preferences
    ADD CONSTRAINT user_map_preferences_save_folder_id_fkey FOREIGN KEY (save_folder_id) REFERENCES public.collections(id) ON DELETE SET NULL;


--
-- Name: user_map_preferences user_map_preferences_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_map_preferences
    ADD CONSTRAINT user_map_preferences_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_ui_preferences user_ui_preferences_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_ui_preferences
    ADD CONSTRAINT user_ui_preferences_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


--
-- PostgreSQL database dump
--


-- Dumped from database version 16.15
-- Dumped by pg_dump version 16.15


--
-- Data for Name: admin_audit_log; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: collections; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federated_outgoing_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: files; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: album_items; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: auth_sessions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: auth_session_forks; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_anonymous_rate_counters; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_anonymous_send_ids; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_attachment_ledger_entities; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_attachment_ledger_history; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_attachment_ledger_operations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_backups; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_backup_bases; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_backup_device_heads; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_backup_media_objects; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_backup_media_operations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_backup_media_reconciliations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_backup_media_reconciliation_entries; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_backup_media_reconciliation_pages; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_backup_media_references; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_backup_provision_operations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_backup_segments; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_call_links; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_call_link_knocks; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_call_link_seats; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_delivery_capabilities; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_device_manifest_history; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_device_manifests; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_devices; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_federation_inbound_state; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_federation_inbound_transactions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_federation_outbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_federation_sequences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_invite_links; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_invite_requests; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_joined_meetings; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mailbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_federation_inbound_pending; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_federation_inbound_state; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_federation_inbound_transactions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_federation_outbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_objects; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_federation_pull_grants; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_federation_sequences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_origin_delivery_operations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_rate_counters; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_references; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_uploads; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_conversations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_admin_audit_events; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_anonymous_send_ids; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_authority_bootstraps; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_authority_bootstrap_pages; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_consensus_evidence; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_incarnations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_control_blocks; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_control_outbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_delivery_capabilities; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_devices; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_federation_inbound_state; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_federation_inbound_transactions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_federation_outbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_federation_sequences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_incarnation_recoveries; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_invitation_feedback; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_invitation_feedback_outbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_key_packages; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_local_member_devices; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_local_members; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_pending_requests; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_mailbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_membership_deliveries; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_ordering_votes; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_owner_approvals; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_participant_bootstraps; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_participant_bootstrap_pages; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_rate_counters; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mls_recovery_outbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_one_time_kyber_pre_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_one_time_pre_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_profiles; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_push_subscriptions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_sealed_federation_inbound; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_sealed_federation_outbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_sealed_federation_sequences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_sends; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_web_push_key; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_ws_tickets; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: collection_key_epoch_history; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: collection_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: contacts; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: contact_emails; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: contact_groups; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: contact_group_members; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_federation_mutations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_profile_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federated_incoming_file_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federated_incoming_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federated_outgoing_file_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_feature_policies; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.federation_feature_policies VALUES ('chat', 'allowlist', 'verified', '2026-10-13 09:46:43.4884+00');
INSERT INTO public.federation_feature_policies VALUES ('drive', 'allowlist', 'verified', '2026-10-13 09:46:43.4884+00');


--
-- Data for Name: federation_domain_rules; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_feature_policy_documents; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_feature_policy_failures; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_local_identity_documents; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_peer_identities; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_peer_identity_documents; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_policy; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.federation_policy VALUES (true, true, '2026-10-13 09:46:43.487182+00');


--
-- Data for Name: federation_request_replays; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: feedback; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: file_assets; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: file_key_history; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: file_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: file_versions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: file_thumbnails; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: user_devices; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: file_update_log; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: identity_pins; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: live_location_streams; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_groups; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_addresses; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_address_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_auto_replies; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_auto_reply_sent; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_change_floors; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_folders; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_messages; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_draft_attachments; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_filter_runs; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_filters; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_group_key_lists; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_group_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_group_key_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_group_members; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_group_objects; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_identities; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_image_senders; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_key_lists; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_labels; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_message_labels; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_message_tombstones; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_outbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_sender_rules; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_sending_events; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_sending_policies; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_settings; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: pass_pin_failures; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: pass_pins; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: pass_settings; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: pass_vault_secrets; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: photos_library; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: photos_library_folders; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: photos_preferences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: public_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: public_link_reports; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: sealed_sender_generated_certificates; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: server_generated_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: site_settings; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.site_settings VALUES ('registration_enabled', 'true');


--
-- Data for Name: uploads; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: user_map_preferences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: user_ui_preferences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Name: admin_audit_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.admin_audit_log_id_seq', 1, false);


--
-- Name: chat_attachment_ledger_cursor_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.chat_attachment_ledger_cursor_seq', 1, false);


--
-- Name: chat_mailbox_cursor_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.chat_mailbox_cursor_seq', 1, false);


--
-- Name: chat_mls_mailbox_cursor_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.chat_mls_mailbox_cursor_seq', 1, false);


--
-- Name: mail_sending_events_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.mail_sending_events_id_seq', 1, false);


--
-- Name: user_devices_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.user_devices_id_seq', 1, false);


--
-- PostgreSQL database dump complete
--


