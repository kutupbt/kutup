-- The wipe-2 baseline: the whole migration chain squashed, proven equal to
-- the chain at the squash commit by scripts/check-migration-baseline.sh, then
-- edited in place before anything applied it (docs/plans/w7-schema.md). Never
-- edit once applied: a change is then a new timestamped migration
-- (docs/contributing.md).
--
-- Refuses a database that already holds tables: an old chain's (`users`) or
-- this one's (`accounts`).
DO $$ BEGIN
  IF to_regclass('public.users') IS NOT NULL OR to_regclass('public.accounts') IS NOT NULL THEN
    RAISE EXCEPTION 'this database predates the baseline: start from an empty one';
  END IF;
END $$;

SET check_function_bodies = false;

--
-- PostgreSQL database dump
--


-- Dumped from database version 16.16
-- Dumped by pg_dump version 16.16


--
-- Name: account_keys; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA account_keys;


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: client_type; Type: DOMAIN; Schema: public; Owner: -
--

CREATE DOMAIN public.client_type AS text
	CONSTRAINT client_type_check CHECK ((VALUE = ANY (ARRAY['web-account'::text, 'web-drive'::text, 'web-chat'::text, 'web-maps'::text, 'web-photos'::text, 'web-office'::text, 'web-contacts'::text, 'web-mail'::text, 'web-pass'::text, 'web-calendar'::text, 'cli'::text, 'mail-bridge'::text])));


--
-- Name: drive_collection_kind; Type: DOMAIN; Schema: public; Owner: -
--

CREATE DOMAIN public.drive_collection_kind AS text
	CONSTRAINT drive_collection_kind_check CHECK ((VALUE = ANY (ARRAY['folder'::text, 'album'::text])));


--
-- Name: federation_rule_action; Type: DOMAIN; Schema: public; Owner: -
--

CREATE DOMAIN public.federation_rule_action AS text
	CONSTRAINT federation_rule_action_check CHECK ((VALUE = ANY (ARRAY['inherit'::text, 'allow'::text, 'block'::text])));


--
-- Name: match_mode; Type: DOMAIN; Schema: public; Owner: -
--

CREATE DOMAIN public.match_mode AS text
	CONSTRAINT match_mode_check CHECK ((VALUE = ANY (ARRAY['all'::text, 'any'::text])));


--
-- Name: suspended_reason; Type: DOMAIN; Schema: public; Owner: -
--

CREATE DOMAIN public.suspended_reason AS text
	CONSTRAINT suspended_reason_check CHECK ((VALUE = ANY (ARRAY['admin'::text, 'operatorOrder'::text, 'security'::text])));


--
-- Name: account_security_events_count_step(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.account_security_events_count_step() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.count <> OLD.count + 1 THEN
        RAISE EXCEPTION 'a security event''s count grows by one at a time';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: kutup_account_federates(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.kutup_account_federates(account uuid) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    -- The account's own switch (an entitlement), else the site's default.
    SELECT EXISTS (SELECT 1 FROM accounts WHERE id = account)
       AND COALESCE(
             (SELECT value = 1 FROM account_entitlements
               WHERE account_id = account AND key = 'server.federation'),
             (SELECT value <> 'off' FROM site_settings WHERE key = 'server.federation_default'),
             true)
$$;


--
-- Name: kutup_account_held(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.kutup_account_held(account uuid) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT EXISTS (SELECT 1 FROM accounts WHERE id = account AND legal_hold_reference IS NOT NULL)
$$;


--
-- Name: kutup_address_folded(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.kutup_address_folded(address text) RETURNS text
    LANGUAGE sql STABLE
    AS $$
    SELECT CASE
        WHEN EXISTS (SELECT 1 FROM mail_domains
                      WHERE name = lower(split_part(address, '@', 2)) AND state IN (1, 2))
        THEN lower(address)
        ELSE kutup_fold(split_part(address, '@', 1)) || '@' || lower(split_part(address, '@', 2))
    END
$$;


--
-- Name: kutup_b64(bytea); Type: FUNCTION; Schema: public; Owner: -
--

-- Bytes out as standard padded base64 on one line (encode() breaks lines
-- every 76 characters): the API's form of a bytea column (w7-schema.md §2).
CREATE FUNCTION public.kutup_b64(value bytea) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $$ SELECT translate(encode(value, 'base64'), E'\n', '') $$;


--
-- Name: kutup_unb64(text); Type: FUNCTION; Schema: public; Owner: -
--

-- Standard padded base64 in, bytes out; anything else (whitespace, the URL
-- alphabet, missing padding, non-zero trailing bits) is refused with
-- SQLSTATE 22023, which the server answers as a client error.
CREATE FUNCTION public.kutup_unb64(value text) RETURNS bytea
    LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
    AS $$
DECLARE
  bytes bytea;
BEGIN
  IF value !~ '^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$' THEN
    RAISE EXCEPTION 'kutup_unb64: not canonical base64' USING ERRCODE = '22023';
  END IF;
  bytes := decode(value, 'base64');
  IF public.kutup_b64(bytes) <> value THEN
    RAISE EXCEPTION 'kutup_unb64: not canonical base64' USING ERRCODE = '22023';
  END IF;
  RETURN bytes;
END
$$;


--
-- Name: kutup_fold(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.kutup_fold(name text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ._-'::text, 'abcdefghijklmnopqrstuvwxyz'::text);




--
-- Name: account_names; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_names (
    folded text NOT NULL,
    name text NOT NULL,
    account_id uuid,
    incarnation_id bytea,
    state text NOT NULL,
    receive_until timestamp with time zone,
    free_at timestamp with time zone,
    CONSTRAINT account_names_check CHECK (((state = 'held'::text) = (free_at IS NOT NULL))),
    CONSTRAINT account_names_check1 CHECK (((state = 'held'::text) OR (account_id IS NOT NULL))),
    CONSTRAINT account_names_folded_check CHECK ((folded ~ '^[a-z0-9]{1,32}$'::text)),
    CONSTRAINT account_names_name_check CHECK ((name ~ '^[a-z0-9_-]{3,32}$'::text)),
    CONSTRAINT account_names_state_check CHECK ((state = ANY (ARRAY['current'::text, 'held'::text]))),
    CONSTRAINT account_names_incarnation_id_bytes CHECK ((octet_length(incarnation_id) = 32))
);


--
-- Name: kutup_current_account(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.kutup_current_account(typed text) RETURNS uuid
    LANGUAGE sql STABLE STRICT PARALLEL SAFE
    RETURN (SELECT n.account_id FROM public.account_names n WHERE ((n.folded = public.kutup_fold(kutup_current_account.typed)) AND (n.state = 'current'::text)));


--
-- Name: kutup_no_files_in_albums(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.kutup_no_files_in_albums() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM drive_collections WHERE id = NEW.collection_id AND kind = 'album') THEN
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
        SELECT 1 FROM drive_collections WHERE id = NEW.parent_collection_id AND kind = 'album'
    ) THEN
        RAISE EXCEPTION 'albums hold no folders' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: kutup_target_blocked(text, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.kutup_target_blocked(kind text, target uuid) RETURNS text
    LANGUAGE sql STABLE
    AS $$
    SELECT b.blocked_reason FROM drive_public_shares b
     WHERE b.blocked_at IS NOT NULL
       AND (b.target_id = target
            OR (kind = 'file' AND b.share_type = 'collection'
                AND b.target_id = (SELECT f.collection_id FROM drive_files f WHERE f.id = target)))
     ORDER BY (b.blocked_reason = 'legalOrder') DESC, b.blocked_at
     LIMIT 1
$$;


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
    IF OLD.mailbox_owner = OLD.account_id THEN
        INSERT INTO mail_message_tombstones (mailbox_owner, id, received_at, change_xid)
        VALUES (OLD.mailbox_owner, OLD.id, OLD.received_at, pg_current_xact_id()::text::bigint)
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NULL;
END
$$;


--
-- Name: organization_after_member_gone(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.organization_after_member_gone() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    heir uuid;
BEGIN
    IF OLD.role <> 'owner' OR EXISTS (
        SELECT 1 FROM organization_members
         WHERE organization_id = OLD.organization_id AND role = 'owner'
    ) THEN
        RETURN NULL;
    END IF;
    SELECT account_id INTO heir FROM organization_members
     WHERE organization_id = OLD.organization_id AND state = 1
     ORDER BY role = 'admin' DESC, joined_at NULLS LAST, account_id
     LIMIT 1;
    IF heir IS NOT NULL THEN
        UPDATE organization_members SET role = 'owner'
         WHERE organization_id = OLD.organization_id AND account_id = heir;
    ELSIF NOT EXISTS (SELECT 1 FROM organization_members
                       WHERE organization_id = OLD.organization_id) THEN
        DELETE FROM organizations WHERE id = OLD.organization_id;
    END IF;
    RETURN NULL;
END $$;


--
-- Name: account_data_keys; Type: TABLE; Schema: account_keys; Owner: -
--

CREATE TABLE account_keys.account_data_keys (
    account_id uuid NOT NULL,
    sealing_key_id smallint NOT NULL,
    generation integer NOT NULL,
    wrapped bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_data_keys_generation_check CHECK ((generation >= 1)),
    CONSTRAINT account_data_keys_sealing_key_id_check CHECK ((sealing_key_id >= 1)),
    CONSTRAINT account_data_keys_wrapped_check CHECK ((octet_length(wrapped) = 86))
);


--
-- Name: destruction_events; Type: TABLE; Schema: account_keys; Owner: -
--

CREATE TABLE account_keys.destruction_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    at timestamp with time zone DEFAULT now() NOT NULL,
    category text NOT NULL,
    subject_key_ids integer[],
    subjects bytea[],
    method text NOT NULL,
    actor text NOT NULL,
    reference text NOT NULL,
    count integer DEFAULT 1 NOT NULL,
    CONSTRAINT destruction_events_actor_check CHECK ((actor = ANY (ARRAY['user'::text, 'admin'::text, 'job'::text]))),
    CONSTRAINT destruction_events_category_check CHECK ((category = ANY (ARRAY['account'::text, 'securityEvents'::text, 'adminAudit'::text, 'sessions'::text, 'destructionEvents'::text]))),
    CONSTRAINT destruction_events_check CHECK (((subjects IS NULL) = (subject_key_ids IS NULL))),
    CONSTRAINT destruction_events_check1 CHECK (((subjects IS NULL) OR ((cardinality(subjects) >= 1) AND (cardinality(subjects) = cardinality(subject_key_ids))))),
    CONSTRAINT destruction_events_count_check CHECK ((count >= 1)),
    CONSTRAINT destruction_events_method_check CHECK ((method = ANY (ARRAY['cryptoShred'::text, 'delete'::text, 'anonymise'::text]))),
    CONSTRAINT destruction_events_reference_check CHECK (((char_length(reference) >= 1) AND (char_length(reference) <= 100)))
);


--
-- Name: mail_group_data_keys; Type: TABLE; Schema: account_keys; Owner: -
--

CREATE TABLE account_keys.mail_group_data_keys (
    group_id uuid NOT NULL,
    sealing_key_id smallint NOT NULL,
    generation integer NOT NULL,
    wrapped bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_group_data_keys_generation_check CHECK ((generation >= 1)),
    CONSTRAINT mail_group_data_keys_sealing_key_id_check CHECK ((sealing_key_id >= 1)),
    CONSTRAINT mail_group_data_keys_wrapped_check CHECK ((octet_length(wrapped) = 86))
);


--
-- Name: account_heads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_heads (
    account_id uuid NOT NULL,
    sequence bigint NOT NULL,
    sealed bytea NOT NULL,
    incarnation_id bytea NOT NULL,
    written_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_heads_sealed_check CHECK (((octet_length(sealed) >= 1) AND (octet_length(sealed) <= 16384))),
    CONSTRAINT account_heads_sequence_check CHECK ((sequence >= 1)),
    CONSTRAINT account_heads_incarnation_id_bytes CHECK ((octet_length(incarnation_id) = 32))
);


--
-- Name: account_record_feeds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_record_feeds (
    account_id uuid NOT NULL,
    change_seq bigint DEFAULT 0 NOT NULL,
    floor_seq bigint DEFAULT 0 NOT NULL,
    CONSTRAINT account_record_feeds_change_seq_check CHECK ((change_seq >= 0)),
    CONSTRAINT account_record_feeds_check CHECK (((floor_seq >= 0) AND (floor_seq <= change_seq)))
);


--
-- Name: account_record_tombstones; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_record_tombstones (
    account_id uuid NOT NULL,
    scope smallint NOT NULL,
    record_id text NOT NULL,
    change_seq bigint NOT NULL,
    deleted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_record_tombstones_change_seq_check CHECK ((change_seq >= 1)),
    CONSTRAINT account_record_tombstones_record_id_check CHECK (((octet_length(record_id) >= 1) AND (octet_length(record_id) <= 64))),
    CONSTRAINT account_record_tombstones_scope_check CHECK (((scope >= 1) AND (scope <= 255)))
);


--
-- Name: account_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_records (
    account_id uuid NOT NULL,
    scope smallint NOT NULL,
    record_id text NOT NULL,
    revision bigint NOT NULL,
    envelope bytea NOT NULL,
    change_seq bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_records_change_seq_check CHECK ((change_seq >= 1)),
    CONSTRAINT account_records_envelope_check CHECK (((octet_length(envelope) >= 1) AND (octet_length(envelope) <= 4325376))),
    CONSTRAINT account_records_record_id_check CHECK (((octet_length(record_id) >= 1) AND (octet_length(record_id) <= 64))),
    CONSTRAINT account_records_revision_check CHECK ((revision >= 1)),
    CONSTRAINT account_records_scope_check CHECK (((scope >= 1) AND (scope <= 255)))
);


--
-- Name: account_renames; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_renames (
    incarnation_id bytea NOT NULL,
    sequence integer NOT NULL,
    account_id uuid,
    authority_public_key bytea NOT NULL,
    previous text NOT NULL,
    current text NOT NULL,
    counted boolean NOT NULL,
    statement jsonb NOT NULL,
    digest bytea NOT NULL,
    accepted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_renames_sequence_check CHECK (((sequence >= 1) AND (sequence <= 1000))),
    CONSTRAINT account_renames_digest_bytes CHECK ((octet_length(digest) = 32)),
    CONSTRAINT account_renames_incarnation_id_bytes CHECK ((octet_length(incarnation_id) = 32))
);


--
-- Name: account_roots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_roots (
    account_id uuid NOT NULL,
    purpose smallint NOT NULL,
    object bytea NOT NULL,
    envelope bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_roots_object_check CHECK ((octet_length(object) = 4)),
    CONSTRAINT account_roots_purpose_check CHECK (((purpose)::integer = ANY (ARRAY[3, 4, 5, 10, 19, 20])))
);


--
-- Name: account_security_events; Type: TABLE; Schema: public; Owner: -
--

-- One shape with admin_audit_log (w7-schema.md §6), unchained (pruned per
-- kind): chain_version 0, no hashes. The kinds, who may act for each and
-- their payload keys are src/security_events.rs's kind table.
CREATE TABLE public.account_security_events (
    id uuid NOT NULL,
    kind text NOT NULL,
    actor_kind text NOT NULL,
    actor_account_id uuid,
    subject_account_id uuid NOT NULL,
    at timestamp with time zone DEFAULT now() NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    count integer DEFAULT 1 NOT NULL,
    chain_version smallint NOT NULL,
    previous_hash bytea,
    row_hash bytea,
    CONSTRAINT account_security_events_actor_kind_check CHECK ((actor_kind = ANY (ARRAY['account'::text, 'admin'::text, 'job'::text, 'peer'::text]))),
    CONSTRAINT account_security_events_chain_check CHECK ((((chain_version = 0) AND (previous_hash IS NULL) AND (row_hash IS NULL)) OR ((chain_version >= 1) AND (octet_length(previous_hash) = 32) AND (octet_length(row_hash) = 32)))),
    CONSTRAINT account_security_events_chain_version_check CHECK ((chain_version = 0)),
    CONSTRAINT account_security_events_count_check CHECK ((count >= 1)),
    CONSTRAINT account_security_events_payload_check CHECK ((jsonb_typeof(payload) = 'object'::text))
);


--
-- Name: admin_audit_anchor; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_audit_anchor (
    only_row boolean DEFAULT true NOT NULL,
    through_id bigint NOT NULL,
    through_hash bytea NOT NULL,
    CONSTRAINT admin_audit_anchor_only_row_check CHECK (only_row),
    CONSTRAINT admin_audit_anchor_through_hash_check CHECK ((octet_length(through_hash) = 32))
);


--
-- Name: admin_audit_log; Type: TABLE; Schema: public; Owner: -
--

-- One shape with account_security_events (w7-schema.md §6). One hash chain
-- (src/audit_log.rs): the first row's previous_hash is 32 zero bytes, so
-- every row has both hashes; kind is AdminAction's string.
CREATE TABLE public.admin_audit_log (
    id bigint NOT NULL,
    kind text NOT NULL,
    actor_kind text NOT NULL,
    actor_account_id uuid,
    subject_account_id uuid,
    at timestamp with time zone DEFAULT now() NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    count integer DEFAULT 1 NOT NULL,
    chain_version smallint NOT NULL,
    previous_hash bytea,
    row_hash bytea,
    CONSTRAINT admin_audit_log_actor_check CHECK (((actor_kind = 'admin'::text) = (actor_account_id IS NOT NULL))),
    CONSTRAINT admin_audit_log_actor_kind_check CHECK ((actor_kind = ANY (ARRAY['admin'::text, 'job'::text]))),
    CONSTRAINT admin_audit_log_chain_check CHECK ((((chain_version = 0) AND (previous_hash IS NULL) AND (row_hash IS NULL)) OR ((chain_version >= 1) AND (octet_length(previous_hash) = 32) AND (octet_length(row_hash) = 32)))),
    CONSTRAINT admin_audit_log_chain_version_check CHECK ((chain_version >= 1)),
    CONSTRAINT admin_audit_log_count_check CHECK ((count = 1)),
    CONSTRAINT admin_audit_log_payload_check CHECK ((jsonb_typeof(payload) = 'object'::text))
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
-- Name: photos_album_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.photos_album_items (
    album_id uuid NOT NULL,
    file_id uuid NOT NULL,
    file_key_envelope bytea NOT NULL,
    key_generation integer NOT NULL,
    album_epoch integer NOT NULL,
    added_by_account_id uuid,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT photos_album_items_album_epoch_check CHECK ((album_epoch > 0)),
    CONSTRAINT photos_album_items_key_generation_check CHECK ((key_generation > 0))
);


--
-- Name: auth_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_grants (
    token_hash bytea NOT NULL,
    account_id uuid NOT NULL,
    purpose text NOT NULL,
    session_id uuid,
    target_account_id uuid,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    CONSTRAINT auth_grants_check CHECK (((target_account_id IS NULL) OR (purpose = 'adminReset'::text))),
    CONSTRAINT auth_grants_check1 CHECK (((purpose = ANY (ARRAY['recovery'::text, 'keep'::text])) = (session_id IS NULL))),
    CONSTRAINT auth_grants_purpose_check CHECK ((purpose = ANY (ARRAY['pass'::text, 'passwordChange'::text, 'totp'::text, 'adminReset'::text, 'recovery'::text, 'rotate'::text, 'rename'::text, 'close'::text, 'keep'::text, 'masterKeyRotation'::text]))),
    CONSTRAINT auth_grants_token_hash_check CHECK ((octet_length(token_hash) = 32))
);


--
-- Name: auth_session_forks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_session_forks (
    selector_hash bytea NOT NULL,
    parent_session_id uuid NOT NULL,
    child_client_type public.client_type NOT NULL,
    payload bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT auth_session_forks_child_client_type_check CHECK (((child_client_type)::text <> ALL (ARRAY['web-account'::text, 'cli'::text, 'mail-bridge'::text]))),
    CONSTRAINT auth_session_forks_payload_check CHECK (((octet_length(payload) >= 1) AND (octet_length(payload) <= 16384))),
    CONSTRAINT auth_session_forks_selector_hash_check CHECK ((octet_length(selector_hash) = 32))
);


--
-- Name: auth_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_sessions (
    id uuid NOT NULL,
    account_id uuid NOT NULL,
    client_type public.client_type NOT NULL,
    parent_session_id uuid,
    refresh_token_hash bytea NOT NULL,
    previous_refresh_token_hash bytea,
    rotated_at timestamp with time zone,
    local_key bytea,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    client_sealed bytea,
    CONSTRAINT auth_sessions_check CHECK (((parent_session_id IS NULL) OR ((client_type)::text <> ALL (ARRAY['web-account'::text, 'cli'::text, 'mail-bridge'::text])))),
    CONSTRAINT auth_sessions_client_sealed_check CHECK (((client_sealed IS NULL) OR ((octet_length(client_sealed) >= 47) AND (octet_length(client_sealed) <= 512)))),
    CONSTRAINT auth_sessions_local_key_check CHECK ((octet_length(local_key) = 32)),
    CONSTRAINT auth_sessions_previous_refresh_token_hash_check CHECK ((octet_length(previous_refresh_token_hash) = 32)),
    CONSTRAINT auth_sessions_refresh_token_hash_check CHECK ((octet_length(refresh_token_hash) = 32))
);


--
-- Name: backup_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.backup_runs (
    kind text NOT NULL,
    name text NOT NULL,
    size_bytes bigint NOT NULL,
    finished_at timestamp with time zone NOT NULL,
    CONSTRAINT backup_runs_kind_check CHECK ((kind = ANY (ARRAY['database'::text, 'mail'::text]))),
    CONSTRAINT backup_runs_size_bytes_check CHECK ((size_bytes >= 0))
);


--
-- Name: calendar_alarm_recomputes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_alarm_recomputes (
    account_id uuid NOT NULL,
    calendar_id uuid NOT NULL,
    after_event uuid,
    requested_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: calendar_alarms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_alarms (
    account_id uuid NOT NULL,
    event_id uuid NOT NULL,
    reminder smallint NOT NULL,
    action text NOT NULL,
    occurrence_start timestamp with time zone NOT NULL,
    fire_at timestamp with time zone NOT NULL,
    CONSTRAINT calendar_alarms_action_check CHECK ((action = ANY (ARRAY['device'::text, 'email'::text]))),
    CONSTRAINT calendar_alarms_reminder_check CHECK ((reminder >= 0))
);


--
-- Name: calendar_event_reminders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_event_reminders (
    event_id uuid NOT NULL,
    account_id uuid NOT NULL,
    reminders jsonb NOT NULL,
    CONSTRAINT calendar_event_reminders_reminders_check CHECK ((jsonb_typeof(reminders) = 'array'::text))
);


--
-- Name: calendar_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    calendar_id uuid NOT NULL,
    shared_event_id uuid NOT NULL,
    shared_key_packet bytea NOT NULL,
    calendar_key_packet bytea NOT NULL,
    calendar_signed text NOT NULL,
    calendar_signed_signature text NOT NULL,
    calendar_encrypted bytea,
    calendar_encrypted_signature text,
    revision bigint NOT NULL,
    bytes bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    modified_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT calendar_events_bytes_check CHECK ((bytes >= 0)),
    CONSTRAINT calendar_events_calendar_encrypted_check CHECK (((octet_length(calendar_encrypted) >= 1) AND (octet_length(calendar_encrypted) <= 262144))),
    CONSTRAINT calendar_events_calendar_encrypted_signature_check CHECK (((octet_length(calendar_encrypted_signature) >= 1) AND (octet_length(calendar_encrypted_signature) <= 4096))),
    CONSTRAINT calendar_events_calendar_key_packet_check CHECK (((octet_length(calendar_key_packet) >= 1) AND (octet_length(calendar_key_packet) <= 1024))),
    CONSTRAINT calendar_events_calendar_signed_check CHECK (((octet_length(calendar_signed) >= 1) AND (octet_length(calendar_signed) <= 65536))),
    CONSTRAINT calendar_events_calendar_signed_signature_check CHECK (((octet_length(calendar_signed_signature) >= 1) AND (octet_length(calendar_signed_signature) <= 4096))),
    CONSTRAINT calendar_events_check CHECK (((calendar_encrypted IS NULL) = (calendar_encrypted_signature IS NULL))),
    CONSTRAINT calendar_events_revision_check CHECK ((revision >= 1)),
    CONSTRAINT calendar_events_shared_key_packet_check CHECK (((octet_length(shared_key_packet) >= 1) AND (octet_length(shared_key_packet) <= 1024)))
);


--
-- Name: calendar_event_attendees; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_event_attendees (
    shared_event_id uuid NOT NULL,
    token bytea NOT NULL,
    optional boolean DEFAULT false NOT NULL,
    answer bytea,
    answer_updated_at timestamp with time zone,
    CONSTRAINT calendar_event_attendees_answer_check CHECK (((octet_length(answer) >= 1) AND (octet_length(answer) <= 4096))),
    CONSTRAINT calendar_event_attendees_check CHECK (((answer IS NULL) = (answer_updated_at IS NULL))),
    CONSTRAINT calendar_event_attendees_token_check CHECK ((octet_length(token) = 32))
);


--
-- Name: calendar_event_invitees; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_event_invitees (
    shared_event_id uuid NOT NULL,
    invitee_account_id uuid NOT NULL,
    invitee_address_id uuid NOT NULL,
    key_packet bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT calendar_event_invitees_key_packet_check CHECK (((octet_length(key_packet) >= 1) AND (octet_length(key_packet) <= 1024)))
);


--
-- Name: calendar_invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_invitations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    calendar_id uuid NOT NULL,
    invitee_account_id uuid NOT NULL,
    invitee_incarnation_id bytea NOT NULL,
    invited_by_account_id uuid NOT NULL,
    permissions integer NOT NULL,
    state text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT calendar_invitations_check CHECK ((expires_at > created_at)),
    CONSTRAINT calendar_invitations_invitee_incarnation_id_check CHECK ((octet_length(invitee_incarnation_id) = 32)),
    CONSTRAINT calendar_invitations_permissions_check CHECK (((permissions >= 0) AND (permissions <= 255))),
    CONSTRAINT calendar_invitations_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'declined'::text])))
);


--
-- Name: calendar_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_keys (
    calendar_id uuid NOT NULL,
    key_generation integer NOT NULL,
    public_key bytea NOT NULL,
    fingerprint text NOT NULL,
    locked_secret_key bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT calendar_keys_fingerprint_check CHECK ((fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'::text)),
    CONSTRAINT calendar_keys_key_generation_check CHECK ((key_generation >= 1)),
    CONSTRAINT calendar_keys_locked_secret_key_check CHECK (((octet_length(locked_secret_key) >= 1) AND (octet_length(locked_secret_key) <= 8192))),
    CONSTRAINT calendar_keys_public_key_check CHECK (((octet_length(public_key) >= 1) AND (octet_length(public_key) <= 8192)))
);


--
-- Name: calendar_link_passphrases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_link_passphrases (
    link_id uuid NOT NULL,
    calendar_id uuid NOT NULL,
    key_generation integer NOT NULL,
    passphrase bytea NOT NULL,
    CONSTRAINT calendar_link_passphrases_passphrase_check CHECK (((octet_length(passphrase) >= 1) AND (octet_length(passphrase) <= 256)))
);


--
-- Name: calendar_links; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_links (
    id uuid NOT NULL,
    calendar_id uuid NOT NULL,
    kind text NOT NULL,
    secret_key_generation integer,
    secret bytea,
    purpose_key_packet bytea,
    purpose_data_packet bytea,
    purpose_signature text,
    created_by_account_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT calendar_links_check CHECK (((kind = 'busy'::text) = (secret IS NULL))),
    CONSTRAINT calendar_links_check1 CHECK (((secret IS NULL) = (secret_key_generation IS NULL))),
    CONSTRAINT calendar_links_check2 CHECK ((((purpose_key_packet IS NULL) = (purpose_data_packet IS NULL)) AND ((purpose_data_packet IS NULL) = (purpose_signature IS NULL)))),
    CONSTRAINT calendar_links_kind_check CHECK ((kind = ANY (ARRAY['full'::text, 'query'::text, 'busy'::text]))),
    CONSTRAINT calendar_links_purpose_data_packet_check CHECK (((octet_length(purpose_data_packet) >= 1) AND (octet_length(purpose_data_packet) <= 4096))),
    CONSTRAINT calendar_links_purpose_key_packet_check CHECK (((octet_length(purpose_key_packet) >= 1) AND (octet_length(purpose_key_packet) <= 1024))),
    CONSTRAINT calendar_links_purpose_signature_check CHECK (((octet_length(purpose_signature) >= 1) AND (octet_length(purpose_signature) <= 4096))),
    CONSTRAINT calendar_links_secret_check CHECK (((octet_length(secret) >= 1) AND (octet_length(secret) <= 256)))
);


--
-- Name: calendar_member_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_member_shares (
    calendar_id uuid NOT NULL,
    account_id uuid NOT NULL,
    key_generation integer NOT NULL,
    share bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT calendar_member_shares_share_check CHECK (((octet_length(share) >= 1) AND (octet_length(share) <= 2048)))
);


--
-- Name: calendar_member_tombstones; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_member_tombstones (
    calendar_id uuid NOT NULL,
    account_id uuid NOT NULL,
    reason text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT calendar_member_tombstones_reason_check CHECK ((reason = ANY (ARRAY['removed'::text, 'left'::text, 'deleted'::text])))
);


--
-- Name: calendar_shared_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_shared_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    home_calendar_id uuid NOT NULL,
    uid text NOT NULL,
    author_address_id uuid,
    author_account_id uuid,
    shared_signed text NOT NULL,
    shared_signed_signature text NOT NULL,
    shared_encrypted bytea NOT NULL,
    shared_encrypted_signature text NOT NULL,
    attendees_encrypted bytea,
    attendees_encrypted_signature text,
    start_utc timestamp with time zone NOT NULL,
    end_utc timestamp with time zone NOT NULL,
    start_tz text,
    end_tz text,
    full_day boolean NOT NULL,
    rrule text,
    recurrence_id timestamp with time zone,
    range_end_utc timestamp with time zone,
    sequence integer NOT NULL,
    revision bigint NOT NULL,
    bytes bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    modified_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT calendar_shared_events_attendees_encrypted_check CHECK (((octet_length(attendees_encrypted) >= 1) AND (octet_length(attendees_encrypted) <= 262144))),
    CONSTRAINT calendar_shared_events_attendees_encrypted_signature_check CHECK (((octet_length(attendees_encrypted_signature) >= 1) AND (octet_length(attendees_encrypted_signature) <= 4096))),
    CONSTRAINT calendar_shared_events_bytes_check CHECK ((bytes >= 0)),
    CONSTRAINT calendar_shared_events_check CHECK ((end_utc >= start_utc)),
    CONSTRAINT calendar_shared_events_check1 CHECK (((attendees_encrypted IS NULL) = (attendees_encrypted_signature IS NULL))),
    CONSTRAINT calendar_shared_events_revision_check CHECK ((revision >= 1)),
    CONSTRAINT calendar_shared_events_sequence_check CHECK ((sequence >= 0)),
    CONSTRAINT calendar_shared_events_shared_encrypted_check CHECK (((octet_length(shared_encrypted) >= 1) AND (octet_length(shared_encrypted) <= 262144))),
    CONSTRAINT calendar_shared_events_shared_encrypted_signature_check CHECK (((octet_length(shared_encrypted_signature) >= 1) AND (octet_length(shared_encrypted_signature) <= 4096))),
    CONSTRAINT calendar_shared_events_shared_signed_check CHECK (((octet_length(shared_signed) >= 1) AND (octet_length(shared_signed) <= 65536))),
    CONSTRAINT calendar_shared_events_shared_signed_signature_check CHECK (((octet_length(shared_signed_signature) >= 1) AND (octet_length(shared_signed_signature) <= 4096))),
    CONSTRAINT calendar_shared_events_uid_check CHECK (((char_length(uid) >= 1) AND (char_length(uid) <= 255)))
);


--
-- Name: calendar_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_members (
    calendar_id uuid NOT NULL,
    account_id uuid NOT NULL,
    permissions integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    default_reminders_timed jsonb DEFAULT '[{"type": "device", "trigger": "-PT15M"}, {"type": "email", "trigger": "-PT15M"}]'::jsonb NOT NULL,
    default_reminders_all_day jsonb DEFAULT '[{"type": "device", "trigger": "-PT15H"}, {"type": "email", "trigger": "-PT15H"}]'::jsonb NOT NULL,
    share_busy boolean DEFAULT false NOT NULL,
    CONSTRAINT calendar_members_default_reminders_all_day_check CHECK ((jsonb_typeof(default_reminders_all_day) = 'array'::text)),
    CONSTRAINT calendar_members_default_reminders_timed_check CHECK ((jsonb_typeof(default_reminders_timed) = 'array'::text)),
    CONSTRAINT calendar_members_permissions_check CHECK (((permissions >= 0) AND (permissions <= 255)))
);


--
-- Name: calendar_push_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_push_subscriptions (
    session_id uuid NOT NULL,
    account_id uuid NOT NULL,
    endpoint text NOT NULL,
    p256dh bytea NOT NULL,
    auth bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT calendar_push_subscriptions_auth_check CHECK ((octet_length(auth) = 16)),
    CONSTRAINT calendar_push_subscriptions_endpoint_check CHECK ((char_length(endpoint) <= 2048)),
    CONSTRAINT calendar_push_subscriptions_p256dh_check CHECK ((octet_length(p256dh) = 65))
);


--
-- Name: calendar_account_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_account_settings (
    account_id uuid NOT NULL,
    zone text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT calendar_account_settings_zone_check CHECK (((char_length(zone) >= 1) AND (char_length(zone) <= 64)))
);


--
-- Name: calendars; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendars (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    owner_account_id uuid NOT NULL,
    suite smallint NOT NULL,
    metadata_key_packet bytea NOT NULL,
    metadata_data_packet bytea NOT NULL,
    metadata_signature text NOT NULL,
    bytes bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    key_generation integer NOT NULL,
    CONSTRAINT calendars_bytes_check CHECK ((bytes >= 0)),
    CONSTRAINT calendars_key_generation_check CHECK ((key_generation >= 1)),
    CONSTRAINT calendars_metadata_data_packet_check CHECK (((octet_length(metadata_data_packet) >= 1) AND (octet_length(metadata_data_packet) <= 4096))),
    CONSTRAINT calendars_metadata_key_packet_check CHECK (((octet_length(metadata_key_packet) >= 1) AND (octet_length(metadata_key_packet) <= 1024))),
    CONSTRAINT calendars_metadata_signature_check CHECK (((octet_length(metadata_signature) >= 1) AND (octet_length(metadata_signature) <= 4096))),
    CONSTRAINT calendars_suite_check CHECK ((suite = 1))
);


--
-- Name: chat_account_identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_account_identities (
    account_id uuid NOT NULL,
    identity_key bytea NOT NULL,
    manifest_version bigint NOT NULL,
    changed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_account_identities_manifest_version_check CHECK ((manifest_version >= 1))
);


--
-- Name: chat_anonymous_send_ids; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_anonymous_send_ids (
    recipient_account_id uuid NOT NULL,
    capability_hash bytea NOT NULL,
    send_id uuid NOT NULL,
    stored_count integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_anonymous_send_ids_capability_hash_check CHECK ((octet_length(capability_hash) = 32)),
    CONSTRAINT chat_anonymous_send_ids_stored_count_check CHECK (((stored_count >= 1) AND (stored_count <= 32)))
);


--
-- Name: chat_backup_bases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_bases (
    account_id uuid NOT NULL,
    object_id uuid NOT NULL,
    generation bigint NOT NULL,
    covered_cursor bigint NOT NULL,
    ciphertext_bytes bigint NOT NULL,
    ciphertext_sha256 bytea NOT NULL,
    storage_path text NOT NULL,
    state text DEFAULT 'staged'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '24:00:00'::interval) NOT NULL,
    committed_at timestamp with time zone,
    CONSTRAINT chat_backup_bases_ciphertext_bytes_check CHECK (((ciphertext_bytes > 0) AND (ciphertext_bytes <= 134218752))),
    CONSTRAINT chat_backup_bases_covered_cursor_check CHECK ((covered_cursor >= 0)),
    CONSTRAINT chat_backup_bases_generation_check CHECK ((generation > 0)),
    CONSTRAINT chat_backup_bases_state_check CHECK ((state = ANY (ARRAY['staged'::text, 'committed'::text]))),
    CONSTRAINT chat_backup_bases_ciphertext_sha256_bytes CHECK ((octet_length(ciphertext_sha256) = 32))
);


--
-- Name: chat_backup_device_heads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_device_heads (
    account_id uuid NOT NULL,
    source_device_id integer NOT NULL,
    last_device_sequence bigint NOT NULL,
    last_segment_digest bytea NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_device_heads_last_device_sequence_check CHECK ((last_device_sequence > 0)),
    CONSTRAINT chat_backup_device_heads_source_device_id_check CHECK ((source_device_id > 0)),
    CONSTRAINT chat_backup_device_heads_last_segment_digest_bytes CHECK ((octet_length(last_segment_digest) = 32))
);


--
-- Name: chat_backup_media_objects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_objects (
    account_id uuid NOT NULL,
    media_id bytea NOT NULL,
    ciphertext_bytes bigint NOT NULL,
    ciphertext_sha256 bytea NOT NULL,
    storage_path text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_media_objects_ciphertext_bytes_check CHECK ((ciphertext_bytes > 0)),
    CONSTRAINT chat_backup_media_objects_media_id_check CHECK ((octet_length(media_id) = 32)),
    CONSTRAINT chat_backup_media_objects_ciphertext_sha256_bytes CHECK ((octet_length(ciphertext_sha256) = 32))
);


--
-- Name: chat_backup_media_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_operations (
    account_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    media_id bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_media_operations_media_id_check CHECK ((octet_length(media_id) = 32)),
    CONSTRAINT chat_backup_media_operations_request_digest_bytes CHECK ((octet_length(request_digest) = 32))
);


--
-- Name: chat_backup_media_reconciliation_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_reconciliation_entries (
    account_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    reference_id uuid NOT NULL,
    media_id bytea NOT NULL,
    CONSTRAINT chat_backup_media_reconciliation_entries_media_id_check CHECK ((octet_length(media_id) = 32))
);


--
-- Name: chat_backup_media_reconciliation_pages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_reconciliation_pages (
    account_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    page_index integer NOT NULL,
    request_digest bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_media_reconciliation_pages_page_index_check CHECK ((page_index >= 0)),
    CONSTRAINT chat_backup_media_reconciliation_pages_request_digest_bytes CHECK ((octet_length(request_digest) = 32))
);


--
-- Name: chat_backup_media_reconciliations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_reconciliations (
    account_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    target_generation bigint NOT NULL,
    reference_set_digest bytea NOT NULL,
    next_page integer DEFAULT 0 NOT NULL,
    completed boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_media_reconciliations_next_page_check CHECK ((next_page >= 0)),
    CONSTRAINT chat_backup_media_reconciliations_target_generation_check CHECK ((target_generation > 0)),
    CONSTRAINT chat_backup_media_reconciliations_reference_set_digest_bytes CHECK ((octet_length(reference_set_digest) = 32))
);


--
-- Name: chat_backup_media_references; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_media_references (
    account_id uuid NOT NULL,
    media_id bytea NOT NULL,
    reference_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_backup_provision_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_provision_operations (
    account_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    backup_incarnation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_provision_operations_request_digest_bytes CHECK ((octet_length(request_digest) = 32))
);


--
-- Name: chat_backup_segments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backup_segments (
    account_id uuid NOT NULL,
    cursor bigint NOT NULL,
    operation_id uuid NOT NULL,
    source_device_id integer NOT NULL,
    device_sequence bigint NOT NULL,
    previous_segment_digest bytea NOT NULL,
    account_manifest_sequence bigint NOT NULL,
    ciphertext_bytes integer NOT NULL,
    ciphertext_sha256 bytea NOT NULL,
    ciphertext bytea NOT NULL,
    acknowledged_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backup_segments_account_manifest_sequence_check CHECK ((account_manifest_sequence > 0)),
    CONSTRAINT chat_backup_segments_check CHECK ((octet_length(ciphertext) = ciphertext_bytes)),
    CONSTRAINT chat_backup_segments_ciphertext_bytes_check CHECK (((ciphertext_bytes > 0) AND (ciphertext_bytes <= 263168))),
    CONSTRAINT chat_backup_segments_cursor_check CHECK ((cursor > 0)),
    CONSTRAINT chat_backup_segments_device_sequence_check CHECK ((device_sequence > 0)),
    CONSTRAINT chat_backup_segments_source_device_id_check CHECK ((source_device_id > 0)),
    CONSTRAINT chat_backup_segments_ciphertext_sha256_bytes CHECK ((octet_length(ciphertext_sha256) = 32)),
    CONSTRAINT chat_backup_segments_previous_segment_digest_bytes CHECK ((octet_length(previous_segment_digest) = 32))
);


--
-- Name: chat_backups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_backups (
    account_id uuid NOT NULL,
    backup_incarnation_id uuid NOT NULL,
    suite smallint NOT NULL,
    protection_domain smallint NOT NULL,
    root_envelope bytea NOT NULL,
    signer_authorization jsonb NOT NULL,
    signer_authorization_digest bytea NOT NULL,
    current_cursor bigint DEFAULT 0 NOT NULL,
    current_generation bigint DEFAULT 0 NOT NULL,
    current_manifest_digest bytea DEFAULT decode(repeat('00'::text, 32), 'hex'::text) NOT NULL,
    current_manifest jsonb,
    current_base_object_id uuid,
    latest_protected_at timestamp with time zone,
    provisioned_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_backups_check CHECK ((((current_generation = 0) AND (current_manifest IS NULL) AND (current_base_object_id IS NULL)) OR ((current_generation > 0) AND (current_manifest IS NOT NULL) AND (current_base_object_id IS NOT NULL)))),
    CONSTRAINT chat_backups_current_cursor_check CHECK ((current_cursor >= 0)),
    CONSTRAINT chat_backups_current_generation_check CHECK ((current_generation >= 0)),
    CONSTRAINT chat_backups_current_manifest_check CHECK (((current_manifest IS NULL) OR (jsonb_typeof(current_manifest) = 'object'::text))),
    CONSTRAINT chat_backups_protection_domain_check CHECK ((protection_domain = 1)),
    CONSTRAINT chat_backups_signer_authorization_check CHECK ((jsonb_typeof(signer_authorization) = 'object'::text)),
    CONSTRAINT chat_backups_suite_check CHECK ((suite = 1)),
    CONSTRAINT chat_backups_current_manifest_digest_bytes CHECK ((octet_length(current_manifest_digest) = 32)),
    CONSTRAINT chat_backups_signer_authorization_digest_bytes CHECK ((octet_length(signer_authorization_digest) = 32))
);


--
-- Name: chat_call_link_knocks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_call_link_knocks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    room_id bytea NOT NULL,
    participant_id bytea NOT NULL,
    label bytea NOT NULL,
    ticket_hash bytea NOT NULL,
    status smallint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    seat_hash bytea NOT NULL,
    account_id uuid,
    CONSTRAINT chat_call_link_knocks_label_check CHECK ((octet_length(label) = 168)),
    CONSTRAINT chat_call_link_knocks_seat_hash_check CHECK ((octet_length(seat_hash) = 32)),
    CONSTRAINT chat_call_link_knocks_status_check CHECK ((status = ANY (ARRAY[0, 1, 2]))),
    CONSTRAINT chat_call_link_knocks_ticket_hash_check CHECK ((octet_length(ticket_hash) = 32)),
    CONSTRAINT chat_call_link_knocks_participant_id_bytes CHECK ((octet_length(participant_id) = 16)),
    CONSTRAINT chat_call_link_knocks_room_id_bytes CHECK ((octet_length(room_id) = 16))
);


--
-- Name: chat_call_link_seats; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_call_link_seats (
    room_id bytea NOT NULL,
    participant_id bytea NOT NULL,
    seat_hash bytea NOT NULL,
    role smallint,
    no_screen boolean DEFAULT false NOT NULL,
    removed_at timestamp with time zone,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    last_minted_at timestamp with time zone DEFAULT now() NOT NULL,
    account_id uuid,
    CONSTRAINT chat_call_link_seats_role_check CHECK ((role = ANY (ARRAY[1, 2]))),
    CONSTRAINT chat_call_link_seats_seat_hash_check CHECK ((octet_length(seat_hash) = 32)),
    CONSTRAINT chat_call_link_seats_participant_id_bytes CHECK ((octet_length(participant_id) = 16)),
    CONSTRAINT chat_call_link_seats_room_id_bytes CHECK ((octet_length(room_id) = 16))
);


--
-- Name: chat_call_links; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_call_links (
    room_id bytea NOT NULL,
    owner_account_id uuid NOT NULL,
    nonce bytea NOT NULL,
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
    CONSTRAINT chat_call_links_nonce_bytes CHECK ((octet_length(nonce) = 16)),
    CONSTRAINT chat_call_links_room_id_bytes CHECK ((octet_length(room_id) = 16))
);


--
-- Name: chat_delivery_capabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_delivery_capabilities (
    account_id uuid NOT NULL,
    profile_version bytea NOT NULL,
    profile_revision bigint NOT NULL,
    capability_hash bytea NOT NULL,
    rotated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_delivery_capabilities_capability_hash_check CHECK ((octet_length(capability_hash) = 32)),
    CONSTRAINT chat_delivery_capabilities_profile_revision_check CHECK ((profile_revision > 0)),
    CONSTRAINT chat_delivery_capabilities_profile_version_bytes CHECK ((octet_length(profile_version) = 32))
);


--
-- Name: chat_device_manifest_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_device_manifest_history (
    account_id uuid NOT NULL,
    incarnation_id bytea NOT NULL,
    version bigint NOT NULL,
    manifest_hash bytea NOT NULL,
    authority_key_id bytea NOT NULL,
    manifest jsonb NOT NULL,
    accepted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_device_manifest_history_manifest_check CHECK ((jsonb_typeof(manifest) = 'object'::text)),
    CONSTRAINT chat_device_manifest_history_version_check CHECK ((version > 0)),
    CONSTRAINT chat_device_manifest_history_authority_key_id_bytes CHECK ((octet_length(authority_key_id) = 32)),
    CONSTRAINT chat_device_manifest_history_incarnation_id_bytes CHECK ((octet_length(incarnation_id) = 32)),
    CONSTRAINT chat_device_manifest_history_manifest_hash_bytes CHECK ((octet_length(manifest_hash) = 32))
);


--
-- Name: chat_device_manifests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_device_manifests (
    account_id uuid NOT NULL,
    version bigint NOT NULL,
    manifest_hash bytea NOT NULL,
    authority_key_id bytea NOT NULL,
    manifest jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_device_manifests_version_check CHECK ((version > 0)),
    CONSTRAINT chat_device_manifests_authority_key_id_bytes CHECK ((octet_length(authority_key_id) = 32)),
    CONSTRAINT chat_device_manifests_manifest_hash_bytes CHECK ((octet_length(manifest_hash) = 32))
);


--
-- Name: chat_group_avatars; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_group_avatars (
    group_id bytea NOT NULL,
    hash bytea NOT NULL,
    blob bytea NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_group_avatars_blob_check CHECK ((octet_length(blob) = ANY (ARRAY[8233, 16425, 32809, 41001]))),
    CONSTRAINT chat_group_avatars_hash_check CHECK ((octet_length(hash) = 32))
);


--
-- Name: chat_group_changes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_group_changes (
    group_id bytea NOT NULL,
    revision bigint NOT NULL,
    change bytea NOT NULL,
    change_hash bytea NOT NULL,
    state_hash bytea NOT NULL,
    notary bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_group_changes_change_hash_check CHECK ((octet_length(change_hash) = 32)),
    CONSTRAINT chat_group_changes_revision_check CHECK ((revision >= 0)),
    CONSTRAINT chat_group_changes_state_hash_check CHECK ((octet_length(state_hash) = 32))
);


--
-- Name: chat_group_endorsements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_group_endorsements (
    group_id bytea NOT NULL,
    pseudonym bytea NOT NULL,
    expiration bigint NOT NULL,
    sealed bytea NOT NULL,
    seq bigint NOT NULL,
    CONSTRAINT chat_group_endorsements_expiration_check CHECK ((expiration > 0)),
    CONSTRAINT chat_group_endorsements_pseudonym_check CHECK ((octet_length(pseudonym) = 32))
);


--
-- Name: chat_group_endorsement_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.chat_group_endorsement_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chat_group_endorsement_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.chat_group_endorsement_seq OWNED BY public.chat_group_endorsements.seq;


--
-- Name: chat_group_nonces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_group_nonces (
    nonce bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT chat_group_nonces_nonce_check CHECK ((octet_length(nonce) = 16))
);


--
-- Name: chat_group_seen_pseudonyms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_group_seen_pseudonyms (
    group_id bytea NOT NULL,
    pseudonym_hash bytea NOT NULL,
    CONSTRAINT chat_group_seen_pseudonyms_pseudonym_hash_check CHECK ((octet_length(pseudonym_hash) = 32))
);


--
-- Name: chat_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_groups (
    group_id bytea NOT NULL,
    revision bigint NOT NULL,
    head bytea NOT NULL,
    state bytea NOT NULL,
    state_hash bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_groups_group_id_check CHECK ((octet_length(group_id) = 32)),
    CONSTRAINT chat_groups_head_check CHECK ((octet_length(head) = 32)),
    CONSTRAINT chat_groups_revision_check CHECK ((revision >= 0)),
    CONSTRAINT chat_groups_state_hash_check CHECK ((octet_length(state_hash) = 32))
);


--
-- Name: chat_link_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_link_tokens (
    token_hash bytea NOT NULL,
    account_id uuid NOT NULL,
    issued_by_device integer NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    CONSTRAINT chat_link_tokens_token_hash_check CHECK ((octet_length(token_hash) = 32))
);


--
-- Name: chat_mailbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_mailbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    cursor bigint NOT NULL,
    recipient_account_id uuid NOT NULL,
    recipient_device_id integer NOT NULL,
    sender_device_id integer NOT NULL,
    envelope_type smallint NOT NULL,
    suite smallint NOT NULL,
    content bytea NOT NULL,
    server_ts timestamp with time zone DEFAULT now() NOT NULL,
    sealed_sender boolean DEFAULT false NOT NULL,
    send_id text,
    sender_server text,
    sender_account_id uuid,
    shared_payload_id uuid,
    CONSTRAINT chat_mailbox_sender_check CHECK (((sender_server IS NULL) = (sender_account_id IS NULL))),
    CONSTRAINT chat_mailbox_sender_server_check CHECK ((sender_server = lower(sender_server))),
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
    transaction_digest bytea NOT NULL,
    recipient_account_id uuid NOT NULL,
    attachment_id uuid NOT NULL,
    ciphertext_bytes bigint NOT NULL,
    lease_id uuid NOT NULL,
    lease_until timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_media_federation_inbound_pending_ciphertext_bytes_check CHECK ((ciphertext_bytes > 0)),
    CONSTRAINT chat_media_federation_inbound_pending_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT chat_media_federation_inbound_pending_transaction_digest_bytes CHECK ((octet_length(transaction_digest) = 32))
);


--
-- Name: chat_media_federation_pull_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_federation_pull_grants (
    origin_account_id uuid NOT NULL,
    destination text NOT NULL,
    operation_id uuid NOT NULL,
    attachment_id uuid NOT NULL,
    retrieval_token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    recipient_account_id uuid NOT NULL,
    CONSTRAINT chat_media_federation_pull_grants_retrieval_token_hash_check CHECK ((octet_length(retrieval_token_hash) = 32))
);


--
-- Name: chat_media_objects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_objects (
    attachment_id uuid NOT NULL,
    origin_account_id uuid,
    origin_server text NOT NULL,
    suite smallint NOT NULL,
    ciphertext_bytes bigint NOT NULL,
    ciphertext_sha256 bytea NOT NULL,
    retrieval_token_hash bytea NOT NULL,
    storage_path text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_media_objects_ciphertext_bytes_check CHECK ((ciphertext_bytes > 0)),
    CONSTRAINT chat_media_objects_retrieval_token_hash_check CHECK ((octet_length(retrieval_token_hash) = 32)),
    CONSTRAINT chat_media_objects_ciphertext_sha256_bytes CHECK ((octet_length(ciphertext_sha256) = 32)),
    CONSTRAINT chat_media_objects_suite_check CHECK ((suite = 2))
);


--
-- Name: chat_media_origin_delivery_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_origin_delivery_operations (
    origin_account_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    recipient_account_id uuid NOT NULL,
    attachment_id uuid NOT NULL,
    ciphertext_bytes bigint NOT NULL,
    ciphertext_sha256 bytea NOT NULL,
    offer_digest bytea NOT NULL,
    storage_reference_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_media_origin_delivery_operations_ciphertext_bytes_check CHECK ((ciphertext_bytes > 0)),
    CONSTRAINT chat_media_origin_delivery_operations_ciphertext_sha256_bytes CHECK ((octet_length(ciphertext_sha256) = 32)),
    CONSTRAINT chat_media_origin_delivery_operations_offer_digest_bytes CHECK ((octet_length(offer_digest) = 32))
);


--
-- Name: chat_media_references; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_media_references (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
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
    account_id uuid NOT NULL,
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
    CONSTRAINT chat_media_uploads_suite_check CHECK ((suite = 2)),
    CONSTRAINT chat_media_uploads_total_bytes_check CHECK ((total_bytes > 0))
);


--
-- Name: chat_multi_send_ids; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_multi_send_ids (
    account_id uuid NOT NULL,
    device_id integer NOT NULL,
    send_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_one_time_kyber_pre_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_one_time_kyber_pre_keys (
    account_id uuid NOT NULL,
    device_id integer NOT NULL,
    key_id bigint NOT NULL,
    public_key bytea NOT NULL,
    signature bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_one_time_pre_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_one_time_pre_keys (
    account_id uuid NOT NULL,
    device_id integer NOT NULL,
    key_id bigint NOT NULL,
    public_key bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_profiles (
    account_id uuid NOT NULL,
    suite smallint NOT NULL,
    profile_version bytea NOT NULL,
    revision bigint NOT NULL,
    source_device_id integer NOT NULL,
    name_ciphertext bytea NOT NULL,
    avatar_ciphertext bytea,
    wrapped_key bytea NOT NULL,
    access_key_verifier bytea NOT NULL,
    is_current boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    about_ciphertext bytea,
    CONSTRAINT chat_profiles_access_key_verifier_check CHECK ((octet_length(access_key_verifier) = 32)),
    CONSTRAINT chat_profiles_revision_check CHECK ((revision > 0)),
    CONSTRAINT chat_profiles_source_device_id_check CHECK ((((source_device_id >= 1) AND (source_device_id <= 127)) OR (source_device_id = 128))),
    CONSTRAINT chat_profiles_suite_check CHECK ((suite = 1)),
    CONSTRAINT chat_profiles_profile_version_bytes CHECK ((octet_length(profile_version) = 32))
);


--
-- Name: chat_push_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_push_subscriptions (
    account_id uuid NOT NULL,
    device_id integer NOT NULL,
    endpoint text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_push_subscriptions_endpoint_check CHECK ((length(endpoint) <= 2048))
);


--
-- Name: chat_sends; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_sends (
    sender_account_id uuid NOT NULL,
    sender_device_id integer NOT NULL,
    send_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    delivery_scope text DEFAULT 'direct'::text NOT NULL,
    CONSTRAINT chat_sends_delivery_scope_check CHECK ((delivery_scope = ANY (ARRAY['direct'::text, 'sync'::text])))
);


--
-- Name: chat_shared_payloads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_shared_payloads (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    payload bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
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
-- Name: chat_zk_server_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_zk_server_keys (
    key_id integer NOT NULL,
    sealing_key_id smallint NOT NULL,
    server_secret_sealed bytea NOT NULL,
    public_key bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    issues_until bigint,
    verifies_until bigint,
    CONSTRAINT chat_zk_server_keys_check CHECK (((issues_until IS NULL) = (verifies_until IS NULL))),
    CONSTRAINT chat_zk_server_keys_key_id_check CHECK ((key_id > 0)),
    CONSTRAINT chat_zk_server_keys_sealing_key_id_check CHECK ((sealing_key_id > 0))
);


--
-- Name: drive_collection_key_epoch_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_collection_key_epoch_history (
    collection_id uuid NOT NULL,
    epoch integer NOT NULL,
    owner_key_envelope bytea NOT NULL,
    epoch_statement bytea NOT NULL,
    epoch_statement_hash bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    previous_key_envelope bytea,
    CONSTRAINT drive_collection_key_epoch_history_epoch_check CHECK ((epoch > 0)),
    CONSTRAINT drive_collection_key_epoch_history_previous_key CHECK (((epoch = 1) = (previous_key_envelope IS NULL))),
    CONSTRAINT drive_collection_key_epoch_history_epoch_statement_hash_bytes CHECK ((octet_length(epoch_statement_hash) = 32))
);


--
-- Name: drive_collection_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_collection_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    collection_id uuid NOT NULL,
    sharer_account_id uuid NOT NULL,
    recipient_account_id uuid NOT NULL,
    named_share_envelope bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    can_upload boolean DEFAULT false NOT NULL,
    can_delete boolean DEFAULT false NOT NULL,
    upload_quota_bytes bigint,
    CONSTRAINT drive_collection_shares_named_share_envelope_check CHECK ((octet_length(named_share_envelope) <= 3072))
);


--
-- Name: drive_collections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_collections (
    id uuid NOT NULL,
    owner_account_id uuid NOT NULL,
    name_envelope bytea NOT NULL,
    owner_key_envelope bytea NOT NULL,
    key_epoch integer NOT NULL,
    name_revision bigint NOT NULL,
    epoch_statement bytea NOT NULL,
    epoch_statement_hash bytea NOT NULL,
    parent_collection_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    color text,
    deleted_at timestamp with time zone,
    trash_root_id uuid,
    kind public.drive_collection_kind DEFAULT 'folder'::text NOT NULL,
    name_hash bytea,
    name_hash_generation integer,
    CONSTRAINT drive_collections_album_top_level CHECK (((kind = 'folder'::text) OR (parent_collection_id IS NULL))),
    CONSTRAINT drive_collections_folder_name_hash CHECK (((kind <> 'folder'::text) OR (name_hash IS NOT NULL))),
    CONSTRAINT drive_collections_key_epoch_check CHECK ((key_epoch > 0)),
    CONSTRAINT drive_collections_name_hash_generation_check CHECK (((name_hash_generation IS NULL) OR ((name_hash_generation > 0) AND (kind = 'folder'::text)))),
    CONSTRAINT drive_collections_name_revision_check CHECK ((name_revision > 0)),
    CONSTRAINT drive_collections_epoch_statement_hash_bytes CHECK ((octet_length(epoch_statement_hash) = 32)),
    CONSTRAINT drive_collections_name_hash_bytes CHECK ((octet_length(name_hash) = 32))
);


--
-- Name: consents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.consents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    seq bigint NOT NULL,
    account_id uuid NOT NULL,
    purpose text NOT NULL,
    given boolean NOT NULL,
    document_id uuid,
    at timestamp with time zone DEFAULT now() NOT NULL,
    channel text NOT NULL,
    CONSTRAINT consents_channel_check CHECK ((channel = ANY (ARRAY['settings'::text, 'signup'::text, 'admin'::text]))),
    CONSTRAINT consents_purpose_check CHECK ((purpose = ANY (ARRAY['federation'::text, 'marketing'::text])))
);


--
-- Name: consents_seq_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.consents ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.consents_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: contacts_emails; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contacts_emails (
    contact_id uuid NOT NULL,
    account_id uuid NOT NULL,
    address text NOT NULL,
    label text,
    "position" integer NOT NULL,
    last_used_at timestamp with time zone,
    CONSTRAINT contacts_emails_address_check CHECK (((address = lower(address)) AND ((length(address) >= 3) AND (length(address) <= 320)))),
    CONSTRAINT contacts_emails_position_check CHECK (("position" >= 0))
);


--
-- Name: contacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contacts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    uid text NOT NULL,
    name text NOT NULL,
    summary text NOT NULL,
    signature bytea NOT NULL,
    card bytea NOT NULL,
    revision bigint NOT NULL,
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
-- Name: account_device_tickets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_device_tickets (
    token_hash text NOT NULL,
    account_id uuid NOT NULL,
    device_id integer NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_device_tickets_token_hash_check CHECK ((length(token_hash) = 64))
);


--
-- Name: account_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_devices (
    account_id uuid NOT NULL,
    device_id integer NOT NULL,
    suite smallint,
    registration_id bigint,
    identity_key bytea,
    signed_pre_key_id bigint,
    signed_pre_key bytea,
    signed_pre_key_signature bytea,
    last_resort_kyber_pre_key_id bigint,
    last_resort_kyber_pre_key bytea,
    last_resort_kyber_pre_key_signature bytea,
    name text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone,
    credential_salt bytea NOT NULL,
    credential_hash bytea NOT NULL,
    expired_at timestamp with time zone,
    kind text NOT NULL,
    session_id uuid NOT NULL,
    frame_key bytea,
    CONSTRAINT chat_devices_credential_hash_check CHECK ((octet_length(credential_hash) = 32)),
    CONSTRAINT chat_devices_credential_salt_check CHECK ((octet_length(credential_salt) = 16)),
    CONSTRAINT account_devices_device_id_check CHECK (((device_id >= 1) AND (device_id <= 127))),
    CONSTRAINT account_devices_frame_key_check CHECK ((octet_length(frame_key) = 32)),
    CONSTRAINT account_devices_kind_check CHECK ((kind = ANY (ARRAY['chat'::text, 'editor'::text, 'cli'::text]))),
    CONSTRAINT account_devices_kind_keys CHECK (((num_nulls(suite, registration_id, identity_key, signed_pre_key_id, signed_pre_key, signed_pre_key_signature, last_resort_kyber_pre_key_id, last_resort_kyber_pre_key, last_resort_kyber_pre_key_signature) = ANY (ARRAY[0, 9])) AND ((kind <> 'chat'::text) OR (suite IS NOT NULL)) AND ((kind <> 'editor'::text) OR (suite IS NULL)) AND ((kind = 'chat'::text) OR (frame_key IS NOT NULL)))),
    CONSTRAINT account_devices_suite_known CHECK ((suite = 1))
);


--
-- Name: document_acknowledgements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.document_acknowledgements (
    account_id uuid NOT NULL,
    document_id uuid NOT NULL,
    at timestamp with time zone DEFAULT now() NOT NULL,
    context text NOT NULL,
    CONSTRAINT document_acknowledgements_context_check CHECK ((context = ANY (ARRAY['signup'::text, 'update'::text])))
);


--
-- Name: drive_federation_mutations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_federation_mutations (
    origin text NOT NULL,
    request_id text NOT NULL,
    request_hash bytea NOT NULL,
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
    CONSTRAINT drive_federation_mutations_request_id_check CHECK (((length(request_id) >= 1) AND (length(request_id) <= 128))),
    CONSTRAINT drive_federation_mutations_request_id_check1 CHECK ((request_id ~ '^[A-Za-z0-9._~-]+$'::text)),
    CONSTRAINT drive_federation_mutations_response_status_check CHECK (((response_status >= 100) AND (response_status <= 599))),
    CONSTRAINT drive_federation_mutations_request_hash_bytes CHECK ((octet_length(request_hash) = 32))
);


--
-- Name: drive_profile_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_profile_keys (
    account_id uuid NOT NULL,
    direction text NOT NULL,
    envelope bytea NOT NULL,
    profile_version bytea NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    peer_incarnation_id bytea NOT NULL,
    peer_server text NOT NULL,
    peer_account_id uuid NOT NULL,
    CONSTRAINT drive_profile_keys_direction_check CHECK ((direction = ANY (ARRAY['sent'::text, 'received'::text]))),
    CONSTRAINT drive_profile_keys_envelope_check CHECK ((octet_length(envelope) <= 3072)),
    CONSTRAINT drive_profile_keys_peer_server_check CHECK (((peer_server = lower(peer_server)) AND ((length(peer_server) >= 3) AND (length(peer_server) <= 253)))),
    CONSTRAINT drive_profile_keys_peer_incarnation_id_bytes CHECK ((octet_length(peer_incarnation_id) = 32)),
    CONSTRAINT drive_profile_keys_profile_version_bytes CHECK ((octet_length(profile_version) = 32))
);


--
-- Name: drive_federated_incoming_file_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_federated_incoming_file_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    owner_server text NOT NULL,
    remote_capability text NOT NULL,
    capability_hash bytea NOT NULL,
    remote_file_id uuid NOT NULL,
    owner_account_id uuid NOT NULL,
    owner_incarnation_id bytea NOT NULL,
    owner_signing_public_key bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT drive_federated_incoming_file_shares_remote_capability_check CHECK (((length(remote_capability) >= 32) AND (length(remote_capability) <= 256))),
    CONSTRAINT drive_federated_incoming_file_shares_remote_capability_check1 CHECK ((remote_capability ~ '^[A-Za-z0-9._~-]+$'::text)),
    CONSTRAINT drive_federated_incoming_file_shares_owner_server_check CHECK ((owner_server = lower(owner_server))),
    CONSTRAINT drive_federated_incoming_file_shares_capability_hash_bytes CHECK ((octet_length(capability_hash) = 32)),
    CONSTRAINT drive_federated_incoming_file_shares_owner_incarnation_id_bytes CHECK ((octet_length(owner_incarnation_id) = 32))
);


--
-- Name: drive_federated_incoming_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_federated_incoming_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    owner_server text NOT NULL,
    remote_capability text NOT NULL,
    capability_hash bytea NOT NULL,
    remote_collection_id uuid NOT NULL,
    named_share_envelope bytea NOT NULL,
    name_envelope bytea NOT NULL,
    key_epoch integer NOT NULL,
    name_revision bigint NOT NULL,
    epoch_statement bytea NOT NULL,
    epoch_statement_hash bytea NOT NULL,
    owner_account_id uuid NOT NULL,
    owner_incarnation_id bytea NOT NULL,
    owner_signing_public_key bytea NOT NULL,
    owner_authority_public_key bytea NOT NULL,
    can_upload boolean DEFAULT false NOT NULL,
    can_delete boolean DEFAULT false NOT NULL,
    upload_quota_bytes bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    collection_kind public.drive_collection_kind DEFAULT 'folder'::text NOT NULL,
    CONSTRAINT drive_federated_incoming_shares_key_epoch_check CHECK ((key_epoch > 0)),
    CONSTRAINT drive_federated_incoming_shares_name_revision_check CHECK ((name_revision > 0)),
    CONSTRAINT drive_federated_incoming_shares_named_share_envelope_check CHECK ((octet_length(named_share_envelope) <= 3072)),
    CONSTRAINT drive_federated_incoming_shares_remote_capability_check CHECK (((length(remote_capability) >= 32) AND (length(remote_capability) <= 256))),
    CONSTRAINT drive_federated_incoming_shares_remote_capability_check1 CHECK ((remote_capability ~ '^[A-Za-z0-9._~-]+$'::text)),
    CONSTRAINT drive_federated_incoming_shares_owner_server_check CHECK ((owner_server = lower(owner_server))),
    CONSTRAINT drive_federated_incoming_shares_owner_server_check1 CHECK (((length(owner_server) >= 3) AND (length(owner_server) <= 253))),
    CONSTRAINT drive_federated_incoming_shares_owner_server_check2 CHECK ((owner_server ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT drive_federated_incoming_shares_upload_quota_bytes_check CHECK (((upload_quota_bytes IS NULL) OR (upload_quota_bytes >= 0))),
    CONSTRAINT drive_federated_incoming_shares_capability_hash_bytes CHECK ((octet_length(capability_hash) = 32)),
    CONSTRAINT drive_federated_incoming_shares_epoch_statement_hash_bytes CHECK ((octet_length(epoch_statement_hash) = 32)),
    CONSTRAINT drive_federated_incoming_shares_owner_incarnation_id_bytes CHECK ((octet_length(owner_incarnation_id) = 32))
);


--
-- Name: drive_federated_outgoing_file_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_federated_outgoing_file_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    file_id uuid NOT NULL,
    sharer_account_id uuid NOT NULL,
    recipient_server text NOT NULL,
    recipient_incarnation_id bytea NOT NULL,
    share_envelope bytea NOT NULL,
    key_generation integer NOT NULL,
    capability_hash bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    can_edit boolean DEFAULT false NOT NULL,
    recipient_account_id uuid NOT NULL,
    CONSTRAINT drive_federated_outgoing_file_shares_key_generation_check CHECK ((key_generation > 0)),
    CONSTRAINT drive_federated_outgoing_file_shares_recipient_server_check CHECK ((recipient_server = lower(recipient_server))),
    CONSTRAINT drive_federated_outgoing_file_shares_recipient_server_check1 CHECK (((length(recipient_server) >= 3) AND (length(recipient_server) <= 253))),
    CONSTRAINT drive_federated_outgoing_file_shares_share_envelope_check CHECK ((octet_length(share_envelope) <= 3072)),
    CONSTRAINT drive_federated_outgoing_file_shares_capability_hash_bytes CHECK ((octet_length(capability_hash) = 32)),
    CONSTRAINT drive_fed_outgoing_file_shares_recipient_incarnation_id_bytes CHECK ((octet_length(recipient_incarnation_id) = 32))
);


--
-- Name: drive_federated_outgoing_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_federated_outgoing_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    collection_id uuid NOT NULL,
    sharer_account_id uuid NOT NULL,
    recipient_server text NOT NULL,
    named_share_envelope bytea NOT NULL,
    capability_hash bytea NOT NULL,
    can_upload boolean DEFAULT false NOT NULL,
    can_delete boolean DEFAULT false NOT NULL,
    upload_quota_bytes bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    recipient_incarnation_id bytea NOT NULL,
    recipient_account_id uuid NOT NULL,
    CONSTRAINT drive_federated_outgoing_shares_named_share_envelope_check CHECK ((octet_length(named_share_envelope) <= 3072)),
    CONSTRAINT drive_federated_outgoing_shares_recipient_server_check CHECK ((recipient_server = lower(recipient_server))),
    CONSTRAINT drive_federated_outgoing_shares_recipient_server_check1 CHECK (((length(recipient_server) >= 3) AND (length(recipient_server) <= 253))),
    CONSTRAINT drive_federated_outgoing_shares_recipient_server_check2 CHECK ((recipient_server ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT drive_federated_outgoing_shares_upload_quota_bytes_check CHECK (((upload_quota_bytes IS NULL) OR (upload_quota_bytes >= 0))),
    CONSTRAINT drive_federated_outgoing_shares_capability_hash_bytes CHECK ((octet_length(capability_hash) = 32)),
    CONSTRAINT drive_federated_outgoing_shares_recipient_incarnation_id_bytes CHECK ((octet_length(recipient_incarnation_id) = 32))
);


--
-- Name: federation_domain_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_domain_rules (
    domain text NOT NULL,
    feature text NOT NULL,
    inbound_action public.federation_rule_action DEFAULT 'inherit'::text NOT NULL,
    outbound_action public.federation_rule_action DEFAULT 'inherit'::text NOT NULL,
    trust_requirement text DEFAULT 'inherit'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_domain_rules_domain_check CHECK ((domain = lower(domain))),
    CONSTRAINT federation_domain_rules_domain_check1 CHECK (((length(domain) >= 3) AND (length(domain) <= 253))),
    CONSTRAINT federation_domain_rules_domain_check2 CHECK ((domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text)),
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
    policy_hash bytea NOT NULL,
    federation_identity_generation bigint NOT NULL,
    envelope jsonb NOT NULL,
    is_local boolean NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_feature_policy_do_federation_identity_generati_check CHECK ((federation_identity_generation >= 0)),
    CONSTRAINT federation_feature_policy_documents_domain_check CHECK ((domain = lower(domain))),
    CONSTRAINT federation_feature_policy_documents_envelope_check CHECK ((jsonb_typeof(envelope) = 'object'::text)),
    CONSTRAINT federation_feature_policy_documents_feature_type_check CHECK ((feature_type = 1)),
    CONSTRAINT federation_feature_policy_documents_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT federation_feature_policy_documents_policy_hash_bytes CHECK ((octet_length(policy_hash) = 32))
);


--
-- Name: federation_feature_policy_failures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_feature_policy_failures (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    domain text NOT NULL,
    feature_type smallint NOT NULL,
    failure_class text NOT NULL,
    evidence_digest bytea NOT NULL,
    received_value jsonb,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_feature_policy_failures_failure_class_check CHECK ((failure_class = ANY (ARRAY['rollback'::text, 'gap'::text, 'wrongDomain'::text, 'unknownType'::text, 'malformed'::text, 'signature'::text, 'identityChain'::text, 'configurationReplacement'::text]))),
    CONSTRAINT federation_feature_policy_failures_evidence_digest_bytes CHECK ((octet_length(evidence_digest) = 32))
);


--
-- Name: federation_inbound; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_inbound (
    kind text NOT NULL,
    origin text NOT NULL,
    sequence bigint NOT NULL,
    transaction_id text,
    digest bytea,
    status smallint NOT NULL,
    answer jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_inbound_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT federation_inbound_status_check CHECK (((status >= 200) AND (status <= 599))),
    CONSTRAINT federation_inbound_digest_bytes CHECK ((octet_length(digest) = 32))
);


--
-- Name: federation_inbound_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_inbound_state (
    kind text NOT NULL,
    origin text NOT NULL,
    last_sequence bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_inbound_state_last_sequence_check CHECK ((last_sequence >= 0))
);


--
-- Name: federation_local_identity_documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_local_identity_documents (
    sequence bigint NOT NULL,
    document_hash bytea NOT NULL,
    key_id bytea NOT NULL,
    document jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_local_identity_documents_document_check CHECK ((jsonb_typeof(document) = 'object'::text)),
    CONSTRAINT federation_local_identity_documents_sequence_check CHECK ((sequence >= 0)),
    CONSTRAINT federation_local_identity_documents_document_hash_bytes CHECK ((octet_length(document_hash) = 32)),
    CONSTRAINT federation_local_identity_documents_key_id_bytes CHECK ((octet_length(key_id) = 32))
);


--
-- Name: federation_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_outbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kind text NOT NULL,
    destination text NOT NULL,
    sequence bigint,
    idempotency_key text NOT NULL,
    sender_account_id uuid,
    recipient_account_id uuid,
    payload jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    error_class text,
    last_error text,
    answer jsonb,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT federation_outbox_kind_check CHECK ((kind = ANY (ARRAY['chat'::text, 'sealed'::text, 'media'::text, 'rename'::text]))),
    CONSTRAINT federation_outbox_payload_check CHECK ((jsonb_typeof(payload) = 'object'::text)),
    CONSTRAINT federation_outbox_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT federation_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'delivered'::text, 'rejected'::text])))
);


--
-- Name: federation_peer_identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_peer_identities (
    domain text NOT NULL,
    trust_state text NOT NULL,
    current_sequence bigint NOT NULL,
    current_document_hash bytea NOT NULL,
    current_key_id bytea NOT NULL,
    current_public_key bytea NOT NULL,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    verified_at timestamp with time zone,
    quarantine_reason text,
    pending_document jsonb,
    pending_identity_chain jsonb,
    pending_document_hash bytea,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    current_api_base text,
    capabilities jsonb DEFAULT '[]'::jsonb NOT NULL,
    discovery_expires_at timestamp with time zone,
    last_discovery_error text,
    CONSTRAINT federation_peer_identities_capabilities_check CHECK ((jsonb_typeof(capabilities) = 'array'::text)),
    CONSTRAINT federation_peer_identities_current_public_key_check CHECK ((octet_length(current_public_key) = 32)),
    CONSTRAINT federation_peer_identities_current_sequence_check CHECK ((current_sequence >= 0)),
    CONSTRAINT federation_peer_identities_domain_check CHECK ((domain = lower(domain))),
    CONSTRAINT federation_peer_identities_domain_check1 CHECK (((length(domain) >= 3) AND (length(domain) <= 253))),
    CONSTRAINT federation_peer_identities_domain_check2 CHECK ((domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT federation_peer_identities_trust_state_check CHECK ((trust_state = ANY (ARRAY['tofu'::text, 'verified'::text, 'quarantined'::text]))),
    CONSTRAINT federation_peer_identities_current_document_hash_bytes CHECK ((octet_length(current_document_hash) = 32)),
    CONSTRAINT federation_peer_identities_current_key_id_bytes CHECK ((octet_length(current_key_id) = 32)),
    CONSTRAINT federation_peer_identities_pending_document_hash_bytes CHECK ((octet_length(pending_document_hash) = 32))
);


--
-- Name: federation_peer_identity_documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_peer_identity_documents (
    domain text NOT NULL,
    sequence bigint NOT NULL,
    document_hash bytea NOT NULL,
    key_id bytea NOT NULL,
    document jsonb NOT NULL,
    acceptance text NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_peer_identity_documents_acceptance_check CHECK ((acceptance = ANY (ARRAY['accepted'::text, 'quarantined'::text, 'superseded'::text]))),
    CONSTRAINT federation_peer_identity_documents_document_check CHECK ((jsonb_typeof(document) = 'object'::text)),
    CONSTRAINT federation_peer_identity_documents_sequence_check CHECK ((sequence >= 0)),
    CONSTRAINT federation_peer_identity_documents_document_hash_bytes CHECK ((octet_length(document_hash) = 32)),
    CONSTRAINT federation_peer_identity_documents_key_id_bytes CHECK ((octet_length(key_id) = 32))
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
    request_hash bytea NOT NULL,
    first_seen_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT federation_request_replays_check CHECK ((expires_at > first_seen_at)),
    CONSTRAINT federation_request_replays_origin_check CHECK ((origin = lower(origin))),
    CONSTRAINT federation_request_replays_origin_check1 CHECK (((length(origin) >= 3) AND (length(origin) <= 253))),
    CONSTRAINT federation_request_replays_origin_check2 CHECK ((origin ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT federation_request_replays_request_id_check CHECK (((length(request_id) >= 1) AND (length(request_id) <= 128))),
    CONSTRAINT federation_request_replays_request_id_check1 CHECK ((request_id ~ '^[A-Za-z0-9._~-]+$'::text)),
    CONSTRAINT federation_request_replays_request_hash_bytes CHECK ((octet_length(request_hash) = 32))
);


--
-- Name: federation_sequences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_sequences (
    kind text NOT NULL,
    destination text NOT NULL,
    next_sequence bigint NOT NULL,
    CONSTRAINT federation_sequences_next_sequence_check CHECK ((next_sequence > 0))
);


--
-- Name: feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feedback (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid,
    kind text NOT NULL,
    app text NOT NULL,
    message text NOT NULL,
    details jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by_account_id uuid,
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
-- Name: drive_file_assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_file_assets (
    file_id uuid NOT NULL,
    asset_id text NOT NULL,
    size_bytes bigint NOT NULL,
    uploader_account_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    key_generation integer NOT NULL,
    CONSTRAINT drive_file_assets_size_bytes_check CHECK ((size_bytes >= 0))
);


--
-- Name: drive_file_key_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_file_key_history (
    file_id uuid NOT NULL,
    generation integer NOT NULL,
    previous_key_envelope bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    previous_metadata_envelope bytea,
    previous_metadata_revision bigint,
    CONSTRAINT drive_file_key_history_generation_check CHECK ((generation > 1))
);


--
-- Name: collab_sender_floors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collab_sender_floors (
    file_id uuid NOT NULL,
    sender_server text NOT NULL,
    sender_account_id uuid NOT NULL,
    sender_device_id integer NOT NULL,
    seq_prefix bigint NOT NULL,
    sender_seq bigint NOT NULL
);


--
-- Name: drive_file_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_file_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    file_id uuid NOT NULL,
    sharer_account_id uuid NOT NULL,
    recipient_account_id uuid NOT NULL,
    share_envelope bytea NOT NULL,
    key_generation integer NOT NULL,
    can_edit boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT drive_file_shares_check CHECK ((sharer_account_id <> recipient_account_id)),
    CONSTRAINT drive_file_shares_key_generation_check CHECK ((key_generation > 0)),
    CONSTRAINT drive_file_shares_share_envelope_check CHECK ((octet_length(share_envelope) <= 3072))
);


--
-- Name: drive_file_thumbnails; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_file_thumbnails (
    file_id uuid NOT NULL,
    variant text NOT NULL,
    size_bytes bigint NOT NULL,
    object_id uuid NOT NULL,
    source_version uuid,
    uploader_account_id uuid NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    key_generation integer NOT NULL,
    CONSTRAINT drive_file_thumbnails_size_bytes_check CHECK ((size_bytes > 0)),
    CONSTRAINT drive_file_thumbnails_variant_check CHECK ((variant = ANY (ARRAY['sm'::text, 'lg'::text])))
);


--
-- Name: collab_update_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collab_update_log (
    file_id uuid NOT NULL,
    seq bigint NOT NULL,
    doc_key_id bigint NOT NULL,
    kind smallint NOT NULL,
    frame bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sender_seq bigint DEFAULT 0 NOT NULL,
    sender_server text DEFAULT ''::text NOT NULL,
    sender_account_id uuid NOT NULL,
    sender_device_id integer NOT NULL,
    CONSTRAINT collab_update_log_sender_device_id_check CHECK (((sender_device_id >= 1) AND (sender_device_id <= 127)))
);


--
-- Name: drive_file_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_file_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    file_id uuid NOT NULL,
    seq_at_snapshot bigint NOT NULL,
    doc_key_id bigint NOT NULL,
    author_account_id uuid NOT NULL,
    size_bytes bigint NOT NULL,
    label text,
    keep_forever boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    kind text NOT NULL,
    ciphertext_sha256 bytea,
    key_generation integer NOT NULL,
    parent_version_id uuid,
    remote_author_server text,
    remote_author_account_id uuid,
    blob_suite smallint NOT NULL,
    revision_content_envelope bytea NOT NULL,
    CONSTRAINT drive_file_versions_blob_suite_check CHECK ((blob_suite = 2)),
    CONSTRAINT drive_file_versions_kind_check CHECK ((kind = ANY (ARRAY['file'::text, 'yjs'::text]))),
    CONSTRAINT drive_file_versions_remote_author_check CHECK (((remote_author_server IS NULL) = (remote_author_account_id IS NULL))),
    CONSTRAINT drive_file_versions_ciphertext_sha256_bytes CHECK ((octet_length(ciphertext_sha256) = 32))
);


--
-- Name: drive_files; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_files (
    id uuid NOT NULL,
    collection_id uuid NOT NULL,
    uploader_account_id uuid NOT NULL,
    metadata_envelope bytea NOT NULL,
    file_key_envelope bytea NOT NULL,
    key_epoch integer NOT NULL,
    metadata_revision bigint NOT NULL,
    encrypted_size_bytes bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    current_doc_key_id bigint NOT NULL,
    seed_committed boolean DEFAULT false NOT NULL,
    deleted_at timestamp with time zone,
    trash_root_id uuid,
    ciphertext_sha256 bytea,
    original_pruned boolean DEFAULT false NOT NULL,
    fed_share_id uuid,
    original_key_generation integer NOT NULL,
    key_generation integer NOT NULL,
    collab_log_floor bigint DEFAULT 0 NOT NULL,
    editors_can_share boolean DEFAULT false NOT NULL,
    name_hash bytea NOT NULL,
    content_hash bytea,
    content_revision_id uuid DEFAULT gen_random_uuid() NOT NULL,
    blob_suite smallint NOT NULL,
    revision_content_envelope bytea NOT NULL,
    CONSTRAINT drive_files_blob_suite_check CHECK ((blob_suite = 2)),
    CONSTRAINT drive_files_collab_log_floor_check CHECK ((collab_log_floor >= 0)),
    CONSTRAINT drive_files_key_epoch_check CHECK ((key_epoch > 0)),
    CONSTRAINT drive_files_key_generation CHECK ((key_generation > 0)),
    CONSTRAINT drive_files_metadata_revision_check CHECK ((metadata_revision > 0)),
    CONSTRAINT drive_files_original_key_generation CHECK ((original_key_generation > 0)),
    CONSTRAINT drive_files_ciphertext_sha256_bytes CHECK ((octet_length(ciphertext_sha256) = 32)),
    CONSTRAINT drive_files_content_hash_bytes CHECK ((octet_length(content_hash) = 32)),
    CONSTRAINT drive_files_name_hash_bytes CHECK ((octet_length(name_hash) = 32))
);


--
-- Name: job_heartbeats; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.job_heartbeats (
    job text NOT NULL,
    last_success_at timestamp with time zone NOT NULL
);


--
-- Name: legal_documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.legal_documents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kind text NOT NULL,
    version text NOT NULL,
    language text NOT NULL,
    url text NOT NULL,
    sha256 bytea NOT NULL,
    required_at_signup boolean DEFAULT false NOT NULL,
    published_at timestamp with time zone DEFAULT now() NOT NULL,
    published_by_account_id uuid,
    CONSTRAINT legal_documents_kind_check CHECK ((kind ~ '^[a-z][A-Za-z0-9]{0,39}$'::text)),
    CONSTRAINT legal_documents_language_check CHECK ((language ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$'::text)),
    CONSTRAINT legal_documents_sha256_check CHECK ((octet_length(sha256) = 32)),
    CONSTRAINT legal_documents_url_check CHECK (((char_length(url) >= 1) AND (char_length(url) <= 2048))),
    CONSTRAINT legal_documents_version_check CHECK (((char_length(version) >= 1) AND (char_length(version) <= 40)))
);


--
-- Name: chat_live_location_streams; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_live_location_streams (
    stream_id bytea NOT NULL,
    write_verifier bytea NOT NULL,
    read_verifier bytea NOT NULL,
    update_bytes bytea,
    counter bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by_account_id uuid NOT NULL,
    CONSTRAINT chat_live_location_streams_counter_check CHECK ((counter >= 0)),
    CONSTRAINT chat_live_location_streams_read_verifier_check CHECK ((octet_length(read_verifier) = 32)),
    CONSTRAINT chat_live_location_streams_stream_id_check CHECK ((octet_length(stream_id) = 16)),
    CONSTRAINT chat_live_location_streams_update_bytes_check CHECK (((update_bytes IS NULL) OR (octet_length(update_bytes) = 88))),
    CONSTRAINT chat_live_location_streams_write_verifier_check CHECK ((octet_length(write_verifier) = 32))
);


--
-- Name: mail_address_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_address_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    address_id uuid NOT NULL,
    fingerprint text NOT NULL,
    sha256_fingerprint text NOT NULL,
    public_key bytea NOT NULL,
    private_key_envelope bytea NOT NULL,
    is_primary boolean NOT NULL,
    flags integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    is_forwarding boolean DEFAULT false NOT NULL,
    forwarding_id uuid,
    CONSTRAINT mail_address_keys_fingerprint_check CHECK ((fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'::text)),
    CONSTRAINT mail_address_keys_flags_check CHECK (((flags >= 0) AND (flags <= 15))),
    CONSTRAINT mail_address_keys_forwarding_check CHECK (((NOT is_forwarding) OR (NOT is_primary))),
    CONSTRAINT mail_address_keys_forwarding_id_check CHECK (((forwarding_id IS NULL) OR is_forwarding)),
    CONSTRAINT mail_address_keys_private_key_envelope_check CHECK (((octet_length(private_key_envelope) >= 1) AND (octet_length(private_key_envelope) <= 8192))),
    CONSTRAINT mail_address_keys_public_key_check CHECK (((octet_length(public_key) >= 1) AND (octet_length(public_key) <= 16384))),
    CONSTRAINT mail_address_keys_sha256_fingerprint_check CHECK ((sha256_fingerprint ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: mail_addresses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_addresses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid,
    address text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    group_id uuid,
    state text DEFAULT 'active'::text NOT NULL,
    receive_until timestamp with time zone,
    key_list_owed boolean DEFAULT false NOT NULL,
    domain_id uuid,
    folded text GENERATED ALWAYS AS (
CASE
    WHEN (domain_id IS NULL) THEN ((public.kutup_fold(split_part(address, '@'::text, 1)) || '@'::text) || lower(split_part(address, '@'::text, 2)))
    ELSE lower(address)
END) STORED NOT NULL,
    "position" integer DEFAULT 0 NOT NULL,
    disabled_at timestamp with time zone,
    CONSTRAINT mail_addresses_address_check CHECK (((address = lower(address)) AND ((length(address) >= 3) AND (length(address) <= 320)))),
    CONSTRAINT mail_addresses_owner CHECK (((account_id IS NULL) <> (group_id IS NULL))),
    CONSTRAINT mail_addresses_state_check CHECK ((state = ANY (ARRAY['active'::text, 'receiving'::text, 'closed'::text, 'freed'::text])))
);


--
-- Name: mail_auto_replies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_auto_replies (
    account_id uuid NOT NULL,
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
    account_id uuid NOT NULL,
    sent_at timestamp with time zone DEFAULT now() NOT NULL,
    sender_hash bytea NOT NULL,
    CONSTRAINT mail_auto_reply_sent_sender_hash_check CHECK ((octet_length(sender_hash) = 32))
);


--
-- Name: mail_change_floors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_change_floors (
    mailbox_owner uuid NOT NULL,
    floor_xid bigint NOT NULL
);


--
-- Name: mail_dkim_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_dkim_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    selector text NOT NULL,
    state text NOT NULL,
    server_key_id integer NOT NULL,
    private_sealed bytea NOT NULL,
    public_spki bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    published_since timestamp with time zone,
    activated_at timestamp with time zone,
    retiring_at timestamp with time zone,
    CONSTRAINT mail_dkim_keys_selector_check CHECK ((selector = ANY (ARRAY['kutup1'::text, 'kutup2'::text, 'kutup3'::text]))),
    CONSTRAINT mail_dkim_keys_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'active'::text, 'retiring'::text, 'retired'::text])))
);


--
-- Name: mail_domain_blocks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_domain_blocks (
    name text NOT NULL,
    blocked_by_account_id uuid,
    blocked_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_domain_blocks_name_check CHECK ((name = lower(name)))
);


--
-- Name: mail_domain_catch_all_days; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_domain_catch_all_days (
    domain_id uuid NOT NULL,
    day date NOT NULL,
    count integer NOT NULL
);


--
-- Name: mail_domains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_domains (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    verify_code text NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    verify_state smallint DEFAULT 0 NOT NULL,
    mx_state smallint DEFAULT 0 NOT NULL,
    spf_state smallint DEFAULT 0 NOT NULL,
    dkim_state smallint DEFAULT 0 NOT NULL,
    dmarc_state smallint DEFAULT 0 NOT NULL,
    dkim_good_once boolean DEFAULT false NOT NULL,
    dkim_warning_since timestamp with time zone,
    approved_at timestamp with time zone,
    removed_at timestamp with time zone,
    catch_all_address_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    checked_at timestamp with time zone,
    verified_at timestamp with time zone,
    failing_since timestamp with time zone,
    warned_at timestamp with time zone,
    stopped_at timestamp with time zone,
    transfer_seen_at timestamp with time zone,
    stalwart_signature_id text,
    stalwart_signature_key text,
    organization_id uuid NOT NULL,
    CONSTRAINT mail_domains_name_check CHECK (((name = lower(name)) AND ((length(name) >= 1) AND (length(name) <= 253)))),
    CONSTRAINT mail_domains_state_check CHECK ((state = ANY (ARRAY[0, 1, 2]))),
    CONSTRAINT mail_domains_verify_code_check CHECK ((verify_code ~ '^kutup-verification=[a-z2-7]{26}$'::text))
);


--
-- Name: mail_draft_attachments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_draft_attachments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    message_id uuid NOT NULL,
    account_id uuid NOT NULL,
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
    account_id uuid NOT NULL,
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
    account_id uuid NOT NULL,
    name_sealed bytea NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    "position" integer DEFAULT 0 NOT NULL,
    match public.match_mode NOT NULL,
    conditions jsonb NOT NULL,
    actions jsonb NOT NULL,
    source text DEFAULT 'manual'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_filters_actions_check CHECK ((jsonb_typeof(actions) = 'object'::text)),
    CONSTRAINT mail_filters_conditions_check CHECK ((jsonb_typeof(conditions) = 'array'::text)),
    CONSTRAINT mail_filters_name_sealed_check CHECK (((octet_length(name_sealed) >= 1) AND (octet_length(name_sealed) <= 750))),
    CONSTRAINT mail_filters_source_check CHECK ((source = ANY (ARRAY['manual'::text, 'sender'::text])))
);


--
-- Name: mail_folders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_folders (
    id uuid NOT NULL,
    account_id uuid NOT NULL,
    parent_id uuid,
    name_sealed bytea,
    color text NOT NULL,
    "position" integer DEFAULT 0 NOT NULL,
    expanded boolean DEFAULT true NOT NULL,
    notify boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_folders_check CHECK (((parent_id IS NULL) OR (parent_id <> id))),
    CONSTRAINT mail_folders_color_check CHECK ((color ~ '^#[0-9a-f]{6}$'::text)),
    CONSTRAINT mail_folders_name_sealed_check CHECK (((octet_length(name_sealed) >= 1) AND (octet_length(name_sealed) <= 750)))
);


--
-- Name: mail_forwarding_code_sends; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_forwarding_code_sends (
    destination text NOT NULL,
    day date NOT NULL,
    sent integer NOT NULL,
    CONSTRAINT mail_forwarding_code_sends_destination_check CHECK ((destination = lower(destination))),
    CONSTRAINT mail_forwarding_code_sends_sent_check CHECK ((sent > 0))
);


--
-- Name: mail_forwarding_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_forwarding_keys (
    forwarding_id uuid NOT NULL,
    forwarder_fingerprint text NOT NULL,
    forwardee_fingerprint text NOT NULL,
    forwardee_public_key bytea NOT NULL,
    proxy_parameter_sealed bytea NOT NULL,
    secret_version smallint NOT NULL,
    CONSTRAINT mail_forwarding_keys_forwardee_fingerprint_check CHECK ((forwardee_fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'::text)),
    CONSTRAINT mail_forwarding_keys_forwardee_public_key_check CHECK (((octet_length(forwardee_public_key) >= 1) AND (octet_length(forwardee_public_key) <= 16384))),
    CONSTRAINT mail_forwarding_keys_forwarder_fingerprint_check CHECK ((forwarder_fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'::text)),
    CONSTRAINT mail_forwarding_keys_proxy_parameter_sealed_check CHECK (((octet_length(proxy_parameter_sealed) >= 1) AND (octet_length(proxy_parameter_sealed) <= 256))),
    CONSTRAINT mail_forwarding_keys_secret_version_check CHECK ((secret_version > 0))
);


--
-- Name: mail_forwarding_quota; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_forwarding_quota (
    account_id uuid NOT NULL,
    hour timestamp with time zone DEFAULT date_trunc('hour'::text, now()) NOT NULL,
    created_this_hour integer DEFAULT 0 NOT NULL,
    day date DEFAULT CURRENT_DATE NOT NULL,
    confirmations_today integer DEFAULT 0 NOT NULL,
    forwards_today integer DEFAULT 0 NOT NULL,
    CONSTRAINT mail_forwarding_quota_confirmations_today_check CHECK ((confirmations_today >= 0)),
    CONSTRAINT mail_forwarding_quota_created_this_hour_check CHECK ((created_this_hour >= 0)),
    CONSTRAINT mail_forwarding_quota_forwards_today_check CHECK ((forwards_today >= 0))
);


--
-- Name: mail_forwardings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_forwardings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    forwarder_address_id uuid NOT NULL,
    forwardee_email text NOT NULL,
    forwardee_address_id uuid,
    kind text NOT NULL,
    state text NOT NULL,
    match public.match_mode DEFAULT 'all'::text NOT NULL,
    conditions jsonb DEFAULT '[]'::jsonb NOT NULL,
    activation text,
    confirmation_hash bytea,
    expires_at timestamp with time zone,
    skipped bigint DEFAULT 0 NOT NULL,
    day date DEFAULT CURRENT_DATE NOT NULL,
    sent_today integer DEFAULT 0 NOT NULL,
    bounces_today integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    notice text,
    invites_today integer DEFAULT 0 NOT NULL,
    verified_at timestamp with time zone,
    code_hash bytea,
    code_key_version smallint,
    code_expires_at timestamp with time zone,
    code_attempts integer DEFAULT 0 NOT NULL,
    code_sent_at timestamp with time zone,
    CONSTRAINT mail_forwardings_activation_check CHECK (((activation IS NULL) OR (length(activation) <= 65536))),
    CONSTRAINT mail_forwardings_bounces_today_check CHECK ((bounces_today >= 0)),
    CONSTRAINT mail_forwardings_check CHECK (((kind = 'endToEnd'::text) = (forwardee_address_id IS NOT NULL))),
    CONSTRAINT mail_forwardings_code_hash_length CHECK (((code_hash IS NULL) OR (length(code_hash) = 32))),
    CONSTRAINT mail_forwardings_code_whole CHECK ((((code_hash IS NULL) = (code_key_version IS NULL)) AND ((code_hash IS NULL) = (code_expires_at IS NULL)))),
    CONSTRAINT mail_forwardings_conditions_check CHECK ((jsonb_typeof(conditions) = 'array'::text)),
    CONSTRAINT mail_forwardings_confirmation_hash_check CHECK (((confirmation_hash IS NULL) OR (octet_length(confirmation_hash) = 32))),
    CONSTRAINT mail_forwardings_forwardee_email_check CHECK (((length(forwardee_email) >= 3) AND (length(forwardee_email) <= 320))),
    CONSTRAINT mail_forwardings_invites_today_check CHECK ((invites_today >= 0)),
    CONSTRAINT mail_forwardings_kind_check CHECK ((kind = ANY (ARRAY['endToEnd'::text, 'outside'::text]))),
    CONSTRAINT mail_forwardings_notice_check CHECK (((notice IS NULL) OR (notice = ANY (ARRAY['bounces'::text, 'budget'::text])))),
    CONSTRAINT mail_forwardings_sent_today_check CHECK ((sent_today >= 0)),
    CONSTRAINT mail_forwardings_skipped_check CHECK ((skipped >= 0)),
    CONSTRAINT mail_forwardings_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'active'::text, 'outdated'::text, 'paused'::text, 'rejected'::text])))
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
    account_id uuid NOT NULL,
    share bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    member_incarnation_id bytea NOT NULL,
    CONSTRAINT mail_group_key_shares_share_check CHECK (((octet_length(share) >= 1) AND (octet_length(share) <= 16384))),
    CONSTRAINT mail_group_key_shares_member_incarnation_id_bytes CHECK ((octet_length(member_incarnation_id) = 32))
);


--
-- Name: mail_group_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_group_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id uuid NOT NULL,
    fingerprint text NOT NULL,
    sha256_fingerprint text NOT NULL,
    public_key bytea NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    flags integer DEFAULT 3 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_group_keys_fingerprint_check CHECK ((fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'::text)),
    CONSTRAINT mail_group_keys_flags_check CHECK (((flags >= 0) AND (flags <= 15))),
    CONSTRAINT mail_group_keys_public_key_check CHECK (((octet_length(public_key) >= 1) AND (octet_length(public_key) <= 16384))),
    CONSTRAINT mail_group_keys_sha256_fingerprint_check CHECK ((sha256_fingerprint ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: mail_group_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_group_members (
    group_id uuid NOT NULL,
    account_id uuid NOT NULL,
    role text NOT NULL,
    can_send_as boolean DEFAULT false NOT NULL,
    added_by_account_id uuid,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_group_members_role_check CHECK ((role = ANY (ARRAY['owner'::text, 'manager'::text, 'member'::text])))
);


--
-- Name: mail_group_objects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_group_objects (
    object_key text NOT NULL,
    group_id uuid NOT NULL,
    size_bytes bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_group_objects_size_bytes_check CHECK ((size_bytes > 0))
);


--
-- Name: mail_group_signers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_group_signers (
    group_id uuid NOT NULL,
    from_sequence bigint NOT NULL,
    public_key bytea NOT NULL,
    handover bytea,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_group_signers_check CHECK (((from_sequence = 1) = (handover IS NULL))),
    CONSTRAINT mail_group_signers_from_sequence_check CHECK ((from_sequence >= 1)),
    CONSTRAINT mail_group_signers_handover_check CHECK ((octet_length(handover) = 154)),
    CONSTRAINT mail_group_signers_public_key_check CHECK ((octet_length(public_key) = 32))
);


--
-- Name: mail_group_signing_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_group_signing_shares (
    group_id uuid NOT NULL,
    signer_public_key bytea NOT NULL,
    account_id uuid NOT NULL,
    share bytea NOT NULL,
    member_incarnation_id bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_group_signing_shares_share_check CHECK (((octet_length(share) >= 1) AND (octet_length(share) <= 2048))),
    CONSTRAINT mail_group_signing_shares_signer_public_key_check CHECK ((octet_length(signer_public_key) = 32)),
    CONSTRAINT mail_group_signing_shares_member_incarnation_id_bytes CHECK ((octet_length(member_incarnation_id) = 32))
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
    created_by_account_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    needs_new_signer boolean DEFAULT false NOT NULL,
    signature_sealed bytea,
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
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    signature_sealed bytea,
    CONSTRAINT mail_identities_display_name_check CHECK ((length(display_name) <= 100))
);


--
-- Name: mail_image_senders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_image_senders (
    account_id uuid NOT NULL,
    address text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_image_senders_address_check CHECK (((length(address) >= 3) AND (length(address) <= 320) AND (address = lower(address))))
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
    account_id uuid NOT NULL,
    name_sealed bytea NOT NULL,
    color text NOT NULL,
    "position" integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_labels_color_check CHECK ((color ~ '^#[0-9a-f]{6}$'::text)),
    CONSTRAINT mail_labels_name_sealed_check CHECK (((octet_length(name_sealed) >= 1) AND (octet_length(name_sealed) <= 750)))
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
    mailbox_owner uuid NOT NULL,
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
    account_id uuid,
    address_id uuid NOT NULL,
    thread_id uuid NOT NULL,
    direction text NOT NULL,
    folder text NOT NULL,
    seen boolean DEFAULT false NOT NULL,
    starred boolean DEFAULT false NOT NULL,
    protection text NOT NULL,
    object_key text NOT NULL,
    size_bytes bigint NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    external_recipients integer DEFAULT 0 NOT NULL,
    attachment_count integer DEFAULT 0 NOT NULL,
    group_id uuid,
    key_packet bytea,
    mailbox_owner uuid GENERATED ALWAYS AS (COALESCE(account_id, group_id)) STORED,
    sent_by_account_id uuid,
    sender_account_id uuid GENERATED ALWAYS AS (COALESCE(sent_by_account_id, account_id)) STORED,
    custom_folder uuid,
    folder_changed_at timestamp with time zone DEFAULT now() NOT NULL,
    unsubscribed boolean DEFAULT false NOT NULL,
    unsubscribable boolean DEFAULT false NOT NULL,
    receipt_sent boolean DEFAULT false NOT NULL,
    snoozed_until timestamp with time zone,
    expires_at timestamp with time zone,
    notify_at timestamp with time zone,
    change_xid bigint DEFAULT 0 NOT NULL,
    forwarded boolean DEFAULT false NOT NULL,
    headers bytea,
    message_id_hash bytea,
    in_reply_to_hash bytea,
    references_hashes bytea[] DEFAULT '{}'::bytea[] NOT NULL,
    search_tokens bytea[] DEFAULT '{}'::bytea[] NOT NULL,
    CONSTRAINT mail_messages_attachment_count_check CHECK ((attachment_count >= 0)),
    CONSTRAINT mail_messages_custom_folder_check CHECK (((folder = 'custom'::text) = (custom_folder IS NOT NULL))),
    CONSTRAINT mail_messages_direction_check CHECK ((direction = ANY (ARRAY['inbound'::text, 'outbound'::text]))),
    CONSTRAINT mail_messages_external_recipients_check CHECK (((external_recipients >= 0) AND (external_recipients <= 100))),
    CONSTRAINT mail_messages_folder_check CHECK ((folder = ANY (ARRAY['inbox'::text, 'drafts'::text, 'scheduled'::text, 'snoozed'::text, 'sent'::text, 'archive'::text, 'spam'::text, 'trash'::text, 'custom'::text]))),
    CONSTRAINT mail_messages_in_reply_to_hash_check CHECK ((octet_length(in_reply_to_hash) = 32)),
    CONSTRAINT mail_messages_key_packet_check CHECK (((octet_length(key_packet) >= 1) AND (octet_length(key_packet) <= 4096))),
    CONSTRAINT mail_messages_message_id_hash_check CHECK ((octet_length(message_id_hash) = 32)),
    CONSTRAINT mail_messages_owner CHECK (((account_id IS NOT NULL) OR (group_id IS NOT NULL))),
    CONSTRAINT mail_messages_protection_check CHECK ((protection = ANY (ARRAY['zeroAccess'::text, 'endToEnd'::text]))),
    CONSTRAINT mail_messages_references_hashes_check CHECK ((cardinality(references_hashes) <= 50)),
    CONSTRAINT mail_messages_search_tokens_check CHECK ((cardinality(search_tokens) <= 4000)),
    CONSTRAINT mail_messages_size_bytes_check CHECK ((size_bytes > 0))
);


--
-- Name: mail_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_outbox (
    id uuid NOT NULL,
    account_id uuid NOT NULL,
    draft_id uuid NOT NULL,
    is_admin boolean NOT NULL,
    deliver_at timestamp with time zone NOT NULL,
    parts_key text NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    scheduled boolean DEFAULT false NOT NULL,
    result_sealed bytea,
    CONSTRAINT mail_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'sending'::text, 'sent'::text, 'cancelled'::text, 'failed'::text])))
);


--
-- Name: mail_sender_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_sender_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    pattern text NOT NULL,
    kind text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_sender_rules_kind_check CHECK ((kind = ANY (ARRAY['spam'::text, 'block'::text, 'allow'::text]))),
    CONSTRAINT mail_sender_rules_pattern_check CHECK (((length(pattern) >= 3) AND (length(pattern) <= 320) AND (pattern = lower(pattern))))
);


--
-- Name: mail_sending_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mail_sending_events (
    id bigint NOT NULL,
    account_id uuid NOT NULL,
    kind text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mail_sending_events_kind_check CHECK ((kind = ANY (ARRAY['bounce'::text, 'spamRefused'::text])))
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
    account_id uuid NOT NULL,
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
    account_id uuid NOT NULL,
    auto_delete_days integer DEFAULT 0 NOT NULL,
    almost_all_mail boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    sign_outside boolean DEFAULT true NOT NULL,
    view_layout text DEFAULT 'column'::text NOT NULL,
    density text DEFAULT 'comfortable'::text NOT NULL,
    composer_mode text DEFAULT 'popup'::text NOT NULL,
    view_mode text DEFAULT 'conversation'::text NOT NULL,
    attach_public_key boolean DEFAULT false NOT NULL,
    pgp_scheme text DEFAULT 'pgpMime'::text NOT NULL,
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
    unread_favicon boolean DEFAULT false NOT NULL,
    keep_moved_sent boolean DEFAULT false NOT NULL,
    CONSTRAINT mail_settings_auto_delete_days_check CHECK ((auto_delete_days = ANY (ARRAY[0, 30]))),
    CONSTRAINT mail_settings_composer_mode_check CHECK ((composer_mode = ANY (ARRAY['popup'::text, 'maximized'::text]))),
    CONSTRAINT mail_settings_delay_send_seconds_check CHECK ((delay_send_seconds = ANY (ARRAY[0, 5, 10, 20]))),
    CONSTRAINT mail_settings_density_check CHECK ((density = ANY (ARRAY['comfortable'::text, 'compact'::text]))),
    CONSTRAINT mail_settings_draft_type_check CHECK ((draft_type = ANY (ARRAY['html'::text, 'plain'::text]))),
    CONSTRAINT mail_settings_font_face_check CHECK ((font_face = ANY (ARRAY['sans-serif'::text, 'serif'::text, 'georgia'::text, 'arial'::text, 'helvetica'::text, 'monospace'::text, 'tahoma'::text, 'verdana'::text, 'times'::text, 'trebuchet'::text]))),
    CONSTRAINT mail_settings_font_size_check CHECK ((font_size = ANY (ARRAY[10, 12, 14, 16, 18, 20, 22, 24, 26]))),
    CONSTRAINT mail_settings_page_size_check CHECK ((page_size = ANY (ARRAY[50, 100, 200]))),
    CONSTRAINT mail_settings_pgp_scheme_check CHECK ((pgp_scheme = ANY (ARRAY['pgpMime'::text, 'inline'::text]))),
    CONSTRAINT mail_settings_remote_images_check CHECK ((remote_images = ANY (ARRAY['ask'::text, 'always'::text]))),
    CONSTRAINT mail_settings_spam_action_check CHECK ((spam_action = ANY (ARRAY['ask'::text, 'justSpam'::text, 'spamAndUnsubscribe'::text]))),
    CONSTRAINT mail_settings_text_direction_check CHECK ((text_direction = ANY (ARRAY['ltr'::text, 'rtl'::text]))),
    CONSTRAINT mail_settings_view_layout_check CHECK ((view_layout = ANY (ARRAY['column'::text, 'row'::text]))),
    CONSTRAINT mail_settings_view_mode_check CHECK ((view_mode = ANY (ARRAY['conversation'::text, 'message'::text])))
);


--
-- Name: opaque_login_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.opaque_login_states (
    login_id uuid NOT NULL,
    canonical_name text NOT NULL,
    account_id uuid,
    purpose text NOT NULL,
    session_id uuid,
    grant_for text,
    source text NOT NULL,
    lockout_key bytea NOT NULL,
    ceiling_account text,
    ceiling_source text,
    server_key_id smallint NOT NULL,
    sealed_state bytea NOT NULL,
    credential_epoch bytea,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT opaque_login_states_check CHECK (((purpose = 'reauth'::text) = ((session_id IS NOT NULL) AND (grant_for IS NOT NULL) AND (account_id IS NOT NULL)))),
    CONSTRAINT opaque_login_states_check1 CHECK (((ceiling_account IS NULL) = (ceiling_source IS NULL))),
    CONSTRAINT opaque_login_states_credential_epoch_check CHECK (((credential_epoch IS NULL) OR (length(credential_epoch) = 16))),
    CONSTRAINT opaque_login_states_grant_for_check CHECK ((grant_for = ANY (ARRAY['pass'::text, 'passwordChange'::text, 'totp'::text, 'adminReset'::text, 'verify'::text, 'rename'::text, 'close'::text, 'masterKeyRotation'::text]))),
    CONSTRAINT opaque_login_states_purpose_check CHECK ((purpose = ANY (ARRAY['session'::text, 'reauth'::text])))
);


--
-- Name: opaque_server_setups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.opaque_server_setups (
    key_id smallint NOT NULL,
    sealed_setup bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    retired_at timestamp with time zone,
    CONSTRAINT opaque_server_setups_key_id_check CHECK ((key_id > 0)),
    CONSTRAINT opaque_server_setups_sealed_setup_check CHECK (((octet_length(sealed_setup) >= 1) AND (octet_length(sealed_setup) <= 4096)))
);


--
-- Name: organization_key_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_key_shares (
    organization_id uuid NOT NULL,
    key_id bytea NOT NULL,
    account_id uuid NOT NULL,
    sealed_share bytea,
    envelope bytea,
    granted_by_account_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_key_shares_check CHECK (((sealed_share IS NULL) <> (envelope IS NULL)))
);


--
-- Name: organization_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_keys (
    id bytea NOT NULL,
    organization_id uuid NOT NULL,
    public_key bytea NOT NULL,
    certificate bytea NOT NULL,
    state text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_keys_id_check CHECK ((length(id) = 32)),
    CONSTRAINT organization_keys_state_check CHECK ((state = ANY (ARRAY['active'::text, 'retired'::text])))
);


--
-- Name: organization_member_escrows; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_member_escrows (
    organization_id uuid NOT NULL,
    account_id uuid NOT NULL,
    key_id bytea NOT NULL,
    mk_generation integer NOT NULL,
    sealed bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_member_escrows_mk_generation_check CHECK ((mk_generation > 0))
);


--
-- Name: organization_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_members (
    organization_id uuid NOT NULL,
    account_id uuid NOT NULL,
    role text NOT NULL,
    state smallint NOT NULL,
    created_by_org boolean DEFAULT false NOT NULL,
    private boolean DEFAULT true NOT NULL,
    org_key_state smallint DEFAULT 0 NOT NULL,
    invited_by_account_id uuid,
    invited_at timestamp with time zone,
    joined_at timestamp with time zone,
    CONSTRAINT organization_members_check CHECK (((state = 2) = ((invited_at IS NOT NULL) AND (joined_at IS NULL)))),
    CONSTRAINT organization_members_org_key_state_check CHECK ((org_key_state = ANY (ARRAY[0, 1, 2, 3]))),
    CONSTRAINT organization_members_role_check CHECK ((role = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text]))),
    CONSTRAINT organization_members_state_check CHECK ((state = ANY (ARRAY[0, 1, 2])))
);


--
-- Name: organization_entitlements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_entitlements (
    organization_id uuid NOT NULL,
    key text NOT NULL,
    value bigint NOT NULL,
    source text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_entitlements_key_check CHECK ((key ~ '^[a-z0-9_.]{1,80}$'::text)),
    CONSTRAINT organization_entitlements_source_check CHECK ((source = ANY (ARRAY['admin'::text, 'plan'::text, 'organization'::text])))
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    state smallint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    disabled_at timestamp with time zone,
    CONSTRAINT organizations_check CHECK (((state = 0) = (disabled_at IS NOT NULL))),
    CONSTRAINT organizations_name_check CHECK (((length(name) >= 1) AND (length(name) <= 200))),
    CONSTRAINT organizations_state_check CHECK ((state = ANY (ARRAY[0, 1])))
);


--
-- Name: pass_pin_failures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pass_pin_failures (
    sign_in_id uuid NOT NULL,
    account_id uuid NOT NULL,
    failures smallint NOT NULL
);


--
-- Name: pass_pins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pass_pins (
    account_id uuid NOT NULL,
    pin_hash text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: pass_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pass_settings (
    account_id uuid NOT NULL,
    site_icons text DEFAULT 'kutup'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pass_settings_site_icons_check CHECK ((site_icons = ANY (ARRAY['kutup'::text, 'off'::text])))
);


--
-- Name: photos_library_folders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.photos_library_folders (
    account_id uuid NOT NULL,
    collection_id uuid NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: photos_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.photos_preferences (
    account_id uuid NOT NULL,
    upload_folder_id uuid,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: drive_public_link_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_public_link_reports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    share_id uuid NOT NULL,
    reason text NOT NULL,
    details text DEFAULT ''::text NOT NULL,
    link text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by_account_id uuid,
    resolution text,
    CONSTRAINT drive_public_link_reports_check CHECK (((resolved_at IS NULL) = (resolution IS NULL))),
    CONSTRAINT drive_public_link_reports_check1 CHECK (((resolved_at IS NULL) OR (link IS NULL))),
    CONSTRAINT drive_public_link_reports_details_check CHECK ((char_length(details) <= 2000)),
    CONSTRAINT drive_public_link_reports_link_check CHECK (((link IS NULL) OR (char_length(link) <= 2048))),
    CONSTRAINT drive_public_link_reports_reason_check CHECK ((reason = ANY (ARRAY['phishing'::text, 'malware'::text, 'illegal'::text, 'abuse'::text, 'other'::text]))),
    CONSTRAINT drive_public_link_reports_resolution_check CHECK ((resolution = ANY (ARRAY['dismissed'::text, 'removed'::text, 'disabled'::text, 'blocked'::text])))
);


--
-- Name: drive_public_shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_public_shares (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    share_type text NOT NULL,
    target_id uuid NOT NULL,
    token text NOT NULL,
    collection_key_envelope bytea NOT NULL,
    collection_key_epoch integer NOT NULL,
    owner_account_id uuid NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    owner_link_key_envelope bytea NOT NULL,
    removed_at timestamp with time zone,
    blocked_at timestamp with time zone,
    blocked_reason text,
    blocked_reference text,
    blocked_by_account_id uuid,
    owner_removed_at timestamp with time zone,
    CONSTRAINT drive_public_shares_blocked CHECK ((((blocked_at IS NULL) = (blocked_reason IS NULL)) AND ((blocked_at IS NOT NULL) OR ((blocked_reference IS NULL) AND (blocked_by_account_id IS NULL))) AND ((owner_removed_at IS NULL) OR (blocked_at IS NOT NULL)))),
    CONSTRAINT drive_public_shares_blocked_reason_check CHECK ((blocked_reason = ANY (ARRAY['legalOrder'::text, 'abuse'::text, 'other'::text]))),
    CONSTRAINT drive_public_shares_blocked_reference_check CHECK (((char_length(blocked_reference) >= 1) AND (char_length(blocked_reference) <= 200))),
    CONSTRAINT drive_public_shares_collection_key_epoch_check CHECK ((collection_key_epoch > 0)),
    CONSTRAINT drive_public_shares_share_type_check CHECK ((share_type = ANY (ARRAY['collection'::text, 'file'::text])))
);


--
-- Name: rate_counters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rate_counters (
    scope text NOT NULL,
    subject bytea NOT NULL,
    window_start timestamp with time zone NOT NULL,
    count bigint NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT rate_counters_count_check CHECK ((count >= 0)),
    CONSTRAINT rate_counters_subject_check CHECK ((octet_length(subject) = 32))
);


--
-- Name: registration_code_uses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.registration_code_uses (
    code_id uuid NOT NULL,
    account_id uuid NOT NULL,
    used_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: registration_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.registration_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    code_hash bytea NOT NULL,
    hint text NOT NULL,
    note text DEFAULT ''::text NOT NULL,
    created_by_account_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    max_uses integer,
    uses integer DEFAULT 0 NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by_account_id uuid,
    CONSTRAINT registration_codes_check CHECK (((max_uses IS NULL) OR (uses <= max_uses))),
    CONSTRAINT registration_codes_code_hash_check CHECK ((octet_length(code_hash) = 32)),
    CONSTRAINT registration_codes_hint_check CHECK (((length(hint) >= 1) AND (length(hint) <= 8))),
    CONSTRAINT registration_codes_max_uses_check CHECK (((max_uses IS NULL) OR ((max_uses >= 1) AND (max_uses <= 100000)))),
    CONSTRAINT registration_codes_note_check CHECK ((length(note) <= 200)),
    CONSTRAINT registration_codes_uses_check CHECK ((uses >= 0))
);


--
-- Name: remote_account_manifests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remote_account_manifests (
    domain text NOT NULL,
    account_id uuid NOT NULL,
    sequence bigint NOT NULL,
    manifest_hash bytea NOT NULL,
    manifest jsonb NOT NULL,
    fetched_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT remote_account_manifests_sequence_check CHECK ((sequence >= 1)),
    CONSTRAINT remote_account_manifests_manifest_hash_bytes CHECK ((octet_length(manifest_hash) = 32))
);


--
-- Name: remote_account_renames; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remote_account_renames (
    server text NOT NULL,
    account_id uuid NOT NULL,
    incarnation_id bytea NOT NULL,
    authority_public_key bytea,
    sequence integer NOT NULL,
    head_digest bytea,
    current_address text NOT NULL,
    state text NOT NULL,
    chain jsonb NOT NULL,
    addresses text[] NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT remote_account_renames_server_check CHECK ((server = lower(server))),
    CONSTRAINT remote_account_renames_head_digest_check CHECK ((octet_length(head_digest) = 32)),
    CONSTRAINT remote_account_renames_sequence_check CHECK (((sequence >= 0) AND (sequence <= 1000))),
    CONSTRAINT remote_account_renames_chain_check CHECK ((((sequence = 0) AND (authority_public_key IS NULL) AND (head_digest IS NULL) AND (chain = '[]'::jsonb)) OR ((sequence >= 1) AND (authority_public_key IS NOT NULL) AND (head_digest IS NOT NULL)))),
    CONSTRAINT remote_account_renames_current_address_check CHECK ((split_part(current_address, '@'::text, 2) = server)),
    CONSTRAINT remote_account_renames_state_check CHECK ((state = ANY (ARRAY['current'::text, 'held'::text, 'gone'::text]))),
    CONSTRAINT remote_account_renames_incarnation_id_bytes CHECK ((octet_length(incarnation_id) = 32))
);


--
-- Name: remote_manifest_failures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remote_manifest_failures (
    domain text NOT NULL,
    account_id uuid NOT NULL,
    failed_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: retired_account_ids; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.retired_account_ids (
    id uuid NOT NULL,
    retired_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chat_sealed_sender_certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_sealed_sender_certificates (
    certificate_id bigint NOT NULL,
    root_id bytea NOT NULL,
    root_public_key bytea NOT NULL,
    certificate bytea NOT NULL,
    online_private_key bytea,
    published_at bigint NOT NULL,
    activates_at bigint NOT NULL,
    expires_at bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_sealed_sender_certificates_certificate_id_check CHECK (((certificate_id > 0) AND (certificate_id <= '4294967295'::bigint))),
    CONSTRAINT chat_sealed_sender_certificates_check CHECK ((activates_at >= published_at)),
    CONSTRAINT chat_sealed_sender_certificates_check1 CHECK ((expires_at > activates_at)),
    CONSTRAINT chat_sealed_sender_certificates_online_private_key_check CHECK ((octet_length(online_private_key) = 32)),
    CONSTRAINT chat_sealed_sender_certificates_root_id_bytes CHECK ((octet_length(root_id) = 32))
);


--
-- Name: server_generated_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.server_generated_keys (
    purpose text NOT NULL,
    private_key bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT server_generated_keys_private_key_check CHECK ((octet_length(private_key) = 32)),
    CONSTRAINT server_generated_keys_purpose_check CHECK ((purpose = ANY (ARRAY['federationIdentity'::text, 'fakeAccounts'::text, 'registrationCodes'::text, 'twoFactorRecoveryCodes'::text])))
);


--
-- Name: site_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.site_settings (
    key text NOT NULL,
    value text NOT NULL
);


--
-- Name: storage_pending_deletions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.storage_pending_deletions (
    id bigint NOT NULL,
    kind text NOT NULL,
    key text NOT NULL,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    CONSTRAINT storage_pending_deletions_key_check CHECK ((key <> ''::text)),
    CONSTRAINT storage_pending_deletions_kind_check CHECK ((kind = ANY (ARRAY['object'::text, 'prefix'::text])))
);


--
-- Name: storage_pending_deletions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.storage_pending_deletions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: storage_pending_deletions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.storage_pending_deletions_id_seq OWNED BY public.storage_pending_deletions.id;


--
-- Name: two_factor_recovery_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.two_factor_recovery_codes (
    account_id uuid NOT NULL,
    code_mac bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT two_factor_recovery_codes_code_mac_check CHECK ((octet_length(code_mac) = 32))
);


--
-- Name: drive_uploads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.drive_uploads (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    collection_id uuid NOT NULL,
    file_id uuid NOT NULL,
    total_bytes bigint NOT NULL,
    received_bytes bigint DEFAULT 0 NOT NULL,
    file_key_envelope bytea,
    key_epoch integer NOT NULL,
    s3_upload_id text NOT NULL,
    s3_part_etags jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    pending_bytes bytea DEFAULT '\x'::bytea NOT NULL,
    name_hash bytea,
    kind text DEFAULT 'file'::text NOT NULL,
    key_generation integer,
    content_hash bytea,
    based_on text,
    revision_id uuid DEFAULT gen_random_uuid() NOT NULL,
    blob_suite smallint NOT NULL,
    uploaded_at timestamp with time zone,
    CONSTRAINT drive_uploads_blob_suite_check CHECK ((blob_suite = 2)),
    CONSTRAINT drive_uploads_key_epoch_check CHECK ((key_epoch > 0)),
    CONSTRAINT drive_uploads_kind_check CHECK ((kind = ANY (ARRAY['file'::text, 'version'::text]))),
    CONSTRAINT drive_uploads_kind_fields CHECK ((((kind = 'file'::text) AND (name_hash IS NOT NULL) AND (file_key_envelope IS NOT NULL) AND (key_generation IS NULL) AND (content_hash IS NULL) AND (based_on IS NULL)) OR ((kind = 'version'::text) AND (name_hash IS NULL) AND (file_key_envelope IS NULL) AND (key_generation IS NOT NULL) AND (key_generation > 0) AND ((content_hash IS NULL) OR (octet_length(content_hash) = 32))))),
    CONSTRAINT drive_uploads_uploaded_check CHECK (((uploaded_at IS NULL) OR ((blob_suite = 2) AND (received_bytes = total_bytes)))),
    CONSTRAINT drive_uploads_content_hash_bytes CHECK ((octet_length(content_hash) = 32)),
    CONSTRAINT drive_uploads_name_hash_bytes CHECK ((octet_length(name_hash) = 32))
);


--
-- Name: account_devices_revocation_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_devices_revocation_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_map_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_map_preferences (
    account_id uuid NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    provider text,
    via_proxy boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    save_folder_id uuid,
    CONSTRAINT account_map_preferences_provider_check CHECK ((provider = ANY (ARRAY['openfreemap'::text, 'openstreetmap'::text, 'custom'::text])))
);


--
-- Name: account_security_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_security_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    transports bytea NOT NULL,
    static_state bytea NOT NULL,
    dynamic_state bytea NOT NULL,
    sign_count bigint DEFAULT 0 NOT NULL,
    aaguid bytea NOT NULL,
    name text NOT NULL,
    compromised boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    CONSTRAINT account_security_keys_aaguid_check CHECK ((octet_length(aaguid) = 16)),
    CONSTRAINT account_security_keys_credential_id_check CHECK (((octet_length(credential_id) >= 16) AND (octet_length(credential_id) <= 1023))),
    CONSTRAINT account_security_keys_name_check CHECK (((char_length(name) >= 1) AND (char_length(name) <= 128))),
    CONSTRAINT account_security_keys_sign_count_check CHECK ((sign_count >= 0)),
    CONSTRAINT account_security_keys_transports_check CHECK ((octet_length(transports) = 1))
);


--
-- Name: account_entitlements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_entitlements (
    account_id uuid NOT NULL,
    key text NOT NULL,
    value bigint NOT NULL,
    source text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_entitlements_key_check CHECK ((key ~ '^[a-z0-9_.]{1,80}$'::text)),
    CONSTRAINT account_entitlements_source_check CHECK ((source = ANY (ARRAY['admin'::text, 'plan'::text, 'organization'::text, 'account'::text])))
);


--
-- Name: account_ui_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_ui_preferences (
    account_id uuid NOT NULL,
    theme text,
    language text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_ui_preferences_language_check CHECK ((language ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$'::text)),
    CONSTRAINT account_ui_preferences_theme_check CHECK ((theme = ANY (ARRAY['light'::text, 'dark'::text, 'system'::text])))
);


--
-- Name: accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.accounts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    master_key_envelope bytea,
    recovery_key_envelope bytea,
    drive_xwing_public_key bytea,
    account_authority_public_key bytea,
    account_authority_key_id bytea,
    account_incarnation_id bytea,
    drive_signing_public_key bytea,
    storage_used_bytes bigint DEFAULT 0 NOT NULL,
    role text DEFAULT 'member'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    keys_set_up_at timestamp with time zone,
    username text NOT NULL,
    recovery_key_verifier text,
    color text,
    version_retention_days integer DEFAULT 30 NOT NULL,
    drive_key_binding bytea,
    key_binding uuid,
    opaque_record bytea,
    opaque_suite smallint,
    opaque_server_key_id smallint,
    identity_suite smallint NOT NULL,
    drive_key_binding_epoch integer NOT NULL,
    security_keys_require_uv boolean DEFAULT false NOT NULL,
    totp_secret_sealed bytea,
    totp_pending_secret_sealed bytea,
    data_key_lost_at timestamp with time zone,
    state text DEFAULT 'active'::text NOT NULL,
    suspended_reason public.suspended_reason,
    state_changed_at timestamp with time zone DEFAULT now() NOT NULL,
    closing_by text,
    closes_at timestamp with time zone,
    purpose_ended_at timestamp with time zone,
    legal_hold_reference text,
    legal_hold_at timestamp with time zone,
    legal_hold_by_account_id uuid,
    suspended_before_close public.suspended_reason,
    deleting_at timestamp with time zone,
    deleting_for text,
    deletion_attempts integer DEFAULT 0 NOT NULL,
    deletion_next_try_at timestamp with time zone,
    master_key_generation integer NOT NULL,
    CONSTRAINT accounts_closing CHECK ((((state = 'closing'::text) = (closing_by IS NOT NULL)) AND ((state = 'closing'::text) = (closes_at IS NOT NULL)))),
    CONSTRAINT accounts_closing_by_check CHECK ((closing_by = ANY (ARRAY['user'::text, 'admin'::text, 'restore'::text]))),
    CONSTRAINT accounts_color_format CHECK (((color IS NULL) OR (color ~ '^#[0-9a-fA-F]{6}$'::text))),
    CONSTRAINT accounts_deleting_for_check CHECK ((deleting_for = ANY (ARRAY['delete'::text, 'reset'::text]))),
    CONSTRAINT accounts_deletion_attempts_check CHECK ((deletion_attempts >= 0)),
    CONSTRAINT accounts_drive_key_binding_epoch_check CHECK ((drive_key_binding_epoch > 0)),
    CONSTRAINT accounts_identity_suite_check CHECK ((identity_suite = 2)),
    CONSTRAINT accounts_key_binding_check CHECK (((key_binding)::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text)),
    CONSTRAINT accounts_legal_hold CHECK ((((legal_hold_reference IS NULL) = (legal_hold_at IS NULL)) AND ((legal_hold_reference IS NOT NULL) OR (legal_hold_by_account_id IS NULL)))),
    CONSTRAINT accounts_legal_hold_reference_check CHECK (((char_length(legal_hold_reference) >= 1) AND (char_length(legal_hold_reference) <= 200))),
    CONSTRAINT accounts_master_key_generation_check CHECK ((master_key_generation > 0)),
    CONSTRAINT accounts_opaque_check CHECK ((((opaque_record IS NULL) = (opaque_suite IS NULL)) AND ((opaque_record IS NULL) = (opaque_server_key_id IS NULL)))),
    CONSTRAINT accounts_opaque_record_check CHECK (((octet_length(opaque_record) >= 1) AND (octet_length(opaque_record) <= 1024))),
    CONSTRAINT accounts_opaque_server_key_id_check CHECK ((opaque_server_key_id > 0)),
    CONSTRAINT accounts_opaque_suite_check CHECK ((opaque_suite = 1)),
    CONSTRAINT accounts_keys_set_up CHECK (((keys_set_up_at IS NULL) OR ((octet_length(master_key_envelope) > 0) AND (octet_length(recovery_key_envelope) > 0) AND (octet_length(drive_xwing_public_key) > 0) AND (octet_length(account_authority_public_key) > 0) AND (account_authority_key_id IS NOT NULL) AND (account_incarnation_id IS NOT NULL) AND (octet_length(drive_signing_public_key) > 0) AND (key_binding IS NOT NULL) AND (octet_length(drive_key_binding) > 0)))),
    CONSTRAINT accounts_role_check CHECK ((role = ANY (ARRAY['member'::text, 'admin'::text, 'breakGlassAdmin'::text]))),
    CONSTRAINT accounts_state_check CHECK ((state = ANY (ARRAY['active'::text, 'suspended'::text, 'closing'::text]))),
    CONSTRAINT accounts_suspended_before_close CHECK (((suspended_before_close IS NULL) OR (state = 'closing'::text))),
    CONSTRAINT accounts_suspended_reason CHECK (((state = 'suspended'::text) = (suspended_reason IS NOT NULL))),
    CONSTRAINT accounts_totp_secret_sealed_check CHECK (((totp_secret_sealed IS NULL) OR ((octet_length(totp_secret_sealed) >= 47) AND (octet_length(totp_secret_sealed) <= 200)))),
    CONSTRAINT accounts_totp_pending_secret_sealed_check CHECK (((totp_pending_secret_sealed IS NULL) OR ((octet_length(totp_pending_secret_sealed) >= 47) AND (octet_length(totp_pending_secret_sealed) <= 200)))),
    CONSTRAINT accounts_username_format CHECK ((username ~ '^[a-z0-9_-]{3,32}$'::text)),
    CONSTRAINT accounts_version_retention_days_check CHECK ((version_retention_days > 0)),
    CONSTRAINT accounts_account_authority_key_id_bytes CHECK ((octet_length(account_authority_key_id) = 32)),
    CONSTRAINT accounts_account_incarnation_id_bytes CHECK ((octet_length(account_incarnation_id) = 32))
);


--
-- Name: webauthn_ceremonies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webauthn_ceremonies (
    challenge bytea NOT NULL,
    kind text NOT NULL,
    account_id uuid NOT NULL,
    bound_to bytea NOT NULL,
    state bytea NOT NULL,
    second_factor_proved boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT webauthn_ceremonies_bound_to_check CHECK ((octet_length(bound_to) = 32)),
    CONSTRAINT webauthn_ceremonies_challenge_check CHECK ((octet_length(challenge) = 16)),
    CONSTRAINT webauthn_ceremonies_kind_check CHECK ((kind = ANY (ARRAY['register'::text, 'signIn'::text, 'proof'::text])))
);


--
-- Name: admin_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit_log ALTER COLUMN id SET DEFAULT nextval('public.admin_audit_log_id_seq'::regclass);


--
-- Name: chat_group_endorsements seq; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_group_endorsements ALTER COLUMN seq SET DEFAULT nextval('public.chat_group_endorsement_seq'::regclass);


--
-- Name: mail_sending_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sending_events ALTER COLUMN id SET DEFAULT nextval('public.mail_sending_events_id_seq'::regclass);


--
-- Name: storage_pending_deletions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.storage_pending_deletions ALTER COLUMN id SET DEFAULT nextval('public.storage_pending_deletions_id_seq'::regclass);


--
-- Name: account_data_keys account_data_keys_pkey; Type: CONSTRAINT; Schema: account_keys; Owner: -
--

ALTER TABLE ONLY account_keys.account_data_keys
    ADD CONSTRAINT account_data_keys_pkey PRIMARY KEY (account_id, generation);


--
-- Name: destruction_events destruction_events_pkey; Type: CONSTRAINT; Schema: account_keys; Owner: -
--

ALTER TABLE ONLY account_keys.destruction_events
    ADD CONSTRAINT destruction_events_pkey PRIMARY KEY (id);


--
-- Name: mail_group_data_keys mail_group_data_keys_pkey; Type: CONSTRAINT; Schema: account_keys; Owner: -
--

ALTER TABLE ONLY account_keys.mail_group_data_keys
    ADD CONSTRAINT mail_group_data_keys_pkey PRIMARY KEY (group_id, generation);


--
-- Name: account_heads account_heads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_heads
    ADD CONSTRAINT account_heads_pkey PRIMARY KEY (account_id, sequence);


--
-- Name: account_names account_names_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_names
    ADD CONSTRAINT account_names_name_key UNIQUE (name);


--
-- Name: account_names account_names_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_names
    ADD CONSTRAINT account_names_pkey PRIMARY KEY (folded);


--
-- Name: account_record_feeds account_record_feeds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_record_feeds
    ADD CONSTRAINT account_record_feeds_pkey PRIMARY KEY (account_id);


--
-- Name: account_record_tombstones account_record_tombstones_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_record_tombstones
    ADD CONSTRAINT account_record_tombstones_pkey PRIMARY KEY (account_id, change_seq);


--
-- Name: account_records account_records_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_records
    ADD CONSTRAINT account_records_pkey PRIMARY KEY (account_id, scope, record_id);


--
-- Name: account_renames account_renames_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_renames
    ADD CONSTRAINT account_renames_pkey PRIMARY KEY (incarnation_id, sequence);


--
-- Name: account_roots account_roots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_roots
    ADD CONSTRAINT account_roots_pkey PRIMARY KEY (account_id, purpose, object);


--
-- Name: account_security_events account_security_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_security_events
    ADD CONSTRAINT account_security_events_pkey PRIMARY KEY (id);


--
-- Name: admin_audit_anchor admin_audit_anchor_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit_anchor
    ADD CONSTRAINT admin_audit_anchor_pkey PRIMARY KEY (only_row);


--
-- Name: admin_audit_log admin_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit_log
    ADD CONSTRAINT admin_audit_log_pkey PRIMARY KEY (id);


--
-- Name: photos_album_items photos_album_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_album_items
    ADD CONSTRAINT photos_album_items_pkey PRIMARY KEY (album_id, file_id);


--
-- Name: auth_grants auth_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_grants
    ADD CONSTRAINT auth_grants_pkey PRIMARY KEY (token_hash);


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
-- Name: backup_runs backup_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_runs
    ADD CONSTRAINT backup_runs_pkey PRIMARY KEY (kind);


--
-- Name: calendar_alarm_recomputes calendar_alarm_recomputes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_alarm_recomputes
    ADD CONSTRAINT calendar_alarm_recomputes_pkey PRIMARY KEY (account_id, calendar_id);


--
-- Name: calendar_alarms calendar_alarms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_alarms
    ADD CONSTRAINT calendar_alarms_pkey PRIMARY KEY (account_id, event_id, reminder);


--
-- Name: calendar_event_reminders calendar_event_reminders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_event_reminders
    ADD CONSTRAINT calendar_event_reminders_pkey PRIMARY KEY (event_id, account_id);


--
-- Name: calendar_events calendar_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_events
    ADD CONSTRAINT calendar_events_pkey PRIMARY KEY (id);


--
-- Name: calendar_members calendar_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_members
    ADD CONSTRAINT calendar_members_pkey PRIMARY KEY (calendar_id, account_id);


--
-- Name: calendar_push_subscriptions calendar_push_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_push_subscriptions
    ADD CONSTRAINT calendar_push_subscriptions_pkey PRIMARY KEY (session_id);


--
-- Name: calendar_push_subscriptions calendar_push_subscriptions_account_id_endpoint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_push_subscriptions
    ADD CONSTRAINT calendar_push_subscriptions_account_id_endpoint_key UNIQUE (account_id, endpoint);


--
-- Name: calendar_account_settings calendar_account_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_account_settings
    ADD CONSTRAINT calendar_account_settings_pkey PRIMARY KEY (account_id);


--
-- Name: calendars calendars_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendars
    ADD CONSTRAINT calendars_pkey PRIMARY KEY (id);


--
-- Name: calendar_event_attendees calendar_event_attendees_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_event_attendees
    ADD CONSTRAINT calendar_event_attendees_pkey PRIMARY KEY (shared_event_id, token);


--
-- Name: calendar_event_invitees calendar_event_invitees_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_event_invitees
    ADD CONSTRAINT calendar_event_invitees_pkey PRIMARY KEY (shared_event_id, invitee_account_id);


--
-- Name: calendar_events calendar_events_calendar_id_shared_event_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_events
    ADD CONSTRAINT calendar_events_calendar_id_shared_event_id_key UNIQUE (calendar_id, shared_event_id);


--
-- Name: calendar_invitations calendar_invitations_calendar_id_invitee_account_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_invitations
    ADD CONSTRAINT calendar_invitations_calendar_id_invitee_account_id_key UNIQUE (calendar_id, invitee_account_id);


--
-- Name: calendar_invitations calendar_invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_invitations
    ADD CONSTRAINT calendar_invitations_pkey PRIMARY KEY (id);


--
-- Name: calendar_keys calendar_keys_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_keys
    ADD CONSTRAINT calendar_keys_fingerprint_key UNIQUE (fingerprint);


--
-- Name: calendar_keys calendar_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_keys
    ADD CONSTRAINT calendar_keys_pkey PRIMARY KEY (calendar_id, key_generation);


--
-- Name: calendar_link_passphrases calendar_link_passphrases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_link_passphrases
    ADD CONSTRAINT calendar_link_passphrases_pkey PRIMARY KEY (link_id, key_generation);


--
-- Name: calendar_links calendar_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_links
    ADD CONSTRAINT calendar_links_pkey PRIMARY KEY (id);


--
-- Name: calendar_member_shares calendar_member_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_member_shares
    ADD CONSTRAINT calendar_member_shares_pkey PRIMARY KEY (calendar_id, account_id, key_generation);


--
-- Name: calendar_member_tombstones calendar_member_tombstones_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_member_tombstones
    ADD CONSTRAINT calendar_member_tombstones_pkey PRIMARY KEY (calendar_id, account_id);


--
-- Name: calendar_shared_events calendar_shared_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_shared_events
    ADD CONSTRAINT calendar_shared_events_pkey PRIMARY KEY (id);


--
-- Name: calendar_shared_events calendar_shared_events_uid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_shared_events
    ADD CONSTRAINT calendar_shared_events_uid_key UNIQUE NULLS NOT DISTINCT (home_calendar_id, uid, recurrence_id);


--
-- Name: chat_account_identities chat_account_identities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_account_identities
    ADD CONSTRAINT chat_account_identities_pkey PRIMARY KEY (account_id);


--
-- Name: chat_anonymous_send_ids chat_anonymous_send_ids_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_anonymous_send_ids
    ADD CONSTRAINT chat_anonymous_send_ids_pkey PRIMARY KEY (recipient_account_id, capability_hash, send_id);


--
-- Name: chat_backup_bases chat_backup_bases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_bases
    ADD CONSTRAINT chat_backup_bases_pkey PRIMARY KEY (account_id, object_id);


--
-- Name: chat_backup_bases chat_backup_bases_storage_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_bases
    ADD CONSTRAINT chat_backup_bases_storage_path_key UNIQUE (storage_path);


--
-- Name: chat_backup_bases chat_backup_bases_account_id_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_bases
    ADD CONSTRAINT chat_backup_bases_account_id_generation_key UNIQUE (account_id, generation);


--
-- Name: chat_backup_device_heads chat_backup_device_heads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_device_heads
    ADD CONSTRAINT chat_backup_device_heads_pkey PRIMARY KEY (account_id, source_device_id);


--
-- Name: chat_backup_media_objects chat_backup_media_objects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_objects
    ADD CONSTRAINT chat_backup_media_objects_pkey PRIMARY KEY (account_id, media_id);


--
-- Name: chat_backup_media_objects chat_backup_media_objects_storage_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_objects
    ADD CONSTRAINT chat_backup_media_objects_storage_path_key UNIQUE (storage_path);


--
-- Name: chat_backup_media_operations chat_backup_media_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_operations
    ADD CONSTRAINT chat_backup_media_operations_pkey PRIMARY KEY (account_id, operation_id);


--
-- Name: chat_backup_media_reconciliation_entries chat_backup_media_reconciliation_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliation_entries
    ADD CONSTRAINT chat_backup_media_reconciliation_entries_pkey PRIMARY KEY (account_id, operation_id, reference_id);


--
-- Name: chat_backup_media_reconciliation_pages chat_backup_media_reconciliation_pages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliation_pages
    ADD CONSTRAINT chat_backup_media_reconciliation_pages_pkey PRIMARY KEY (account_id, operation_id, page_index);


--
-- Name: chat_backup_media_reconciliations chat_backup_media_reconciliations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliations
    ADD CONSTRAINT chat_backup_media_reconciliations_pkey PRIMARY KEY (account_id, operation_id);


--
-- Name: chat_backup_media_reconciliations chat_backup_media_reconciliations_account_id_target_generation_; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliations
    ADD CONSTRAINT chat_backup_media_reconciliations_account_id_target_generation_ UNIQUE (account_id, target_generation);


--
-- Name: chat_backup_media_references chat_backup_media_references_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_references
    ADD CONSTRAINT chat_backup_media_references_pkey PRIMARY KEY (account_id, reference_id);


--
-- Name: chat_backup_provision_operations chat_backup_provision_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_provision_operations
    ADD CONSTRAINT chat_backup_provision_operations_pkey PRIMARY KEY (account_id, operation_id);


--
-- Name: chat_backup_segments chat_backup_segments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_segments
    ADD CONSTRAINT chat_backup_segments_pkey PRIMARY KEY (account_id, cursor);


--
-- Name: chat_backup_segments chat_backup_segments_account_id_operation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_segments
    ADD CONSTRAINT chat_backup_segments_account_id_operation_id_key UNIQUE (account_id, operation_id);


--
-- Name: chat_backup_segments chat_backup_segments_account_id_source_device_id_device_sequen_; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_segments
    ADD CONSTRAINT chat_backup_segments_account_id_source_device_id_device_sequen_ UNIQUE (account_id, source_device_id, device_sequence);


--
-- Name: chat_backups chat_backups_backup_incarnation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backups
    ADD CONSTRAINT chat_backups_backup_incarnation_id_key UNIQUE (backup_incarnation_id);


--
-- Name: chat_backups chat_backups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backups
    ADD CONSTRAINT chat_backups_pkey PRIMARY KEY (account_id);


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
-- Name: chat_call_links chat_call_links_owner_account_id_nonce_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_links
    ADD CONSTRAINT chat_call_links_owner_account_id_nonce_key UNIQUE (owner_account_id, nonce);


--
-- Name: chat_call_links chat_call_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_links
    ADD CONSTRAINT chat_call_links_pkey PRIMARY KEY (room_id);


--
-- Name: chat_delivery_capabilities chat_delivery_capabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_delivery_capabilities
    ADD CONSTRAINT chat_delivery_capabilities_pkey PRIMARY KEY (account_id);


--
-- Name: chat_device_manifest_history chat_device_manifest_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_device_manifest_history
    ADD CONSTRAINT chat_device_manifest_history_pkey PRIMARY KEY (account_id, incarnation_id, version);


--
-- Name: chat_device_manifests chat_device_manifests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_device_manifests
    ADD CONSTRAINT chat_device_manifests_pkey PRIMARY KEY (account_id);


--
-- Name: chat_group_avatars chat_group_avatars_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_group_avatars
    ADD CONSTRAINT chat_group_avatars_pkey PRIMARY KEY (group_id, hash);


--
-- Name: chat_group_changes chat_group_changes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_group_changes
    ADD CONSTRAINT chat_group_changes_pkey PRIMARY KEY (group_id, revision);


--
-- Name: chat_group_endorsements chat_group_endorsements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_group_endorsements
    ADD CONSTRAINT chat_group_endorsements_pkey PRIMARY KEY (group_id, pseudonym, expiration);


--
-- Name: chat_group_nonces chat_group_nonces_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_group_nonces
    ADD CONSTRAINT chat_group_nonces_pkey PRIMARY KEY (nonce);


--
-- Name: chat_group_seen_pseudonyms chat_group_seen_pseudonyms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_group_seen_pseudonyms
    ADD CONSTRAINT chat_group_seen_pseudonyms_pkey PRIMARY KEY (group_id, pseudonym_hash);


--
-- Name: chat_groups chat_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_groups
    ADD CONSTRAINT chat_groups_pkey PRIMARY KEY (group_id);


--
-- Name: chat_link_tokens chat_link_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_link_tokens
    ADD CONSTRAINT chat_link_tokens_pkey PRIMARY KEY (token_hash);


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
-- Name: chat_media_federation_pull_grants chat_media_federation_pull_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_pull_grants
    ADD CONSTRAINT chat_media_federation_pull_grants_pkey PRIMARY KEY (destination, operation_id);


--
-- Name: chat_media_federation_pull_grants chat_media_federation_pull_grants_recipient_attachment_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_pull_grants
    ADD CONSTRAINT chat_media_federation_pull_grants_recipient_attachment_key UNIQUE (destination, recipient_account_id, attachment_id);


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
    ADD CONSTRAINT chat_media_origin_delivery_operations_pkey PRIMARY KEY (origin_account_id, operation_id);


--
-- Name: chat_media_references chat_media_references_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_references
    ADD CONSTRAINT chat_media_references_pkey PRIMARY KEY (id);


--
-- Name: chat_media_references chat_media_references_account_id_attachment_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_references
    ADD CONSTRAINT chat_media_references_account_id_attachment_id_key UNIQUE (account_id, attachment_id);


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
-- Name: chat_multi_send_ids chat_multi_send_ids_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_multi_send_ids
    ADD CONSTRAINT chat_multi_send_ids_pkey PRIMARY KEY (account_id, device_id, send_id);


--
-- Name: chat_one_time_kyber_pre_keys chat_one_time_kyber_pre_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_one_time_kyber_pre_keys
    ADD CONSTRAINT chat_one_time_kyber_pre_keys_pkey PRIMARY KEY (account_id, device_id, key_id);


--
-- Name: chat_one_time_pre_keys chat_one_time_pre_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_one_time_pre_keys
    ADD CONSTRAINT chat_one_time_pre_keys_pkey PRIMARY KEY (account_id, device_id, key_id);


--
-- Name: chat_profiles chat_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_profiles
    ADD CONSTRAINT chat_profiles_pkey PRIMARY KEY (account_id, profile_version);


--
-- Name: chat_push_subscriptions chat_push_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_push_subscriptions
    ADD CONSTRAINT chat_push_subscriptions_pkey PRIMARY KEY (account_id, device_id);


--
-- Name: chat_sends chat_sends_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sends
    ADD CONSTRAINT chat_sends_pkey PRIMARY KEY (sender_account_id, sender_device_id, send_id, delivery_scope);


--
-- Name: chat_shared_payloads chat_shared_payloads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_shared_payloads
    ADD CONSTRAINT chat_shared_payloads_pkey PRIMARY KEY (id);


--
-- Name: chat_web_push_key chat_web_push_key_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_web_push_key
    ADD CONSTRAINT chat_web_push_key_pkey PRIMARY KEY (id);


--
-- Name: chat_zk_server_keys chat_zk_server_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_zk_server_keys
    ADD CONSTRAINT chat_zk_server_keys_pkey PRIMARY KEY (key_id);


--
-- Name: drive_collection_key_epoch_history drive_collection_key_epoch_history_collection_id_epoch_statemen; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_collection_key_epoch_history
    ADD CONSTRAINT drive_collection_key_epoch_history_collection_id_epoch_statemen UNIQUE (collection_id, epoch_statement_hash);


--
-- Name: drive_collection_key_epoch_history drive_collection_key_epoch_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_collection_key_epoch_history
    ADD CONSTRAINT drive_collection_key_epoch_history_pkey PRIMARY KEY (collection_id, epoch);


--
-- Name: drive_collection_shares drive_collection_shares_collection_id_recipient_account_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_collection_shares
    ADD CONSTRAINT drive_collection_shares_collection_id_recipient_account_id_key UNIQUE (collection_id, recipient_account_id);


--
-- Name: drive_collection_shares drive_collection_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_collection_shares
    ADD CONSTRAINT drive_collection_shares_pkey PRIMARY KEY (id);


--
-- Name: drive_collections drive_collections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_collections
    ADD CONSTRAINT drive_collections_pkey PRIMARY KEY (id);


--
-- Name: consents consents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.consents
    ADD CONSTRAINT consents_pkey PRIMARY KEY (id);


--
-- Name: consents consents_seq_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.consents
    ADD CONSTRAINT consents_seq_key UNIQUE (seq);


--
-- Name: contacts_emails contacts_emails_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts_emails
    ADD CONSTRAINT contacts_emails_pkey PRIMARY KEY (contact_id, address);


--
-- Name: contacts contacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts
    ADD CONSTRAINT contacts_pkey PRIMARY KEY (id);


--
-- Name: contacts contacts_account_id_uid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts
    ADD CONSTRAINT contacts_account_id_uid_key UNIQUE (account_id, uid);


--
-- Name: account_device_tickets account_device_tickets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_device_tickets
    ADD CONSTRAINT account_device_tickets_pkey PRIMARY KEY (token_hash);


--
-- Name: account_devices account_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_devices
    ADD CONSTRAINT account_devices_pkey PRIMARY KEY (account_id, device_id);


--
-- Name: document_acknowledgements document_acknowledgements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_acknowledgements
    ADD CONSTRAINT document_acknowledgements_pkey PRIMARY KEY (account_id, document_id);


--
-- Name: drive_federation_mutations drive_federation_mutations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federation_mutations
    ADD CONSTRAINT drive_federation_mutations_pkey PRIMARY KEY (origin, request_id);


--
-- Name: drive_profile_keys drive_profile_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_profile_keys
    ADD CONSTRAINT drive_profile_keys_pkey PRIMARY KEY (account_id, direction, peer_server, peer_account_id);


--
-- Name: drive_federated_incoming_file_shares federated_incoming_file_share_account_id_owner_server_capabil_k; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_incoming_file_shares
    ADD CONSTRAINT federated_incoming_file_share_account_id_owner_server_capabil_k UNIQUE (account_id, owner_server, capability_hash);


--
-- Name: drive_federated_incoming_file_shares drive_federated_incoming_file_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_incoming_file_shares
    ADD CONSTRAINT drive_federated_incoming_file_shares_pkey PRIMARY KEY (id);


--
-- Name: drive_federated_incoming_shares drive_federated_incoming_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_incoming_shares
    ADD CONSTRAINT drive_federated_incoming_shares_pkey PRIMARY KEY (id);


--
-- Name: drive_federated_incoming_shares drive_federated_incoming_shares_account_id_owner_server_capabil; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_incoming_shares
    ADD CONSTRAINT drive_federated_incoming_shares_account_id_owner_server_capabil UNIQUE (account_id, owner_server, capability_hash);


--
-- Name: drive_federated_outgoing_file_shares drive_federated_outgoing_file_shares_capability_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_outgoing_file_shares
    ADD CONSTRAINT drive_federated_outgoing_file_shares_capability_hash_key UNIQUE (capability_hash);


--
-- Name: drive_federated_outgoing_file_shares drive_federated_outgoing_file_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_outgoing_file_shares
    ADD CONSTRAINT drive_federated_outgoing_file_shares_pkey PRIMARY KEY (id);


--
-- Name: drive_federated_outgoing_shares drive_federated_outgoing_shares_capability_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_outgoing_shares
    ADD CONSTRAINT drive_federated_outgoing_shares_capability_hash_key UNIQUE (capability_hash);


--
-- Name: drive_federated_outgoing_shares drive_federated_outgoing_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_outgoing_shares
    ADD CONSTRAINT drive_federated_outgoing_shares_pkey PRIMARY KEY (id);


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
-- Name: federation_inbound federation_inbound_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_inbound
    ADD CONSTRAINT federation_inbound_pkey PRIMARY KEY (kind, origin, sequence);


--
-- Name: federation_inbound_state federation_inbound_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_inbound_state
    ADD CONSTRAINT federation_inbound_state_pkey PRIMARY KEY (kind, origin);


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
-- Name: federation_outbox federation_outbox_kind_destination_sequence_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_outbox
    ADD CONSTRAINT federation_outbox_kind_destination_sequence_key UNIQUE (kind, destination, sequence);


--
-- Name: federation_outbox federation_outbox_kind_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_outbox
    ADD CONSTRAINT federation_outbox_kind_idempotency_key_key UNIQUE (kind, idempotency_key);


--
-- Name: federation_outbox federation_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_outbox
    ADD CONSTRAINT federation_outbox_pkey PRIMARY KEY (id);


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
-- Name: federation_sequences federation_sequences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_sequences
    ADD CONSTRAINT federation_sequences_pkey PRIMARY KEY (kind, destination);


--
-- Name: feedback feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback
    ADD CONSTRAINT feedback_pkey PRIMARY KEY (id);


--
-- Name: drive_file_assets drive_file_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_assets
    ADD CONSTRAINT drive_file_assets_pkey PRIMARY KEY (file_id, asset_id);


--
-- Name: drive_file_key_history drive_file_key_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_key_history
    ADD CONSTRAINT drive_file_key_history_pkey PRIMARY KEY (file_id, generation);


--
-- Name: collab_sender_floors collab_sender_floors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collab_sender_floors
    ADD CONSTRAINT collab_sender_floors_pkey PRIMARY KEY (file_id, sender_server, sender_account_id, sender_device_id, seq_prefix);


--
-- Name: drive_file_shares drive_file_shares_file_id_recipient_account_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_shares
    ADD CONSTRAINT drive_file_shares_file_id_recipient_account_id_key UNIQUE (file_id, recipient_account_id);


--
-- Name: drive_file_shares drive_file_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_shares
    ADD CONSTRAINT drive_file_shares_pkey PRIMARY KEY (id);


--
-- Name: drive_file_thumbnails drive_file_thumbnails_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_thumbnails
    ADD CONSTRAINT drive_file_thumbnails_pkey PRIMARY KEY (file_id, variant);


--
-- Name: collab_update_log collab_update_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collab_update_log
    ADD CONSTRAINT collab_update_log_pkey PRIMARY KEY (file_id, seq);


--
-- Name: drive_file_versions drive_file_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_versions
    ADD CONSTRAINT drive_file_versions_pkey PRIMARY KEY (id);


--
-- Name: drive_file_versions drive_file_versions_revision_content_check; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.drive_file_versions
    ADD CONSTRAINT drive_file_versions_revision_content_check CHECK ((octet_length(revision_content_envelope) = 356));


--
-- Name: drive_files drive_files_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_files
    ADD CONSTRAINT drive_files_pkey PRIMARY KEY (id);


--
-- Name: drive_files drive_files_revision_content_check; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.drive_files
    ADD CONSTRAINT drive_files_revision_content_check CHECK ((octet_length(revision_content_envelope) = 356));


--
-- Name: job_heartbeats job_heartbeats_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_heartbeats
    ADD CONSTRAINT job_heartbeats_pkey PRIMARY KEY (job);


--
-- Name: legal_documents legal_documents_kind_version_language_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.legal_documents
    ADD CONSTRAINT legal_documents_kind_version_language_key UNIQUE (kind, version, language);


--
-- Name: legal_documents legal_documents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.legal_documents
    ADD CONSTRAINT legal_documents_pkey PRIMARY KEY (id);


--
-- Name: chat_live_location_streams chat_live_location_streams_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_live_location_streams
    ADD CONSTRAINT chat_live_location_streams_pkey PRIMARY KEY (stream_id);


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
    ADD CONSTRAINT mail_auto_replies_pkey PRIMARY KEY (account_id);


--
-- Name: mail_auto_reply_sent mail_auto_reply_sent_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_auto_reply_sent
    ADD CONSTRAINT mail_auto_reply_sent_pkey PRIMARY KEY (account_id, sender_hash);


--
-- Name: mail_change_floors mail_change_floors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_change_floors
    ADD CONSTRAINT mail_change_floors_pkey PRIMARY KEY (mailbox_owner);


--
-- Name: mail_dkim_keys mail_dkim_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_dkim_keys
    ADD CONSTRAINT mail_dkim_keys_pkey PRIMARY KEY (id);


--
-- Name: mail_domain_blocks mail_domain_blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_domain_blocks
    ADD CONSTRAINT mail_domain_blocks_pkey PRIMARY KEY (name);


--
-- Name: mail_domain_catch_all_days mail_domain_catch_all_days_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_domain_catch_all_days
    ADD CONSTRAINT mail_domain_catch_all_days_pkey PRIMARY KEY (domain_id, day);


--
-- Name: mail_domains mail_domains_organization_name; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_domains
    ADD CONSTRAINT mail_domains_organization_name UNIQUE (organization_id, name);


--
-- Name: mail_domains mail_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_domains
    ADD CONSTRAINT mail_domains_pkey PRIMARY KEY (id);


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
-- Name: mail_folders mail_folders_account_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_folders
    ADD CONSTRAINT mail_folders_account_id_id_key UNIQUE (account_id, id);


--
-- Name: mail_forwarding_code_sends mail_forwarding_code_sends_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_forwarding_code_sends
    ADD CONSTRAINT mail_forwarding_code_sends_pkey PRIMARY KEY (destination, day);


--
-- Name: mail_forwarding_keys mail_forwarding_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_forwarding_keys
    ADD CONSTRAINT mail_forwarding_keys_pkey PRIMARY KEY (forwarding_id, forwarder_fingerprint);


--
-- Name: mail_forwarding_quota mail_forwarding_quota_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_forwarding_quota
    ADD CONSTRAINT mail_forwarding_quota_pkey PRIMARY KEY (account_id);


--
-- Name: mail_forwardings mail_forwardings_forwarder_address_id_forwardee_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_forwardings
    ADD CONSTRAINT mail_forwardings_forwarder_address_id_forwardee_email_key UNIQUE (forwarder_address_id, forwardee_email);


--
-- Name: mail_forwardings mail_forwardings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_forwardings
    ADD CONSTRAINT mail_forwardings_pkey PRIMARY KEY (id);


--
-- Name: mail_group_key_lists mail_group_key_lists_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_key_lists
    ADD CONSTRAINT mail_group_key_lists_pkey PRIMARY KEY (group_id, sequence);


--
-- Name: mail_group_key_shares mail_group_key_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_key_shares
    ADD CONSTRAINT mail_group_key_shares_pkey PRIMARY KEY (group_key_id, account_id);


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
    ADD CONSTRAINT mail_group_members_pkey PRIMARY KEY (group_id, account_id);


--
-- Name: mail_group_objects mail_group_objects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_objects
    ADD CONSTRAINT mail_group_objects_pkey PRIMARY KEY (object_key);


--
-- Name: mail_group_signers mail_group_signers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_signers
    ADD CONSTRAINT mail_group_signers_pkey PRIMARY KEY (group_id, from_sequence);


--
-- Name: mail_group_signing_shares mail_group_signing_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_signing_shares
    ADD CONSTRAINT mail_group_signing_shares_pkey PRIMARY KEY (group_id, signer_public_key, account_id);


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
    ADD CONSTRAINT mail_image_senders_pkey PRIMARY KEY (account_id, address);


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
-- Name: mail_labels mail_labels_account_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_labels
    ADD CONSTRAINT mail_labels_account_id_id_key UNIQUE (account_id, id);


--
-- Name: mail_message_labels mail_message_labels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_message_labels
    ADD CONSTRAINT mail_message_labels_pkey PRIMARY KEY (message_id, label_id);


--
-- Name: mail_message_tombstones mail_message_tombstones_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_message_tombstones
    ADD CONSTRAINT mail_message_tombstones_pkey PRIMARY KEY (mailbox_owner, change_xid, id);


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
-- Name: mail_sender_rules mail_sender_rules_account_id_pattern_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sender_rules
    ADD CONSTRAINT mail_sender_rules_account_id_pattern_key UNIQUE (account_id, pattern);


--
-- Name: mail_sending_events mail_sending_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sending_events
    ADD CONSTRAINT mail_sending_events_pkey PRIMARY KEY (id);


--
-- Name: mail_sending_policies mail_sending_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sending_policies
    ADD CONSTRAINT mail_sending_policies_pkey PRIMARY KEY (account_id);


--
-- Name: mail_settings mail_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_settings
    ADD CONSTRAINT mail_settings_pkey PRIMARY KEY (account_id);


--
-- Name: opaque_login_states opaque_login_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.opaque_login_states
    ADD CONSTRAINT opaque_login_states_pkey PRIMARY KEY (login_id);


--
-- Name: opaque_server_setups opaque_server_setups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.opaque_server_setups
    ADD CONSTRAINT opaque_server_setups_pkey PRIMARY KEY (key_id);


--
-- Name: organization_key_shares organization_key_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_key_shares
    ADD CONSTRAINT organization_key_shares_pkey PRIMARY KEY (key_id, account_id);


--
-- Name: organization_keys organization_keys_of_organization; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_keys
    ADD CONSTRAINT organization_keys_of_organization UNIQUE (id, organization_id);


--
-- Name: organization_keys organization_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_keys
    ADD CONSTRAINT organization_keys_pkey PRIMARY KEY (id);


--
-- Name: organization_member_escrows organization_member_escrows_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_member_escrows
    ADD CONSTRAINT organization_member_escrows_pkey PRIMARY KEY (organization_id, account_id, key_id);


--
-- Name: organization_members organization_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_members
    ADD CONSTRAINT organization_members_pkey PRIMARY KEY (organization_id, account_id);


--
-- Name: organization_entitlements organization_entitlements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_entitlements
    ADD CONSTRAINT organization_entitlements_pkey PRIMARY KEY (organization_id, key);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: pass_pin_failures pass_pin_failures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_pin_failures
    ADD CONSTRAINT pass_pin_failures_pkey PRIMARY KEY (sign_in_id);


--
-- Name: pass_pins pass_pins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_pins
    ADD CONSTRAINT pass_pins_pkey PRIMARY KEY (account_id);


--
-- Name: pass_settings pass_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_settings
    ADD CONSTRAINT pass_settings_pkey PRIMARY KEY (account_id);


--
-- Name: photos_library_folders photos_library_folders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_library_folders
    ADD CONSTRAINT photos_library_folders_pkey PRIMARY KEY (account_id, collection_id);


--
-- Name: photos_preferences photos_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_preferences
    ADD CONSTRAINT photos_preferences_pkey PRIMARY KEY (account_id);


--
-- Name: drive_public_link_reports drive_public_link_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_public_link_reports
    ADD CONSTRAINT drive_public_link_reports_pkey PRIMARY KEY (id);


--
-- Name: drive_public_shares drive_public_shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_public_shares
    ADD CONSTRAINT drive_public_shares_pkey PRIMARY KEY (id);


--
-- Name: drive_public_shares drive_public_shares_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_public_shares
    ADD CONSTRAINT drive_public_shares_token_key UNIQUE (token);


--
-- Name: rate_counters rate_counters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_counters
    ADD CONSTRAINT rate_counters_pkey PRIMARY KEY (scope, subject, window_start);


--
-- Name: registration_code_uses registration_code_uses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_code_uses
    ADD CONSTRAINT registration_code_uses_pkey PRIMARY KEY (code_id, account_id);


--
-- Name: registration_code_uses registration_code_uses_account_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_code_uses
    ADD CONSTRAINT registration_code_uses_account_id_key UNIQUE (account_id);


--
-- Name: registration_codes registration_codes_code_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_codes
    ADD CONSTRAINT registration_codes_code_hash_key UNIQUE (code_hash);


--
-- Name: registration_codes registration_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_codes
    ADD CONSTRAINT registration_codes_pkey PRIMARY KEY (id);


--
-- Name: remote_account_manifests remote_account_manifests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remote_account_manifests
    ADD CONSTRAINT remote_account_manifests_pkey PRIMARY KEY (domain, account_id);


--
-- Name: remote_account_renames remote_account_renames_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remote_account_renames
    ADD CONSTRAINT remote_account_renames_pkey PRIMARY KEY (server, account_id);


--
-- Name: remote_manifest_failures remote_manifest_failures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remote_manifest_failures
    ADD CONSTRAINT remote_manifest_failures_pkey PRIMARY KEY (domain, account_id);


--
-- Name: retired_account_ids retired_account_ids_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.retired_account_ids
    ADD CONSTRAINT retired_account_ids_pkey PRIMARY KEY (id);


--
-- Name: chat_sealed_sender_certificates chat_sealed_sender_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sealed_sender_certificates
    ADD CONSTRAINT chat_sealed_sender_certificates_pkey PRIMARY KEY (certificate_id);


--
-- Name: chat_sealed_sender_certificates chat_sealed_sender_certificates_root_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sealed_sender_certificates
    ADD CONSTRAINT chat_sealed_sender_certificates_root_id_key UNIQUE (root_id);


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
-- Name: storage_pending_deletions storage_pending_deletions_kind_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.storage_pending_deletions
    ADD CONSTRAINT storage_pending_deletions_kind_key_key UNIQUE (kind, key);


--
-- Name: storage_pending_deletions storage_pending_deletions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.storage_pending_deletions
    ADD CONSTRAINT storage_pending_deletions_pkey PRIMARY KEY (id);


--
-- Name: two_factor_recovery_codes two_factor_recovery_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.two_factor_recovery_codes
    ADD CONSTRAINT two_factor_recovery_codes_pkey PRIMARY KEY (account_id, code_mac);


--
-- Name: drive_uploads drive_uploads_file_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_uploads
    ADD CONSTRAINT drive_uploads_file_id_key UNIQUE (file_id);


--
-- Name: drive_uploads drive_uploads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_uploads
    ADD CONSTRAINT drive_uploads_pkey PRIMARY KEY (id);


--
-- Name: account_map_preferences account_map_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_map_preferences
    ADD CONSTRAINT account_map_preferences_pkey PRIMARY KEY (account_id);


--
-- Name: account_security_keys account_security_keys_credential_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_security_keys
    ADD CONSTRAINT account_security_keys_credential_id_key UNIQUE (credential_id);


--
-- Name: account_security_keys account_security_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_security_keys
    ADD CONSTRAINT account_security_keys_pkey PRIMARY KEY (id);


--
-- Name: account_entitlements account_entitlements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_entitlements
    ADD CONSTRAINT account_entitlements_pkey PRIMARY KEY (account_id, key);


--
-- Name: account_ui_preferences account_ui_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_ui_preferences
    ADD CONSTRAINT account_ui_preferences_pkey PRIMARY KEY (account_id);


--
-- Name: accounts accounts_key_binding_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_key_binding_key UNIQUE (key_binding);


--
-- Name: accounts accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);


--
-- Name: accounts accounts_username_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_username_unique UNIQUE (username);


--
-- Name: webauthn_ceremonies webauthn_ceremonies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_pkey PRIMARY KEY (challenge);


--
-- Name: account_data_keys_sealing_key_id; Type: INDEX; Schema: account_keys; Owner: -
--

CREATE INDEX account_data_keys_sealing_key_id ON account_keys.account_data_keys USING btree (sealing_key_id);


--
-- Name: destruction_events_accounts; Type: INDEX; Schema: account_keys; Owner: -
--

CREATE INDEX destruction_events_accounts ON account_keys.destruction_events USING btree (category) WHERE (subjects IS NOT NULL);


--
-- Name: destruction_events_at; Type: INDEX; Schema: account_keys; Owner: -
--

CREATE INDEX destruction_events_at ON account_keys.destruction_events USING btree (at);


--
-- Name: mail_group_data_keys_sealing_key_id; Type: INDEX; Schema: account_keys; Owner: -
--

CREATE INDEX mail_group_data_keys_sealing_key_id ON account_keys.mail_group_data_keys USING btree (sealing_key_id);


--
-- Name: account_names_free; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_names_free ON public.account_names USING btree (free_at) WHERE (state = 'held'::text);


--
-- Name: account_names_one_current; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX account_names_one_current ON public.account_names USING btree (account_id) WHERE (state = 'current'::text);


--
-- Name: account_names_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_names_account ON public.account_names USING btree (account_id);


--
-- Name: account_record_tombstones_age; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_record_tombstones_age ON public.account_record_tombstones USING btree (deleted_at);


--
-- Name: account_record_tombstones_feed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_record_tombstones_feed ON public.account_record_tombstones USING btree (account_id, scope, change_seq);


--
-- Name: account_records_feed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_records_feed ON public.account_records USING btree (account_id, scope, change_seq);


--
-- Name: account_renames_current; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_renames_current ON public.account_renames USING btree (current);


--
-- Name: account_renames_previous; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_renames_previous ON public.account_renames USING btree (previous);


--
-- Name: account_renames_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_renames_account ON public.account_renames USING btree (account_id, accepted_at DESC);


--
-- Name: account_security_events_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_security_events_subject ON public.account_security_events USING btree (subject_account_id, at DESC, id DESC);


--
-- Name: auth_grants_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_grants_expiry ON public.auth_grants USING btree (expires_at);


--
-- Name: auth_grants_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_grants_account ON public.auth_grants USING btree (account_id);


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
-- Name: auth_sessions_account_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_sessions_account_idx ON public.auth_sessions USING btree (account_id) WHERE (revoked_at IS NULL);


--
-- Name: calendar_alarms_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_alarms_due ON public.calendar_alarms USING btree (fire_at);


--
-- Name: calendar_alarms_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_alarms_event ON public.calendar_alarms USING btree (event_id);


--
-- Name: calendar_event_reminders_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_event_reminders_account ON public.calendar_event_reminders USING btree (account_id);


--
-- Name: calendar_events_shared_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_events_shared_event ON public.calendar_events USING btree (shared_event_id);


--
-- Name: calendar_event_invitees_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_event_invitees_account ON public.calendar_event_invitees USING btree (invitee_account_id);


--
-- Name: calendar_invitations_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_invitations_pending ON public.calendar_invitations USING btree (invitee_account_id) WHERE (state = 'pending'::text);


--
-- Name: calendar_links_calendar; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_links_calendar ON public.calendar_links USING btree (calendar_id);


--
-- Name: calendar_member_shares_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_member_shares_account ON public.calendar_member_shares USING btree (account_id);


--
-- Name: calendar_member_tombstones_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_member_tombstones_account ON public.calendar_member_tombstones USING btree (account_id);


--
-- Name: calendar_shared_events_author_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_shared_events_author_account ON public.calendar_shared_events USING btree (author_account_id);


--
-- Name: calendar_shared_events_author_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_shared_events_author_address ON public.calendar_shared_events USING btree (author_address_id);


--
-- Name: calendar_shared_events_uid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_shared_events_uid ON public.calendar_shared_events USING btree (uid);


--
-- Name: calendar_shared_events_window; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_shared_events_window ON public.calendar_shared_events USING btree (start_utc, range_end_utc);


--
-- Name: calendar_members_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_members_account ON public.calendar_members USING btree (account_id);


--
-- Name: calendars_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendars_owner ON public.calendars USING btree (owner_account_id);


--
-- Name: chat_backup_bases_staging_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_backup_bases_staging_idx ON public.chat_backup_bases USING btree (state, created_at);


--
-- Name: chat_backup_media_reconciliation_entries_order_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_backup_media_reconciliation_entries_order_idx ON public.chat_backup_media_reconciliation_entries USING btree (account_id, operation_id, reference_id);


--
-- Name: chat_backup_media_references_media_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_backup_media_references_media_idx ON public.chat_backup_media_references USING btree (account_id, media_id);


--
-- Name: chat_backup_segments_restore_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_backup_segments_restore_idx ON public.chat_backup_segments USING btree (account_id, cursor);


--
-- Name: chat_group_avatars_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_group_avatars_expires_at ON public.chat_group_avatars USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: chat_group_avatars_one_current; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_group_avatars_one_current ON public.chat_group_avatars USING btree (group_id) WHERE (expires_at IS NULL);


--
-- Name: chat_group_avatars_one_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_group_avatars_one_pending ON public.chat_group_avatars USING btree (group_id) WHERE (expires_at IS NOT NULL);


--
-- Name: chat_group_endorsements_by_seq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_group_endorsements_by_seq ON public.chat_group_endorsements USING btree (group_id, seq);


--
-- Name: chat_group_endorsements_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_group_endorsements_expiry ON public.chat_group_endorsements USING btree (expiration);


--
-- Name: chat_group_nonces_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_group_nonces_expires_at ON public.chat_group_nonces USING btree (expires_at);


--
-- Name: chat_link_tokens_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_link_tokens_account ON public.chat_link_tokens USING btree (account_id, expires_at);


--
-- Name: chat_mailbox_recipient_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mailbox_recipient_idx ON public.chat_mailbox USING btree (recipient_account_id, recipient_device_id, cursor);


--
-- Name: chat_mailbox_shared_payload; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_mailbox_shared_payload ON public.chat_mailbox USING btree (shared_payload_id) WHERE (shared_payload_id IS NOT NULL);


--
-- Name: chat_multi_send_ids_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_multi_send_ids_created_at ON public.chat_multi_send_ids USING btree (created_at);


--
-- Name: chat_profiles_one_current; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_profiles_one_current ON public.chat_profiles USING btree (account_id) WHERE is_current;


--
-- Name: chat_zk_server_keys_issuing; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX chat_zk_server_keys_issuing ON public.chat_zk_server_keys USING btree ((true)) WHERE (issues_until IS NULL);


--
-- Name: drive_collections_unique_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX drive_collections_unique_name ON public.drive_collections USING btree (parent_collection_id, name_hash) WHERE ((deleted_at IS NULL) AND (name_hash IS NOT NULL) AND (parent_collection_id IS NOT NULL));


--
-- Name: drive_collections_unique_top_level_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX drive_collections_unique_top_level_name ON public.drive_collections USING btree (owner_account_id, name_hash) WHERE ((deleted_at IS NULL) AND (name_hash IS NOT NULL) AND (parent_collection_id IS NULL) AND (kind = 'folder'::text));


--
-- Name: consents_latest; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX consents_latest ON public.consents USING btree (account_id, purpose, seq DESC);


--
-- Name: account_device_tickets_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_device_tickets_expiry_idx ON public.account_device_tickets USING btree (expires_at);


--
-- Name: account_devices_session; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_devices_session ON public.account_devices USING btree (session_id);


--
-- Name: drive_federation_mutations_share_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_federation_mutations_share_created_idx ON public.drive_federation_mutations USING btree (share_id, created_at DESC);


--
-- Name: drive_federated_incoming_shares_owner_server_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_federated_incoming_shares_owner_server_idx ON public.drive_federated_incoming_shares USING btree (owner_server, created_at DESC);


--
-- Name: drive_federated_outgoing_file_shares_file_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_federated_outgoing_file_shares_file_idx ON public.drive_federated_outgoing_file_shares USING btree (file_id);


--
-- Name: drive_federated_outgoing_file_shares_recipient; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_federated_outgoing_file_shares_recipient ON public.drive_federated_outgoing_file_shares USING btree (recipient_server, recipient_account_id);


--
-- Name: drive_federated_outgoing_shares_recipient; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_federated_outgoing_shares_recipient ON public.drive_federated_outgoing_shares USING btree (recipient_server, recipient_account_id);


--
-- Name: drive_federated_outgoing_shares_recipient_server_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_federated_outgoing_shares_recipient_server_idx ON public.drive_federated_outgoing_shares USING btree (recipient_server, created_at DESC);


--
-- Name: federation_domain_rules_updated_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_domain_rules_updated_idx ON public.federation_domain_rules USING btree (updated_at DESC, domain, feature);


--
-- Name: federation_feature_policy_current_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_feature_policy_current_idx ON public.federation_feature_policy_documents USING btree (domain, feature_type, sequence DESC);


--
-- Name: federation_inbound_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_inbound_created ON public.federation_inbound USING btree (created_at);


--
-- Name: federation_inbound_media_operation; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX federation_inbound_media_operation ON public.federation_inbound USING btree (origin, transaction_id) WHERE (kind = 'media'::text);


--
-- Name: federation_outbox_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_outbox_due ON public.federation_outbox USING btree (kind, next_attempt_at) WHERE (state = 'pending'::text);


--
-- Name: federation_outbox_media_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_outbox_media_pending ON public.federation_outbox USING btree (sender_account_id) WHERE ((kind = 'media'::text) AND (state = 'pending'::text));


--
-- Name: federation_outbox_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_outbox_pending ON public.federation_outbox USING btree (kind, destination, sequence) WHERE (state = 'pending'::text);


--
-- Name: federation_outbox_rename_incarnation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_outbox_rename_incarnation ON public.federation_outbox USING btree (((payload ->> 'incarnation'::text))) WHERE (kind = 'rename'::text);


--
-- Name: federation_outbox_settled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX federation_outbox_settled ON public.federation_outbox USING btree (updated_at) WHERE (state <> 'pending'::text);


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
-- Name: drive_file_assets_uploader_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_file_assets_uploader_idx ON public.drive_file_assets USING btree (uploader_account_id);


--
-- Name: drive_file_shares_recipient_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_file_shares_recipient_idx ON public.drive_file_shares USING btree (recipient_account_id);


--
-- Name: drive_file_thumbnails_uploader_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_file_thumbnails_uploader_idx ON public.drive_file_thumbnails USING btree (uploader_account_id);


--
-- Name: collab_update_log_sender_seq_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX collab_update_log_sender_seq_unique ON public.collab_update_log USING btree (file_id, sender_server, sender_account_id, sender_device_id, sender_seq);


--
-- Name: drive_file_versions_timeline; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_file_versions_timeline ON public.drive_file_versions USING btree (file_id, created_at DESC);


--
-- Name: drive_files_ciphertext_digest_backfill_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_files_ciphertext_digest_backfill_idx ON public.drive_files USING btree (created_at, id) WHERE ((ciphertext_sha256 IS NULL) AND (deleted_at IS NULL) AND (NOT original_pruned));


--
-- Name: drive_files_content_revision_id_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX drive_files_content_revision_id_key ON public.drive_files USING btree (content_revision_id);


--
-- Name: drive_files_fed_share_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_files_fed_share_idx ON public.drive_files USING btree (fed_share_id) WHERE (fed_share_id IS NOT NULL);


--
-- Name: drive_files_unique_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX drive_files_unique_name ON public.drive_files USING btree (collection_id, name_hash) WHERE ((deleted_at IS NULL) AND (name_hash IS NOT NULL));


--
-- Name: idx_admin_audit_log_id_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_admin_audit_log_id_desc ON public.admin_audit_log USING btree (id DESC);


--
-- Name: idx_photos_album_items_file; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_photos_album_items_file ON public.photos_album_items USING btree (file_id);


--
-- Name: idx_chat_call_link_knocks_room; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_call_link_knocks_room ON public.chat_call_link_knocks USING btree (room_id, status, created_at);


--
-- Name: idx_chat_call_links_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_call_links_owner ON public.chat_call_links USING btree (owner_account_id, created_at DESC);


--
-- Name: idx_chat_media_inbound_pending_recipient; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_media_inbound_pending_recipient ON public.chat_media_federation_inbound_pending USING btree (recipient_account_id);


--
-- Name: idx_chat_media_references_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_media_references_account ON public.chat_media_references USING btree (account_id);


--
-- Name: idx_chat_media_uploads_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_media_uploads_updated ON public.chat_media_uploads USING btree (updated_at);


--
-- Name: idx_chat_media_uploads_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_media_uploads_account ON public.chat_media_uploads USING btree (account_id);


--
-- Name: idx_drive_collections_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_drive_collections_deleted_at ON public.drive_collections USING btree (deleted_at) WHERE (deleted_at IS NOT NULL);


--
-- Name: idx_drive_collections_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_drive_collections_owner ON public.drive_collections USING btree (owner_account_id);


--
-- Name: idx_drive_collections_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_drive_collections_parent ON public.drive_collections USING btree (parent_collection_id);


--
-- Name: idx_drive_collections_trash_root; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_drive_collections_trash_root ON public.drive_collections USING btree (trash_root_id) WHERE (trash_root_id IS NOT NULL);


--
-- Name: idx_contacts_emails_account_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_contacts_emails_account_address ON public.contacts_emails USING btree (account_id, address text_pattern_ops);


--
-- Name: idx_contacts_account_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_contacts_account_name ON public.contacts USING btree (account_id, lower(name), id);


--
-- Name: idx_drive_files_collection; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_drive_files_collection ON public.drive_files USING btree (collection_id);


--
-- Name: idx_drive_files_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_drive_files_deleted_at ON public.drive_files USING btree (deleted_at) WHERE (deleted_at IS NOT NULL);


--
-- Name: idx_drive_files_trash_root; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_drive_files_trash_root ON public.drive_files USING btree (trash_root_id) WHERE (trash_root_id IS NOT NULL);


--
-- Name: idx_drive_files_uploader; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_drive_files_uploader ON public.drive_files USING btree (uploader_account_id);


--
-- Name: idx_mail_address_keys_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_address_keys_address ON public.mail_address_keys USING btree (address_id);


--
-- Name: idx_mail_address_keys_one_primary; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mail_address_keys_one_primary ON public.mail_address_keys USING btree (address_id) WHERE is_primary;


--
-- Name: idx_mail_addresses_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_addresses_account ON public.mail_addresses USING btree (account_id);


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

CREATE UNIQUE INDEX idx_mail_filter_runs_one ON public.mail_filter_runs USING btree (account_id) WHERE (finished_at IS NULL);


--
-- Name: idx_mail_filters_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_filters_account ON public.mail_filters USING btree (account_id, "position") WHERE enabled;


--
-- Name: idx_mail_folders_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_folders_account ON public.mail_folders USING btree (account_id, parent_id, "position");


--
-- Name: idx_mail_group_key_shares_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_group_key_shares_account ON public.mail_group_key_shares USING btree (account_id);


--
-- Name: idx_mail_group_keys_primary; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mail_group_keys_primary ON public.mail_group_keys USING btree (group_id) WHERE is_primary;


--
-- Name: idx_mail_group_members_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_group_members_account ON public.mail_group_members USING btree (account_id);


--
-- Name: idx_mail_group_objects_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_group_objects_group ON public.mail_group_objects USING btree (group_id);


--
-- Name: idx_mail_labels_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_labels_account ON public.mail_labels USING btree (account_id, "position");


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

CREATE INDEX idx_mail_messages_changes ON public.mail_messages USING btree (mailbox_owner, change_xid, id);


--
-- Name: idx_mail_messages_custom_folder; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_custom_folder ON public.mail_messages USING btree (account_id, custom_folder, received_at DESC, id) WHERE (custom_folder IS NOT NULL);


--
-- Name: idx_mail_messages_folder; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_folder ON public.mail_messages USING btree (account_id, folder, received_at DESC, id);


--
-- Name: idx_mail_messages_inbound_once; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mail_messages_inbound_once ON public.mail_messages USING btree (address_id, message_id_hash) WHERE ((direction = 'inbound'::text) AND (message_id_hash IS NOT NULL));


--
-- Name: idx_mail_messages_message_id_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_message_id_hash ON public.mail_messages USING btree (mailbox_owner, message_id_hash) WHERE (message_id_hash IS NOT NULL);


--
-- Name: idx_mail_messages_notify; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_notify ON public.mail_messages USING btree (mailbox_owner, notify_at) WHERE (notify_at IS NOT NULL);


--
-- Name: idx_mail_messages_object_once; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mail_messages_object_once ON public.mail_messages USING btree (object_key) WHERE (key_packet IS NULL);


--
-- Name: idx_mail_messages_owner_folder; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_owner_folder ON public.mail_messages USING btree (mailbox_owner, folder, received_at DESC, id);


--
-- Name: idx_mail_messages_owner_received; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_owner_received ON public.mail_messages USING btree (mailbox_owner, received_at DESC, id DESC);


--
-- Name: idx_mail_messages_owner_thread; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_owner_thread ON public.mail_messages USING btree (mailbox_owner, thread_id, received_at);


--
-- Name: idx_mail_messages_search_tokens; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_search_tokens ON public.mail_messages USING gin (search_tokens);


--
-- Name: idx_mail_messages_sender_recently; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_sender_recently ON public.mail_messages USING btree (sender_account_id, received_at) WHERE (external_recipients > 0);


--
-- Name: idx_mail_messages_sent_message_id_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_sent_message_id_hash ON public.mail_messages USING btree (sender_account_id, message_id_hash) WHERE ((direction = 'outbound'::text) AND (message_id_hash IS NOT NULL));


--
-- Name: idx_mail_messages_sent_recently; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_messages_sent_recently ON public.mail_messages USING btree (account_id, received_at) WHERE (external_recipients > 0);


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

CREATE INDEX idx_mail_messages_unwanted ON public.mail_messages USING btree (mailbox_owner, folder_changed_at) WHERE (folder = ANY (ARRAY['trash'::text, 'spam'::text]));


--
-- Name: idx_mail_sending_events_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_sending_events_account ON public.mail_sending_events USING btree (account_id, kind, created_at);


--
-- Name: idx_mail_sending_policies_attention; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mail_sending_policies_attention ON public.mail_sending_policies USING btree (updated_at) WHERE ((paused_at IS NOT NULL) OR (flagged_at IS NOT NULL));


--
-- Name: idx_drive_public_shares_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_drive_public_shares_token ON public.drive_public_shares USING btree (token);


--
-- Name: idx_shares_collection; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shares_collection ON public.drive_collection_shares USING btree (collection_id);


--
-- Name: idx_shares_recipient; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shares_recipient ON public.drive_collection_shares USING btree (recipient_account_id);


--
-- Name: idx_drive_uploads_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_drive_uploads_updated_at ON public.drive_uploads USING btree (updated_at);


--
-- Name: idx_drive_uploads_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_drive_uploads_account_id ON public.drive_uploads USING btree (account_id);


--
-- Name: idx_accounts_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_accounts_username ON public.accounts USING btree (username);


--
-- Name: legal_documents_current; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX legal_documents_current ON public.legal_documents USING btree (kind, published_at DESC);


--
-- Name: chat_live_location_streams_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX chat_live_location_streams_expires_idx ON public.chat_live_location_streams USING btree (expires_at);


--
-- Name: mail_addresses_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_addresses_address ON public.mail_addresses USING btree (address);


--
-- Name: mail_addresses_live; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mail_addresses_live ON public.mail_addresses USING btree (folded) WHERE (state <> 'freed'::text);


--
-- Name: mail_dkim_keys_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mail_dkim_keys_active ON public.mail_dkim_keys USING btree (state) WHERE (state = 'active'::text);


--
-- Name: mail_dkim_keys_selector; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mail_dkim_keys_selector ON public.mail_dkim_keys USING btree (selector) WHERE (state <> 'retired'::text);


--
-- Name: mail_domains_checked; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_domains_checked ON public.mail_domains USING btree (checked_at) WHERE (removed_at IS NULL);


--
-- Name: mail_domains_held; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mail_domains_held ON public.mail_domains USING btree (name) WHERE (state = ANY (ARRAY[1, 2]));


--
-- Name: mail_forwardings_forwardee; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_forwardings_forwardee ON public.mail_forwardings USING btree (forwardee_address_id) WHERE (forwardee_address_id IS NOT NULL);


--
-- Name: mail_forwardings_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_forwardings_account ON public.mail_forwardings USING btree (account_id);


--
-- Name: mail_group_signing_shares_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_group_signing_shares_account ON public.mail_group_signing_shares USING btree (account_id);


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
-- Name: mail_outbox_finished; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_outbox_finished ON public.mail_outbox USING btree (finished_at) WHERE (finished_at IS NOT NULL);


--
-- Name: mail_outbox_one_per_draft; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mail_outbox_one_per_draft ON public.mail_outbox USING btree (draft_id) WHERE (state = ANY (ARRAY['pending'::text, 'sending'::text]));


--
-- Name: opaque_login_states_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX opaque_login_states_expiry ON public.opaque_login_states USING btree (expires_at);


--
-- Name: opaque_login_states_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX opaque_login_states_name ON public.opaque_login_states USING btree (canonical_name, expires_at);


--
-- Name: opaque_login_states_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX opaque_login_states_source ON public.opaque_login_states USING btree (source, expires_at);


--
-- Name: organization_keys_one_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX organization_keys_one_active ON public.organization_keys USING btree (organization_id) WHERE (state = 'active'::text);


--
-- Name: organization_members_one_per_account; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX organization_members_one_per_account ON public.organization_members USING btree (account_id);


--
-- Name: pass_pin_failures_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX pass_pin_failures_account ON public.pass_pin_failures USING btree (account_id);


--
-- Name: drive_public_link_reports_open; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_public_link_reports_open ON public.drive_public_link_reports USING btree (created_at) WHERE (resolved_at IS NULL);


--
-- Name: drive_public_link_reports_share; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_public_link_reports_share ON public.drive_public_link_reports USING btree (share_id);


--
-- Name: drive_public_shares_file_target_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX drive_public_shares_file_target_idx ON public.drive_public_shares USING btree (target_id) WHERE (share_type = 'file'::text);


--
-- Name: rate_counters_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rate_counters_expiry ON public.rate_counters USING btree (expires_at);


--
-- Name: registration_codes_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX registration_codes_created_at ON public.registration_codes USING btree (created_at DESC);


--
-- Name: remote_account_renames_addresses; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX remote_account_renames_addresses ON public.remote_account_renames USING gin (addresses);


--
-- Name: storage_pending_deletions_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX storage_pending_deletions_due ON public.storage_pending_deletions USING btree (queued_at, id);


--
-- Name: storage_pending_deletions_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX storage_pending_deletions_key ON public.storage_pending_deletions USING btree (key);


--
-- Name: drive_uploads_revision_id_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX drive_uploads_revision_id_key ON public.drive_uploads USING btree (revision_id);


--
-- Name: account_security_keys_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_security_keys_account ON public.account_security_keys USING btree (account_id);


--
-- Name: accounts_closing_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX accounts_closing_due ON public.accounts USING btree (closes_at) WHERE (state = 'closing'::text);


--
-- Name: accounts_one_break_glass; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX accounts_one_break_glass ON public.accounts USING btree ((true)) WHERE (role = 'breakGlassAdmin'::text);


--
-- Name: webauthn_ceremonies_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webauthn_ceremonies_expiry ON public.webauthn_ceremonies USING btree (expires_at);


--
-- Name: account_security_events account_security_events_count_step; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER account_security_events_count_step BEFORE UPDATE OF count ON public.account_security_events FOR EACH ROW EXECUTE FUNCTION public.account_security_events_count_step();


--
-- Name: drive_collections drive_collections_not_in_albums; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER drive_collections_not_in_albums BEFORE INSERT OR UPDATE OF parent_collection_id ON public.drive_collections FOR EACH ROW EXECUTE FUNCTION public.kutup_no_folders_in_albums();


--
-- Name: drive_files drive_files_not_in_albums; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER drive_files_not_in_albums BEFORE INSERT OR UPDATE OF collection_id ON public.drive_files FOR EACH ROW EXECUTE FUNCTION public.kutup_no_files_in_albums();


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
-- Name: organization_members organization_after_member_gone; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER organization_after_member_gone AFTER DELETE ON public.organization_members FOR EACH ROW EXECUTE FUNCTION public.organization_after_member_gone();


--
-- Name: account_data_keys account_data_keys_account_id_fkey; Type: FK CONSTRAINT; Schema: account_keys; Owner: -
--

ALTER TABLE ONLY account_keys.account_data_keys
    ADD CONSTRAINT account_data_keys_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_group_data_keys mail_group_data_keys_group_id_fkey; Type: FK CONSTRAINT; Schema: account_keys; Owner: -
--

ALTER TABLE ONLY account_keys.mail_group_data_keys
    ADD CONSTRAINT mail_group_data_keys_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: account_heads account_heads_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_heads
    ADD CONSTRAINT account_heads_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_names account_names_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_names
    ADD CONSTRAINT account_names_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: account_record_feeds account_record_feeds_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_record_feeds
    ADD CONSTRAINT account_record_feeds_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_record_tombstones account_record_tombstones_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_record_tombstones
    ADD CONSTRAINT account_record_tombstones_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_records account_records_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_records
    ADD CONSTRAINT account_records_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_renames account_renames_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_renames
    ADD CONSTRAINT account_renames_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: account_roots account_roots_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_roots
    ADD CONSTRAINT account_roots_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_security_events account_security_events_actor_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_security_events
    ADD CONSTRAINT account_security_events_actor_account_id_fkey FOREIGN KEY (actor_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: account_security_events account_security_events_subject_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_security_events
    ADD CONSTRAINT account_security_events_subject_account_id_fkey FOREIGN KEY (subject_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: photos_album_items photos_album_items_added_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_album_items
    ADD CONSTRAINT photos_album_items_added_by_account_id_fkey FOREIGN KEY (added_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: photos_album_items photos_album_items_album_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_album_items
    ADD CONSTRAINT photos_album_items_album_id_fkey FOREIGN KEY (album_id) REFERENCES public.drive_collections(id) ON DELETE CASCADE;


--
-- Name: photos_album_items photos_album_items_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_album_items
    ADD CONSTRAINT photos_album_items_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.drive_files(id) ON DELETE CASCADE;


--
-- Name: auth_grants auth_grants_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_grants
    ADD CONSTRAINT auth_grants_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.auth_sessions(id) ON DELETE CASCADE;


--
-- Name: auth_grants auth_grants_target_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_grants
    ADD CONSTRAINT auth_grants_target_account_id_fkey FOREIGN KEY (target_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: auth_grants auth_grants_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_grants
    ADD CONSTRAINT auth_grants_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


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
-- Name: auth_sessions auth_sessions_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_alarm_recomputes calendar_alarm_recomputes_calendar_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_alarm_recomputes
    ADD CONSTRAINT calendar_alarm_recomputes_calendar_id_fkey FOREIGN KEY (calendar_id) REFERENCES public.calendars(id) ON DELETE CASCADE;


--
-- Name: calendar_alarm_recomputes calendar_alarm_recomputes_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_alarm_recomputes
    ADD CONSTRAINT calendar_alarm_recomputes_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_alarms calendar_alarms_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_alarms
    ADD CONSTRAINT calendar_alarms_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.calendar_events(id) ON DELETE CASCADE;


--
-- Name: calendar_alarms calendar_alarms_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_alarms
    ADD CONSTRAINT calendar_alarms_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_event_reminders calendar_event_reminders_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_event_reminders
    ADD CONSTRAINT calendar_event_reminders_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.calendar_events(id) ON DELETE CASCADE;


--
-- Name: calendar_event_reminders calendar_event_reminders_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_event_reminders
    ADD CONSTRAINT calendar_event_reminders_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_events calendar_events_calendar_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_events
    ADD CONSTRAINT calendar_events_calendar_id_fkey FOREIGN KEY (calendar_id) REFERENCES public.calendars(id) ON DELETE CASCADE;


--
-- Name: calendar_event_attendees calendar_event_attendees_shared_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_event_attendees
    ADD CONSTRAINT calendar_event_attendees_shared_event_id_fkey FOREIGN KEY (shared_event_id) REFERENCES public.calendar_shared_events(id) ON DELETE CASCADE;


--
-- Name: calendar_event_invitees calendar_event_invitees_invitee_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_event_invitees
    ADD CONSTRAINT calendar_event_invitees_invitee_account_id_fkey FOREIGN KEY (invitee_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_event_invitees calendar_event_invitees_invitee_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_event_invitees
    ADD CONSTRAINT calendar_event_invitees_invitee_address_id_fkey FOREIGN KEY (invitee_address_id) REFERENCES public.mail_addresses(id) ON DELETE CASCADE;


--
-- Name: calendar_event_invitees calendar_event_invitees_shared_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_event_invitees
    ADD CONSTRAINT calendar_event_invitees_shared_event_id_fkey FOREIGN KEY (shared_event_id) REFERENCES public.calendar_shared_events(id) ON DELETE CASCADE;


--
-- Name: calendar_events calendar_events_shared_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_events
    ADD CONSTRAINT calendar_events_shared_event_id_fkey FOREIGN KEY (shared_event_id) REFERENCES public.calendar_shared_events(id) ON DELETE CASCADE;


--
-- Name: calendar_invitations calendar_invitations_calendar_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_invitations
    ADD CONSTRAINT calendar_invitations_calendar_id_fkey FOREIGN KEY (calendar_id) REFERENCES public.calendars(id) ON DELETE CASCADE;


--
-- Name: calendar_invitations calendar_invitations_invited_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_invitations
    ADD CONSTRAINT calendar_invitations_invited_by_account_id_fkey FOREIGN KEY (invited_by_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_invitations calendar_invitations_invitee_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_invitations
    ADD CONSTRAINT calendar_invitations_invitee_account_id_fkey FOREIGN KEY (invitee_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_keys calendar_keys_calendar_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_keys
    ADD CONSTRAINT calendar_keys_calendar_id_fkey FOREIGN KEY (calendar_id) REFERENCES public.calendars(id) ON DELETE CASCADE;


--
-- Name: calendar_link_passphrases calendar_link_passphrases_calendar_id_key_generation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_link_passphrases
    ADD CONSTRAINT calendar_link_passphrases_calendar_id_key_generation_fkey FOREIGN KEY (calendar_id, key_generation) REFERENCES public.calendar_keys(calendar_id, key_generation) ON DELETE CASCADE;


--
-- Name: calendar_link_passphrases calendar_link_passphrases_link_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_link_passphrases
    ADD CONSTRAINT calendar_link_passphrases_link_id_fkey FOREIGN KEY (link_id) REFERENCES public.calendar_links(id) ON DELETE CASCADE;


--
-- Name: calendar_links calendar_links_calendar_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_links
    ADD CONSTRAINT calendar_links_calendar_id_fkey FOREIGN KEY (calendar_id) REFERENCES public.calendars(id) ON DELETE CASCADE;


--
-- Name: calendar_links calendar_links_created_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_links
    ADD CONSTRAINT calendar_links_created_by_account_id_fkey FOREIGN KEY (created_by_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_member_shares calendar_member_shares_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_member_shares
    ADD CONSTRAINT calendar_member_shares_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_member_shares calendar_member_shares_calendar_id_key_generation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_member_shares
    ADD CONSTRAINT calendar_member_shares_calendar_id_key_generation_fkey FOREIGN KEY (calendar_id, key_generation) REFERENCES public.calendar_keys(calendar_id, key_generation) ON DELETE CASCADE;


--
-- Name: calendar_member_tombstones calendar_member_tombstones_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_member_tombstones
    ADD CONSTRAINT calendar_member_tombstones_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_shared_events calendar_shared_events_author_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_shared_events
    ADD CONSTRAINT calendar_shared_events_author_account_id_fkey FOREIGN KEY (author_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: calendar_shared_events calendar_shared_events_author_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_shared_events
    ADD CONSTRAINT calendar_shared_events_author_address_id_fkey FOREIGN KEY (author_address_id) REFERENCES public.mail_addresses(id) ON DELETE SET NULL;


--
-- Name: calendar_shared_events calendar_shared_events_home_calendar_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_shared_events
    ADD CONSTRAINT calendar_shared_events_home_calendar_id_fkey FOREIGN KEY (home_calendar_id) REFERENCES public.calendars(id) ON DELETE CASCADE;


--
-- Name: calendar_members calendar_members_calendar_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_members
    ADD CONSTRAINT calendar_members_calendar_id_fkey FOREIGN KEY (calendar_id) REFERENCES public.calendars(id) ON DELETE CASCADE;


--
-- Name: calendar_members calendar_members_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_members
    ADD CONSTRAINT calendar_members_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_push_subscriptions calendar_push_subscriptions_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_push_subscriptions
    ADD CONSTRAINT calendar_push_subscriptions_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.auth_sessions(id) ON DELETE CASCADE;


--
-- Name: calendar_push_subscriptions calendar_push_subscriptions_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_push_subscriptions
    ADD CONSTRAINT calendar_push_subscriptions_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendar_account_settings calendar_account_settings_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_account_settings
    ADD CONSTRAINT calendar_account_settings_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: calendars calendars_owner_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendars
    ADD CONSTRAINT calendars_owner_account_id_fkey FOREIGN KEY (owner_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_account_identities chat_account_identities_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_account_identities
    ADD CONSTRAINT chat_account_identities_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_anonymous_send_ids chat_anonymous_send_ids_recipient_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_anonymous_send_ids
    ADD CONSTRAINT chat_anonymous_send_ids_recipient_account_id_fkey FOREIGN KEY (recipient_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_backup_bases chat_backup_bases_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_bases
    ADD CONSTRAINT chat_backup_bases_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.chat_backups(account_id) ON DELETE CASCADE;


--
-- Name: chat_backup_device_heads chat_backup_device_heads_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_device_heads
    ADD CONSTRAINT chat_backup_device_heads_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.chat_backups(account_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_objects chat_backup_media_objects_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_objects
    ADD CONSTRAINT chat_backup_media_objects_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.chat_backups(account_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_operations chat_backup_media_operations_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_operations
    ADD CONSTRAINT chat_backup_media_operations_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.chat_backups(account_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_operations chat_backup_media_operations_account_id_media_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_operations
    ADD CONSTRAINT chat_backup_media_operations_account_id_media_id_fkey FOREIGN KEY (account_id, media_id) REFERENCES public.chat_backup_media_objects(account_id, media_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_reconciliation_entries chat_backup_media_reconciliation_entr_account_id_operation_id_f; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliation_entries
    ADD CONSTRAINT chat_backup_media_reconciliation_entr_account_id_operation_id_f FOREIGN KEY (account_id, operation_id) REFERENCES public.chat_backup_media_reconciliations(account_id, operation_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_reconciliation_entries chat_backup_media_reconciliation_entries_account_id_media_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliation_entries
    ADD CONSTRAINT chat_backup_media_reconciliation_entries_account_id_media_id_fk FOREIGN KEY (account_id, media_id) REFERENCES public.chat_backup_media_objects(account_id, media_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_reconciliation_pages chat_backup_media_reconciliation_page_account_id_operation_id_f; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliation_pages
    ADD CONSTRAINT chat_backup_media_reconciliation_page_account_id_operation_id_f FOREIGN KEY (account_id, operation_id) REFERENCES public.chat_backup_media_reconciliations(account_id, operation_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_reconciliations chat_backup_media_reconciliations_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_reconciliations
    ADD CONSTRAINT chat_backup_media_reconciliations_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.chat_backups(account_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_references chat_backup_media_references_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_references
    ADD CONSTRAINT chat_backup_media_references_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.chat_backups(account_id) ON DELETE CASCADE;


--
-- Name: chat_backup_media_references chat_backup_media_references_account_id_media_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_media_references
    ADD CONSTRAINT chat_backup_media_references_account_id_media_id_fkey FOREIGN KEY (account_id, media_id) REFERENCES public.chat_backup_media_objects(account_id, media_id) ON DELETE CASCADE;


--
-- Name: chat_backup_provision_operations chat_backup_provision_operations_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_provision_operations
    ADD CONSTRAINT chat_backup_provision_operations_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_backup_segments chat_backup_segments_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backup_segments
    ADD CONSTRAINT chat_backup_segments_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.chat_backups(account_id) ON DELETE CASCADE;


--
-- Name: chat_backups chat_backups_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_backups
    ADD CONSTRAINT chat_backups_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_call_link_knocks chat_call_link_knocks_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_link_knocks
    ADD CONSTRAINT chat_call_link_knocks_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: chat_call_link_knocks chat_call_link_knocks_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_link_knocks
    ADD CONSTRAINT chat_call_link_knocks_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.chat_call_links(room_id) ON DELETE CASCADE;


--
-- Name: chat_call_link_seats chat_call_link_seats_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_link_seats
    ADD CONSTRAINT chat_call_link_seats_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: chat_call_link_seats chat_call_link_seats_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_link_seats
    ADD CONSTRAINT chat_call_link_seats_room_id_fkey FOREIGN KEY (room_id) REFERENCES public.chat_call_links(room_id) ON DELETE CASCADE;


--
-- Name: chat_call_links chat_call_links_owner_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_call_links
    ADD CONSTRAINT chat_call_links_owner_account_id_fkey FOREIGN KEY (owner_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_delivery_capabilities chat_delivery_capabilities_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_delivery_capabilities
    ADD CONSTRAINT chat_delivery_capabilities_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_device_manifest_history chat_device_manifest_history_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_device_manifest_history
    ADD CONSTRAINT chat_device_manifest_history_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_device_manifests chat_device_manifests_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_device_manifests
    ADD CONSTRAINT chat_device_manifests_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_group_avatars chat_group_avatars_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_group_avatars
    ADD CONSTRAINT chat_group_avatars_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.chat_groups(group_id) ON DELETE CASCADE;


--
-- Name: chat_group_changes chat_group_changes_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_group_changes
    ADD CONSTRAINT chat_group_changes_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.chat_groups(group_id) ON DELETE CASCADE;


--
-- Name: chat_group_endorsements chat_group_endorsements_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_group_endorsements
    ADD CONSTRAINT chat_group_endorsements_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.chat_groups(group_id) ON DELETE CASCADE;


--
-- Name: chat_group_seen_pseudonyms chat_group_seen_pseudonyms_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_group_seen_pseudonyms
    ADD CONSTRAINT chat_group_seen_pseudonyms_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.chat_groups(group_id) ON DELETE CASCADE;


--
-- Name: chat_link_tokens chat_link_tokens_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_link_tokens
    ADD CONSTRAINT chat_link_tokens_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_mailbox chat_mailbox_recipient_account_id_recipient_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mailbox
    ADD CONSTRAINT chat_mailbox_recipient_account_id_recipient_device_id_fkey FOREIGN KEY (recipient_account_id, recipient_device_id) REFERENCES public.account_devices(account_id, device_id) ON DELETE CASCADE;


--
-- Name: chat_mailbox chat_mailbox_shared_payload_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_mailbox
    ADD CONSTRAINT chat_mailbox_shared_payload_id_fkey FOREIGN KEY (shared_payload_id) REFERENCES public.chat_shared_payloads(id) ON DELETE RESTRICT;


--
-- Name: chat_media_federation_inbound_pending chat_media_federation_inbound_pending_recipient_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_inbound_pending
    ADD CONSTRAINT chat_media_federation_inbound_pending_recipient_account_id_fkey FOREIGN KEY (recipient_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_media_federation_pull_grants chat_media_federation_pull_grants_attachment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_pull_grants
    ADD CONSTRAINT chat_media_federation_pull_grants_attachment_id_fkey FOREIGN KEY (attachment_id) REFERENCES public.chat_media_objects(attachment_id) ON DELETE CASCADE;


--
-- Name: chat_media_federation_pull_grants chat_media_federation_pull_grants_origin_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_federation_pull_grants
    ADD CONSTRAINT chat_media_federation_pull_grants_origin_account_id_fkey FOREIGN KEY (origin_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_media_objects chat_media_objects_origin_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_objects
    ADD CONSTRAINT chat_media_objects_origin_account_id_fkey FOREIGN KEY (origin_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_media_origin_delivery_operations chat_media_origin_delivery_operations_attachment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_origin_delivery_operations
    ADD CONSTRAINT chat_media_origin_delivery_operations_attachment_id_fkey FOREIGN KEY (attachment_id) REFERENCES public.chat_media_objects(attachment_id) ON DELETE CASCADE;


--
-- Name: chat_media_origin_delivery_operations chat_media_origin_delivery_operations_origin_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_origin_delivery_operations
    ADD CONSTRAINT chat_media_origin_delivery_operations_origin_account_id_fkey FOREIGN KEY (origin_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_media_origin_delivery_operations chat_media_origin_delivery_operations_recipient_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_origin_delivery_operations
    ADD CONSTRAINT chat_media_origin_delivery_operations_recipient_account_id_fkey FOREIGN KEY (recipient_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_media_references chat_media_references_attachment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_references
    ADD CONSTRAINT chat_media_references_attachment_id_fkey FOREIGN KEY (attachment_id) REFERENCES public.chat_media_objects(attachment_id) ON DELETE CASCADE;


--
-- Name: chat_media_references chat_media_references_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_references
    ADD CONSTRAINT chat_media_references_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_media_uploads chat_media_uploads_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_media_uploads
    ADD CONSTRAINT chat_media_uploads_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_multi_send_ids chat_multi_send_ids_account_id_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_multi_send_ids
    ADD CONSTRAINT chat_multi_send_ids_account_id_device_id_fkey FOREIGN KEY (account_id, device_id) REFERENCES public.account_devices(account_id, device_id) ON DELETE CASCADE;


--
-- Name: chat_one_time_kyber_pre_keys chat_one_time_kyber_pre_keys_account_id_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_one_time_kyber_pre_keys
    ADD CONSTRAINT chat_one_time_kyber_pre_keys_account_id_device_id_fkey FOREIGN KEY (account_id, device_id) REFERENCES public.account_devices(account_id, device_id) ON DELETE CASCADE;


--
-- Name: chat_one_time_pre_keys chat_one_time_pre_keys_account_id_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_one_time_pre_keys
    ADD CONSTRAINT chat_one_time_pre_keys_account_id_device_id_fkey FOREIGN KEY (account_id, device_id) REFERENCES public.account_devices(account_id, device_id) ON DELETE CASCADE;


--
-- Name: chat_profiles chat_profiles_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_profiles
    ADD CONSTRAINT chat_profiles_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: chat_push_subscriptions chat_push_subscriptions_account_id_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_push_subscriptions
    ADD CONSTRAINT chat_push_subscriptions_account_id_device_id_fkey FOREIGN KEY (account_id, device_id) REFERENCES public.account_devices(account_id, device_id) ON DELETE CASCADE;


--
-- Name: chat_sends chat_sends_sender_account_id_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_sends
    ADD CONSTRAINT chat_sends_sender_account_id_id_fkey FOREIGN KEY (sender_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_collection_key_epoch_history drive_collection_key_epoch_history_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_collection_key_epoch_history
    ADD CONSTRAINT drive_collection_key_epoch_history_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.drive_collections(id) ON DELETE CASCADE;


--
-- Name: drive_collection_shares drive_collection_shares_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_collection_shares
    ADD CONSTRAINT drive_collection_shares_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.drive_collections(id) ON DELETE CASCADE;


--
-- Name: drive_collection_shares drive_collection_shares_recipient_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_collection_shares
    ADD CONSTRAINT drive_collection_shares_recipient_account_id_fkey FOREIGN KEY (recipient_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_collection_shares drive_collection_shares_sharer_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_collection_shares
    ADD CONSTRAINT drive_collection_shares_sharer_account_id_fkey FOREIGN KEY (sharer_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_collections drive_collections_owner_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_collections
    ADD CONSTRAINT drive_collections_owner_account_id_fkey FOREIGN KEY (owner_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_collections drive_collections_parent_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_collections
    ADD CONSTRAINT drive_collections_parent_collection_id_fkey FOREIGN KEY (parent_collection_id) REFERENCES public.drive_collections(id) ON DELETE SET NULL;


--
-- Name: consents consents_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.consents
    ADD CONSTRAINT consents_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.legal_documents(id);


--
-- Name: consents consents_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.consents
    ADD CONSTRAINT consents_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: contacts_emails contacts_emails_contact_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts_emails
    ADD CONSTRAINT contacts_emails_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.contacts(id) ON DELETE CASCADE;


--
-- Name: contacts_emails contacts_emails_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts_emails
    ADD CONSTRAINT contacts_emails_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: contacts contacts_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts
    ADD CONSTRAINT contacts_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_device_tickets account_device_tickets_account_id_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_device_tickets
    ADD CONSTRAINT account_device_tickets_account_id_device_id_fkey FOREIGN KEY (account_id, device_id) REFERENCES public.account_devices(account_id, device_id) ON DELETE CASCADE;


--
-- Name: account_devices account_devices_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_devices
    ADD CONSTRAINT account_devices_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: document_acknowledgements document_acknowledgements_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_acknowledgements
    ADD CONSTRAINT document_acknowledgements_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.legal_documents(id);


--
-- Name: document_acknowledgements document_acknowledgements_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_acknowledgements
    ADD CONSTRAINT document_acknowledgements_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_federation_mutations drive_federation_mutations_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federation_mutations
    ADD CONSTRAINT drive_federation_mutations_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.drive_federated_outgoing_shares(id) ON DELETE CASCADE;


--
-- Name: drive_profile_keys drive_profile_keys_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_profile_keys
    ADD CONSTRAINT drive_profile_keys_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_federated_incoming_file_shares drive_federated_incoming_file_shares_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_incoming_file_shares
    ADD CONSTRAINT drive_federated_incoming_file_shares_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_federated_incoming_file_shares drive_federated_incoming_file_shares_owner_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_incoming_file_shares
    ADD CONSTRAINT drive_federated_incoming_file_shares_owner_fkey FOREIGN KEY (owner_server, owner_account_id) REFERENCES public.remote_account_renames(server, account_id);


--
-- Name: drive_federated_incoming_shares drive_federated_incoming_shares_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_incoming_shares
    ADD CONSTRAINT drive_federated_incoming_shares_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_federated_incoming_shares drive_federated_incoming_shares_owner_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_incoming_shares
    ADD CONSTRAINT drive_federated_incoming_shares_owner_fkey FOREIGN KEY (owner_server, owner_account_id) REFERENCES public.remote_account_renames(server, account_id);


--
-- Name: drive_federated_outgoing_file_shares drive_federated_outgoing_file_shares_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_outgoing_file_shares
    ADD CONSTRAINT drive_federated_outgoing_file_shares_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.drive_files(id) ON DELETE CASCADE;


--
-- Name: drive_federated_outgoing_file_shares drive_federated_outgoing_file_shares_recipient_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_outgoing_file_shares
    ADD CONSTRAINT drive_federated_outgoing_file_shares_recipient_fkey FOREIGN KEY (recipient_server, recipient_account_id) REFERENCES public.remote_account_renames(server, account_id);


--
-- Name: drive_federated_outgoing_file_shares drive_federated_outgoing_file_shares_sharer_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_outgoing_file_shares
    ADD CONSTRAINT drive_federated_outgoing_file_shares_sharer_account_id_fkey FOREIGN KEY (sharer_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_federated_outgoing_shares drive_federated_outgoing_shares_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_outgoing_shares
    ADD CONSTRAINT drive_federated_outgoing_shares_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.drive_collections(id) ON DELETE CASCADE;


--
-- Name: drive_federated_outgoing_shares drive_federated_outgoing_shares_recipient_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_outgoing_shares
    ADD CONSTRAINT drive_federated_outgoing_shares_recipient_fkey FOREIGN KEY (recipient_server, recipient_account_id) REFERENCES public.remote_account_renames(server, account_id);


--
-- Name: drive_federated_outgoing_shares drive_federated_outgoing_shares_sharer_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_federated_outgoing_shares
    ADD CONSTRAINT drive_federated_outgoing_shares_sharer_account_id_fkey FOREIGN KEY (sharer_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: federation_domain_rules federation_domain_rules_feature_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_domain_rules
    ADD CONSTRAINT federation_domain_rules_feature_fkey FOREIGN KEY (feature) REFERENCES public.federation_feature_policies(feature) ON DELETE CASCADE;


--
-- Name: federation_outbox federation_outbox_sender_account_id_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_outbox
    ADD CONSTRAINT federation_outbox_sender_account_id_id_fkey FOREIGN KEY (sender_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: federation_peer_identity_documents federation_peer_identity_documents_domain_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_peer_identity_documents
    ADD CONSTRAINT federation_peer_identity_documents_domain_fkey FOREIGN KEY (domain) REFERENCES public.federation_peer_identities(domain) ON DELETE CASCADE;


--
-- Name: feedback feedback_resolved_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback
    ADD CONSTRAINT feedback_resolved_by_account_id_fkey FOREIGN KEY (resolved_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: feedback feedback_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback
    ADD CONSTRAINT feedback_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: drive_file_assets drive_file_assets_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_assets
    ADD CONSTRAINT drive_file_assets_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.drive_files(id) ON DELETE CASCADE;


--
-- Name: drive_file_assets drive_file_assets_uploader_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_assets
    ADD CONSTRAINT drive_file_assets_uploader_account_id_fkey FOREIGN KEY (uploader_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_file_key_history drive_file_key_history_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_key_history
    ADD CONSTRAINT drive_file_key_history_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.drive_files(id) ON DELETE CASCADE;


--
-- Name: collab_sender_floors collab_sender_floors_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collab_sender_floors
    ADD CONSTRAINT collab_sender_floors_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.drive_files(id) ON DELETE CASCADE;


--
-- Name: drive_file_shares drive_file_shares_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_shares
    ADD CONSTRAINT drive_file_shares_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.drive_files(id) ON DELETE CASCADE;


--
-- Name: drive_file_shares drive_file_shares_recipient_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_shares
    ADD CONSTRAINT drive_file_shares_recipient_account_id_fkey FOREIGN KEY (recipient_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_file_shares drive_file_shares_sharer_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_shares
    ADD CONSTRAINT drive_file_shares_sharer_account_id_fkey FOREIGN KEY (sharer_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_file_thumbnails drive_file_thumbnails_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_thumbnails
    ADD CONSTRAINT drive_file_thumbnails_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.drive_files(id) ON DELETE CASCADE;


--
-- Name: drive_file_thumbnails drive_file_thumbnails_source_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_thumbnails
    ADD CONSTRAINT drive_file_thumbnails_source_version_fkey FOREIGN KEY (source_version) REFERENCES public.drive_file_versions(id) ON DELETE SET NULL;


--
-- Name: drive_file_thumbnails drive_file_thumbnails_uploader_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_thumbnails
    ADD CONSTRAINT drive_file_thumbnails_uploader_account_id_fkey FOREIGN KEY (uploader_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: collab_update_log collab_update_log_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collab_update_log
    ADD CONSTRAINT collab_update_log_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.drive_files(id) ON DELETE CASCADE;


--
-- Name: drive_file_versions drive_file_versions_author_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_versions
    ADD CONSTRAINT drive_file_versions_author_account_id_fkey FOREIGN KEY (author_account_id) REFERENCES public.accounts(id);


--
-- Name: drive_file_versions drive_file_versions_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_file_versions
    ADD CONSTRAINT drive_file_versions_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.drive_files(id) ON DELETE CASCADE;


--
-- Name: drive_files drive_files_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_files
    ADD CONSTRAINT drive_files_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.drive_collections(id) ON DELETE CASCADE;


--
-- Name: drive_files drive_files_fed_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_files
    ADD CONSTRAINT drive_files_fed_share_id_fkey FOREIGN KEY (fed_share_id) REFERENCES public.drive_federated_outgoing_shares(id) ON DELETE SET NULL;


--
-- Name: drive_files drive_files_uploader_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_files
    ADD CONSTRAINT drive_files_uploader_account_id_fkey FOREIGN KEY (uploader_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: legal_documents legal_documents_published_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.legal_documents
    ADD CONSTRAINT legal_documents_published_by_account_id_fkey FOREIGN KEY (published_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: chat_live_location_streams chat_live_location_streams_created_by_account_id_account_id_fke; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_live_location_streams
    ADD CONSTRAINT chat_live_location_streams_created_by_account_id_account_id_fke FOREIGN KEY (created_by_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_address_keys mail_address_keys_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_address_keys
    ADD CONSTRAINT mail_address_keys_address_id_fkey FOREIGN KEY (address_id) REFERENCES public.mail_addresses(id) ON DELETE CASCADE;


--
-- Name: mail_address_keys mail_address_keys_forwarding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_address_keys
    ADD CONSTRAINT mail_address_keys_forwarding_id_fkey FOREIGN KEY (forwarding_id) REFERENCES public.mail_forwardings(id) ON DELETE SET NULL;


--
-- Name: mail_addresses mail_addresses_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_addresses
    ADD CONSTRAINT mail_addresses_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.mail_domains(id);


--
-- Name: mail_addresses mail_addresses_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_addresses
    ADD CONSTRAINT mail_addresses_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: mail_addresses mail_addresses_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_addresses
    ADD CONSTRAINT mail_addresses_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_auto_replies mail_auto_replies_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_auto_replies
    ADD CONSTRAINT mail_auto_replies_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_auto_reply_sent mail_auto_reply_sent_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_auto_reply_sent
    ADD CONSTRAINT mail_auto_reply_sent_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_domain_blocks mail_domain_blocks_blocked_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_domain_blocks
    ADD CONSTRAINT mail_domain_blocks_blocked_by_account_id_fkey FOREIGN KEY (blocked_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: mail_domain_catch_all_days mail_domain_catch_all_days_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_domain_catch_all_days
    ADD CONSTRAINT mail_domain_catch_all_days_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.mail_domains(id) ON DELETE CASCADE;


--
-- Name: mail_domains mail_domains_catch_all; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_domains
    ADD CONSTRAINT mail_domains_catch_all FOREIGN KEY (catch_all_address_id) REFERENCES public.mail_addresses(id) ON DELETE SET NULL;


--
-- Name: mail_domains mail_domains_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_domains
    ADD CONSTRAINT mail_domains_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: mail_draft_attachments mail_draft_attachments_message_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_draft_attachments
    ADD CONSTRAINT mail_draft_attachments_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.mail_messages(id) ON DELETE CASCADE;


--
-- Name: mail_draft_attachments mail_draft_attachments_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_draft_attachments
    ADD CONSTRAINT mail_draft_attachments_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_filter_runs mail_filter_runs_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_filter_runs
    ADD CONSTRAINT mail_filter_runs_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_filters mail_filters_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_filters
    ADD CONSTRAINT mail_filters_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_folders mail_folders_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_folders
    ADD CONSTRAINT mail_folders_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_folders mail_folders_account_id_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_folders
    ADD CONSTRAINT mail_folders_account_id_parent_id_fkey FOREIGN KEY (account_id, parent_id) REFERENCES public.mail_folders(account_id, id) ON DELETE CASCADE;


--
-- Name: mail_forwarding_keys mail_forwarding_keys_forwarding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_forwarding_keys
    ADD CONSTRAINT mail_forwarding_keys_forwarding_id_fkey FOREIGN KEY (forwarding_id) REFERENCES public.mail_forwardings(id) ON DELETE CASCADE;


--
-- Name: mail_forwarding_quota mail_forwarding_quota_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_forwarding_quota
    ADD CONSTRAINT mail_forwarding_quota_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_forwardings mail_forwardings_forwardee_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_forwardings
    ADD CONSTRAINT mail_forwardings_forwardee_address_id_fkey FOREIGN KEY (forwardee_address_id) REFERENCES public.mail_addresses(id) ON DELETE CASCADE;


--
-- Name: mail_forwardings mail_forwardings_forwarder_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_forwardings
    ADD CONSTRAINT mail_forwardings_forwarder_address_id_fkey FOREIGN KEY (forwarder_address_id) REFERENCES public.mail_addresses(id) ON DELETE CASCADE;


--
-- Name: mail_forwardings mail_forwardings_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_forwardings
    ADD CONSTRAINT mail_forwardings_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


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
-- Name: mail_group_key_shares mail_group_key_shares_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_key_shares
    ADD CONSTRAINT mail_group_key_shares_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_group_keys mail_group_keys_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_keys
    ADD CONSTRAINT mail_group_keys_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: mail_group_members mail_group_members_added_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_members
    ADD CONSTRAINT mail_group_members_added_by_account_id_fkey FOREIGN KEY (added_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: mail_group_members mail_group_members_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_members
    ADD CONSTRAINT mail_group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: mail_group_members mail_group_members_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_members
    ADD CONSTRAINT mail_group_members_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_group_objects mail_group_objects_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_objects
    ADD CONSTRAINT mail_group_objects_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: mail_group_signers mail_group_signers_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_signers
    ADD CONSTRAINT mail_group_signers_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: mail_group_signing_shares mail_group_signing_shares_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_signing_shares
    ADD CONSTRAINT mail_group_signing_shares_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE CASCADE;


--
-- Name: mail_group_signing_shares mail_group_signing_shares_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_group_signing_shares
    ADD CONSTRAINT mail_group_signing_shares_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_groups mail_groups_created_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_groups
    ADD CONSTRAINT mail_groups_created_by_account_id_fkey FOREIGN KEY (created_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: mail_identities mail_identities_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_identities
    ADD CONSTRAINT mail_identities_address_id_fkey FOREIGN KEY (address_id) REFERENCES public.mail_addresses(id) ON DELETE CASCADE;


--
-- Name: mail_image_senders mail_image_senders_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_image_senders
    ADD CONSTRAINT mail_image_senders_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_key_lists mail_key_lists_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_key_lists
    ADD CONSTRAINT mail_key_lists_address_id_fkey FOREIGN KEY (address_id) REFERENCES public.mail_addresses(id) ON DELETE CASCADE;


--
-- Name: mail_labels mail_labels_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_labels
    ADD CONSTRAINT mail_labels_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


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
    ADD CONSTRAINT mail_messages_custom_folder_fk FOREIGN KEY (account_id, custom_folder) REFERENCES public.mail_folders(account_id, id);


--
-- Name: mail_messages mail_messages_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_messages
    ADD CONSTRAINT mail_messages_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.mail_groups(id) ON DELETE SET NULL;


--
-- Name: mail_messages mail_messages_sent_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_messages
    ADD CONSTRAINT mail_messages_sent_by_account_id_fkey FOREIGN KEY (sent_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: mail_messages mail_messages_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_messages
    ADD CONSTRAINT mail_messages_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_outbox mail_outbox_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_outbox
    ADD CONSTRAINT mail_outbox_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_sender_rules mail_sender_rules_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sender_rules
    ADD CONSTRAINT mail_sender_rules_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_sending_events mail_sending_events_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sending_events
    ADD CONSTRAINT mail_sending_events_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_sending_policies mail_sending_policies_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_sending_policies
    ADD CONSTRAINT mail_sending_policies_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: mail_settings mail_settings_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_settings
    ADD CONSTRAINT mail_settings_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: opaque_login_states opaque_login_states_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.opaque_login_states
    ADD CONSTRAINT opaque_login_states_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.auth_sessions(id) ON DELETE CASCADE;


--
-- Name: opaque_login_states opaque_login_states_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.opaque_login_states
    ADD CONSTRAINT opaque_login_states_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: organization_key_shares organization_key_shares_granted_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_key_shares
    ADD CONSTRAINT organization_key_shares_granted_by_account_id_fkey FOREIGN KEY (granted_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: organization_key_shares organization_key_shares_key_id_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_key_shares
    ADD CONSTRAINT organization_key_shares_key_id_organization_id_fkey FOREIGN KEY (key_id, organization_id) REFERENCES public.organization_keys(id, organization_id) ON DELETE CASCADE;


--
-- Name: organization_key_shares organization_key_shares_organization_id_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_key_shares
    ADD CONSTRAINT organization_key_shares_organization_id_account_id_fkey FOREIGN KEY (organization_id, account_id) REFERENCES public.organization_members(organization_id, account_id) ON DELETE CASCADE;


--
-- Name: organization_keys organization_keys_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_keys
    ADD CONSTRAINT organization_keys_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: organization_member_escrows organization_member_escrows_key_id_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_member_escrows
    ADD CONSTRAINT organization_member_escrows_key_id_organization_id_fkey FOREIGN KEY (key_id, organization_id) REFERENCES public.organization_keys(id, organization_id) ON DELETE CASCADE;


--
-- Name: organization_member_escrows organization_member_escrows_organization_id_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_member_escrows
    ADD CONSTRAINT organization_member_escrows_organization_id_account_id_fkey FOREIGN KEY (organization_id, account_id) REFERENCES public.organization_members(organization_id, account_id) ON DELETE CASCADE;


--
-- Name: organization_members organization_members_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_members
    ADD CONSTRAINT organization_members_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: organization_members organization_members_invited_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_members
    ADD CONSTRAINT organization_members_invited_by_account_id_fkey FOREIGN KEY (invited_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: organization_members organization_members_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_members
    ADD CONSTRAINT organization_members_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: organization_entitlements organization_entitlements_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_entitlements
    ADD CONSTRAINT organization_entitlements_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: pass_pin_failures pass_pin_failures_sign_in_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_pin_failures
    ADD CONSTRAINT pass_pin_failures_sign_in_id_fkey FOREIGN KEY (sign_in_id) REFERENCES public.auth_sessions(id) ON DELETE CASCADE;


--
-- Name: pass_pin_failures pass_pin_failures_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_pin_failures
    ADD CONSTRAINT pass_pin_failures_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: pass_pins pass_pins_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_pins
    ADD CONSTRAINT pass_pins_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: pass_settings pass_settings_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pass_settings
    ADD CONSTRAINT pass_settings_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: photos_library_folders photos_library_folders_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_library_folders
    ADD CONSTRAINT photos_library_folders_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.drive_collections(id) ON DELETE CASCADE;


--
-- Name: photos_library_folders photos_library_folders_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_library_folders
    ADD CONSTRAINT photos_library_folders_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: photos_preferences photos_preferences_upload_folder_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_preferences
    ADD CONSTRAINT photos_preferences_upload_folder_id_fkey FOREIGN KEY (upload_folder_id) REFERENCES public.drive_collections(id) ON DELETE SET NULL;


--
-- Name: photos_preferences photos_preferences_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.photos_preferences
    ADD CONSTRAINT photos_preferences_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_public_link_reports drive_public_link_reports_resolved_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_public_link_reports
    ADD CONSTRAINT drive_public_link_reports_resolved_by_account_id_fkey FOREIGN KEY (resolved_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: drive_public_link_reports drive_public_link_reports_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_public_link_reports
    ADD CONSTRAINT drive_public_link_reports_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.drive_public_shares(id) ON DELETE CASCADE;


--
-- Name: drive_public_shares drive_public_shares_blocked_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_public_shares
    ADD CONSTRAINT drive_public_shares_blocked_by_account_id_fkey FOREIGN KEY (blocked_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: drive_public_shares drive_public_shares_owner_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_public_shares
    ADD CONSTRAINT drive_public_shares_owner_account_id_fkey FOREIGN KEY (owner_account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: registration_code_uses registration_code_uses_code_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_code_uses
    ADD CONSTRAINT registration_code_uses_code_id_fkey FOREIGN KEY (code_id) REFERENCES public.registration_codes(id) ON DELETE CASCADE;


--
-- Name: registration_code_uses registration_code_uses_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_code_uses
    ADD CONSTRAINT registration_code_uses_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: registration_codes registration_codes_created_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_codes
    ADD CONSTRAINT registration_codes_created_by_account_id_fkey FOREIGN KEY (created_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: registration_codes registration_codes_revoked_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_codes
    ADD CONSTRAINT registration_codes_revoked_by_account_id_fkey FOREIGN KEY (revoked_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: two_factor_recovery_codes two_factor_recovery_codes_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.two_factor_recovery_codes
    ADD CONSTRAINT two_factor_recovery_codes_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: drive_uploads drive_uploads_collection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_uploads
    ADD CONSTRAINT drive_uploads_collection_id_fkey FOREIGN KEY (collection_id) REFERENCES public.drive_collections(id) ON DELETE CASCADE;


--
-- Name: drive_uploads drive_uploads_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.drive_uploads
    ADD CONSTRAINT drive_uploads_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_map_preferences account_map_preferences_save_folder_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_map_preferences
    ADD CONSTRAINT account_map_preferences_save_folder_id_fkey FOREIGN KEY (save_folder_id) REFERENCES public.drive_collections(id) ON DELETE SET NULL;


--
-- Name: account_map_preferences account_map_preferences_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_map_preferences
    ADD CONSTRAINT account_map_preferences_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_security_keys account_security_keys_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_security_keys
    ADD CONSTRAINT account_security_keys_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_entitlements account_entitlements_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_entitlements
    ADD CONSTRAINT account_entitlements_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_ui_preferences account_ui_preferences_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_ui_preferences
    ADD CONSTRAINT account_ui_preferences_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: accounts accounts_legal_hold_by_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_legal_hold_by_account_id_fkey FOREIGN KEY (legal_hold_by_account_id) REFERENCES public.accounts(id) ON DELETE SET NULL;


--
-- Name: webauthn_ceremonies webauthn_ceremonies_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


--
-- PostgreSQL database dump
--


-- Dumped from database version 16.16
-- Dumped by pg_dump version 16.16


--
-- Data for Name: accounts; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_data_keys; Type: TABLE DATA; Schema: account_keys; Owner: -
--



--
-- Data for Name: destruction_events; Type: TABLE DATA; Schema: account_keys; Owner: -
--



--
-- Data for Name: mail_groups; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_group_data_keys; Type: TABLE DATA; Schema: account_keys; Owner: -
--



--
-- Data for Name: account_heads; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_names; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_record_feeds; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_record_tombstones; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_records; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_renames; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_roots; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_security_events; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: admin_audit_anchor; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: admin_audit_log; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_collections; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_federated_outgoing_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_files; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: photos_album_items; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: auth_sessions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: auth_grants; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: auth_session_forks; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: backup_runs; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendars; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_alarm_recomputes; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_addresses; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_events; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_alarms; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_event_reminders; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_event_attendees; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_event_invitees; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_invitations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_link_passphrases; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_links; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_member_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_member_tombstones; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_shared_events; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_members; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_push_subscriptions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: calendar_account_settings; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_account_identities; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_anonymous_send_ids; Type: TABLE DATA; Schema: public; Owner: -
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
-- Data for Name: chat_groups; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_group_avatars; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_group_changes; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_group_endorsements; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_group_nonces; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_group_seen_pseudonyms; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_link_tokens; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_shared_payloads; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_devices; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_mailbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_federation_inbound_pending; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_objects; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_federation_pull_grants; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_origin_delivery_operations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_references; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_media_uploads; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_multi_send_ids; Type: TABLE DATA; Schema: public; Owner: -
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
-- Data for Name: chat_sends; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_web_push_key; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_zk_server_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_collection_key_epoch_history; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_collection_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: legal_documents; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: consents; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: contacts; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: contacts_emails; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_device_tickets; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: document_acknowledgements; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_federation_mutations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_profile_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_federated_incoming_file_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_federated_incoming_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_federated_outgoing_file_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_feature_policies; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.federation_feature_policies VALUES ('chat', 'allowlist', 'verified', '2026-10-13 12:07:28.277676+00');
INSERT INTO public.federation_feature_policies VALUES ('drive', 'allowlist', 'verified', '2026-10-13 12:07:28.277676+00');


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
-- Data for Name: federation_inbound; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_inbound_state; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_local_identity_documents; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_outbox; Type: TABLE DATA; Schema: public; Owner: -
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

INSERT INTO public.federation_policy VALUES (true, true, '2026-10-13 12:07:28.276512+00');


--
-- Data for Name: federation_request_replays; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_sequences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: feedback; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_file_assets; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_file_key_history; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: collab_sender_floors; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_file_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_file_versions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_file_thumbnails; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: collab_update_log; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: job_heartbeats; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_live_location_streams; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_forwardings; Type: TABLE DATA; Schema: public; Owner: -
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
-- Data for Name: mail_dkim_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_domain_blocks; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: organizations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_domains; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_domain_catch_all_days; Type: TABLE DATA; Schema: public; Owner: -
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
-- Data for Name: mail_forwarding_code_sends; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_forwarding_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_forwarding_quota; Type: TABLE DATA; Schema: public; Owner: -
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
-- Data for Name: mail_group_signers; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: mail_group_signing_shares; Type: TABLE DATA; Schema: public; Owner: -
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
-- Data for Name: opaque_login_states; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: opaque_server_setups; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: organization_members; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: organization_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: organization_key_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: organization_member_escrows; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: organization_entitlements; Type: TABLE DATA; Schema: public; Owner: -
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
-- Data for Name: photos_library_folders; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: photos_preferences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_public_shares; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_public_link_reports; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: registration_codes; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: rate_counters; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: registration_code_uses; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: remote_account_manifests; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: remote_account_renames; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: remote_manifest_failures; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: retired_account_ids; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: chat_sealed_sender_certificates; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: server_generated_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: site_settings; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: storage_pending_deletions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: two_factor_recovery_codes; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: drive_uploads; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_map_preferences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_security_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_entitlements; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: account_ui_preferences; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: webauthn_ceremonies; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Name: admin_audit_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.admin_audit_log_id_seq', 1, false);


--
-- Name: chat_group_endorsement_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.chat_group_endorsement_seq', 1, false);


--
-- Name: chat_mailbox_cursor_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.chat_mailbox_cursor_seq', 1, false);


--
-- Name: consents_seq_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.consents_seq_seq', 1, false);


--
-- Name: mail_sending_events_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.mail_sending_events_id_seq', 1, false);


--
-- Name: storage_pending_deletions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.storage_pending_deletions_id_seq', 1, false);


--
-- Name: account_devices_revocation_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.account_devices_revocation_seq', 1, false);


--
-- PostgreSQL database dump complete
--
