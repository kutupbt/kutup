-- The records of the two scopes go back with the old stores (no data moves).
DELETE FROM account_records WHERE scope IN (5, 6);
DELETE FROM account_record_tombstones WHERE scope IN (5, 6);
ALTER TABLE account_records DROP CONSTRAINT account_records_envelope_check;
ALTER TABLE account_records ADD CONSTRAINT account_records_envelope_check
    CHECK (octet_length(envelope) BETWEEN 1 AND 65536);

CREATE TABLE photos_library (
    user_id uuid NOT NULL PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    envelope_digest text NOT NULL,
    envelope bytea NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE chat_attachment_ledger_cursor_seq
    START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;

CREATE TABLE chat_attachment_ledger_entities (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entity_id uuid NOT NULL,
    revision bigint NOT NULL,
    envelope_digest character(64) NOT NULL,
    cursor bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_attachment_ledger_entities_envelope_digest_check CHECK ((envelope_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_attachment_ledger_entities_revision_check CHECK ((revision > 0)),
    CONSTRAINT chat_attachment_ledger_entities_pkey PRIMARY KEY (user_id, entity_id),
    CONSTRAINT chat_attachment_ledger_entities_user_id_cursor_key UNIQUE (user_id, cursor)
);
CREATE INDEX idx_chat_attachment_ledger_cursor ON chat_attachment_ledger_entities USING btree (user_id, cursor);

CREATE TABLE chat_attachment_ledger_history (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entity_id uuid NOT NULL,
    revision bigint NOT NULL,
    envelope_digest character(64) NOT NULL,
    envelope text NOT NULL,
    cursor bigint DEFAULT nextval('chat_attachment_ledger_cursor_seq'::regclass) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_attachment_ledger_history_envelope_digest_check CHECK ((envelope_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_attachment_ledger_history_revision_check CHECK ((revision > 0)),
    CONSTRAINT chat_attachment_ledger_history_pkey PRIMARY KEY (user_id, entity_id, revision),
    CONSTRAINT chat_attachment_ledger_history_user_id_cursor_key UNIQUE (user_id, cursor),
    CONSTRAINT chat_attachment_ledger_history_user_id_entity_id_fkey FOREIGN KEY (user_id, entity_id)
        REFERENCES chat_attachment_ledger_entities(user_id, entity_id) ON DELETE CASCADE
);
CREATE INDEX idx_chat_attachment_ledger_history_cursor ON chat_attachment_ledger_history USING btree (user_id, cursor);

CREATE TABLE chat_attachment_ledger_operations (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    operation_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    revision bigint NOT NULL,
    envelope_digest character(64) NOT NULL,
    cursor bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chat_attachment_ledger_operations_envelope_digest_check CHECK ((envelope_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT chat_attachment_ledger_operations_revision_check CHECK ((revision > 0)),
    CONSTRAINT chat_attachment_ledger_operations_pkey PRIMARY KEY (user_id, operation_id)
);
