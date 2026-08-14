-- Immutable E2EE Chat-media storage and account-private attachment ledger.
-- Runtime capability advertisement was enabled only after the clean
-- federation, browser, restart, quota, and metadata-privacy gates passed.

CREATE TABLE chat_media_objects (
    attachment_id          UUID PRIMARY KEY,
    -- Present only on the sender's homeserver. Destination copies retain the
    -- authenticated origin domain but never receive a sender account/device.
    origin_user_id         UUID REFERENCES users(id) ON DELETE CASCADE,
    origin_domain          TEXT NOT NULL,
    suite                  SMALLINT NOT NULL CHECK (suite = 1),
    ciphertext_bytes       BIGINT NOT NULL CHECK (ciphertext_bytes > 0),
    ciphertext_sha256      CHAR(64) NOT NULL CHECK (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
    retrieval_token_hash   BYTEA NOT NULL CHECK (octet_length(retrieval_token_hash) = 32),
    storage_path           TEXT NOT NULL UNIQUE,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE chat_media_references (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attachment_id          UUID NOT NULL REFERENCES chat_media_objects(attachment_id) ON DELETE CASCADE,
    logical_bytes          BIGINT NOT NULL CHECK (logical_bytes > 0),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, attachment_id)
);

CREATE INDEX idx_chat_media_references_user ON chat_media_references(user_id);

-- Origin-owned retry/idempotency state. A future federated destination uses a
-- separate sender-free receipt table; this row never enters its transaction.
CREATE TABLE chat_media_origin_delivery_operations (
    origin_user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    operation_id           UUID NOT NULL,
    recipient_user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attachment_id          UUID NOT NULL REFERENCES chat_media_objects(attachment_id) ON DELETE CASCADE,
    ciphertext_bytes       BIGINT NOT NULL CHECK (ciphertext_bytes > 0),
    ciphertext_sha256      CHAR(64) NOT NULL CHECK (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
    offer_digest           CHAR(64) NOT NULL CHECK (offer_digest ~ '^[0-9a-f]{64}$'),
    storage_reference_id   UUID NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (origin_user_id, operation_id)
);

-- A pull is authorized only after this homeserver has authenticated its local
-- sender and durably staged the exact destination/recipient operation. The
-- browser upload token is never sufficient without a signed request from the
-- bound destination server.
CREATE TABLE chat_media_federation_pull_grants (
    origin_user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    destination            TEXT NOT NULL,
    recipient              TEXT NOT NULL,
    operation_id           UUID NOT NULL,
    attachment_id          UUID NOT NULL REFERENCES chat_media_objects(attachment_id) ON DELETE CASCADE,
    retrieval_token_hash   BYTEA NOT NULL CHECK (octet_length(retrieval_token_hash) = 32),
    expires_at             TIMESTAMPTZ NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (destination, operation_id),
    UNIQUE (destination, recipient, attachment_id)
);

CREATE TABLE chat_media_federation_sequences (
    destination            TEXT PRIMARY KEY,
    next_sequence          BIGINT NOT NULL DEFAULT 1 CHECK (next_sequence > 0)
);

-- Sender identity is intentionally origin-local. Only the sender-free
-- transaction JSON crosses federation or enters a destination database.
CREATE TABLE chat_media_federation_outbox (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    destination            TEXT NOT NULL,
    sequence               BIGINT NOT NULL CHECK (sequence > 0),
    origin_user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    operation_id           UUID NOT NULL,
    transaction            JSONB NOT NULL,
    state                  TEXT NOT NULL DEFAULT 'pending'
                             CHECK (state IN ('pending','delivered','rejected')),
    attempts               INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error_class       TEXT,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (destination, sequence),
    UNIQUE (origin_user_id, operation_id)
);

CREATE INDEX idx_chat_media_federation_outbox_retry
    ON chat_media_federation_outbox(state, next_attempt_at, destination, sequence);

CREATE TABLE chat_media_federation_inbound_state (
    origin                 TEXT PRIMARY KEY,
    last_sequence          BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A destination reserves quota and the next origin sequence before it pulls a
-- potentially large object.  The renewable lease prevents duplicate pulls;
-- no database transaction or user row lock is held across network/storage IO.
CREATE TABLE chat_media_federation_inbound_pending (
    origin                 TEXT NOT NULL,
    sequence               BIGINT NOT NULL CHECK (sequence > 0),
    operation_id           UUID NOT NULL,
    transaction_digest     CHAR(64) NOT NULL CHECK (transaction_digest ~ '^[0-9a-f]{64}$'),
    recipient_user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attachment_id          UUID NOT NULL,
    ciphertext_bytes       BIGINT NOT NULL CHECK (ciphertext_bytes > 0),
    lease_id               UUID NOT NULL,
    lease_until            TIMESTAMPTZ NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (origin, sequence),
    UNIQUE (origin, operation_id)
);

CREATE INDEX idx_chat_media_inbound_pending_recipient
    ON chat_media_federation_inbound_pending(recipient_user_id);

CREATE TABLE chat_media_federation_inbound_transactions (
    origin                 TEXT NOT NULL,
    sequence               BIGINT NOT NULL CHECK (sequence > 0),
    operation_id           UUID NOT NULL,
    transaction_digest     CHAR(64) NOT NULL CHECK (transaction_digest ~ '^[0-9a-f]{64}$'),
    response_status        SMALLINT NOT NULL,
    response               JSONB NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (origin, sequence),
    UNIQUE (origin, operation_id)
);

-- Chat media has its own abuse-accounting namespace. Keeping these scopes out
-- of chat_anonymous_rate_counters prevents a future media change from silently
-- changing sealed-sender limits or their schema contract.
CREATE TABLE chat_media_rate_counters (
    scope_type   TEXT        NOT NULL
      CHECK (scope_type IN ('capability_minute', 'capability_day', 'recipient', 'federation_origin')),
    scope_digest BYTEA       NOT NULL CHECK (octet_length(scope_digest) = 32),
    window_start TIMESTAMPTZ NOT NULL,
    count        BIGINT      NOT NULL CHECK (count >= 0),
    expires_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope_type, scope_digest, window_start)
);

CREATE INDEX idx_chat_media_rate_expiry ON chat_media_rate_counters(expires_at);

CREATE TABLE chat_media_uploads (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attachment_id          UUID NOT NULL UNIQUE,
    suite                  SMALLINT NOT NULL CHECK (suite = 1),
    total_bytes            BIGINT NOT NULL CHECK (total_bytes > 0),
    received_bytes         BIGINT NOT NULL DEFAULT 0 CHECK (received_bytes >= 0),
    retrieval_token_hash   BYTEA NOT NULL CHECK (octet_length(retrieval_token_hash) = 32),
    storage_path           TEXT NOT NULL UNIQUE,
    s3_upload_id           TEXT NOT NULL,
    s3_part_etags          JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (received_bytes <= total_bytes)
);

CREATE INDEX idx_chat_media_uploads_user ON chat_media_uploads(user_id);
CREATE INDEX idx_chat_media_uploads_updated ON chat_media_uploads(updated_at);

CREATE SEQUENCE chat_attachment_ledger_cursor_seq AS BIGINT;

CREATE TABLE chat_attachment_ledger_entities (
    user_id                UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entity_id              UUID NOT NULL,
    revision               BIGINT NOT NULL CHECK (revision > 0),
    envelope_digest        CHAR(64) NOT NULL CHECK (envelope_digest ~ '^[0-9a-f]{64}$'),
    cursor                 BIGINT NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, entity_id),
    UNIQUE (user_id, cursor)
);

CREATE INDEX idx_chat_attachment_ledger_cursor
    ON chat_attachment_ledger_entities(user_id, cursor);

CREATE TABLE chat_attachment_ledger_history (
    user_id                UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entity_id              UUID NOT NULL,
    revision               BIGINT NOT NULL CHECK (revision > 0),
    envelope_digest        CHAR(64) NOT NULL CHECK (envelope_digest ~ '^[0-9a-f]{64}$'),
    envelope               TEXT NOT NULL,
    cursor                 BIGINT NOT NULL DEFAULT nextval('chat_attachment_ledger_cursor_seq'),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, entity_id, revision),
    UNIQUE (user_id, cursor),
    FOREIGN KEY (user_id, entity_id)
        REFERENCES chat_attachment_ledger_entities(user_id, entity_id) ON DELETE CASCADE
);

CREATE INDEX idx_chat_attachment_ledger_history_cursor
    ON chat_attachment_ledger_history(user_id, cursor);

CREATE TABLE chat_attachment_ledger_operations (
    user_id                UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    operation_id           UUID NOT NULL,
    entity_id              UUID NOT NULL,
    revision               BIGINT NOT NULL CHECK (revision > 0),
    envelope_digest        CHAR(64) NOT NULL CHECK (envelope_digest ~ '^[0-9a-f]{64}$'),
    cursor                 BIGINT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, operation_id)
);
