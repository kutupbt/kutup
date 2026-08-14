-- Authenticated feature policies, complete account-signed manifest history,
-- and contacts-only sealed delivery.

CREATE TABLE federation_feature_policy_documents (
    domain                       TEXT        NOT NULL,
    feature_type                 SMALLINT    NOT NULL CHECK (feature_type IN (1, 2)),
    sequence                     BIGINT      NOT NULL CHECK (sequence > 0),
    policy_hash                  CHAR(64)    NOT NULL,
    federation_identity_generation BIGINT   NOT NULL CHECK (federation_identity_generation >= 0),
    envelope                     JSONB       NOT NULL CHECK (jsonb_typeof(envelope) = 'object'),
    is_local                     BOOLEAN     NOT NULL,
    recorded_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (domain, feature_type, sequence),
    UNIQUE (domain, feature_type, policy_hash),
    CHECK (domain = lower(domain)),
    CHECK (policy_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX federation_feature_policy_current_idx
    ON federation_feature_policy_documents (domain, feature_type, sequence DESC);

CREATE TABLE federation_feature_policy_failures (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT        NOT NULL,
    feature_type    SMALLINT    NOT NULL,
    failure_class   TEXT        NOT NULL,
    evidence_digest CHAR(64)    NOT NULL,
    received_value  JSONB,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (failure_class IN (
        'rollback', 'gap', 'wrong_domain', 'unknown_type', 'malformed',
        'signature', 'identity_chain', 'configuration_replacement'
    )),
    CHECK (evidence_digest ~ '^[0-9a-f]{64}$')
);

-- Every accepted complete manifest is inserted in the same publication
-- transaction as the mutable head. Clients verify the account signature and
-- complete hash-linked sequence before atomically advancing their durable pin.
CREATE TABLE chat_device_manifest_history (
    user_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    incarnation_id   CHAR(64)    NOT NULL,
    version          BIGINT      NOT NULL CHECK (version > 0),
    manifest_hash    CHAR(64)    NOT NULL,
    authority_key_id CHAR(64)    NOT NULL,
    manifest         JSONB       NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    accepted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, incarnation_id, version),
    CHECK (incarnation_id ~ '^[0-9a-f]{64}$'),
    CHECK (manifest_hash ~ '^[0-9a-f]{64}$'),
    CHECK (authority_key_id ~ '^[0-9a-f]{64}$')
);

INSERT INTO chat_device_manifest_history
    (user_id, incarnation_id, version, manifest_hash, authority_key_id, manifest, accepted_at)
SELECT user_id, manifest->>'incarnationId', version, manifest_hash, authority_key_id, manifest, updated_at
FROM chat_device_manifests;

-- One current verifier per recipient. Raw 16-byte capabilities are never
-- persisted at the destination.
CREATE TABLE chat_delivery_capabilities (
    user_id          UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    profile_version  CHAR(64)    NOT NULL,
    profile_revision BIGINT      NOT NULL CHECK (profile_revision > 0),
    capability_hash  BYTEA       NOT NULL CHECK (octet_length(capability_hash) = 32),
    rotated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE chat_anonymous_send_ids (
    recipient_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    capability_hash   BYTEA       NOT NULL CHECK (octet_length(capability_hash) = 32),
    send_id           UUID        NOT NULL,
    stored_count      INTEGER     NOT NULL CHECK (stored_count BETWEEN 1 AND 32),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (recipient_user_id, capability_hash, send_id)
);

CREATE TABLE chat_anonymous_rate_counters (
    scope_type   TEXT        NOT NULL CHECK (scope_type IN ('capability_bundle', 'capability_minute', 'capability_day', 'recipient', 'federation_origin')),
    scope_digest BYTEA       NOT NULL CHECK (octet_length(scope_digest) = 32),
    window_start TIMESTAMPTZ NOT NULL,
    count        BIGINT      NOT NULL CHECK (count >= 0),
    expires_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope_type, scope_digest, window_start)
);

CREATE INDEX chat_anonymous_rate_expiry_idx
    ON chat_anonymous_rate_counters (expires_at);

ALTER TABLE chat_mailbox ADD COLUMN sealed_sender BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE chat_sealed_federation_sequences (
    destination   TEXT PRIMARY KEY,
    next_sequence BIGINT NOT NULL CHECK (next_sequence > 0)
);

CREATE TABLE chat_sealed_federation_outbox (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    destination      TEXT        NOT NULL,
    sequence         BIGINT      NOT NULL CHECK (sequence > 0),
    sender_user_id   UUID        REFERENCES users(id) ON DELETE SET NULL,
    sender_device_id INTEGER     CHECK (sender_device_id IS NULL OR sender_device_id BETWEEN 1 AND 127),
    recipient        TEXT        NOT NULL,
    send_id          UUID        NOT NULL,
    transaction      JSONB       NOT NULL CHECK (jsonb_typeof(transaction) = 'object'),
    state            TEXT        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'rejected')),
    attempts         INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error_class TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (destination, sequence),
    UNIQUE (destination, recipient, send_id)
);

CREATE TABLE chat_sealed_federation_inbound (
    origin       TEXT        NOT NULL,
    sequence     BIGINT      NOT NULL CHECK (sequence > 0),
    send_id      UUID        NOT NULL,
    response_status SMALLINT NOT NULL CHECK (response_status BETWEEN 200 AND 599),
    response     JSONB       NOT NULL CHECK (jsonb_typeof(response) = 'object'),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (origin, sequence),
    UNIQUE (origin, send_id)
);
