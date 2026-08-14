-- Owner-approved append-only MLS incarnation recovery. The complete signed
-- public recovery is immutable; destination-private replicas are retried from
-- a dedicated durable outbox without reusing the ordered-control stack.

CREATE TABLE chat_mls_incarnation_recoveries (
    recovery_digest      CHAR(64)    PRIMARY KEY,
    conversation_id      UUID        NOT NULL REFERENCES chat_mls_conversations ON DELETE CASCADE,
    previous_incarnation BIGINT      NOT NULL CHECK (previous_incarnation > 0),
    new_incarnation      BIGINT      NOT NULL CHECK (new_incarnation > previous_incarnation),
    proposal_id          UUID        NOT NULL,
    origin_domain        TEXT        NOT NULL,
    initiated_by         UUID        REFERENCES users(id) ON DELETE SET NULL,
    recovery             JSONB       NOT NULL CHECK (jsonb_typeof(recovery) = 'object'),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (conversation_id, previous_incarnation),
    UNIQUE (conversation_id, new_incarnation),
    UNIQUE (conversation_id, previous_incarnation, proposal_id),
    FOREIGN KEY (conversation_id, previous_incarnation)
        REFERENCES chat_mls_incarnations ON DELETE CASCADE,
    FOREIGN KEY (conversation_id, new_incarnation)
        REFERENCES chat_mls_incarnations ON DELETE CASCADE,
    CHECK (recovery_digest ~ '^[0-9a-f]{64}$'),
    CHECK (origin_domain = lower(origin_domain)),
    CHECK (new_incarnation = previous_incarnation + 1)
);

CREATE TABLE chat_mls_recovery_outbox (
    destination          TEXT        NOT NULL,
    recovery_digest      CHAR(64)    NOT NULL REFERENCES chat_mls_incarnation_recoveries ON DELETE CASCADE,
    conversation_id      UUID        NOT NULL,
    previous_incarnation BIGINT      NOT NULL CHECK (previous_incarnation > 0),
    replica              JSONB       NOT NULL CHECK (jsonb_typeof(replica) = 'object'),
    state                TEXT        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'delivered')),
    attempts             INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error_class     TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (destination, recovery_digest),
    CHECK (destination = lower(destination))
);

CREATE INDEX chat_mls_recovery_outbox_due_idx
    ON chat_mls_recovery_outbox (state, next_attempt_at, destination, recovery_digest);

CREATE TRIGGER chat_mls_incarnation_recoveries_append_only
    BEFORE UPDATE OR DELETE ON chat_mls_incarnation_recoveries
    FOR EACH ROW EXECUTE FUNCTION reject_chat_mls_append_only_mutation();
