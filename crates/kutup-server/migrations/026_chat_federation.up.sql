-- Durable, strictly ordered transport-only chat federation.

-- The next sequence allocated to each remote destination. Allocation and
-- outbox insertion happen in one transaction, so committed sequences have no
-- local gaps.
CREATE TABLE chat_federation_sequences (
    destination   TEXT PRIMARY KEY,
    next_sequence BIGINT NOT NULL CHECK (next_sequence > 0)
);

-- One durable server-to-server transaction per logical client send. Delivered
-- rows remain for the normal send-id retention window so client retries can be
-- answered without duplicating a remote mailbox delivery.
CREATE TABLE chat_federation_outbox (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    destination      TEXT        NOT NULL,
    sequence         BIGINT      NOT NULL CHECK (sequence > 0),
    sender_user_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender_device_id INT         NOT NULL,
    send_id          TEXT        NOT NULL,
    recipient        TEXT        NOT NULL,
    sender           TEXT        NOT NULL,
    request          JSONB       NOT NULL,
    state            TEXT        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'mismatch', 'delivered')),
    response         JSONB,
    attempts         INT         NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (destination, sequence),
    UNIQUE (sender_user_id, sender_device_id, send_id)
);

CREATE INDEX chat_federation_outbox_due_idx
    ON chat_federation_outbox (state, next_attempt_at, destination, sequence);

-- Receiver-side contiguous sequence and replay record. The response row and
-- mailbox inserts commit atomically before last_sequence advances.
CREATE TABLE chat_federation_inbound_state (
    origin        TEXT PRIMARY KEY,
    last_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE chat_federation_inbound_transactions (
    origin         TEXT        NOT NULL REFERENCES chat_federation_inbound_state(origin)
                                 ON DELETE CASCADE,
    sequence       BIGINT      NOT NULL CHECK (sequence > 0),
    transaction_id TEXT        NOT NULL,
    response       JSONB       NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (origin, sequence),
    UNIQUE (origin, transaction_id)
);
