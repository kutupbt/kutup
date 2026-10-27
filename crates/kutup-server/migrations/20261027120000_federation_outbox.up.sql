-- One federation outbox (docs/plans/federation-outbox.md): every kind of
-- delivery to a peer server in one table, each kind with its own sequence
-- per destination (what every receiver checks, so nothing changes on the
-- wire), and one inbound record of the answers given, per kind and origin.
-- This migration moves plain and sealed chat; media and rename announces
-- move in the next.
CREATE TABLE federation_outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK (kind IN ('chat', 'sealed', 'media', 'rename')),
    destination text NOT NULL,
    -- NULL for a kind without a transport sequence (rename announces).
    sequence bigint CHECK (sequence > 0),
    -- The kind's own idempotency, across destinations: chat
    -- `sender:device:sendId`, sealed `destination:recipient:sendId`, media
    -- `user:operation`.
    idempotency_key text NOT NULL,
    -- The local account that sent it. Its deletion leaves the row, which
    -- still goes (its payload names the sender): a destination must see
    -- every sequence, and a row dropped here would leave it a gap.
    sender_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    recipient_account_id uuid,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'rejected')),
    -- Why a row was rejected, or why its last try failed.
    error_class text,
    last_error text,
    -- The destination's final answer, read back by a repeated send.
    answer jsonb,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, destination, sequence),
    UNIQUE (kind, idempotency_key)
);
-- Each destination's head per kind, and what is due.
CREATE INDEX federation_outbox_pending
    ON federation_outbox (kind, destination, sequence) WHERE state = 'pending';
CREATE INDEX federation_outbox_due
    ON federation_outbox (kind, next_attempt_at) WHERE state = 'pending';
-- Delivered and rejected rows, for pruning.
CREATE INDEX federation_outbox_settled
    ON federation_outbox (updated_at) WHERE state <> 'pending';

CREATE TABLE federation_sequences (
    kind text NOT NULL,
    destination text NOT NULL,
    next_sequence bigint NOT NULL CHECK (next_sequence > 0),
    PRIMARY KEY (kind, destination)
);

-- The highest sequence each origin's stream has used up, per kind: every
-- final answer uses one up, delivered or not.
CREATE TABLE federation_inbound_state (
    kind text NOT NULL,
    origin text NOT NULL,
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, origin)
);

-- The final answer given to each (origin, sequence), replayed to a retry.
CREATE TABLE federation_inbound (
    kind text NOT NULL,
    origin text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    -- What the origin named the transaction (chat: its row id; sealed: the
    -- sendId; media: the operation), and the digest of its body where a
    -- replay must be byte-identical.
    transaction_id text,
    digest text,
    status smallint NOT NULL CHECK (status BETWEEN 200 AND 599),
    answer jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, origin, sequence)
);
CREATE INDEX federation_inbound_created ON federation_inbound (created_at);

-- Plain chat. A device mismatch was kept pending under its sequence; it is a
-- final, rejected answer now, and the corrected resend takes a new sequence.
INSERT INTO federation_outbox
    (id, kind, destination, sequence, idempotency_key, sender_user_id, recipient_account_id,
     payload, state, error_class, last_error, answer, attempts, next_attempt_at,
     created_at, updated_at)
SELECT id, 'chat', destination, sequence,
       sender_user_id::text || ':' || sender_device_id::text || ':' || send_id,
       sender_user_id, recipient_account_id,
       jsonb_build_object('request', request, 'sender', sender_user_id),
       CASE state WHEN 'mismatch' THEN 'rejected' ELSE state END,
       CASE state WHEN 'mismatch' THEN 'device_mismatch' END,
       last_error, response, attempts, next_attempt_at, created_at, updated_at
FROM chat_federation_outbox;
INSERT INTO federation_sequences (kind, destination, next_sequence)
    SELECT 'chat', destination, next_sequence FROM chat_federation_sequences;
INSERT INTO federation_inbound_state (kind, origin, last_sequence, updated_at)
    SELECT 'chat', origin, last_sequence, updated_at FROM chat_federation_inbound_state;
INSERT INTO federation_inbound (kind, origin, sequence, transaction_id, status, answer, created_at)
    SELECT 'chat', origin, sequence, transaction_id, 200, response, created_at
    FROM chat_federation_inbound_transactions;

-- Sealed chat.
INSERT INTO federation_outbox
    (id, kind, destination, sequence, idempotency_key, sender_user_id, recipient_account_id,
     payload, state, error_class, answer, attempts, next_attempt_at, created_at, updated_at)
SELECT id, 'sealed', destination, sequence,
       destination || ':' || recipient_account_id::text || ':' || send_id::text,
       sender_user_id, recipient_account_id,
       jsonb_build_object('transaction', transaction)
           || CASE WHEN sender_device_id IS NULL THEN '{}'::jsonb
                   ELSE jsonb_build_object('senderDeviceId', sender_device_id) END,
       state, last_error_class, answer, attempts, next_attempt_at, created_at, updated_at
FROM chat_sealed_federation_outbox;
INSERT INTO federation_sequences (kind, destination, next_sequence)
    SELECT 'sealed', destination, next_sequence FROM chat_sealed_federation_sequences;
-- Its receiver read the high-water mark from its records; now it has one.
INSERT INTO federation_inbound_state (kind, origin, last_sequence)
    SELECT 'sealed', origin, max(sequence) FROM chat_sealed_federation_inbound GROUP BY origin;
INSERT INTO federation_inbound (kind, origin, sequence, transaction_id, status, answer, created_at)
    SELECT 'sealed', origin, sequence, send_id::text, response_status, response, created_at
    FROM chat_sealed_federation_inbound;

DROP TABLE chat_federation_outbox;
DROP TABLE chat_federation_sequences;
DROP TABLE chat_federation_inbound_transactions;
DROP TABLE chat_federation_inbound_state;
DROP TABLE chat_sealed_federation_outbox;
DROP TABLE chat_sealed_federation_sequences;
DROP TABLE chat_sealed_federation_inbound;
