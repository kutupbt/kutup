-- Back to the separate plain and sealed chat tables, as the baseline and
-- 20261018120000 made them, with their rows.
CREATE TABLE chat_federation_outbox (
    id uuid PRIMARY KEY,
    destination text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    sender_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender_device_id integer NOT NULL,
    send_id text NOT NULL,
    request jsonb NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'mismatch', 'delivered')),
    response jsonb,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    recipient_account_id uuid NOT NULL,
    UNIQUE (destination, sequence),
    UNIQUE (sender_user_id, sender_device_id, send_id)
);
CREATE TABLE chat_federation_sequences (
    destination text PRIMARY KEY,
    next_sequence bigint NOT NULL
);
CREATE TABLE chat_federation_inbound_state (
    origin text PRIMARY KEY,
    last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE chat_federation_inbound_transactions (
    origin text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    transaction_id text NOT NULL,
    response jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (origin, sequence),
    UNIQUE (origin, transaction_id)
);
CREATE TABLE chat_sealed_federation_outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    destination text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    sender_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    sender_device_id integer CHECK (sender_device_id IS NULL OR sender_device_id BETWEEN 1 AND 127),
    send_id uuid NOT NULL,
    transaction jsonb NOT NULL CHECK (jsonb_typeof(transaction) = 'object'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'rejected')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error_class text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    recipient_account_id uuid NOT NULL,
    answer jsonb,
    UNIQUE (destination, sequence),
    UNIQUE (destination, recipient_account_id, send_id)
);
CREATE TABLE chat_sealed_federation_sequences (
    destination text PRIMARY KEY,
    next_sequence bigint NOT NULL
);
CREATE TABLE chat_sealed_federation_inbound (
    origin text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    send_id uuid NOT NULL,
    response_status smallint NOT NULL CHECK (response_status BETWEEN 200 AND 599),
    response jsonb NOT NULL CHECK (jsonb_typeof(response) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (origin, sequence)
);

-- A rejected plain chat row was a pending device mismatch before; one with
-- a later answer than that has no older form and is dropped.
INSERT INTO chat_federation_outbox
    (id, destination, sequence, sender_user_id, sender_device_id, send_id, request, state,
     response, attempts, next_attempt_at, last_error, created_at, updated_at,
     recipient_account_id)
SELECT id, destination, sequence, sender_user_id, split_part(idempotency_key, ':', 2)::integer,
       substr(idempotency_key, length(split_part(idempotency_key, ':', 1))
                               + length(split_part(idempotency_key, ':', 2)) + 3),
       payload->'request',
       CASE state WHEN 'rejected' THEN 'mismatch' ELSE state END,
       answer, attempts, next_attempt_at, last_error, created_at, updated_at, recipient_account_id
FROM federation_outbox
WHERE kind = 'chat' AND sender_user_id IS NOT NULL
  AND (state <> 'rejected' OR error_class = 'device_mismatch');
INSERT INTO chat_federation_sequences
    SELECT destination, next_sequence FROM federation_sequences WHERE kind = 'chat';
INSERT INTO chat_federation_inbound_state (origin, last_sequence, updated_at)
    SELECT origin, last_sequence, updated_at FROM federation_inbound_state WHERE kind = 'chat';
INSERT INTO chat_federation_inbound_transactions (origin, sequence, transaction_id, response, created_at)
    SELECT DISTINCT ON (origin, transaction_id) origin, sequence, transaction_id, answer, created_at
    FROM federation_inbound WHERE kind = 'chat' AND status = 200
    ORDER BY origin, transaction_id, sequence DESC;
INSERT INTO chat_sealed_federation_outbox
    (id, destination, sequence, sender_user_id, sender_device_id, send_id, transaction, state,
     attempts, next_attempt_at, last_error_class, created_at, updated_at, recipient_account_id,
     answer)
SELECT id, destination, sequence, sender_user_id, (payload->>'senderDeviceId')::integer,
       split_part(idempotency_key, ':', 3)::uuid, payload->'transaction', state, attempts,
       next_attempt_at, error_class, created_at, updated_at, recipient_account_id, answer
FROM federation_outbox WHERE kind = 'sealed';
INSERT INTO chat_sealed_federation_sequences
    SELECT destination, next_sequence FROM federation_sequences WHERE kind = 'sealed';
INSERT INTO chat_sealed_federation_inbound (origin, sequence, send_id, response_status, response, created_at)
    SELECT origin, sequence, transaction_id::uuid, status, answer, created_at
    FROM federation_inbound WHERE kind = 'sealed';

DROP TABLE federation_inbound;
DROP TABLE federation_inbound_state;
DROP TABLE federation_sequences;
DROP TABLE federation_outbox;
