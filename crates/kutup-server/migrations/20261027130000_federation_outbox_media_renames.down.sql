-- Back to Chat media's and rename announces' own tables, as the baseline
-- made them, with their rows (a media row whose sender was deleted has no
-- older form and is dropped).
CREATE TABLE chat_media_federation_inbound_state (
    origin text PRIMARY KEY,
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE chat_media_federation_inbound_transactions (
    origin text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    operation_id uuid NOT NULL,
    transaction_digest character(64) NOT NULL CHECK (transaction_digest ~ '^[0-9a-f]{64}$'),
    response_status smallint NOT NULL,
    response jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (origin, sequence),
    UNIQUE (origin, operation_id)
);
CREATE TABLE chat_media_federation_outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    destination text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    origin_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    operation_id uuid NOT NULL,
    transaction jsonb NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'rejected')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error_class text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (destination, sequence),
    UNIQUE (origin_user_id, operation_id)
);
CREATE INDEX idx_chat_media_federation_outbox_retry
    ON chat_media_federation_outbox (state, next_attempt_at, destination, sequence);
CREATE TABLE chat_media_federation_sequences (
    destination text PRIMARY KEY,
    next_sequence bigint NOT NULL DEFAULT 1 CHECK (next_sequence > 0)
);
CREATE TABLE rename_announce_outbox (
    destination text NOT NULL,
    incarnation_id character(64) NOT NULL CHECK (incarnation_id ~ '^[0-9a-f]{64}$'),
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 1000),
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_error text,
    PRIMARY KEY (destination, incarnation_id, sequence)
);
CREATE INDEX rename_announce_outbox_due ON rename_announce_outbox (next_attempt_at);

-- The old table names every offer's sender; one of a deleted account can't
-- go back. A settled one is dropped (its sequence is used up at the
-- destination, so nothing waits on it); a pending one would leave its
-- destination a gap, so the down migration stops until it has settled.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM federation_outbox
              WHERE kind = 'media' AND state = 'pending' AND sender_user_id IS NULL) THEN
    RAISE EXCEPTION 'pending Chat media offers of deleted accounts: let them settle first';
  END IF;
END $$;

INSERT INTO chat_media_federation_outbox
    (id, destination, sequence, origin_user_id, operation_id, transaction, state, attempts,
     next_attempt_at, last_error_class, created_at, updated_at)
SELECT id, destination, sequence, sender_user_id, (payload->>'operationId')::uuid,
       payload->'transaction', state, attempts, next_attempt_at, error_class, created_at,
       updated_at
FROM federation_outbox WHERE kind = 'media' AND sender_user_id IS NOT NULL;
INSERT INTO chat_media_federation_sequences
    SELECT destination, next_sequence FROM federation_sequences WHERE kind = 'media';
INSERT INTO chat_media_federation_inbound_state (origin, last_sequence, updated_at)
    SELECT origin, last_sequence, updated_at FROM federation_inbound_state WHERE kind = 'media';
INSERT INTO chat_media_federation_inbound_transactions
    (origin, sequence, operation_id, transaction_digest, response_status, response, created_at)
-- A refusal recorded without its operation (it may be of a reused one) gets
-- an id of its own: v1 checks a replay by its digest, not its operation.
SELECT origin, sequence, COALESCE(transaction_id::uuid, gen_random_uuid()), digest, status,
       answer, created_at
FROM federation_inbound WHERE kind = 'media';
INSERT INTO rename_announce_outbox
    (destination, incarnation_id, sequence, attempts, next_attempt_at, created_at, last_error)
SELECT destination, payload->>'incarnation', (payload->>'chainSequence')::integer, attempts,
       next_attempt_at, created_at, last_error
FROM federation_outbox WHERE kind = 'rename' AND state = 'pending';

DROP INDEX federation_outbox_rename_incarnation;
DROP INDEX federation_outbox_media_pending;
DROP INDEX federation_inbound_media_operation;
DELETE FROM federation_outbox WHERE kind IN ('media', 'rename');
DELETE FROM federation_sequences WHERE kind = 'media';
DELETE FROM federation_inbound_state WHERE kind = 'media';
DELETE FROM federation_inbound WHERE kind = 'media';
