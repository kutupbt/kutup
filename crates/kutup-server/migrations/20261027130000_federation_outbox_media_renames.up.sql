-- One federation outbox, part 2 (docs/plans/federation-outbox.md): Chat media
-- offers and rename announces join plain and sealed chat in
-- federation_outbox, and media's answers join federation_inbound. Media's
-- pull lease (chat_media_federation_inbound_pending) stays its own: it is a
-- reservation, not a queue.

-- Media offers: one sequence per destination, as their receivers check.
INSERT INTO federation_outbox
    (id, kind, destination, sequence, idempotency_key, sender_user_id, recipient_account_id,
     payload, state, error_class, attempts, next_attempt_at, created_at, updated_at)
SELECT id, 'media', destination, sequence,
       origin_user_id::text || ':' || operation_id::text,
       origin_user_id,
       (transaction->'offer'->'recipient'->>'accountId')::uuid,
       jsonb_build_object('transaction', transaction, 'operationId', operation_id),
       state, last_error_class, attempts, next_attempt_at, created_at, updated_at
FROM chat_media_federation_outbox;
INSERT INTO federation_sequences (kind, destination, next_sequence)
    SELECT 'media', destination, next_sequence FROM chat_media_federation_sequences;
INSERT INTO federation_inbound_state (kind, origin, last_sequence, updated_at)
    SELECT 'media', origin, last_sequence, updated_at FROM chat_media_federation_inbound_state;
INSERT INTO federation_inbound
    (kind, origin, sequence, transaction_id, digest, status, answer, created_at)
SELECT 'media', origin, sequence, operation_id::text, transaction_digest, response_status,
       response, created_at
FROM chat_media_federation_inbound_transactions;

-- Rename announces carry the account's whole rename chain and have no
-- transport sequence: one row per (destination, incarnation), up to the
-- chain sequence it announces.
INSERT INTO federation_outbox
    (kind, destination, idempotency_key, payload, attempts, next_attempt_at, last_error,
     created_at, updated_at)
SELECT 'rename', destination,
       destination || ':' || incarnation_id || ':' || sequence::text,
       jsonb_build_object('incarnation', incarnation_id, 'chainSequence', sequence),
       attempts, next_attempt_at, last_error, created_at, created_at
FROM rename_announce_outbox;
-- An account's announces, by its incarnation.
CREATE INDEX federation_outbox_rename_incarnation
    ON federation_outbox ((payload->>'incarnation')) WHERE kind = 'rename';
-- A sender's media offers still going (deleting a copy waits for them).
CREATE INDEX federation_outbox_media_pending
    ON federation_outbox (sender_user_id) WHERE kind = 'media' AND state = 'pending';
-- An origin names each media operation once, at one sequence.
CREATE UNIQUE INDEX federation_inbound_media_operation
    ON federation_inbound (origin, transaction_id) WHERE kind = 'media';

DROP TABLE chat_media_federation_outbox;
DROP TABLE chat_media_federation_sequences;
DROP TABLE chat_media_federation_inbound_transactions;
DROP TABLE chat_media_federation_inbound_state;
DROP TABLE rename_announce_outbox;
