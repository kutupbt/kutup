-- One federation outbox, part 2 (docs/plans/federation-outbox.md): Chat media
-- offers and rename announces join plain and sealed chat in
-- federation_outbox, and media's answers join federation_inbound. Media's
-- pull lease (chat_media_federation_inbound_pending) stays its own: it is a
-- reservation, not a queue.

-- Media offers: one sequence per destination, as their receivers check.
--
-- A v1 receiver recorded only some of its final answers (stored, storage
-- full, the uniform 404 of a capability); a refusal it did not record (an
-- offer invalid or expired on arrival, a routing or identity mismatch) left
-- its mark below the sequence, so every later offer to it would meet a gap.
-- So a refused v1 offer is not taken as settled: it goes pending again under
-- its own sequence ("closing_sequence", as plain chat's v1 mismatches), and
-- the receiver now replays the answer it recorded or refuses it and records
-- that, which uses the sequence up. A delivered v1 offer kept no answer: it
-- gets the one a repeat of it should read (already stored).
INSERT INTO federation_outbox
    (id, kind, destination, sequence, idempotency_key, sender_user_id, recipient_account_id,
     payload, state, error_class, answer, attempts, next_attempt_at, created_at, updated_at)
SELECT id, 'media', destination, sequence,
       origin_user_id::text || ':' || operation_id::text,
       origin_user_id,
       (transaction->'offer'->'recipient'->>'accountId')::uuid,
       jsonb_build_object('transaction', transaction, 'operationId', operation_id),
       CASE state WHEN 'rejected' THEN 'pending' ELSE state END,
       CASE state WHEN 'rejected' THEN 'closing_sequence' ELSE last_error_class END,
       CASE state WHEN 'delivered' THEN jsonb_build_object(
           'outcome', 'receipt',
           'receipt', jsonb_build_object('operationId', operation_id::text,
                                         'status', 'already_stored'))
       END,
       attempts,
       CASE state WHEN 'rejected' THEN now() ELSE next_attempt_at END,
       created_at, updated_at
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
