-- Every answer to a sealed federation transaction uses up its sequence
-- (docs/chat-protocol.md §7): a device mismatch is recorded like a delivery,
-- a refusal or the uniform 404, and the corrected resend takes a new
-- sequence with the same sendId. So one sendId may have several recorded
-- answers. Nothing looks answers up by sendId: the recipient's own dedup is
-- chat_anonymous_send_ids.
ALTER TABLE chat_sealed_federation_inbound
    DROP CONSTRAINT chat_sealed_federation_inbound_origin_send_id_key;

-- Sends that met a device mismatch before this kept their sequence open at
-- the destination, holding every later send to it. Each is sent once more
-- under that sequence, so the destination records its answer and the
-- origin's queue moves on; its client's corrected resend takes a new one.
UPDATE chat_sealed_federation_outbox
   SET state = 'pending', last_error_class = 'closing_sequence',
       next_attempt_at = now(), updated_at = now()
 WHERE state = 'rejected' AND last_error_class = 'device_mismatch';

-- A settled send keeps its destination's answer, so a client whose send
-- another flush settled (the retry worker's) still learns what it was.
ALTER TABLE chat_sealed_federation_outbox ADD COLUMN answer jsonb;

-- Queued sends from before version 2 go out at version 2: the server stamps
-- each send with its own version anyway; this keeps the stored rows true.
UPDATE chat_sealed_federation_outbox
   SET transaction = jsonb_set(transaction, '{version}', '2')
 WHERE state <> 'delivered';
