-- Chat names every account by its full `username@server` address, in the
-- mailbox as on the wire. Rows written with a bare local username (before
-- this change) are dropped rather than converted: no pre-change Chat data is
-- kept readable. Sealed rows keep a NULL sender.
DELETE FROM chat_mailbox
WHERE sender IS NOT NULL AND sender !~ '^[a-z0-9_-]{3,32}@[a-z0-9.-]{1,253}$';
ALTER TABLE chat_mailbox
    ADD CONSTRAINT chat_mailbox_sender_qualified
    CHECK (sender IS NULL OR sender ~ '^[a-z0-9_-]{3,32}@[a-z0-9.-]{1,253}$');

-- Queued sealed federation transactions named the recipient by a bare
-- username, which a destination now refuses. Qualify them in place (rather
-- than delete them) so each destination's sequence stays contiguous.
UPDATE chat_sealed_federation_outbox
SET transaction = jsonb_set(transaction, '{recipient}', to_jsonb(recipient || '@' || destination))
WHERE position('@' IN transaction->>'recipient') = 0;
