-- no-transaction
-- The rows naming a shared payload, for collecting payloads no row names
-- (alone in its migration: CONCURRENTLY can't run in a transaction).
CREATE INDEX CONCURRENTLY IF NOT EXISTS chat_mailbox_shared_payload
    ON chat_mailbox (shared_payload_id) WHERE shared_payload_id IS NOT NULL;
