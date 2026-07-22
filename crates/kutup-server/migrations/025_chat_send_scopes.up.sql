-- One logical direct message has two independently retryable fan-outs from the
-- same sending device: recipient delivery and the sender's linked-device sent
-- transcript. Idempotency therefore needs an endpoint/delivery namespace.
ALTER TABLE chat_sends
    ADD COLUMN delivery_scope TEXT NOT NULL DEFAULT 'direct';

ALTER TABLE chat_sends DROP CONSTRAINT chat_sends_pkey;
ALTER TABLE chat_sends
    ADD CONSTRAINT chat_sends_pkey
    PRIMARY KEY (sender_user_id, sender_device_id, send_id, delivery_scope);

ALTER TABLE chat_sends
    ADD CONSTRAINT chat_sends_delivery_scope_check
    CHECK (delivery_scope IN ('direct', 'sync'));
