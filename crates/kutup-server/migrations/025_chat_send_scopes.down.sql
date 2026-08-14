-- Sync claims have no representation in the original unscoped key.
DELETE FROM chat_sends WHERE delivery_scope = 'sync';

ALTER TABLE chat_sends DROP CONSTRAINT chat_sends_delivery_scope_check;
ALTER TABLE chat_sends DROP CONSTRAINT chat_sends_pkey;
ALTER TABLE chat_sends
    ADD CONSTRAINT chat_sends_pkey
    PRIMARY KEY (sender_user_id, sender_device_id, send_id);
ALTER TABLE chat_sends DROP COLUMN delivery_scope;
