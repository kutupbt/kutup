-- A locally durable registration request may be retried after the server
-- committed but before the client persisted its assigned device id. The
-- identity key is install-unique, so it is the natural idempotency key.
ALTER TABLE chat_devices
    ADD CONSTRAINT chat_devices_identity_unique UNIQUE (user_id, identity_key);
