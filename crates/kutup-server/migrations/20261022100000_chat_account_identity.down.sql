DROP TABLE chat_link_tokens;
ALTER TABLE chat_devices
    DROP COLUMN expired_at,
    DROP COLUMN credential_hash,
    DROP COLUMN credential_salt;
DELETE FROM chat_devices;
ALTER TABLE chat_devices
    ADD CONSTRAINT chat_devices_identity_unique UNIQUE (user_id, identity_key);
DROP TABLE chat_account_identities;
