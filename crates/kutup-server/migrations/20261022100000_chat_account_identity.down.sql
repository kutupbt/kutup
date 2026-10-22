-- Destructive, as the up migration is: every Chat device and every V2
-- manifest goes (there is no way back to per-device identities); accounts
-- re-register their Chat devices.
DELETE FROM chat_device_manifest_history;
DELETE FROM chat_device_manifests;
DROP TABLE chat_link_tokens;
ALTER TABLE chat_devices
    DROP COLUMN expired_at,
    DROP COLUMN credential_hash,
    DROP COLUMN credential_salt;
DELETE FROM chat_devices;
ALTER TABLE chat_devices
    ADD CONSTRAINT chat_devices_identity_unique UNIQUE (user_id, identity_key);
DROP TABLE chat_account_identities;
