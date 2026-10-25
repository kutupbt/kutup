-- Back to Chat's own device table. Its rows can't go back to V2 manifests,
-- so every device and manifest goes, as on the way up.

DELETE FROM chat_link_tokens;
DELETE FROM devices;
DELETE FROM chat_device_manifest_history;
DELETE FROM chat_device_manifests;
DELETE FROM chat_account_identities;

DROP INDEX devices_session;
ALTER TABLE devices
    DROP CONSTRAINT devices_kind_keys,
    DROP COLUMN kind,
    DROP COLUMN session_id,
    DROP COLUMN frame_key,
    ALTER COLUMN suite SET NOT NULL,
    ALTER COLUMN registration_id SET NOT NULL,
    ALTER COLUMN identity_key SET NOT NULL,
    ALTER COLUMN signed_pre_key_id SET NOT NULL,
    ALTER COLUMN signed_pre_key SET NOT NULL,
    ALTER COLUMN signed_pre_key_signature SET NOT NULL,
    ALTER COLUMN last_resort_kyber_pre_key_id SET NOT NULL,
    ALTER COLUMN last_resort_kyber_pre_key SET NOT NULL,
    ALTER COLUMN last_resort_kyber_pre_key_signature SET NOT NULL;

ALTER TABLE devices RENAME CONSTRAINT devices_suite_known TO chat_devices_suite_known;
ALTER TABLE devices RENAME CONSTRAINT devices_device_id_check TO chat_devices_device_id_check;
ALTER TABLE devices RENAME CONSTRAINT devices_user_id_fkey TO chat_devices_user_id_fkey;
ALTER TABLE devices RENAME CONSTRAINT devices_pkey TO chat_devices_pkey;
ALTER TABLE devices RENAME TO chat_devices;
