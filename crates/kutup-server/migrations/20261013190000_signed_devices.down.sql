DROP TABLE device_registration_challenges;
ALTER TABLE user_devices
    DROP CONSTRAINT user_devices_public_signing_key,
    DROP CONSTRAINT user_devices_registration_challenge_check,
    DROP CONSTRAINT user_devices_incarnation_id_check,
    DROP COLUMN registration_signature,
    DROP COLUMN registration_challenge,
    DROP COLUMN incarnation_id;
