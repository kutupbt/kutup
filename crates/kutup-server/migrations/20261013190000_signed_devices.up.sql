-- Collaboration devices signed by their account (docs/plans/device-registration.md):
-- each device row keeps the account authority's statement for its key and the
-- incarnation it was made under (a device of an earlier incarnation is not
-- trusted); a key belongs to one account; registrations answer a one-time
-- challenge. Devices made before this carry no statement: there are none
-- after the clean-slate wipe, and any left are dropped.
DELETE FROM user_devices;
ALTER TABLE user_devices
    ADD COLUMN incarnation_id character(64) NOT NULL,
    ADD COLUMN registration_challenge bytea NOT NULL,
    -- When the newest statement was made (renewed every two weeks).
    ADD COLUMN registration_issued_at_ms bigint NOT NULL,
    ADD COLUMN registration_signature text NOT NULL,
    -- The sign-in session that registered (or last renewed) it: the device
    -- is in use only while that session is live, so a sign-out anywhere, an
    -- expired session or a password change retires it without a signature.
    ADD COLUMN session_id uuid REFERENCES auth_sessions(id) ON DELETE SET NULL,
    -- The account's signed revocation (DeviceRevocationV1), once revoked.
    ADD COLUMN revoked_at_ms bigint,
    ADD COLUMN revocation_signature text,
    ADD CONSTRAINT user_devices_revocation_check CHECK (
        (revoked_at_ms IS NULL) = (revocation_signature IS NULL)
        AND (revoked_at_ms IS NULL OR NOT is_active)),
    ADD CONSTRAINT user_devices_incarnation_id_check CHECK (incarnation_id ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT user_devices_registration_challenge_check CHECK (octet_length(registration_challenge) = 32),
    ADD CONSTRAINT user_devices_public_signing_key UNIQUE (public_signing);

CREATE INDEX user_devices_session ON user_devices (session_id);

CREATE TABLE device_registration_challenges (
    challenge_hash bytea PRIMARY KEY CHECK (octet_length(challenge_hash) = 32),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX device_registration_challenges_expiry ON device_registration_challenges (expires_at);
