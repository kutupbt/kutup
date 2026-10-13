-- Collaboration devices of people on other servers (docs/plans/device-registration.md,
-- "Remote devices"): a bridge announces each device with its account's signed
-- statement; home keeps a frame only from an announced, fresh device of the
-- share's recipient. Devices are bound to the account's incarnation (the hash
-- of its authority), not its name, so a rename does not orphan them.

-- The recipient's incarnation, read from the verified named share envelope
-- (a field the sharer signed): whose devices may write through this share.
DELETE FROM federated_outgoing_shares;
ALTER TABLE federated_outgoing_shares
    ADD COLUMN recipient_incarnation_id character(64) NOT NULL,
    ADD CONSTRAINT federated_outgoing_shares_recipient_incarnation_check
        CHECK (recipient_incarnation_id ~ '^[0-9a-f]{64}$');

CREATE TABLE remote_collab_devices (
    domain text NOT NULL,
    device_id bigint NOT NULL,
    incarnation_id character(64) NOT NULL CHECK (incarnation_id ~ '^[0-9a-f]{64}$'),
    -- `username@domain` when announced: shown, never trusted (renames).
    account text NOT NULL,
    -- The remote server's id for the account, as the statement signs it.
    user_id text NOT NULL,
    authority_public_key text NOT NULL,
    public_signing bytea NOT NULL CHECK (octet_length(public_signing) = 32),
    -- The newest statement (DeviceRegistrationV1): its age is the lease.
    registration_challenge bytea NOT NULL CHECK (octet_length(registration_challenge) = 32),
    registration_issued_at_ms bigint NOT NULL,
    registration_signature text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    revoked_at_ms bigint,
    revocation_signature text,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz,
    PRIMARY KEY (domain, device_id),
    UNIQUE (domain, public_signing),
    CHECK ((revoked_at_ms IS NULL) = (revocation_signature IS NULL)),
    CHECK (revoked_at_ms IS NULL OR NOT active)
);
CREATE INDEX remote_collab_devices_incarnation ON remote_collab_devices (domain, incarnation_id);

-- A revoked remote key, for good (only its hash): it is never announced
-- again, even after its device rows are swept.
CREATE TABLE remote_revoked_device_keys (
    key_hash bytea PRIMARY KEY CHECK (octet_length(key_hash) = 32),
    domain text NOT NULL,
    -- Whose: how far a bridge's revocations for that account have reached.
    incarnation_id character(64) NOT NULL,
    revoked_at_ms bigint NOT NULL
);
CREATE INDEX remote_revoked_device_keys_account ON remote_revoked_device_keys (domain, incarnation_id);

-- A bridge's progress telling a home its users' revocations: the newest
-- revocation time home has stored, per home and account.
CREATE TABLE collab_revocation_marks (
    home_domain text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    through_ms bigint NOT NULL,
    PRIMARY KEY (home_domain, user_id)
);
