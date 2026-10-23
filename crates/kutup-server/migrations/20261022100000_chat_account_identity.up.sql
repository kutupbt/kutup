-- One libsignal identity per account, as Signal's ACI
-- (docs/plans/account-identity-key.md). No migration of the old per-device
-- identities: every Chat device and manifest goes (prekeys, mailboxes, push
-- subscriptions and socket tickets cascade), and each account's next Chat
-- device registers by re-registration under a new account identity. Run on a
-- live server only after the user's confirmation right before the deploy.

DELETE FROM chat_mls_devices;
DELETE FROM chat_devices;
DELETE FROM chat_device_manifest_history;
DELETE FROM chat_device_manifests;

-- The account's identity: one row per account with a Chat device.
CREATE TABLE chat_account_identities (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    -- Canonical base64 of libsignal's 33-byte public key.
    identity_key text NOT NULL,
    -- The V2 manifest sequence that set it.
    manifest_version bigint NOT NULL CHECK (manifest_version >= 1),
    changed_at timestamptz NOT NULL DEFAULT now()
);

-- Every device of an account carries the account's identity (checked where
-- rows are written: a cross-table CHECK isn't possible), so the old
-- per-device uniqueness goes.
ALTER TABLE chat_devices DROP CONSTRAINT chat_devices_identity_unique;
-- The device's credential (Signal's per-device password): SHA-256 over the
-- salt and 32 random bytes the device drew; device-bound calls present it.
ALTER TABLE chat_devices
    ADD COLUMN credential_salt bytea NOT NULL CHECK (octet_length(credential_salt) = 16),
    ADD COLUMN credential_hash bytea NOT NULL CHECK (octet_length(credential_hash) = 32),
    -- Idle too long: out of sends and bundles at once, dropped by the
    -- account's next manifest.
    ADD COLUMN expired_at timestamptz;

-- One-time link tokens (Signal's provisioning codes); only the hash is kept.
CREATE TABLE chat_link_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    issued_by_device integer NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE INDEX chat_link_tokens_user ON chat_link_tokens (user_id, expires_at);
