-- Collab devices onto the account manifest (docs/plans/one-device-list.md,
-- wipe W5, slice 2): an editor or CLI device is a `devices` row and an entry
-- of the account's signed manifest, with its frame key there. The separate
-- collab device registry, its signed statements and revocations, and their
-- federation copies go.
--
-- The update log is cleared: its senders were global collab device ids, and
-- the wipe this lands with clears every file. Run on a live server only after
-- the user's confirmation right before the deploy.

DELETE FROM file_update_log;
ALTER TABLE file_update_log
    DROP CONSTRAINT file_update_log_sender_device_fkey,
    DROP CONSTRAINT file_update_log_remote_sender,
    DROP COLUMN sender_device,
    DROP COLUMN remote_domain,
    DROP COLUMN remote_device,
    -- The sender: a device of an account, '' for this server's accounts.
    ADD COLUMN sender_domain text NOT NULL DEFAULT '',
    ADD COLUMN sender_account uuid NOT NULL,
    ADD COLUMN sender_device integer NOT NULL CHECK (sender_device BETWEEN 1 AND 127);
-- Each sender's frame counter once per file: an exact replay is refused.
CREATE UNIQUE INDEX file_update_log_sender_seq_unique
    ON file_update_log (file_id, sender_domain, sender_account, sender_device, sender_seq);
-- What a trim of the log took with it: per sender and counter prefix (the
-- high 32 bits, drawn per editing session), the highest counter trimmed. A
-- frame at or below it under that prefix is still a replay once its row is
-- gone.
CREATE TABLE file_sender_floors (
    file_id uuid NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    sender_domain text NOT NULL,
    sender_account uuid NOT NULL,
    sender_device integer NOT NULL,
    seq_prefix bigint NOT NULL,
    sender_seq bigint NOT NULL,
    PRIMARY KEY (file_id, sender_domain, sender_account, sender_device, seq_prefix)
);

DROP TABLE collab_revocation_marks;
DROP TABLE remote_revocation_marks;
DROP TABLE remote_revoked_device_keys;
DROP TABLE remote_collab_devices;
DROP TABLE device_registration_challenges;
DROP TABLE user_devices;

-- Chat's socket tickets are every device's.
ALTER TABLE chat_ws_tickets RENAME TO device_tickets;
ALTER TABLE device_tickets RENAME CONSTRAINT chat_ws_tickets_pkey TO device_tickets_pkey;
ALTER TABLE device_tickets RENAME CONSTRAINT chat_ws_tickets_token_hash_check
    TO device_tickets_token_hash_check;
ALTER TABLE device_tickets RENAME CONSTRAINT chat_ws_tickets_user_id_device_id_fkey
    TO device_tickets_user_id_device_id_fkey;
ALTER INDEX chat_ws_tickets_expiry_idx RENAME TO device_tickets_expiry_idx;

-- Other servers' accounts' manifests, as this server last verified them:
-- the frame keys their devices sign collab frames with. A head moves only
-- forward along its chain.
CREATE TABLE remote_account_manifests (
    domain text NOT NULL,
    account_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    manifest_hash text NOT NULL CHECK (manifest_hash ~ '^[0-9a-f]{64}$'),
    manifest jsonb NOT NULL,
    fetched_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (domain, account_id)
);

-- A failed read of such a manifest with none cached: further frames of that
-- account wait out the refetch interval instead of each starting a read.
CREATE TABLE remote_manifest_failures (
    domain text NOT NULL,
    account_id uuid NOT NULL,
    failed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (domain, account_id)
);
