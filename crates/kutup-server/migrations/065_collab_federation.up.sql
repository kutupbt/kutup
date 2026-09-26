-- Live editing across servers (docs/plans/collab-federation.md).

-- Frames kept from an editor on another server: that server and its device
-- (the local `sender_device` is null). Exact replays are refused per sender,
-- as for local devices.
ALTER TABLE file_update_log
    ADD COLUMN remote_domain TEXT,
    ADD COLUMN remote_device BIGINT,
    ADD CONSTRAINT file_update_log_remote_sender CHECK ((remote_domain IS NULL) = (remote_device IS NULL));
CREATE UNIQUE INDEX file_update_log_remote_sender_seq_unique
    ON file_update_log (file_id, remote_domain, remote_device, sender_seq)
    WHERE remote_domain IS NOT NULL;

-- A version saved by someone on another server: who (`user@server`). The
-- file's owner is its `author_user_id` and pays for it, as for uploads into
-- shared folders from other servers.
ALTER TABLE file_versions ADD COLUMN remote_author TEXT CHECK (length(remote_author) <= 320);

-- A file shared by itself across servers may now allow editing.
ALTER TABLE federated_outgoing_file_shares ADD COLUMN can_edit BOOLEAN NOT NULL DEFAULT false;
