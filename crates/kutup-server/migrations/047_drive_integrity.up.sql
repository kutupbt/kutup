-- Drive integrity fixes (docs/drive-security-threat-model.md, "Write rights
-- and accounting").

-- A federated upload remembers the share that made it: a peer may delete only
-- what it uploaded, and a share's usage is measured from its files instead of
-- a counter that local deletes never decreased.
ALTER TABLE files
    ADD COLUMN fed_share_id UUID REFERENCES federated_outgoing_shares(id) ON DELETE SET NULL;
UPDATE files f SET fed_share_id = s.id
  FROM federated_outgoing_shares s
 WHERE f.storage_path LIKE 'fed/' || s.id::text || '/%';
CREATE INDEX files_fed_share_idx ON files (fed_share_id) WHERE fed_share_id IS NOT NULL;
ALTER TABLE federated_outgoing_shares DROP COLUMN upload_used_bytes;

-- Collaboration frames belong to the document, not the device that sent
-- them: removing a device (account wipe) must not be blocked by, or delete,
-- edits in someone else's file.
ALTER TABLE file_update_log ALTER COLUMN sender_device DROP NOT NULL;
ALTER TABLE file_update_log
    DROP CONSTRAINT file_update_log_sender_device_fkey,
    ADD CONSTRAINT file_update_log_sender_device_fkey
        FOREIGN KEY (sender_device) REFERENCES user_devices(id) ON DELETE SET NULL;

-- A pruned original has no bytes left to hash.
DROP INDEX files_ciphertext_digest_backfill_idx;
CREATE INDEX files_ciphertext_digest_backfill_idx
    ON files (created_at, id)
    WHERE ciphertext_sha256 IS NULL AND deleted_at IS NULL AND NOT original_pruned;
