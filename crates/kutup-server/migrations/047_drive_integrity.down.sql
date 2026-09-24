DROP INDEX files_ciphertext_digest_backfill_idx;
CREATE INDEX files_ciphertext_digest_backfill_idx
    ON files (created_at, id) WHERE ciphertext_sha256 IS NULL AND deleted_at IS NULL;

DELETE FROM file_update_log WHERE sender_device IS NULL;
ALTER TABLE file_update_log
    DROP CONSTRAINT file_update_log_sender_device_fkey,
    ADD CONSTRAINT file_update_log_sender_device_fkey
        FOREIGN KEY (sender_device) REFERENCES user_devices(id);
ALTER TABLE file_update_log ALTER COLUMN sender_device SET NOT NULL;

ALTER TABLE federated_outgoing_shares
    ADD COLUMN upload_used_bytes BIGINT NOT NULL DEFAULT 0 CHECK (upload_used_bytes >= 0);
UPDATE federated_outgoing_shares s SET upload_used_bytes = COALESCE(
    (SELECT SUM(encrypted_size_bytes) FROM files f WHERE f.fed_share_id = s.id), 0);
DROP INDEX files_fed_share_idx;
ALTER TABLE files DROP COLUMN fed_share_id;
