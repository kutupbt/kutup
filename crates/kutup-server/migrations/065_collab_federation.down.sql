ALTER TABLE federated_outgoing_file_shares DROP COLUMN can_edit;
ALTER TABLE file_versions DROP COLUMN remote_author;
DROP INDEX IF EXISTS file_update_log_remote_sender_seq_unique;
DELETE FROM file_update_log WHERE remote_domain IS NOT NULL;
ALTER TABLE file_update_log DROP CONSTRAINT file_update_log_remote_sender, DROP COLUMN remote_device, DROP COLUMN remote_domain;
