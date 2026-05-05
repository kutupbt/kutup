DROP INDEX IF EXISTS file_update_log_sender_seq_unique;
ALTER TABLE file_update_log DROP COLUMN sender_seq;
