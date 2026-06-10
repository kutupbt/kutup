-- Per-device sequence tracking for replay protection. Spec §5.
-- Each (file_id, sender_device) pair must see strictly-increasing sender_seq.
-- The UNIQUE constraint causes Postgres to reject replays at INSERT time.

ALTER TABLE file_update_log ADD COLUMN sender_seq BIGINT NOT NULL DEFAULT 0;

-- Default 0 only for any pre-migration rows. New inserts must populate explicitly.
-- After this migration, the relay handler will populate sender_seq from frame.Sequence.

CREATE UNIQUE INDEX file_update_log_sender_seq_unique
  ON file_update_log (file_id, sender_device, sender_seq);
