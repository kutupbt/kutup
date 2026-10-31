-- Back: the column, empty for every account (its envelopes were never kept
-- after the up migration; clients derive the key from the master key).
ALTER TABLE users ADD COLUMN drive_private_key_envelope text NOT NULL DEFAULT '';
