-- Collaboration log positions only ever go up (docs/plans/maps.md, 4a).
--
-- A saved version trims the log up to the position it contains. Trimming
-- the whole log used to make the next frame restart at 1; the floor keeps
-- the position counting from where the trimmed log ended.
ALTER TABLE files ADD COLUMN collab_log_floor BIGINT NOT NULL DEFAULT 0
    CHECK (collab_log_floor >= 0);

-- Notes recorded a client counter (a random prefix above 2^32) as the saved
-- version's log position. Those positions mean nothing: start readers of
-- such versions from the beginning of whatever log is left.
UPDATE file_versions SET seq_at_snapshot = 0 WHERE seq_at_snapshot > 2147483647;
