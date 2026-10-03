-- Drive move (docs/plans/drive-move.md). Everything sealed under a file's key
-- is bound to the file and the key's generation, not to its folder; only the
-- file-key wrap names the folder, so a move re-wraps one envelope. Files
-- stored before this used the folder-bound formats and must be uploaded
-- again (pre-tag).

-- The generation of the file's current key. `key_epoch` stays the folder
-- epoch that key is wrapped at.
ALTER TABLE files ADD COLUMN key_generation INTEGER NOT NULL DEFAULT 1,
    ADD CONSTRAINT files_key_generation CHECK (key_generation > 0);
ALTER TABLE files ALTER COLUMN key_generation DROP DEFAULT;

-- Each stored object records the generation of the file key that sealed it.
ALTER TABLE files RENAME COLUMN original_key_epoch TO original_key_generation;
ALTER TABLE files RENAME CONSTRAINT files_original_key_epoch TO files_original_key_generation;
ALTER TABLE file_versions RENAME COLUMN key_epoch TO key_generation;
ALTER TABLE file_assets RENAME COLUMN key_epoch TO key_generation;
ALTER TABLE file_thumbnails RENAME COLUMN key_epoch TO key_generation;
UPDATE files SET original_key_generation = 1;
UPDATE file_versions SET key_generation = 1;
UPDATE file_assets SET key_generation = 1;
UPDATE file_thumbnails SET key_generation = 1;

-- A file's history is a chain: generation g keeps the key of g − 1 sealed
-- under its own, so it travels with the file between folders.
DROP TABLE file_key_history;
CREATE TABLE file_key_history (
    file_id               UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    generation            INTEGER     NOT NULL CHECK (generation > 1),
    previous_key_envelope TEXT        NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (file_id, generation)
);

-- Collaboration frames are now sealed under the file key; the stored log
-- used the folder key and cannot be replayed.
DELETE FROM file_update_log;
