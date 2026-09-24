DELETE FROM file_update_log;
DROP TABLE file_key_history;
CREATE TABLE file_key_history (
    file_id           UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    epoch             INTEGER     NOT NULL CHECK (epoch > 0),
    file_key_envelope TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (file_id, epoch)
);
ALTER TABLE file_thumbnails RENAME COLUMN key_generation TO key_epoch;
ALTER TABLE file_assets RENAME COLUMN key_generation TO key_epoch;
ALTER TABLE file_versions RENAME COLUMN key_generation TO key_epoch;
ALTER TABLE files RENAME CONSTRAINT files_original_key_generation TO files_original_key_epoch;
ALTER TABLE files RENAME COLUMN original_key_generation TO original_key_epoch;
UPDATE files SET original_key_epoch = key_epoch;
ALTER TABLE files DROP COLUMN key_generation;
