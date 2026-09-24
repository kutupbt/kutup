-- Share revocation and folder-key rotation
-- (docs/plans/drive-share-revocation.md).

-- Each epoch after the first keeps the previous epoch's key sealed under its
-- own, so the current key unlocks the whole history.
ALTER TABLE collection_key_epoch_history
    ADD COLUMN previous_key_envelope TEXT,
    ADD CONSTRAINT collection_key_epoch_history_previous_key
        CHECK ((epoch = 1) = (previous_key_envelope IS NULL));

-- A file keeps the epoch its content was sealed at. A re-key moves the file
-- (its key and metadata) to the current epoch; the key it leaves stays here
-- so what was sealed under it stays readable.
CREATE TABLE file_key_history (
    file_id           UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    epoch             INTEGER     NOT NULL CHECK (epoch > 0),
    file_key_envelope TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (file_id, epoch)
);

-- The epoch (and so the file key) each stored object was sealed under.
ALTER TABLE files ADD COLUMN original_key_epoch INTEGER;
UPDATE files SET original_key_epoch = key_epoch;
ALTER TABLE files ALTER COLUMN original_key_epoch SET NOT NULL,
    ADD CONSTRAINT files_original_key_epoch CHECK (original_key_epoch > 0);

ALTER TABLE file_versions ADD COLUMN key_epoch INTEGER;
UPDATE file_versions v SET key_epoch = f.key_epoch FROM files f WHERE f.id = v.file_id;
ALTER TABLE file_versions ALTER COLUMN key_epoch SET NOT NULL;

ALTER TABLE file_assets ADD COLUMN key_epoch INTEGER;
UPDATE file_assets a SET key_epoch = f.key_epoch FROM files f WHERE f.id = a.file_id;
ALTER TABLE file_assets ALTER COLUMN key_epoch SET NOT NULL;

ALTER TABLE file_thumbnails ADD COLUMN key_epoch INTEGER;
UPDATE file_thumbnails t SET key_epoch = f.key_epoch FROM files f WHERE f.id = t.file_id;
ALTER TABLE file_thumbnails ALTER COLUMN key_epoch SET NOT NULL;

-- A public link's key, sealed for the owner (purpose 9), so the owner can
-- list and copy links and re-wrap them when the folder key rotates. Links
-- from before this have none; a rotation removes them.
ALTER TABLE public_shares ADD COLUMN owner_link_key_envelope TEXT;
