-- Every name in Drive has its hash (docs/plans/drive-unique-names.md), as
-- Proton Drive requires its `Hash`: files, and folders (albums have none).
-- Uploads in progress carry theirs from the start.
ALTER TABLE files ALTER COLUMN name_hash SET NOT NULL;
ALTER TABLE uploads ALTER COLUMN name_hash SET NOT NULL;
ALTER TABLE collections
    ADD CONSTRAINT collections_folder_name_hash CHECK (kind <> 'folder' OR name_hash IS NOT NULL);
