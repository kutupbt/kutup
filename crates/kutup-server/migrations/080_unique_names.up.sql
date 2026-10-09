-- Names unique in a folder, and files recognised as already there, without
-- the server reading either (docs/plans/drive-unique-names.md). Lowercase
-- hex HMACs under the folder's hash key; null until a client fills them in.
ALTER TABLE files
    ADD COLUMN name_hash TEXT CHECK (name_hash ~ '^[0-9a-f]{64}$'),
    ADD COLUMN content_hash TEXT CHECK (content_hash ~ '^[0-9a-f]{64}$');
ALTER TABLE collections
    ADD COLUMN name_hash TEXT CHECK (name_hash ~ '^[0-9a-f]{64}$');
-- An upload under way holds the name it will take, checked again when it ends.
ALTER TABLE uploads
    ADD COLUMN name_hash TEXT CHECK (name_hash ~ '^[0-9a-f]{64}$');

-- Each place holds a name once among what is not in the trash. A file and a
-- folder of one name in the same folder are refused by the handlers, which
-- check both tables under one lock (crates/kutup-server/src/drive_names.rs).
CREATE UNIQUE INDEX files_unique_name ON files (collection_id, name_hash)
    WHERE deleted_at IS NULL AND name_hash IS NOT NULL;
CREATE UNIQUE INDEX collections_unique_name ON collections (parent_collection_id, name_hash)
    WHERE deleted_at IS NULL AND name_hash IS NOT NULL AND parent_collection_id IS NOT NULL;
CREATE UNIQUE INDEX collections_unique_top_level_name ON collections (owner_user_id, name_hash)
    WHERE deleted_at IS NULL AND name_hash IS NOT NULL AND parent_collection_id IS NULL AND kind = 'folder';
