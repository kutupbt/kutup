-- Albums (docs/plans/photos.md): a kind of collection that holds references
-- to photos, not files. Its key, epochs and (later) members work as a
-- folder's; each photo's file key is sealed under the album key (Drive
-- envelope purpose 12), so one photo in five albums is one file.
ALTER TABLE collections
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'folder' CHECK (kind IN ('folder', 'album'));
-- Albums sit at the top level: never inside a folder.
ALTER TABLE collections
    ADD CONSTRAINT collections_album_top_level CHECK (kind = 'folder' OR parent_collection_id IS NULL);

-- Whatever path writes a file or a folder, none lands in an album.
CREATE FUNCTION kutup_no_files_in_albums() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM collections WHERE id = NEW.collection_id AND kind = 'album') THEN
        RAISE EXCEPTION 'albums hold references, not files' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER files_not_in_albums BEFORE INSERT OR UPDATE OF collection_id ON files
    FOR EACH ROW EXECUTE FUNCTION kutup_no_files_in_albums();

CREATE FUNCTION kutup_no_folders_in_albums() RETURNS trigger AS $$
BEGIN
    IF NEW.parent_collection_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM collections WHERE id = NEW.parent_collection_id AND kind = 'album'
    ) THEN
        RAISE EXCEPTION 'albums hold no folders' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER collections_not_in_albums BEFORE INSERT OR UPDATE OF parent_collection_id ON collections
    FOR EACH ROW EXECUTE FUNCTION kutup_no_folders_in_albums();

CREATE TABLE album_items (
    album_id UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    -- The file key of `key_generation`, sealed under the album key of `album_epoch`.
    file_key_envelope TEXT NOT NULL,
    key_generation INTEGER NOT NULL CHECK (key_generation > 0),
    album_epoch INTEGER NOT NULL CHECK (album_epoch > 0),
    added_by UUID REFERENCES users(id) ON DELETE SET NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (album_id, file_id)
);
CREATE INDEX idx_album_items_file ON album_items(file_id);
