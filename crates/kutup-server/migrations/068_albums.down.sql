DROP TABLE album_items;
DROP TRIGGER collections_not_in_albums ON collections;
DROP FUNCTION kutup_no_folders_in_albums();
DROP TRIGGER files_not_in_albums ON files;
DROP FUNCTION kutup_no_files_in_albums();
DELETE FROM collections WHERE kind = 'album';
ALTER TABLE collections DROP CONSTRAINT collections_album_top_level;
ALTER TABLE collections DROP COLUMN kind;
