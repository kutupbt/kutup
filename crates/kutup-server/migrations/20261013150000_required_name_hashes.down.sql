ALTER TABLE collections DROP CONSTRAINT collections_folder_name_hash;
ALTER TABLE uploads ALTER COLUMN name_hash DROP NOT NULL;
ALTER TABLE files ALTER COLUMN name_hash DROP NOT NULL;
