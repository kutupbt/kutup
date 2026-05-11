ALTER TABLE uploads RENAME COLUMN storage_path TO storage_temp_key;
ALTER TABLE uploads DROP COLUMN file_id;
