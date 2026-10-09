DROP INDEX IF EXISTS collections_unique_top_level_name;
DROP INDEX IF EXISTS collections_unique_name;
DROP INDEX IF EXISTS files_unique_name;
ALTER TABLE uploads DROP COLUMN IF EXISTS name_hash;
ALTER TABLE collections DROP COLUMN IF EXISTS name_hash;
ALTER TABLE files DROP COLUMN IF EXISTS content_hash, DROP COLUMN IF EXISTS name_hash;
