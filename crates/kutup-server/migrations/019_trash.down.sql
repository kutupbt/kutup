DROP INDEX IF EXISTS idx_collections_deleted_at;
DROP INDEX IF EXISTS idx_files_deleted_at;
DROP INDEX IF EXISTS idx_collections_trash_root;
DROP INDEX IF EXISTS idx_files_trash_root;
ALTER TABLE collections DROP COLUMN trash_root_id, DROP COLUMN deleted_at;
ALTER TABLE files DROP COLUMN trash_root_id, DROP COLUMN deleted_at;
