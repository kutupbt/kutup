-- backend/db/migrations/012_collab_edit.down.sql
ALTER TABLE files DROP COLUMN current_doc_key_id;
DROP INDEX IF EXISTS file_versions_timeline;
DROP TABLE file_versions;
DROP TABLE file_update_log;
DROP INDEX IF EXISTS user_devices_active;
DROP TABLE user_devices;
