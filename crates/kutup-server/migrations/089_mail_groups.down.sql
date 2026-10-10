DROP INDEX IF EXISTS idx_mail_messages_shared_object;
DROP INDEX IF EXISTS idx_mail_messages_object_once;
-- List copies share objects; they cannot survive the unique key below.
DELETE FROM mail_messages WHERE key_packet IS NOT NULL;
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_object_key_key UNIQUE (object_key);
ALTER TABLE mail_messages DROP COLUMN IF EXISTS key_packet;
ALTER TABLE mail_messages DROP COLUMN IF EXISTS group_id;
DROP TABLE IF EXISTS mail_group_objects;
DELETE FROM mail_addresses WHERE group_id IS NOT NULL;
ALTER TABLE mail_addresses DROP CONSTRAINT IF EXISTS mail_addresses_owner;
ALTER TABLE mail_addresses DROP COLUMN IF EXISTS group_id;
ALTER TABLE mail_addresses ALTER COLUMN user_id SET NOT NULL;
DROP TABLE IF EXISTS mail_group_members;
DROP TABLE IF EXISTS mail_groups;
