DROP INDEX IF EXISTS idx_mail_messages_sender_recently;
ALTER TABLE mail_messages DROP COLUMN IF EXISTS sender_account;
ALTER TABLE mail_messages DROP COLUMN IF EXISTS sent_by;
DROP INDEX IF EXISTS idx_mail_messages_owner_thread;
DROP INDEX IF EXISTS idx_mail_messages_owner_folder;
ALTER TABLE mail_messages DROP COLUMN IF EXISTS owner;
-- Shared mailboxes' messages have no account to stay with.
DELETE FROM mail_messages WHERE user_id IS NULL;
ALTER TABLE mail_messages DROP CONSTRAINT IF EXISTS mail_messages_owner;
ALTER TABLE mail_messages ALTER COLUMN user_id SET NOT NULL;
DELETE FROM server_generated_keys WHERE purpose = 'mail-group-authority';
ALTER TABLE server_generated_keys DROP CONSTRAINT server_generated_keys_purpose_check;
ALTER TABLE server_generated_keys ADD CONSTRAINT server_generated_keys_purpose_check
    CHECK (purpose IN ('federation-identity', 'mls-control'));
DROP TABLE IF EXISTS mail_group_key_lists;
DROP TABLE IF EXISTS mail_group_key_shares;
DROP TABLE IF EXISTS mail_group_keys;
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
