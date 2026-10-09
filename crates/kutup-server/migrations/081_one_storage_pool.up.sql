-- One storage pool per account: Drive, Photos, Office, Maps and Chat (media,
-- history backup) all charge users.storage_used_bytes against
-- users.storage_quota_bytes. Chat's separate quota and counter go; what Chat
-- already stores moves onto the account counter, and the account quota is
-- unchanged (10 GiB unless an administrator set another).

UPDATE users
SET storage_used_bytes = storage_used_bytes + chat_storage_used_bytes
WHERE chat_storage_used_bytes > 0;

ALTER TABLE users
    DROP COLUMN chat_storage_quota_bytes,
    DROP COLUMN chat_storage_used_bytes;

DELETE FROM site_settings WHERE key = 'default_chat_storage_quota_bytes';
