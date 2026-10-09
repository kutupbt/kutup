-- Restore Chat's separate quota and counter (migration 042) and move Chat's
-- stored bytes back off the account counter.

ALTER TABLE users
    ADD COLUMN chat_storage_quota_bytes BIGINT NOT NULL DEFAULT 2147483648
        CHECK (chat_storage_quota_bytes > 0),
    ADD COLUMN chat_storage_used_bytes BIGINT NOT NULL DEFAULT 0
        CHECK (chat_storage_used_bytes >= 0);

WITH chat_usage AS (
    SELECT u.id AS user_id,
           (COALESCE((SELECT SUM(logical_bytes) FROM chat_media_references WHERE user_id = u.id), 0)
          + COALESCE((SELECT SUM(ciphertext_bytes) FROM chat_backup_segments WHERE user_id = u.id), 0)
          + COALESCE((SELECT SUM(ciphertext_bytes) FROM chat_backup_bases WHERE user_id = u.id), 0)
          + COALESCE((SELECT SUM(ciphertext_bytes) FROM chat_backup_media_objects WHERE user_id = u.id), 0))::BIGINT AS bytes
    FROM users u
)
UPDATE users
SET chat_storage_used_bytes = chat_usage.bytes,
    storage_used_bytes = GREATEST(0, storage_used_bytes - chat_usage.bytes)
FROM chat_usage
WHERE users.id = chat_usage.user_id AND chat_usage.bytes > 0;

INSERT INTO site_settings(key, value)
VALUES ('default_chat_storage_quota_bytes', '2147483648')
ON CONFLICT (key) DO NOTHING;
