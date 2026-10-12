-- no-transaction
DROP INDEX CONCURRENTLY IF EXISTS idx_mail_messages_notify;
ALTER TABLE mail_messages DROP COLUMN IF EXISTS notify_at;
