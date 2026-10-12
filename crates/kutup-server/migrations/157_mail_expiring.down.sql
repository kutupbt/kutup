DROP INDEX mail_messages_expiring;
ALTER TABLE mail_messages DROP COLUMN expires_at;
