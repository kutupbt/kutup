DROP INDEX idx_mail_messages_unwanted;
DROP TRIGGER mail_messages_folder_changed ON mail_messages;
DROP FUNCTION mail_messages_folder_changed();
ALTER TABLE mail_messages DROP COLUMN folder_changed_at;
DROP TABLE mail_settings;
