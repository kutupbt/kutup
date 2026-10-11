DROP TABLE mail_message_labels;
UPDATE mail_messages SET folder = 'archive', custom_folder = NULL WHERE folder = 'custom';
DROP INDEX idx_mail_messages_custom_folder;
ALTER TABLE mail_messages DROP CONSTRAINT mail_messages_custom_folder_check;
ALTER TABLE mail_messages DROP CONSTRAINT mail_messages_custom_folder_fk;
ALTER TABLE mail_messages DROP COLUMN custom_folder;
ALTER TABLE mail_messages DROP CONSTRAINT mail_messages_folder_check;
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_folder_check
    CHECK (folder IN ('inbox', 'drafts', 'sent', 'archive', 'spam', 'trash'));
DROP TABLE mail_labels;
DROP TABLE mail_folders;
