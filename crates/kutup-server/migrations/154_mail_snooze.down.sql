UPDATE mail_messages SET folder = 'inbox' WHERE folder = 'snoozed';
DROP INDEX mail_messages_snoozed;
ALTER TABLE mail_messages DROP COLUMN snoozed_until;
ALTER TABLE mail_messages DROP CONSTRAINT IF EXISTS mail_messages_folder_check;
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_folder_check
    CHECK (folder IN ('inbox', 'drafts', 'scheduled', 'sent', 'archive', 'spam', 'trash', 'custom'));
