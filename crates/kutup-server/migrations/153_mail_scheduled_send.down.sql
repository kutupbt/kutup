UPDATE mail_messages SET folder = 'drafts' WHERE folder = 'scheduled';
ALTER TABLE mail_outbox DROP COLUMN scheduled;
ALTER TABLE mail_messages DROP CONSTRAINT IF EXISTS mail_messages_folder_check;
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_folder_check
    CHECK (folder IN ('inbox', 'drafts', 'sent', 'archive', 'spam', 'trash', 'custom'));
