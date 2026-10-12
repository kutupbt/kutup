-- Scheduled send (docs/plans/mail-parity.md, P4), as Proton's: a draft sent
-- for later waits in the Scheduled folder, held in the outbox until then.
ALTER TABLE mail_messages DROP CONSTRAINT IF EXISTS mail_messages_folder_check;
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_folder_check
    CHECK (folder IN ('inbox', 'drafts', 'scheduled', 'sent', 'archive', 'spam', 'trash', 'custom'));
ALTER TABLE mail_outbox ADD COLUMN scheduled BOOLEAN NOT NULL DEFAULT false;
