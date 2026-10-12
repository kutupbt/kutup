-- Snooze (docs/plans/mail-parity.md, P4), as Proton's: Inbox mail waits in
-- Snoozed until its time, then comes back to the Inbox unread.
ALTER TABLE mail_messages DROP CONSTRAINT IF EXISTS mail_messages_folder_check;
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_folder_check
    CHECK (folder IN ('inbox', 'drafts', 'scheduled', 'snoozed', 'sent', 'archive', 'spam', 'trash', 'custom'));
ALTER TABLE mail_messages ADD COLUMN snoozed_until TIMESTAMPTZ;
CREATE INDEX mail_messages_snoozed ON mail_messages (snoozed_until) WHERE folder = 'snoozed';
