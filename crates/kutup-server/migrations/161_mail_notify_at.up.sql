-- New-mail notifications (docs/plans/mail-parity.md, P6), as Proton's: when
-- a message became worth telling the reader about (it arrived unread, or
-- snoozed mail came back). Whether it notifies is decided when asked: unread,
-- in the Inbox, Starred, or a folder with notifications on.
ALTER TABLE mail_messages ADD COLUMN notify_at TIMESTAMPTZ;
CREATE INDEX idx_mail_messages_notify ON mail_messages(owner, notify_at) WHERE notify_at IS NOT NULL;
