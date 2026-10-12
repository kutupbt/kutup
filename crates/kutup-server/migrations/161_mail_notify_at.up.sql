-- no-transaction
-- New-mail notifications (docs/plans/mail-parity.md, P6), as Proton's: when
-- a message became worth telling the reader about (it arrived unread, or
-- snoozed mail came back). Whether it notifies is decided when asked: unread,
-- in the Inbox, Starred, or a folder with notifications on.
-- Outside a transaction, so the index is built without blocking writes
-- (a nullable column is added at once).
ALTER TABLE mail_messages ADD COLUMN IF NOT EXISTS notify_at TIMESTAMPTZ;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mail_messages_notify
    ON mail_messages(owner, notify_at) WHERE notify_at IS NOT NULL;
