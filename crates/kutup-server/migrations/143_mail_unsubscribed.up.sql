-- Unsubscribe (docs/plans/mail-parity.md, P3), as Proton's: a message from a
-- mailing list whose reader unsubscribed says so instead of offering it again.
ALTER TABLE mail_messages ADD COLUMN unsubscribed BOOLEAN NOT NULL DEFAULT false;
