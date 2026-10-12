-- Expiring messages (docs/plans/mail-parity.md, P5), as Proton's: a message
-- sent with an expiration is deleted for good, every Kutup copy of it, when
-- the time comes.
ALTER TABLE mail_messages ADD COLUMN expires_at TIMESTAMPTZ;
CREATE INDEX mail_messages_expiring ON mail_messages (expires_at) WHERE expires_at IS NOT NULL;
