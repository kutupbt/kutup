-- Auto-unsubscribe on moving to Spam (docs/plans/mail-parity.md, P3),
-- Proton's SpamAction. Arrival notes whether a message came from a list
-- (a List-Unsubscribe header); the ways out stay in the encrypted message,
-- read by the client when it unsubscribes.
ALTER TABLE mail_messages ADD COLUMN unsubscribable BOOLEAN NOT NULL DEFAULT false;
-- ask (each time), just_spam, or spam_and_unsubscribe.
ALTER TABLE mail_settings ADD COLUMN spam_action TEXT NOT NULL DEFAULT 'ask'
    CHECK (spam_action IN ('ask', 'just_spam', 'spam_and_unsubscribe'));
