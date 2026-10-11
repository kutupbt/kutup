-- Confirm link URLs (docs/plans/mail-parity.md, P3), Proton's ConfirmLink: a
-- link in a message that leads outside Kutup asks first (on by default).
ALTER TABLE mail_settings ADD COLUMN confirm_link BOOLEAN NOT NULL DEFAULT true;
