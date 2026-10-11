-- "Sign outside mail" (docs/plans/mail-encrypt-sign.md), Proton's "Sign
-- external messages": whether mail to people outside Kutup starts signed.
-- Mail between Kutup users is always offered signed.
ALTER TABLE mail_settings ADD COLUMN sign_outside BOOLEAN NOT NULL DEFAULT true;
