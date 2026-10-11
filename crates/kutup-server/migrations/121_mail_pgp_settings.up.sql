-- PGP settings for mail to people outside Kutup (docs/plans/mail-parity.md,
-- P2), as Proton's External PGP settings: attach your public key to each
-- message (AttachPublicKey, off), and the default PGP scheme, PGP/MIME or
-- Inline (PGPScheme; Inline forces plain text).
ALTER TABLE mail_settings
    ADD COLUMN attach_public_key BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN pgp_scheme        TEXT NOT NULL DEFAULT 'pgp_mime' CHECK (pgp_scheme IN ('pgp_mime', 'inline'));
