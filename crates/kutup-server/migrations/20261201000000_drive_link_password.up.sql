-- A public link's password and its key revision (docs/plans/drive-link-password.md).
-- key_revision rises with every password change: re-key routes name the
-- revision they sealed under and a stale one is refused. The password
-- columns are all set (a protected link) or all null.
ALTER TABLE drive_public_shares
    ADD COLUMN key_revision integer NOT NULL DEFAULT 1,
    ADD COLUMN password_salt bytea,
    ADD COLUMN password_operations integer,
    ADD COLUMN password_memory integer,
    ADD COLUMN password_verifier bytea,
    ADD COLUMN password_link_key_envelope bytea,
    ADD COLUMN owner_secret_envelope bytea,
    ADD CONSTRAINT drive_public_shares_key_revision_check CHECK (key_revision > 0),
    ADD CONSTRAINT drive_public_shares_password CHECK (
        (password_salt IS NULL) = (password_operations IS NULL)
        AND (password_salt IS NULL) = (password_memory IS NULL)
        AND (password_salt IS NULL) = (password_verifier IS NULL)
        AND (password_salt IS NULL) = (password_link_key_envelope IS NULL)
        AND (password_salt IS NULL) = (owner_secret_envelope IS NULL)
        AND (password_salt IS NULL OR octet_length(password_salt) = 16)
        AND (password_verifier IS NULL OR octet_length(password_verifier) = 32)
    );

-- A report on a password-protected link may carry its password, as Proton's
-- report form lets the reporter give it, so administrators can open what
-- they review. Kept like the report's link: only with the link, only while
-- the report is open (every resolution clears both).
ALTER TABLE drive_public_link_reports
    ADD COLUMN link_password text,
    ADD CONSTRAINT drive_public_link_reports_link_password CHECK (
        link_password IS NULL
        OR (link IS NOT NULL AND resolved_at IS NULL AND char_length(link_password) BETWEEN 1 AND 1024)
    );
