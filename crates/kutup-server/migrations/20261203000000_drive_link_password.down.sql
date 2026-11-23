-- ROLLBACK RUNBOOK (docs/plans/drive-link-password.md, "Rolling back"):
-- dropping these columns does not move any target key back under its URL
-- secret. A password-protected link's folder or file key stays sealed under
-- its separate link key L, and its owner's copy (owner_link_key_envelope)
-- holds L, so after the rollback the owner's "copy link" builds `#v1.<L>`:
-- a link that opens WITHOUT the password. Before rolling back, have owners
-- remove passwords (or remove those links); after it, treat every link that
-- had a password as unprotected.
ALTER TABLE drive_public_link_reports
    DROP CONSTRAINT drive_public_link_reports_link_password,
    DROP COLUMN link_password;

ALTER TABLE drive_public_shares
    DROP CONSTRAINT drive_public_shares_password,
    DROP CONSTRAINT drive_public_shares_key_revision_check,
    DROP COLUMN owner_secret_envelope,
    DROP COLUMN password_link_key_envelope,
    DROP COLUMN password_verifier,
    DROP COLUMN password_memory,
    DROP COLUMN password_operations,
    DROP COLUMN password_salt,
    DROP COLUMN key_revision;
