-- Messages or conversations per page (docs/plans/mail-parity.md, P3),
-- Proton's PageSize: 50, 100 or 200.
ALTER TABLE mail_settings ADD COLUMN page_size INTEGER NOT NULL DEFAULT 50
    CHECK (page_size IN (50, 100, 200));
