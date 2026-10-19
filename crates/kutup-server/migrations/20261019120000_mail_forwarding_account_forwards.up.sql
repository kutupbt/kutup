-- An account's outside forwards today, counted with its other forwarding
-- allowances (docs/plans/mail-forwarding.md): apart from the forwardings,
-- so deleting one gives nothing back.
ALTER TABLE mail_forwarding_quota
    ADD COLUMN forwards_today integer NOT NULL DEFAULT 0 CHECK (forwards_today >= 0);
