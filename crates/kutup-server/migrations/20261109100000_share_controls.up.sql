-- Share-link controls (docs/plans/server-personal-data.md, A11; slice L5).

-- An operator's block on one public link: a legal order (the link answers
-- 451), abuse or another reason (410). Its reference (an order's number) is
-- for the administrators only. Unblocking clears it; both are audited.
ALTER TABLE public_shares
    ADD COLUMN blocked_at timestamptz,
    ADD COLUMN blocked_reason text CHECK (blocked_reason IN ('legal_order', 'abuse', 'other')),
    ADD COLUMN blocked_reference text CHECK (char_length(blocked_reference) BETWEEN 1 AND 200),
    ADD COLUMN blocked_by uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD CONSTRAINT public_shares_blocked
        CHECK ((blocked_at IS NULL) = (blocked_reason IS NULL)
           AND (blocked_at IS NOT NULL OR (blocked_reference IS NULL AND blocked_by IS NULL)));

-- Whether an account may share by public link, set by an administrator.
-- While `off` it makes none, and its links answer 410 sharing_off.
ALTER TABLE users
    ADD COLUMN public_sharing text NOT NULL DEFAULT 'on' CHECK (public_sharing IN ('on', 'off'));

-- A report answered by blocking its link.
ALTER TABLE public_link_reports DROP CONSTRAINT public_link_reports_resolution_check;
ALTER TABLE public_link_reports ADD CONSTRAINT public_link_reports_resolution_check
    CHECK (resolution = ANY (ARRAY['dismissed', 'removed', 'disabled', 'blocked']));
