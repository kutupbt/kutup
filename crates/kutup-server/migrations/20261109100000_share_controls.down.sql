UPDATE public_link_reports SET resolution = 'removed' WHERE resolution = 'blocked';
ALTER TABLE public_link_reports DROP CONSTRAINT public_link_reports_resolution_check;
ALTER TABLE public_link_reports ADD CONSTRAINT public_link_reports_resolution_check
    CHECK (resolution = ANY (ARRAY['dismissed', 'removed', 'disabled']));
ALTER TABLE users DROP COLUMN public_sharing;
ALTER TABLE public_shares
    DROP CONSTRAINT public_shares_blocked,
    DROP COLUMN blocked_by, DROP COLUMN blocked_reference,
    DROP COLUMN blocked_reason, DROP COLUMN blocked_at;
