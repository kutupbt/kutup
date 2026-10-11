-- Moderation of public links (docs/architecture.md, "File editor route").
-- An administrator takes a link down: it answers 410 `link_removed`, as every
-- link of a disabled account does.
ALTER TABLE public_shares ADD COLUMN removed_at TIMESTAMPTZ;

-- Reports from anyone who opened a link. The server cannot read what a link
-- shows; a reporter may hand over the whole link (`link`, its key in the
-- fragment) so an administrator can look. It is erased once the report is
-- resolved. No reporter identity or address is kept.
CREATE TABLE public_link_reports (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    share_id    UUID NOT NULL REFERENCES public_shares(id) ON DELETE CASCADE,
    reason      TEXT NOT NULL CHECK (reason IN ('phishing', 'malware', 'illegal', 'abuse', 'other')),
    details     TEXT NOT NULL DEFAULT '' CHECK (char_length(details) <= 2000),
    link        TEXT CHECK (link IS NULL OR char_length(link) <= 2048),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution  TEXT CHECK (resolution IN ('dismissed', 'removed', 'disabled')),
    CHECK ((resolved_at IS NULL) = (resolution IS NULL)),
    CHECK (resolved_at IS NULL OR link IS NULL)
);

CREATE INDEX public_link_reports_open ON public_link_reports (created_at) WHERE resolved_at IS NULL;
CREATE INDEX public_link_reports_share ON public_link_reports (share_id);
