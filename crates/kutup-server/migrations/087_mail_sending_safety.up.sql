-- Sending safety (docs/plans/mail.md, "Sending safety"): one account sending
-- spam can get the server's address blocklisted and stop everyone's mail.
-- Per-account overrides of the sending limits, a pause, and a flag for the
-- administrator; and the events that pause or flag automatically.

CREATE TABLE mail_sending_policies (
    user_id      UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- Outside recipients per hour and per day; null: the server's limits
    -- (lower in an account's first week).
    per_hour     INTEGER CHECK (per_hour BETWEEN 0 AND 100000),
    per_day      INTEGER CHECK (per_day BETWEEN 0 AND 100000),
    -- No mail to outside recipients while set (mail between Kutup users
    -- still flows).
    paused_at    TIMESTAMPTZ,
    paused_reason TEXT CHECK (paused_reason IN ('admin', 'bounces', 'spam')),
    flagged_at   TIMESTAMPTZ,
    flag_reason  TEXT CHECK (flag_reason IN ('bounces', 'spam')),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mail_sending_policies_attention ON mail_sending_policies(updated_at)
    WHERE paused_at IS NOT NULL OR flagged_at IS NOT NULL;

-- A bounce (a delivery failure report for mail the account sent) or a
-- refusal of its mail as spam. Kept 30 days.
CREATE TABLE mail_sending_events (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('bounce', 'spam_refused')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mail_sending_events_user ON mail_sending_events(user_id, kind, created_at);
