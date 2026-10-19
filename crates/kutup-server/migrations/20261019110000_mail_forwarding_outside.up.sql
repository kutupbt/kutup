-- Forwarding outside Kutup (docs/plans/mail-forwarding.md, the outside path).
ALTER TABLE mail_forwardings
    -- Why a forwarding stopped on its own: too many bounces, or the day's
    -- budget spent (it goes on the next day). Shown to the forwarder.
    ADD COLUMN notice text CHECK (notice IS NULL OR notice IN ('bounces', 'budget')),
    -- Confirmation emails sent today (at most 3 a day per forwarding).
    ADD COLUMN invites_today integer NOT NULL DEFAULT 0 CHECK (invites_today >= 0);

-- What an account has spent of its forwarding allowances: forwardings made
-- this hour and confirmation emails sent today. Kept apart from the
-- forwardings themselves, so deleting one gives nothing back.
CREATE TABLE mail_forwarding_quota (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hour timestamptz NOT NULL DEFAULT date_trunc('hour', now()),
    created_this_hour integer NOT NULL DEFAULT 0 CHECK (created_this_hour >= 0),
    day date NOT NULL DEFAULT current_date,
    confirmations_today integer NOT NULL DEFAULT 0 CHECK (confirmations_today >= 0)
);
