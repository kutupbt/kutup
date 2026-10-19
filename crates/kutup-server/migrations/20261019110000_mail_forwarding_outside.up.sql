-- Forwarding outside Kutup (docs/plans/mail-forwarding.md, the outside path).
ALTER TABLE mail_forwardings
    -- Why a forwarding stopped on its own: too many bounces, or the day's
    -- budget spent (it goes on the next day). Shown to the forwarder.
    ADD COLUMN notice text CHECK (notice IS NULL OR notice IN ('bounces', 'budget')),
    -- Confirmation emails sent today (at most 3 a day per forwarding).
    ADD COLUMN invites_today integer NOT NULL DEFAULT 0 CHECK (invites_today >= 0);
