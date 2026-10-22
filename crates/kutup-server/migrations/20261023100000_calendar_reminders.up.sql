-- Calendar reminders (docs/plans/calendar.md, E2 §4), as Proton's
-- notifications: a member's own for an event, or the defaults on their
-- membership; the next alarm the server fires per member, event and
-- reminder; and the browsers that take reminder pushes.

-- A member's reminders for one event; none: their calendar's defaults.
CREATE TABLE calendar_event_reminders (
    event_id uuid NOT NULL REFERENCES calendar_events(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reminders jsonb NOT NULL CHECK (jsonb_typeof(reminders) = 'array'),
    PRIMARY KEY (event_id, user_id)
);
CREATE INDEX calendar_event_reminders_user ON calendar_event_reminders (user_id);

-- Each member's defaults (Proton's DefaultPartDayNotifications and
-- DefaultFullDayNotifications), under the member's revision.
ALTER TABLE calendar_members
    ADD COLUMN default_reminders_timed jsonb NOT NULL
        DEFAULT '[{"type":"device","trigger":"-PT15M"},{"type":"email","trigger":"-PT15M"}]'
        CHECK (jsonb_typeof(default_reminders_timed) = 'array'),
    ADD COLUMN default_reminders_all_day jsonb NOT NULL
        DEFAULT '[{"type":"device","trigger":"-PT15H"},{"type":"email","trigger":"-PT15H"}]'
        CHECK (jsonb_typeof(default_reminders_all_day) = 'array');

-- An account's calendar settings that reach the server: the zone its
-- all-day reminders fire in (an all-day event has no zone of its own).
CREATE TABLE calendar_user_settings (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    zone text NOT NULL CHECK (char_length(zone) BETWEEN 1 AND 64),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- The next time each member's reminder of an event fires: recomputed when
-- the event, its reminders or the member's defaults change, and after it
-- fires. The job takes the due ones (FOR UPDATE SKIP LOCKED).
CREATE TABLE calendar_alarms (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_id uuid NOT NULL REFERENCES calendar_events(id) ON DELETE CASCADE,
    -- Its place in the member's list for the event.
    reminder smallint NOT NULL CHECK (reminder >= 0),
    action text NOT NULL CHECK (action IN ('device', 'email')),
    -- The occurrence it is for, and when it fires.
    occurrence_start timestamptz NOT NULL,
    fire_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, event_id, reminder)
);
CREATE INDEX calendar_alarms_due ON calendar_alarms (fire_at);
CREATE INDEX calendar_alarms_event ON calendar_alarms (event_id);

-- The browsers that take reminder pushes: one per signed-in session (a
-- sign-out ends it), its keys for RFC 8291.
CREATE TABLE calendar_push_subscriptions (
    session_id uuid PRIMARY KEY REFERENCES auth_sessions(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint text NOT NULL UNIQUE CHECK (char_length(endpoint) <= 2048),
    p256dh bytea NOT NULL CHECK (octet_length(p256dh) = 65),
    auth bytea NOT NULL CHECK (octet_length(auth) = 16),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX calendar_push_subscriptions_user ON calendar_push_subscriptions (user_id);
