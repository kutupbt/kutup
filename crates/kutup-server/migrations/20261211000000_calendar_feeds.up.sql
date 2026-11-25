-- Calendars from a URL (docs/plans/calendar.md, E5a): the server fetches a
-- public .ics feed and seals its events to the calendar's public key, signed
-- by its own feed key.

-- The server's feed key: made once, kept (one row).
CREATE TABLE calendar_feed_key (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    secret_key bytea NOT NULL CHECK (octet_length(secret_key) BETWEEN 1 AND 8192),
    public_key bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 8192),
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

-- One feed per subscribed calendar; the calendar can't be written, shared
-- or published while it has one.
CREATE TABLE calendar_feeds (
    calendar_id uuid PRIMARY KEY REFERENCES calendars(id) ON DELETE CASCADE,
    url text NOT NULL CHECK (char_length(url) BETWEEN 1 AND 8192),
    -- Proton's subscription statuses, plus what Kutup's limits add.
    status text NOT NULL DEFAULT 'syncing' CHECK (status IN (
        'syncing', 'ok', 'unreachable', 'tooBig', 'notACalendar',
        'tooManyEvents', 'storageFull', 'unavailable')),
    -- SHA-256 of the last body applied: an unchanged feed costs nothing.
    content_hash bytea CHECK (octet_length(content_hash) = 32),
    -- The last fetch that ended with the calendar matching the feed.
    synced_at timestamp with time zone,
    -- The last attempt, whatever came of it.
    checked_at timestamp with time zone,
    next_at timestamp with time zone NOT NULL DEFAULT now(),
    -- Events the feed held that couldn't be taken (unsupported, invalid).
    skipped integer NOT NULL DEFAULT 0 CHECK (skipped >= 0),
    created_at timestamp with time zone NOT NULL DEFAULT now()
);
CREATE INDEX calendar_feeds_next ON calendar_feeds (next_at);

-- A feed event's source (SHA-256 of its fields as read): a refresh reseals
-- only what changed.
ALTER TABLE calendar_events ADD COLUMN feed_source_hash bytea
    CHECK (octet_length(feed_source_hash) = 32);
