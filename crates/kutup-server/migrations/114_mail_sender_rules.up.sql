-- Block, spam and allow lists (docs/plans/mail-filters.md, F3), as Proton's
-- "incoming defaults": an address or a whole domain, checked as mail
-- arrives, before filters. Readable, since the server applies them.

CREATE TABLE mail_sender_rules (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- A lowercase address (`a@example.com`) or domain (`example.com`).
    pattern    TEXT NOT NULL CHECK (length(pattern) BETWEEN 3 AND 320 AND pattern = lower(pattern)),
    kind       TEXT NOT NULL CHECK (kind IN ('spam', 'block', 'allow')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, pattern)
);
