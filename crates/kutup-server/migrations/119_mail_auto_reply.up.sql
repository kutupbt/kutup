-- Auto-reply (docs/plans/mail-parity.md, P2), as Proton's AutoResponder: on
-- for a fixed period, every day on chosen weekdays, weekly, monthly, or
-- until turned off. Times are wall-clock times in `zone` (an IANA name), so
-- the server checks them against now() AT TIME ZONE zone. The server sends
-- the reply while the account is away, so it keeps the text readable, as
-- Proton does.

CREATE TABLE mail_auto_replies (
    user_id      UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    enabled      BOOLEAN NOT NULL DEFAULT false,
    repeat       TEXT NOT NULL CHECK (repeat IN ('fixed', 'daily', 'weekly', 'monthly', 'permanent')),
    zone         TEXT NOT NULL,
    -- Fixed: from and until.
    start_local  TIMESTAMP,
    end_local    TIMESTAMP,
    -- Daily: the weekdays it is on, 0 Sunday to 6 Saturday.
    days         SMALLINT[] NOT NULL DEFAULT '{}',
    -- Weekly: weekdays 0–6; monthly: days of the month 1–31.
    start_day    SMALLINT,
    end_day      SMALLINT,
    -- Daily, weekly, monthly: minutes after midnight.
    start_minute SMALLINT CHECK (start_minute BETWEEN 0 AND 1439),
    end_minute   SMALLINT CHECK (end_minute BETWEEN 0 AND 1439),
    message_html TEXT NOT NULL CHECK (octet_length(message_html) <= 10000),
    message_text TEXT NOT NULL CHECK (octet_length(message_text) <= 10000),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Who got a reply lately: one per sender every 7 days (RFC 3834 §2, the
-- Sieve vacation default). Saving the auto-reply starts it over.
CREATE TABLE mail_auto_reply_sent (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender  TEXT NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, sender)
);
CREATE INDEX idx_mail_auto_reply_sent_at ON mail_auto_reply_sent (sent_at);
