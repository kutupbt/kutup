-- Running a meeting (docs/chat-calls.md, "Hosts").
--
-- A **seat** is one browser's place in a meeting: the random SFU identity it
-- joins under, bound to a secret only that browser holds (`seat_hash` is its
-- SHA-256). This server mints SFU tokens for an identity only to whoever
-- holds its seat secret, so nobody can ask for a token under someone else's
-- identity, and a browser that reconnects keeps its identity and with it:
--
--   role        1 the meeting's owner (presented the host token), 2 a
--               co-host (named by the owner, or promoted because the meeting
--               was left without a host);
--   account     the account address this server vouches for, when the
--               joiner was signed in here and chose to show it;
--   no_screen   a host stopped this participant sharing their screen;
--   removed_at  a host removed this participant. The SFU token they hold
--               cannot be withdrawn, so the identity is remembered and
--               removed again whenever it is back in the room.
CREATE TABLE chat_call_link_seats (
    room_id         TEXT NOT NULL REFERENCES chat_call_links(room_id) ON DELETE CASCADE,
    participant_id  TEXT NOT NULL CHECK (participant_id ~ '^[0-9a-f]{32}$'),
    seat_hash       BYTEA NOT NULL CHECK (octet_length(seat_hash) = 32),
    role            SMALLINT CHECK (role IN (1, 2)),
    account         TEXT,
    no_screen       BOOLEAN NOT NULL DEFAULT FALSE,
    removed_at      TIMESTAMPTZ,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- When a token was last minted for it: seats unused for a day are forgotten.
    last_minted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (room_id, participant_id)
);

-- A meeting, each time it is held:
--   sitting         counts the times its owner ended it for everyone. The
--                   SFU room is named after the room id and the sitting, so
--                   a token from an ended sitting opens nothing.
--   locked          nobody new comes in, not even by knocking.
--   hostless_since  since when no host has been in the room, while people
--                   are: after a short while the longest-present
--                   participant is made a co-host.
ALTER TABLE chat_call_links
    ADD COLUMN sitting BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN locked BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN hostless_since TIMESTAMPTZ;

-- A knock carries the seat it will become, and the knocker's vouched-for
-- account when they show one. Knocks are short-lived: the ones waiting now
-- are dropped rather than given a seat they did not ask with.
DELETE FROM chat_call_link_knocks;
ALTER TABLE chat_call_link_knocks
    ADD COLUMN seat_hash BYTEA NOT NULL CHECK (octet_length(seat_hash) = 32),
    ADD COLUMN account TEXT;
