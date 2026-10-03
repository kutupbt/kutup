-- A meeting's waiting room (docs/chat-calls.md): with it on, holding the
-- link is not enough to join. A joiner knocks and waits; the meeting's owner
-- admits or turns away each one.
--
--   waiting_room     whether joiners must be admitted. This server enforces
--                    it, so it is kept in the clear: a policy, not content.
--   host_token_hash  SHA-256 of the owner's host token, which only the
--                    owner's account can derive. Presenting the token skips
--                    the wait and decides the knocks.
ALTER TABLE chat_call_links
    ADD COLUMN waiting_room BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN host_token_hash BYTEA CHECK (host_token_hash IS NULL OR octet_length(host_token_hash) = 32),
    ADD CONSTRAINT chat_call_links_waiting_room_needs_host
        CHECK (NOT waiting_room OR host_token_hash IS NOT NULL);

-- One person waiting to be let in. `label` is their chosen name, sealed
-- under a key from the link (the owner opens it; this server cannot).
-- `ticket_hash` is the SHA-256 of a secret only the knocker holds, so only
-- they can ask how their knock went and collect the SFU token.
CREATE TABLE chat_call_link_knocks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id         TEXT NOT NULL REFERENCES chat_call_links(room_id) ON DELETE CASCADE,
    participant_id  TEXT NOT NULL CHECK (participant_id ~ '^[0-9a-f]{32}$'),
    label           BYTEA NOT NULL CHECK (octet_length(label) = 168),
    ticket_hash     BYTEA NOT NULL CHECK (octet_length(ticket_hash) = 32),
    -- 0 waiting, 1 admitted, 2 turned away
    status          SMALLINT NOT NULL DEFAULT 0 CHECK (status IN (0, 1, 2)),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- When the knocker last asked: one who stopped asking has gone.
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_chat_call_link_knocks_room ON chat_call_link_knocks(room_id, status, created_at);
