-- Who was removed from a meeting (docs/chat-calls.md, "Hosts"). The SFU
-- token a removed participant holds cannot be withdrawn and works until it
-- runs out, so this server remembers the identity and removes it again
-- whenever it is back in the room. `removed_at` is when it was last removed;
-- rows are forgotten a day after that.
CREATE TABLE chat_call_link_removed (
    room_id         TEXT NOT NULL REFERENCES chat_call_links(room_id) ON DELETE CASCADE,
    participant_id  TEXT NOT NULL CHECK (participant_id ~ '^[0-9a-f]{32}$'),
    removed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (room_id, participant_id)
);
