-- The meetings an account joined (docs/chat-calls.md, "History"), so the
-- list is the same on all of its devices. Each record is one stay (the
-- link, the title, when and for how long), sealed in the browser under a
-- key from the account master key: this server stores it and reads none of
-- it. `id` is chosen by the browser that recorded the stay, so recording
-- it twice keeps one.
CREATE TABLE chat_joined_meetings (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id          TEXT NOT NULL CHECK (id ~ '^[0-9a-f]{32}$'),
    -- nonce (24) + padded record (1024) + tag (16)
    entry       BYTEA NOT NULL CHECK (octet_length(entry) = 1064),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, id)
);

CREATE INDEX idx_chat_joined_meetings_user ON chat_joined_meetings(user_id, created_at DESC);
