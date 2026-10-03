-- Call links (docs/chat-calls.md): a call anyone holding the link can join,
-- with or without an account, on this server's SFU. Everything about a link
-- derives from a secret in the link's URL fragment, which no server sees.
-- This server keeps what it needs to admit joiners and to let the owner list
-- and delete links:
--   room_id            the SFU room (derived from the secret);
--   access_token_hash  SHA-256 of the access token a joiner presents (also
--                      derived from the secret; the token itself is not kept);
--   nonce              public and random: the owner's devices derive the
--                      secret again from it and the account master key.
CREATE TABLE chat_call_links (
    room_id            TEXT PRIMARY KEY CHECK (room_id ~ '^[0-9a-f]{32}$'),
    owner_user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nonce              TEXT NOT NULL CHECK (nonce ~ '^[0-9a-f]{32}$'),
    access_token_hash  BYTEA NOT NULL CHECK (octet_length(access_token_hash) = 32),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (owner_user_id, nonce)
);

CREATE INDEX idx_chat_call_links_owner ON chat_call_links(owner_user_id, created_at DESC);
