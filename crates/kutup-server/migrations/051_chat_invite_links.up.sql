-- Group invite link mailboxes (docs/chat-invite-links.md). Everything here is
-- keyed or sealed with values derived from the link's secret, which the
-- server never sees.
CREATE TABLE chat_invite_links (
    link_id       TEXT PRIMARY KEY CHECK (length(link_id) = 44),
    manage_hash   BYTEA NOT NULL CHECK (octet_length(manage_hash) = 32),
    preview       TEXT NOT NULL,
    -- The server whose account created it (this one for local accounts).
    origin_domain TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    touched_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX chat_invite_links_origin ON chat_invite_links (origin_domain);
CREATE INDEX chat_invite_links_touched ON chat_invite_links (touched_at);

CREATE TABLE chat_invite_requests (
    id            UUID PRIMARY KEY,
    link_id       TEXT NOT NULL REFERENCES chat_invite_links (link_id) ON DELETE CASCADE,
    -- The server the request came through: the requester's own.
    origin_domain TEXT NOT NULL,
    request       TEXT NOT NULL,
    status_hash   BYTEA NOT NULL CHECK (octet_length(status_hash) = 32),
    -- 0 pending, 1 approved, 2 denied.
    status        SMALLINT NOT NULL DEFAULT 0 CHECK (status IN (0, 1, 2)),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at    TIMESTAMPTZ
);
CREATE INDEX chat_invite_requests_link ON chat_invite_requests (link_id, created_at);
