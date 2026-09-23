-- Server-side sessions (docs/plans/multi-app-web-rewrite.md).
--
-- Every sign-in is a row. Refresh tokens are opaque 32-byte secrets stored
-- only as SHA-256; each refresh rotates them. The previous hash is kept for a
-- short grace window so two tabs refreshing with the same cookie do not
-- trip reuse detection; a replay after the window revokes the session.
--
-- Web apps on drive. and chat. get *child* sessions forked from the
-- account. session; revoking the parent revokes its children.
CREATE TABLE auth_sessions (
    id                           UUID PRIMARY KEY,
    user_id                      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_type                  TEXT NOT NULL CHECK (client_type IN (
                                     'web-account', 'web-drive', 'web-chat', 'cli',
                                     'android-drive', 'android-chat', 'ios-drive', 'ios-chat')),
    parent_session_id            UUID REFERENCES auth_sessions(id) ON DELETE CASCADE,
    refresh_token_hash           BYTEA NOT NULL UNIQUE CHECK (octet_length(refresh_token_hash) = 32),
    previous_refresh_token_hash  BYTEA CHECK (octet_length(previous_refresh_token_hash) = 32),
    rotated_at                   TIMESTAMPTZ,
    -- Unlocks the web app's persisted key blob; never set for CLI sessions.
    local_key                    BYTEA CHECK (octet_length(local_key) = 32),
    user_agent                   TEXT CHECK (char_length(user_agent) <= 512),
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                   TIMESTAMPTZ NOT NULL,
    revoked_at                   TIMESTAMPTZ,
    CHECK (parent_session_id IS NULL OR client_type IN ('web-drive', 'web-chat'))
);

CREATE INDEX auth_sessions_user_idx ON auth_sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX auth_sessions_parent_idx ON auth_sessions (parent_session_id);
CREATE INDEX auth_sessions_previous_hash_idx ON auth_sessions (previous_refresh_token_hash)
    WHERE previous_refresh_token_hash IS NOT NULL;

-- One-time session-fork hand-offs. The payload is an opaque local-state
-- envelope whose key travels only in the URL fragment; the row is deleted
-- when consumed and expires after 60 seconds.
CREATE TABLE auth_session_forks (
    selector_hash      BYTEA PRIMARY KEY CHECK (octet_length(selector_hash) = 32),
    parent_session_id  UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    child_client_type  TEXT NOT NULL CHECK (child_client_type IN ('web-drive', 'web-chat')),
    payload            BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 16384),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL
);

CREATE INDEX auth_session_forks_expiry_idx ON auth_session_forks (expires_at);
