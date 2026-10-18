-- Chat groups on their home server (docs/plans/pairwise-groups.md §3).
-- Members are per-group pseudonyms inside the state's plain part; no table
-- here holds an account id, local or remote.

CREATE TABLE chat_groups (
    group_id bytea PRIMARY KEY CHECK (octet_length(group_id) = 32),
    revision bigint NOT NULL CHECK (revision >= 0),
    -- The hash of the last accepted change, which the next one names.
    head bytea NOT NULL CHECK (octet_length(head) = 32),
    -- The state's canonical bytes (plain part with sealed fields).
    state bytea NOT NULL,
    state_hash bytea NOT NULL CHECK (octet_length(state_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE chat_group_changes (
    group_id bytea NOT NULL REFERENCES chat_groups (group_id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision >= 0),
    change bytea NOT NULL,
    change_hash bytea NOT NULL CHECK (octet_length(change_hash) = 32),
    state_hash bytea NOT NULL CHECK (octet_length(state_hash) = 32),
    -- The home's GroupNotaryV1 over the change, as canonical JSON.
    notary bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, revision)
);

-- The encrypted avatar, at most 40 KiB (counted against the server's own
-- allowance, not a member's storage pool).
CREATE TABLE chat_group_avatars (
    group_id bytea PRIMARY KEY REFERENCES chat_groups (group_id) ON DELETE CASCADE,
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) <= 40960),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Nonces of anonymous-route requests, kept for twice the clock window so a
-- request can't be replayed at either edge.
CREATE TABLE chat_group_nonces (
    nonce bytea PRIMARY KEY CHECK (octet_length(nonce) = 16),
    expires_at timestamptz NOT NULL
);
CREATE INDEX chat_group_nonces_expires_at ON chat_group_nonces (expires_at);
