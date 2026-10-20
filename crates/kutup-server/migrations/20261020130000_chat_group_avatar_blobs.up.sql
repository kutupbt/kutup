-- Group avatars (docs/plans/pairwise-groups.md, "Avatar"): each sealed blob
-- by its SHA-256, the hash the group's state names. A group has at most its
-- current blob and one pending upload, which waits 24 hours for a change to
-- name it. Replaces the never-used one-blob table.
DROP TABLE chat_group_avatars;

CREATE TABLE chat_group_avatars (
    group_id bytea NOT NULL REFERENCES chat_groups (group_id) ON DELETE CASCADE,
    hash bytea NOT NULL CHECK (octet_length(hash) = 32),
    blob bytea NOT NULL CHECK (octet_length(blob) IN (8233, 16425, 32809, 41001)),
    -- NULL for the current blob; the pending one's deadline otherwise.
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, hash)
);
CREATE UNIQUE INDEX chat_group_avatars_one_current
    ON chat_group_avatars (group_id) WHERE expires_at IS NULL;
CREATE UNIQUE INDEX chat_group_avatars_one_pending
    ON chat_group_avatars (group_id) WHERE expires_at IS NOT NULL;
CREATE INDEX chat_group_avatars_expires_at
    ON chat_group_avatars (expires_at) WHERE expires_at IS NOT NULL;
