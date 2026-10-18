-- An account's group list (docs/plans/pairwise-groups.md §5): one sealed entry
-- per pairwise group, keyed by a hash of the group id under a key of the
-- account's own, so lists can't be matched across members. Listed under the
-- account head's `chatGroups` scope.
CREATE TABLE chat_group_list (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id text NOT NULL CHECK (id ~ '^[A-Za-z0-9_-]{43}$'),
    revision bigint NOT NULL CHECK (revision > 0),
    envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 4096),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id)
);
