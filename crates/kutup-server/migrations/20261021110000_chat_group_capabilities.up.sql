-- Group delivery capabilities (docs/plans/pairwise-groups.md, slice 2 §2):
-- each account publishes the SHA-256 of one random capability per group it
-- is in, with no group id, so a sender holding a member's capability may
-- deliver one multi-recipient copy to it. The raw capability is never
-- stored.
CREATE TABLE chat_group_capabilities (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    capability_hash bytea NOT NULL CHECK (octet_length(capability_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, capability_hash)
);
