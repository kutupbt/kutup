-- Every pseudonym a group has seen, as a member or a requester, so a
-- newcomer can't come back under one the members knew
-- (docs/plans/pairwise-groups.md, "A pseudonym comes back only once"). The
-- log is pruned and the state forgets who left, so neither can answer that.
-- Kept as SHA-256 under a domain label: a lookup key, not a secret (the
-- pseudonyms are public keys the home saw anyway).
CREATE TABLE chat_group_seen_pseudonyms (
    group_id bytea NOT NULL REFERENCES chat_groups (group_id) ON DELETE CASCADE,
    pseudonym_hash bytea NOT NULL CHECK (octet_length(pseudonym_hash) = 32),
    PRIMARY KEY (group_id, pseudonym_hash)
);
