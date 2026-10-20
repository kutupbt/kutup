-- Every pseudonym that was ever a member of a group, as a hash, so a
-- newcomer can't come back under a pseudonym the members knew
-- (docs/plans/pairwise-groups.md, "pseudonymUsed"). The log is pruned, so
-- it can't answer that.
CREATE TABLE chat_group_seen_pseudonyms (
    group_id bytea NOT NULL REFERENCES chat_groups (group_id) ON DELETE CASCADE,
    pseudonym_hash bytea NOT NULL CHECK (octet_length(pseudonym_hash) = 32),
    PRIMARY KEY (group_id, pseudonym_hash)
);
