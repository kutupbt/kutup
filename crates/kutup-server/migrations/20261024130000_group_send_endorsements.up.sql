-- Group send endorsements (docs/plans/group-send-endorsements.md) replace the
-- per-group delivery capabilities of slice 2.

-- §4: this server's endorsement keys. Only the endorsement root of a
-- ServerSecretParams is kept, sealed under OPAQUE_SETUP_KEYS' entry
-- `sealing_key_id` and bound to its key id. The current key issues
-- (`issues_until` NULL); after a rotation the previous one only verifies,
-- until `verifies_until`, then its row goes.
CREATE TABLE chat_zk_server_keys (
    key_id integer PRIMARY KEY CHECK (key_id > 0),
    sealing_key_id smallint NOT NULL CHECK (sealing_key_id > 0),
    server_secret_sealed bytea NOT NULL,
    -- The EndorsementPublicKey, as discovery publishes it.
    public_key bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    issues_until bigint,
    verifies_until bigint,
    CHECK ((issues_until IS NULL) = (verifies_until IS NULL))
);
-- One key issues at a time.
CREATE UNIQUE INDEX chat_zk_server_keys_issuing
    ON chat_zk_server_keys ((true)) WHERE issues_until IS NULL;

-- §3.3: each member's sealed blob per expiration, on the group's home. The
-- home reads only the expiration; `seq` orders the group's uploads for
-- readers' cursors. At most two per pseudonym (the current and the next).
CREATE SEQUENCE chat_group_endorsement_seq;
CREATE TABLE chat_group_endorsements (
    group_id bytea NOT NULL REFERENCES chat_groups(group_id) ON DELETE CASCADE,
    pseudonym bytea NOT NULL CHECK (octet_length(pseudonym) = 32),
    expiration bigint NOT NULL CHECK (expiration > 0),
    sealed bytea NOT NULL,
    seq bigint NOT NULL DEFAULT nextval('chat_group_endorsement_seq'),
    PRIMARY KEY (group_id, pseudonym, expiration)
);
ALTER SEQUENCE chat_group_endorsement_seq OWNED BY chat_group_endorsements.seq;
CREATE UNIQUE INDEX chat_group_endorsements_by_seq ON chat_group_endorsements (group_id, seq);
CREATE INDEX chat_group_endorsements_expiry ON chat_group_endorsements (expiration);

-- The budgets' counters: an account's endorsements a day (§3.2), a member's
-- uploads a day (§3.3), and on the multi route a token's requests and a
-- recipient's sends a minute (§3.6), in place of the capabilities'.
DELETE FROM chat_anonymous_rate_counters
    WHERE scope_type IN ('group_capability_minute', 'group_capability_day');
ALTER TABLE chat_anonymous_rate_counters DROP CONSTRAINT chat_anonymous_rate_counters_scope_type_check;
ALTER TABLE chat_anonymous_rate_counters ADD CONSTRAINT chat_anonymous_rate_counters_scope_type_check
    CHECK (scope_type = ANY (ARRAY['capability_bundle', 'capability_minute', 'capability_day',
        'recipient', 'federation_origin', 'ip_bytes', 'origin_multi_requests',
        'origin_multi_bytes', 'group_send_issue', 'group_endorsement_upload',
        'group_send_token', 'multi_recipient']));

-- The capabilities and their settings go.
DROP TABLE chat_group_capabilities;
DELETE FROM site_settings WHERE key IN (
    'chat_group_capabilities_per_account',
    'chat_group_capability_sends_per_min',
    'chat_group_capability_sends_per_day'
);
