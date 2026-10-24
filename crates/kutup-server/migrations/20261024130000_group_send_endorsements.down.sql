DELETE FROM chat_anonymous_rate_counters
    WHERE scope_type IN ('group_send_issue', 'group_endorsement_upload',
        'group_send_token', 'multi_recipient');
ALTER TABLE chat_anonymous_rate_counters DROP CONSTRAINT chat_anonymous_rate_counters_scope_type_check;
ALTER TABLE chat_anonymous_rate_counters ADD CONSTRAINT chat_anonymous_rate_counters_scope_type_check
    CHECK (scope_type = ANY (ARRAY['capability_bundle', 'capability_minute', 'capability_day',
        'recipient', 'federation_origin', 'group_capability_minute', 'group_capability_day',
        'ip_bytes', 'origin_multi_requests', 'origin_multi_bytes']));
CREATE TABLE chat_group_capabilities (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    capability_hash bytea NOT NULL CHECK (octet_length(capability_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, capability_hash)
);
DROP TABLE IF EXISTS chat_group_endorsements;
DROP TABLE IF EXISTS chat_zk_server_keys;
