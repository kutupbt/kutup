DELETE FROM chat_anonymous_rate_counters
 WHERE scope_type IN ('group_capability_minute', 'group_capability_day', 'ip_bytes');
ALTER TABLE chat_anonymous_rate_counters DROP CONSTRAINT chat_anonymous_rate_counters_scope_type_check;
ALTER TABLE chat_anonymous_rate_counters ADD CONSTRAINT chat_anonymous_rate_counters_scope_type_check
    CHECK (scope_type = ANY (ARRAY['capability_bundle', 'capability_minute', 'capability_day',
        'recipient', 'federation_origin']));
DELETE FROM chat_mailbox WHERE shared_payload_id IS NOT NULL;
ALTER TABLE chat_mailbox DROP COLUMN shared_payload_id;
DROP TABLE chat_shared_payloads;
