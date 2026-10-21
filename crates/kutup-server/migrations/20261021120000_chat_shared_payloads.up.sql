-- Multi-recipient sends stored once (docs/plans/pairwise-groups.md, slice 2
-- §6; Signal-Server's shared payload): `e_pub ‖ ciphertext` once per send
-- and destination, and each recipient device's mailbox row naming it, with
-- its account's 48 bytes of key material as its content. A payload goes
-- when no row names it any more (collected by reference).
CREATE TABLE chat_shared_payloads (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    payload bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE chat_mailbox
    ADD COLUMN shared_payload_id uuid REFERENCES chat_shared_payloads(id) ON DELETE RESTRICT;

-- The multi-recipient route's budgets: per group capability, and an
-- address's bytes a minute.
ALTER TABLE chat_anonymous_rate_counters DROP CONSTRAINT chat_anonymous_rate_counters_scope_type_check;
ALTER TABLE chat_anonymous_rate_counters ADD CONSTRAINT chat_anonymous_rate_counters_scope_type_check
    CHECK (scope_type = ANY (ARRAY['capability_bundle', 'capability_minute', 'capability_day',
        'recipient', 'federation_origin', 'group_capability_minute', 'group_capability_day',
        'ip_bytes', 'origin_multi_requests', 'origin_multi_bytes']));

-- A multi-recipient send stored for a device, by its sendId: a retry stores
-- nothing again for that device, and a device added since gets its copy.
CREATE TABLE chat_multi_send_ids (
    user_id uuid NOT NULL,
    device_id integer NOT NULL,
    send_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, send_id),
    FOREIGN KEY (user_id, device_id) REFERENCES chat_devices (user_id, device_id) ON DELETE CASCADE
);
CREATE INDEX chat_multi_send_ids_created_at ON chat_multi_send_ids (created_at);
