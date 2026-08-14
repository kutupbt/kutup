ALTER TABLE chat_mls_mailbox
    DROP CONSTRAINT chat_mls_mailbox_metadata_shape_check;

ALTER TABLE chat_mls_mailbox
    ADD CONSTRAINT chat_mls_mailbox_metadata_shape_check
    CHECK (
        (delivery_kind = 'identified_request' AND request_id IS NOT NULL
            AND conversation_id IS NOT NULL AND incarnation IS NULL)
        OR (delivery_kind = 'anonymous' AND request_id IS NULL
            AND conversation_id IS NULL AND incarnation IS NULL)
        OR (delivery_kind = 'self_sync' AND request_id IS NULL
            AND conversation_id IS NOT NULL AND incarnation IS NULL)
        OR (delivery_kind = 'membership_control' AND request_id IS NULL
            AND conversation_id IS NOT NULL AND incarnation > 0)
    );
