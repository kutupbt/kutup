-- PostgreSQL CHECK constraints accept UNKNOWN. The original MLS mailbox shape
-- used `incarnation > 0`, which evaluates to UNKNOWN for NULL and therefore did
-- not require membership-control rows to bind an exact incarnation.
DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    SELECT conname
      INTO constraint_name
      FROM pg_constraint
     WHERE conrelid = 'chat_mls_mailbox'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) LIKE '%identified_request%'
       AND pg_get_constraintdef(oid) LIKE '%request_id%'
     LIMIT 1;
    IF constraint_name IS NULL THEN
        RAISE EXCEPTION 'MLS mailbox metadata-shape constraint not found';
    END IF;
    EXECUTE format(
        'ALTER TABLE chat_mls_mailbox DROP CONSTRAINT %I',
        constraint_name
    );
END
$$;

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
            AND conversation_id IS NOT NULL
            AND incarnation IS NOT NULL AND incarnation > 0)
    );
