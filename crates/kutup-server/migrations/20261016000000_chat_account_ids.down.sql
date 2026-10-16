ALTER TABLE chat_call_link_knocks DROP COLUMN account_id;
ALTER TABLE chat_call_link_seats DROP COLUMN account_id;

CREATE TABLE chat_mls_pending_requests (
    request_id uuid NOT NULL PRIMARY KEY,
    conversation_id uuid NOT NULL,
    incarnation bigint NOT NULL CHECK (incarnation > 0),
    sender_address text NOT NULL,
    sender_origin text NOT NULL CHECK (sender_origin = lower(sender_origin)),
    recipient_user_id uuid NOT NULL,
    status text DEFAULT 'pending' NOT NULL
        CHECK (status = ANY (ARRAY['pending', 'accepted', 'rejected', 'blocked', 'expired'])),
    maximum_messages integer NOT NULL CHECK (maximum_messages BETWEEN 1 AND 128),
    maximum_ciphertext_bytes bigint NOT NULL
        CHECK (maximum_ciphertext_bytes BETWEEN 65536 AND 16777216),
    message_count integer DEFAULT 0 NOT NULL CHECK (message_count >= 0),
    ciphertext_bytes bigint DEFAULT 0 NOT NULL CHECK (ciphertext_bytes >= 0),
    genesis jsonb NOT NULL CHECK (jsonb_typeof(genesis) = 'object'),
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CHECK (message_count <= maximum_messages),
    CHECK (ciphertext_bytes <= maximum_ciphertext_bytes)
);
CREATE UNIQUE INDEX chat_mls_one_pending_request_per_sender_idx
    ON chat_mls_pending_requests (recipient_user_id, sender_address) WHERE status = 'pending';
CREATE INDEX chat_mls_pending_requests_recipient_idx
    ON chat_mls_pending_requests (recipient_user_id, status, created_at);

DELETE FROM chat_mls_invitation_feedback_outbox;
ALTER TABLE chat_mls_invitation_feedback_outbox
    DROP CONSTRAINT chat_mls_invitation_feedback_outbox_pkey,
    DROP COLUMN member_account,
    ADD COLUMN member_address text NOT NULL,
    ADD CONSTRAINT chat_mls_invitation_feedback_outbox_pkey
        PRIMARY KEY (destination, conversation_id, incarnation, member_address, invited_epoch);

DELETE FROM chat_mls_invitation_feedback;
ALTER TABLE chat_mls_invitation_feedback
    DROP CONSTRAINT chat_mls_invitation_feedback_pkey,
    DROP COLUMN member_account,
    ADD COLUMN member_address text NOT NULL,
    ADD CONSTRAINT chat_mls_invitation_feedback_pkey
        PRIMARY KEY (conversation_id, incarnation, member_address, invited_epoch);

DELETE FROM chat_media_federation_pull_grants;
ALTER TABLE chat_media_federation_pull_grants
    DROP CONSTRAINT chat_media_federation_pull_grants_recipient_attachment_key,
    DROP COLUMN recipient_account_id,
    ADD COLUMN recipient text NOT NULL,
    ADD CONSTRAINT chat_media_federation_pull_gr_destination_recipient_attachm_key
        UNIQUE (destination, recipient, attachment_id);

DELETE FROM chat_mls_federation_outbox;
ALTER TABLE chat_mls_federation_outbox
    DROP CONSTRAINT chat_mls_federation_outbox_destination_recipient_send_id_key,
    DROP COLUMN recipient_account_id,
    ADD COLUMN recipient text NOT NULL,
    ADD CONSTRAINT chat_mls_federation_outbox_destination_recipient_send_id_key
        UNIQUE (destination, recipient, send_id);

DELETE FROM chat_sealed_federation_outbox;
ALTER TABLE chat_sealed_federation_outbox
    DROP CONSTRAINT chat_sealed_federation_outbox_destination_recipient_send_id_key,
    DROP COLUMN recipient_account_id,
    ADD COLUMN recipient text NOT NULL,
    ADD CONSTRAINT chat_sealed_federation_outbox_destination_recipient_send_id_key
        UNIQUE (destination, recipient, send_id);

DELETE FROM chat_federation_outbox;
ALTER TABLE chat_federation_outbox
    DROP COLUMN recipient_account_id,
    ADD COLUMN recipient text NOT NULL,
    ADD COLUMN sender text NOT NULL;

DELETE FROM chat_mailbox;
ALTER TABLE chat_mailbox
    DROP CONSTRAINT chat_mailbox_sender_check,
    DROP COLUMN sender_account_id,
    DROP COLUMN sender_server,
    ADD COLUMN sender text,
    ADD CONSTRAINT chat_mailbox_sender_qualified CHECK (
        sender IS NULL
        OR sender ~ '^[a-z0-9_-]{3,32}@([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$');
