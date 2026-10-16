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
