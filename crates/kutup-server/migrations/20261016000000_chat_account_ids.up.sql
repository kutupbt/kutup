-- Chat keyed by account ids (docs/plans/account-ids.md, slice 3): every
-- account Chat stores or routes to is (server, account id), never a name.
-- Before the wipe: Chat's queued and stored rows made under names are
-- dropped, as no client reads them now.

-- A stored message names its sender's account, or nobody (sealed sender).
DELETE FROM chat_mailbox;
ALTER TABLE chat_mailbox
    DROP CONSTRAINT chat_mailbox_sender_qualified,
    DROP COLUMN sender,
    ADD COLUMN sender_server text
        CONSTRAINT chat_mailbox_sender_server_check CHECK (sender_server = lower(sender_server)),
    ADD COLUMN sender_account_id uuid,
    ADD CONSTRAINT chat_mailbox_sender_check
        CHECK ((sender_server IS NULL) = (sender_account_id IS NULL));

-- Outboxes route to the recipient's account on the destination.
DELETE FROM chat_federation_outbox;
ALTER TABLE chat_federation_outbox
    DROP COLUMN recipient,
    DROP COLUMN sender,
    ADD COLUMN recipient_account_id uuid NOT NULL;

DELETE FROM chat_sealed_federation_outbox;
ALTER TABLE chat_sealed_federation_outbox
    DROP CONSTRAINT chat_sealed_federation_outbox_destination_recipient_send_id_key,
    DROP COLUMN recipient,
    ADD COLUMN recipient_account_id uuid NOT NULL,
    ADD CONSTRAINT chat_sealed_federation_outbox_destination_recipient_send_id_key
        UNIQUE (destination, recipient_account_id, send_id);

DELETE FROM chat_mls_federation_outbox;
ALTER TABLE chat_mls_federation_outbox
    DROP CONSTRAINT chat_mls_federation_outbox_destination_recipient_send_id_key,
    DROP COLUMN recipient,
    ADD COLUMN recipient_account_id uuid NOT NULL,
    ADD CONSTRAINT chat_mls_federation_outbox_destination_recipient_send_id_key
        UNIQUE (destination, recipient_account_id, send_id);

DELETE FROM chat_media_federation_pull_grants;
ALTER TABLE chat_media_federation_pull_grants
    DROP CONSTRAINT chat_media_federation_pull_gr_destination_recipient_attachm_key,
    DROP COLUMN recipient,
    ADD COLUMN recipient_account_id uuid NOT NULL,
    ADD CONSTRAINT chat_media_federation_pull_grants_recipient_attachment_key
        UNIQUE (destination, recipient_account_id, attachment_id);

-- Invitation feedback names the member's account, as its canonical
-- `aci:<account id>@<server>` (one value, so it keys the rows as the
-- address did).
DELETE FROM chat_mls_invitation_feedback;
ALTER TABLE chat_mls_invitation_feedback
    DROP CONSTRAINT chat_mls_invitation_feedback_pkey,
    DROP COLUMN member_address,
    ADD COLUMN member_account text NOT NULL
        CONSTRAINT chat_mls_invitation_feedback_member_account_check
        CHECK (member_account ~ '^aci:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@[a-z0-9.-]+$'),
    ADD CONSTRAINT chat_mls_invitation_feedback_pkey
        PRIMARY KEY (conversation_id, incarnation, member_account, invited_epoch);

DELETE FROM chat_mls_invitation_feedback_outbox;
ALTER TABLE chat_mls_invitation_feedback_outbox
    DROP CONSTRAINT chat_mls_invitation_feedback_outbox_pkey,
    DROP COLUMN member_address,
    ADD COLUMN member_account text NOT NULL
        CONSTRAINT chat_mls_invitation_feedback_outbox_member_account_check
        CHECK (member_account ~ '^aci:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@[a-z0-9.-]+$'),
    ADD CONSTRAINT chat_mls_invitation_feedback_outbox_pkey
        PRIMARY KEY (destination, conversation_id, incarnation, member_account, invited_epoch);

-- Unused, and unique on an address.
DROP TABLE chat_mls_pending_requests;

-- A meeting seat or knock keeps the account it belongs to; `account` stays
-- the name shown.
ALTER TABLE chat_call_link_seats ADD COLUMN account_id text
    CONSTRAINT chat_call_link_seats_account_id_check CHECK (account_id ~ '^aci:');
ALTER TABLE chat_call_link_knocks ADD COLUMN account_id text
    CONSTRAINT chat_call_link_knocks_account_id_check CHECK (account_id ~ '^aci:');
