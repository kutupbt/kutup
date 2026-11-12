-- Mail metadata sealed (docs/plans/server-personal-data.md, A2, slice L7).
-- A message's headers (subject, sender, recipients, Message-IDs, attached
-- file names) are one value sealed under its mailbox's data key: the
-- account's, or for a shared mailbox the group's own. What the server must
-- find by is a keyed hash under the same key (threading, duplicates,
-- bounces, search words), so destroying the key destroys all of it.
-- This lands with the wipe: rows already there keep no headers.

-- A shared mailbox's data key, as an account's (account_keys.account_data_keys).
CREATE TABLE account_keys.mail_group_data_keys (
    group_id uuid NOT NULL REFERENCES public.mail_groups(id) ON DELETE CASCADE,
    sealing_key_id smallint NOT NULL CHECK (sealing_key_id >= 1),
    generation integer NOT NULL CHECK (generation >= 1),
    wrapped bytea NOT NULL CHECK (octet_length(wrapped) = 86),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, generation)
);
CREATE INDEX mail_group_data_keys_sealing_key_id
    ON account_keys.mail_group_data_keys (sealing_key_id);

DROP INDEX idx_mail_messages_inbound_once;
DROP INDEX idx_mail_messages_message_id;
ALTER TABLE mail_messages
    DROP COLUMN subject,
    DROP COLUMN from_address,
    DROP COLUMN from_name,
    DROP COLUMN to_list,
    DROP COLUMN cc_list,
    DROP COLUMN reply_to,
    DROP COLUMN bcc_list,
    DROP COLUMN message_id,
    DROP COLUMN in_reply_to,
    DROP COLUMN references_list,
    DROP COLUMN attachments,
    -- The address it was forwarded from goes into the headers; whether it
    -- came by forwarding (never forwarded again) stays.
    DROP COLUMN forwarded_from,
    ADD COLUMN forwarded boolean NOT NULL DEFAULT false,
    -- kutup-server/src/mail/sealed.rs: the headers, sealed (none: not kept).
    ADD COLUMN headers bytea,
    -- Keyed hashes (kutup_crypto::server_data::Lookup::MailThread) of its
    -- Message-ID, In-Reply-To and References.
    ADD COLUMN message_id_hash bytea CHECK (octet_length(message_id_hash) = 32),
    ADD COLUMN in_reply_to_hash bytea CHECK (octet_length(in_reply_to_hash) = 32),
    ADD COLUMN references_hashes bytea[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(references_hashes) <= 50),
    -- Keyed hashes (Lookup::MailSearchToken) of its header words, each
    -- tagged with its field: what search matches.
    ADD COLUMN search_tokens bytea[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(search_tokens) <= 4000);

-- The same incoming message is stored once per address.
CREATE UNIQUE INDEX idx_mail_messages_inbound_once ON mail_messages (address_id, message_id_hash)
    WHERE direction = 'inbound' AND message_id_hash IS NOT NULL;
-- Threading: an ancestor's thread, in the mailbox.
CREATE INDEX idx_mail_messages_message_id_hash ON mail_messages (owner, message_id_hash)
    WHERE message_id_hash IS NOT NULL;
-- Bounces: a message an account sent outside.
CREATE INDEX idx_mail_messages_sent_message_id_hash ON mail_messages (sender_account, message_id_hash)
    WHERE direction = 'outbound' AND message_id_hash IS NOT NULL;
CREATE INDEX idx_mail_messages_search_tokens ON mail_messages USING gin (search_tokens);

-- An address's signature, sealed under its account's data key.
ALTER TABLE mail_identities
    DROP COLUMN signature,
    ADD COLUMN signature_sealed bytea;
