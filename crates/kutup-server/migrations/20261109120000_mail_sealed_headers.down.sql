ALTER TABLE mail_identities
    DROP COLUMN signature_sealed,
    ADD COLUMN signature text NOT NULL DEFAULT '' CHECK (length(signature) <= 10000);

DROP INDEX idx_mail_messages_search_tokens;
DROP INDEX idx_mail_messages_sent_message_id_hash;
DROP INDEX idx_mail_messages_message_id_hash;
DROP INDEX idx_mail_messages_inbound_once;
ALTER TABLE mail_messages
    DROP COLUMN search_tokens,
    DROP COLUMN references_hashes,
    DROP COLUMN in_reply_to_hash,
    DROP COLUMN message_id_hash,
    DROP COLUMN headers,
    DROP COLUMN forwarded,
    ADD COLUMN forwarded_from text CHECK (forwarded_from IS NULL OR length(forwarded_from) <= 320),
    ADD COLUMN subject text NOT NULL DEFAULT '' CHECK (length(subject) <= 1000),
    ADD COLUMN from_address text NOT NULL DEFAULT '' CHECK (length(from_address) <= 320),
    ADD COLUMN from_name text NOT NULL DEFAULT '',
    ADD COLUMN to_list jsonb NOT NULL DEFAULT '[]'
        CHECK (jsonb_typeof(to_list) = 'array' AND jsonb_array_length(to_list) <= 100),
    ADD COLUMN cc_list jsonb NOT NULL DEFAULT '[]',
    ADD COLUMN reply_to jsonb NOT NULL DEFAULT '[]',
    ADD COLUMN bcc_list jsonb NOT NULL DEFAULT '[]',
    ADD COLUMN message_id text,
    ADD COLUMN in_reply_to text,
    ADD COLUMN references_list text[] NOT NULL DEFAULT '{}',
    ADD COLUMN attachments jsonb NOT NULL DEFAULT '[]';
CREATE UNIQUE INDEX idx_mail_messages_inbound_once ON mail_messages (address_id, message_id)
    WHERE direction = 'inbound' AND message_id IS NOT NULL;
CREATE INDEX idx_mail_messages_message_id ON mail_messages (user_id, message_id)
    WHERE message_id IS NOT NULL;

DROP TABLE account_keys.mail_group_data_keys;
