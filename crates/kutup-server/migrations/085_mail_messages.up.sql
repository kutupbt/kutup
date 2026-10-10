-- Mail messages (docs/plans/mail.md). Each message is stored whole in S3,
-- encrypted to its address key (mail from outside on arrival, "zero-access";
-- mail between Kutup users end to end). What the server reads, as Proton's
-- does: the subject, the addresses, the dates, the size, the folder and the
-- flags. Bodies and attachments never appear here. Charged to the pool.

CREATE TABLE mail_messages (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    address_id       UUID NOT NULL REFERENCES mail_addresses(id) ON DELETE CASCADE,
    thread_id        UUID NOT NULL,
    -- Whether the message came in or went out; never changes, unlike folder.
    direction        TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    folder           TEXT NOT NULL CHECK (folder IN ('inbox', 'drafts', 'sent', 'archive', 'spam', 'trash')),
    seen             BOOLEAN NOT NULL DEFAULT false,
    starred          BOOLEAN NOT NULL DEFAULT false,
    protection       TEXT NOT NULL CHECK (protection IN ('zero_access', 'end_to_end')),
    object_key       TEXT NOT NULL UNIQUE,
    object_version   TEXT NOT NULL DEFAULT '',
    size_bytes       BIGINT NOT NULL CHECK (size_bytes > 0),
    received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at          TIMESTAMPTZ,
    subject          TEXT NOT NULL DEFAULT '' CHECK (length(subject) <= 1000),
    from_address     TEXT NOT NULL DEFAULT '' CHECK (length(from_address) <= 320),
    from_name        TEXT NOT NULL DEFAULT '' CHECK (length(from_name) <= 400),
    -- [{"address": "...", "name": "..."}], at most 100 each.
    to_list          JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(to_list) = 'array' AND jsonb_array_length(to_list) <= 100),
    cc_list          JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(cc_list) = 'array' AND jsonb_array_length(cc_list) <= 100),
    reply_to         JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(reply_to) = 'array' AND jsonb_array_length(reply_to) <= 100),
    message_id       TEXT CHECK (length(message_id) BETWEEN 1 AND 998),
    in_reply_to      TEXT CHECK (length(in_reply_to) BETWEEN 1 AND 998),
    references_list  TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(references_list) <= 50),
    attachment_count INTEGER NOT NULL DEFAULT 0 CHECK (attachment_count >= 0)
);
CREATE INDEX idx_mail_messages_folder ON mail_messages(user_id, folder, received_at DESC, id);
CREATE INDEX idx_mail_messages_thread ON mail_messages(thread_id, received_at);
CREATE INDEX idx_mail_messages_message_id ON mail_messages(user_id, message_id) WHERE message_id IS NOT NULL;
-- One stored copy of each incoming message per address: a mailing-list copy
-- of a message already received directly, or a delivery retried after a
-- lost reply, is acknowledged and not stored again.
CREATE UNIQUE INDEX idx_mail_messages_inbound_once ON mail_messages(address_id, message_id)
    WHERE direction = 'inbound' AND message_id IS NOT NULL;
