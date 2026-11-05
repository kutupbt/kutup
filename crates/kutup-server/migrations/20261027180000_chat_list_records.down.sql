-- Back to the fixed sizes of the old list formats (no record-format entry
-- passes them: run on an emptied database).
ALTER TABLE chat_group_list DROP CONSTRAINT chat_group_list_envelope_check;
ALTER TABLE chat_group_list
    ADD CONSTRAINT chat_group_list_envelope_check CHECK (octet_length(envelope) = 4032);
ALTER TABLE chat_contact_list DROP CONSTRAINT chat_contact_list_envelope_check;
ALTER TABLE chat_contact_list
    ADD CONSTRAINT chat_contact_list_envelope_check CHECK (octet_length(envelope) = 2048);
