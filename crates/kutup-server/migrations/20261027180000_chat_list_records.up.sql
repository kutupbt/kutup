-- W1 slice 3a (docs/plans/w1-account-record.md): Chat group and contact list
-- entries are account records (KUTPAR1). Their plaintext is padded to one
-- size and their header is fixed (a canonical key binding, a 32-byte object,
-- a revision), so every entry is still exactly one length, and the column
-- keeps requiring it (kutup_crypto::chat_{group,contact}_list::SEALED_LEN):
-- the server can't tell entries apart by their length.
ALTER TABLE chat_group_list DROP CONSTRAINT chat_group_list_envelope_check;
ALTER TABLE chat_group_list
    ADD CONSTRAINT chat_group_list_envelope_check CHECK (octet_length(envelope) = 4144);
ALTER TABLE chat_contact_list DROP CONSTRAINT chat_contact_list_envelope_check;
ALTER TABLE chat_contact_list
    ADD CONSTRAINT chat_contact_list_envelope_check CHECK (octet_length(envelope) = 2160);
