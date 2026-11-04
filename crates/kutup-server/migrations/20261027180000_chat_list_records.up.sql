-- W1 slice 3a (docs/plans/w1-account-record.md): Chat group and contact list
-- entries are account records (KUTPAR1). Every entry of one account is one
-- length, but that length depends on the record's header, so the column keeps
-- an upper bound (kutup_crypto::chat_{group,contact}_list::MAX_SEALED_LEN)
-- instead of the old fixed sizes; the server validates each entry whole.
ALTER TABLE chat_group_list DROP CONSTRAINT chat_group_list_envelope_check;
ALTER TABLE chat_group_list
    ADD CONSTRAINT chat_group_list_envelope_check CHECK (octet_length(envelope) <= 4176);
ALTER TABLE chat_contact_list DROP CONSTRAINT chat_contact_list_envelope_check;
ALTER TABLE chat_contact_list
    ADD CONSTRAINT chat_contact_list_envelope_check CHECK (octet_length(envelope) <= 2192);
