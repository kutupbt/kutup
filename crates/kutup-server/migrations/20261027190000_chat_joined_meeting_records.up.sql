-- W1 slice 3b (docs/plans/w1-account-record.md): an account's joined
-- meetings are account records (KUTPAR1, purpose JoinedMeeting), bound to
-- the account and to the row's id. The stay is padded and the header fixed
-- (a canonical key binding, a 16-byte object, no revision), so every record
-- is still exactly one length, and the column keeps requiring it
-- (kutup_crypto::chat_call_link::JOINED_MEETING_SEALED_BYTES).
ALTER TABLE chat_joined_meetings DROP CONSTRAINT chat_joined_meetings_entry_check;
ALTER TABLE chat_joined_meetings
    ADD CONSTRAINT chat_joined_meetings_entry_check CHECK (octet_length(entry) = 1171);
