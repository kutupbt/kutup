-- Back to the fixed size of the old joined-meeting format (no record-format
-- entry passes it: run on an emptied database).
ALTER TABLE chat_joined_meetings DROP CONSTRAINT chat_joined_meetings_entry_check;
ALTER TABLE chat_joined_meetings
    ADD CONSTRAINT chat_joined_meetings_entry_check CHECK (octet_length(entry) = 1064);
