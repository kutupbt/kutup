ALTER TABLE chat_call_link_knocks
    DROP COLUMN account_id,
    ADD COLUMN account text;

ALTER TABLE chat_call_link_seats
    DROP COLUMN account_id,
    ADD COLUMN account text;
