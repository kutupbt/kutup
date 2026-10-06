ALTER TABLE chat_call_link_knocks DROP COLUMN IF EXISTS seat_hash, DROP COLUMN IF EXISTS account;
ALTER TABLE chat_call_links
    DROP COLUMN IF EXISTS sitting,
    DROP COLUMN IF EXISTS locked,
    DROP COLUMN IF EXISTS hostless_since;
DROP TABLE IF EXISTS chat_call_link_seats;
