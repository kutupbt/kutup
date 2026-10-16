-- A meeting seat or knock records the account this server vouches for by its
-- id (docs/plans/account-ids.md); the name shown is the account's current
-- one, read whenever a token is minted or the knocks are listed. Seats and
-- knocks are short-lived, so the names they held are simply dropped.
ALTER TABLE chat_call_link_seats
    DROP COLUMN account,
    ADD COLUMN account_id uuid REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE chat_call_link_knocks
    DROP COLUMN account,
    ADD COLUMN account_id uuid REFERENCES users(id) ON DELETE SET NULL;
