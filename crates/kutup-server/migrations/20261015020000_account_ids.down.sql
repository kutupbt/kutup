ALTER TABLE file_versions
    DROP CONSTRAINT file_versions_remote_author_check,
    DROP COLUMN remote_author_account_id,
    DROP COLUMN remote_author_server,
    ADD COLUMN remote_author text,
    ADD CONSTRAINT file_versions_remote_author_check CHECK (length(remote_author) <= 320);
DROP INDEX IF EXISTS federated_outgoing_file_shares_recipient;
DROP INDEX IF EXISTS federated_outgoing_shares_recipient;
ALTER TABLE federated_outgoing_file_shares DROP COLUMN recipient_account_id;
ALTER TABLE federated_outgoing_shares DROP COLUMN recipient_account_id;
DELETE FROM drive_profile_keys;
ALTER TABLE drive_profile_keys
    DROP CONSTRAINT drive_profile_keys_pkey,
    DROP COLUMN peer_account_id,
    DROP COLUMN peer_server,
    ALTER COLUMN peer_incarnation_id DROP NOT NULL,
    ADD COLUMN peer_account text NOT NULL
        CONSTRAINT drive_profile_keys_peer_account_check
        CHECK (length(peer_account) >= 3 AND length(peer_account) <= 320),
    ADD PRIMARY KEY (user_id, direction, peer_account);
DROP TABLE retired_account_ids;
DROP INDEX IF EXISTS users_one_break_glass;
ALTER TABLE users DROP COLUMN is_break_glass;
