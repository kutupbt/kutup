-- Permanent account ids (docs/plans/account-ids.md): records about a person
-- are keyed by their server and account id (`users.id`), never their name.
-- Before the wipe: nothing here is kept across it.

-- The break-glass admin by its account id, recorded when it is made (its
-- name is configuration; the protection follows the account).
ALTER TABLE users ADD COLUMN is_break_glass boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX users_one_break_glass ON users ((true)) WHERE is_break_glass;

-- An account id is never given again once its account is deleted.
CREATE TABLE retired_account_ids (
    id         uuid PRIMARY KEY,
    retired_at timestamptz NOT NULL DEFAULT now()
);

-- Profile keys by the peer's account, not their address. The rows held so
-- far name addresses only; clients exchange the keys again.
DELETE FROM drive_profile_keys;
ALTER TABLE drive_profile_keys
    DROP CONSTRAINT drive_profile_keys_pkey,
    DROP CONSTRAINT drive_profile_keys_peer_account_check,
    DROP COLUMN peer_account,
    ADD COLUMN peer_server text NOT NULL
        CHECK (peer_server = lower(peer_server) AND length(peer_server) BETWEEN 3 AND 253),
    ADD COLUMN peer_account_id uuid NOT NULL,
    ALTER COLUMN peer_incarnation_id SET NOT NULL,
    ADD PRIMARY KEY (user_id, direction, peer_server, peer_account_id);

-- A federated share's recipient by their account id; the username stays,
-- shown only (kept current by rename announces).
ALTER TABLE federated_outgoing_shares ADD COLUMN recipient_account_id uuid NOT NULL;
ALTER TABLE federated_outgoing_file_shares ADD COLUMN recipient_account_id uuid NOT NULL;
CREATE INDEX federated_outgoing_shares_recipient
    ON federated_outgoing_shares (recipient_domain, recipient_account_id);
CREATE INDEX federated_outgoing_file_shares_recipient
    ON federated_outgoing_file_shares (recipient_domain, recipient_account_id);

-- A version saved by someone on another server: their server and account id.
ALTER TABLE file_versions
    DROP CONSTRAINT file_versions_remote_author_check,
    DROP COLUMN remote_author,
    ADD COLUMN remote_author_server text,
    ADD COLUMN remote_author_account_id uuid,
    ADD CONSTRAINT file_versions_remote_author_check
        CHECK ((remote_author_server IS NULL) = (remote_author_account_id IS NULL));
