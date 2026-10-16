-- Shared mailboxes (docs/plans/mail-groups.md, docs/plans/account-ids.md):
-- - their key shares are sealed to each member's account key, not to an
--   address key, so a rename keeps them;
-- - their key lists are signed by a group signing key the owners and
--   managers hold (Proton's Signed Key Lists), never by this server: the
--   server's mail-group authority is gone.
-- Every shared mailbox key, list and share made so far is deleted: the
-- shares were sealed to address keys and the lists signed by the server,
-- formats no client reads now (before the wipe; managers make a new key).
DELETE FROM mail_group_key_shares;
DELETE FROM mail_group_key_lists;
DELETE FROM mail_group_keys;
DELETE FROM server_generated_keys WHERE purpose = 'mail-group-authority';
ALTER TABLE server_generated_keys DROP CONSTRAINT server_generated_keys_purpose_check;
ALTER TABLE server_generated_keys ADD CONSTRAINT server_generated_keys_purpose_check
    CHECK (purpose = ANY (ARRAY['federation-identity', 'mls-control', 'fake-accounts',
                                'registration-codes']));
ALTER TABLE mail_group_key_shares
    DROP CONSTRAINT mail_group_key_shares_member_fingerprint_check,
    DROP COLUMN member_fingerprint,
    ADD COLUMN member_incarnation_id text NOT NULL
        CONSTRAINT mail_group_key_shares_member_incarnation_check
        CHECK (member_incarnation_id ~ '^[0-9a-f]{64}$');

-- The signers of a shared mailbox's key-list chain, in order: the first one
-- from list 1, each later one from the list its handover (signed by the one
-- before) starts at. A new chain (an administrator starting over) replaces
-- them all.
CREATE TABLE mail_group_signers (
    group_id      uuid NOT NULL REFERENCES mail_groups (id) ON DELETE CASCADE,
    from_sequence bigint NOT NULL CHECK (from_sequence >= 1),
    public_key    bytea NOT NULL CHECK (octet_length(public_key) = 32),
    -- `GroupSignerHandoverV1` bytes; none for the first signer.
    handover      bytea CHECK (octet_length(handover) = 154),
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, from_sequence),
    CHECK ((from_sequence = 1) = (handover IS NULL))
);

-- The current signer's seed, sealed to each owner and manager's account key.
CREATE TABLE mail_group_signing_shares (
    group_id              uuid NOT NULL REFERENCES mail_groups (id) ON DELETE CASCADE,
    signer_public_key     bytea NOT NULL CHECK (octet_length(signer_public_key) = 32),
    user_id               uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    share                 bytea NOT NULL CHECK (octet_length(share) BETWEEN 1 AND 1024),
    member_incarnation_id text NOT NULL CHECK (member_incarnation_id ~ '^[0-9a-f]{64}$'),
    created_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, signer_public_key, user_id)
);
CREATE INDEX mail_group_signing_shares_user ON mail_group_signing_shares (user_id);

-- Set when an owner or manager's account is deleted or deactivated: they may
-- still hold the signer's seed, so no list is published until a manager
-- hands over to a new signer (or an administrator starts a new chain).
ALTER TABLE mail_groups ADD COLUMN needs_new_signer boolean NOT NULL DEFAULT false;
