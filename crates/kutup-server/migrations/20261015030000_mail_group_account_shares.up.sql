-- Shared mailboxes' key shares sealed to each member's account key, not to
-- an address key (docs/plans/account-ids.md): a rename keeps them. Every
-- share made so far is deleted: they were sealed to address keys, a format
-- no client reads now (before the wipe; managers share again).
DELETE FROM mail_group_key_shares;
ALTER TABLE mail_group_key_shares
    DROP CONSTRAINT mail_group_key_shares_member_fingerprint_check,
    DROP COLUMN member_fingerprint,
    ADD COLUMN member_incarnation_id text NOT NULL
        CONSTRAINT mail_group_key_shares_member_incarnation_check
        CHECK (member_incarnation_id ~ '^[0-9a-f]{64}$');
