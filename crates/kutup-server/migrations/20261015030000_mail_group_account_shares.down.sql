DELETE FROM mail_group_key_shares;
ALTER TABLE mail_group_key_shares
    DROP CONSTRAINT mail_group_key_shares_member_incarnation_check,
    DROP COLUMN member_incarnation_id,
    ADD COLUMN member_fingerprint character(40) NOT NULL
        CONSTRAINT mail_group_key_shares_member_fingerprint_check
        CHECK (member_fingerprint ~ '^[0-9a-f]{40}$');
