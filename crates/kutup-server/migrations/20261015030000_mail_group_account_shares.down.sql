DROP TABLE mail_group_signing_shares;
DROP TABLE mail_group_signers;
DELETE FROM mail_group_key_shares;
DELETE FROM mail_group_key_lists;
DELETE FROM mail_group_keys;
ALTER TABLE mail_group_key_shares
    DROP CONSTRAINT mail_group_key_shares_member_incarnation_check,
    DROP COLUMN member_incarnation_id,
    ADD COLUMN member_fingerprint character(40) NOT NULL
        CONSTRAINT mail_group_key_shares_member_fingerprint_check
        CHECK (member_fingerprint ~ '^[0-9a-f]{40}$');
ALTER TABLE server_generated_keys DROP CONSTRAINT server_generated_keys_purpose_check;
ALTER TABLE server_generated_keys ADD CONSTRAINT server_generated_keys_purpose_check
    CHECK (purpose = ANY (ARRAY['federation-identity', 'mls-control', 'mail-group-authority',
                                'fake-accounts', 'registration-codes']));
