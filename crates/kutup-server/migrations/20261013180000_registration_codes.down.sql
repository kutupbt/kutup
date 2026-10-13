DELETE FROM server_generated_keys WHERE purpose = 'registration-codes';
ALTER TABLE server_generated_keys DROP CONSTRAINT server_generated_keys_purpose_check;
ALTER TABLE server_generated_keys ADD CONSTRAINT server_generated_keys_purpose_check
    CHECK (purpose = ANY (ARRAY['federation-identity', 'mls-control', 'mail-group-authority',
                                'fake-accounts']));
DROP TABLE IF EXISTS registration_code_uses;
DROP TABLE IF EXISTS registration_codes;
DELETE FROM site_settings WHERE key = 'registration_mode';
