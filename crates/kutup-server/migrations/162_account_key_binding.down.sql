DELETE FROM server_generated_keys WHERE purpose = 'fake-accounts';
ALTER TABLE server_generated_keys DROP CONSTRAINT server_generated_keys_purpose_check;
ALTER TABLE server_generated_keys ADD CONSTRAINT server_generated_keys_purpose_check
    CHECK (purpose IN ('federation-identity', 'mls-control', 'mail-group-authority'));
ALTER TABLE users DROP COLUMN key_binding;
