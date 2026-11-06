ALTER TABLE users DROP COLUMN totp_secret_sealed;
ALTER TABLE users ADD COLUMN totp_secret text;
DROP TABLE account_keys.account_data_keys;
DROP SCHEMA account_keys;
