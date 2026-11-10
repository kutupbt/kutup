-- The secrets are gone with their sealed column: two-step sign-in by the
-- authenticator app is off for every account.
UPDATE users SET totp_enabled = false WHERE totp_enabled;
ALTER TABLE users DROP COLUMN totp_secret_sealed;
ALTER TABLE users ADD COLUMN totp_secret text;
DROP TABLE account_keys.account_data_keys;
DROP SCHEMA account_keys;
