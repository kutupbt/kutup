DELETE FROM server_generated_keys WHERE purpose = 'registration-codes';
ALTER TABLE server_generated_keys DROP CONSTRAINT server_generated_keys_purpose_check;
ALTER TABLE server_generated_keys ADD CONSTRAINT server_generated_keys_purpose_check
    CHECK (purpose = ANY (ARRAY['federation-identity', 'mls-control', 'mail-group-authority',
                                'fake-accounts']));
DROP TABLE IF EXISTS registration_code_uses;
DROP TABLE IF EXISTS registration_codes;
-- Back to the open/closed switch: open only if the mode was `on`; `code`
-- and `off` (and no mode at all) close registration rather than open it.
INSERT INTO site_settings (key, value)
SELECT 'registration_enabled',
       CASE WHEN (SELECT value FROM site_settings WHERE key = 'registration_mode') = 'on'
            THEN 'true' ELSE 'false' END
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
DELETE FROM site_settings WHERE key = 'registration_mode';
