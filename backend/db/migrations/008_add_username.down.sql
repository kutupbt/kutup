DROP INDEX IF EXISTS idx_users_username;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_format;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_unique;
ALTER TABLE users DROP COLUMN IF EXISTS username;
