ALTER TABLE users ADD COLUMN username TEXT;
UPDATE users SET username = split_part(email, '@', 1) || '_' || substr(id::text, 1, 4);
ALTER TABLE users ALTER COLUMN username SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_username_unique UNIQUE (username);
ALTER TABLE users ADD CONSTRAINT users_username_format
  CHECK (username ~ '^[a-z0-9_-]{3,32}$');
CREATE INDEX idx_users_username ON users(username);
