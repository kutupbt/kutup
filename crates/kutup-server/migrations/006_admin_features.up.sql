ALTER TABLE users ADD COLUMN is_first_login BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE site_settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO site_settings (key, value) VALUES ('registration_enabled', 'true');
