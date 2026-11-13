ALTER TABLE account_security_events DROP COLUMN client_sealed;
ALTER TABLE account_security_events ADD COLUMN acting_user_agent text;
ALTER TABLE auth_sessions DROP COLUMN client_sealed;
ALTER TABLE auth_sessions ADD COLUMN user_agent text CHECK (char_length(user_agent) <= 512);
