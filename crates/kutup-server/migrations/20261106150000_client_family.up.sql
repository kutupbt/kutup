-- Sessions and security events keep the browser family, never the raw
-- User-Agent (docs/plans/server-personal-data.md, A10, slice L3): parsed once
-- ("Firefox 128 on Linux"), sealed under the account's data key, bound to its
-- row (kutup_crypto::server_data).
ALTER TABLE auth_sessions DROP COLUMN user_agent;
ALTER TABLE auth_sessions ADD COLUMN client_sealed bytea
    CHECK (client_sealed IS NULL OR octet_length(client_sealed) BETWEEN 47 AND 512);
ALTER TABLE account_security_events DROP COLUMN acting_user_agent;
ALTER TABLE account_security_events ADD COLUMN client_sealed bytea
    CHECK (client_sealed IS NULL OR octet_length(client_sealed) BETWEEN 47 AND 512);
