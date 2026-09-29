-- Online signing keys a server makes for itself when its operator configures
-- none (docs/self-hosting.md, "Chat groups"): its federation identity key and
-- its MLS ordering control key. Made once; every instance uses the stored
-- copy. Configured keys (FEDERATION_SIGNING_KEY, CHAT_MLS_CONTROL_SIGNING_KEY)
-- take precedence and are never written here.
CREATE TABLE server_generated_keys (
    purpose     TEXT        PRIMARY KEY CHECK (purpose IN ('federation-identity', 'mls-control')),
    private_key BYTEA       NOT NULL CHECK (octet_length(private_key) = 32),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
