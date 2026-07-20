ALTER TABLE federation_peer_identities
    DROP COLUMN last_discovery_error,
    DROP COLUMN discovery_expires_at,
    DROP COLUMN capabilities,
    DROP COLUMN current_api_base;

-- Schema-only rollback for the removed experimental policy control plane.
-- Destructive v1 transport rows cannot be reconstructed and intentionally stay
-- empty; local product data was never deleted by the forward migration.
CREATE TABLE chat_federation_policy (
    singleton  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    mode       TEXT NOT NULL DEFAULT 'allowlist'
        CHECK (mode IN ('disabled', 'allowlist', 'blocklist', 'open')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO chat_federation_policy (singleton, mode) VALUES (TRUE, 'allowlist');

CREATE TABLE chat_federation_domain_rules (
    domain          TEXT PRIMARY KEY,
    inbound_action  TEXT NOT NULL DEFAULT 'inherit'
        CHECK (inbound_action IN ('inherit', 'allow', 'block')),
    outbound_action TEXT NOT NULL DEFAULT 'inherit'
        CHECK (outbound_action IN ('inherit', 'allow', 'block')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (domain = lower(domain)),
    CHECK (length(domain) BETWEEN 1 AND 253)
);
CREATE INDEX chat_federation_domain_rules_updated_idx
    ON chat_federation_domain_rules (updated_at DESC);
