-- Administrator-managed operational admission policy for chat federation.
--
-- Existing deployments were implicitly open before this migration, so a
-- database that already has users retains `open` to preserve connectivity.
-- A fresh database has no users at migration time and starts in the safer
-- `allowlist` mode.
CREATE TABLE chat_federation_policy (
    singleton  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    mode       TEXT NOT NULL DEFAULT 'open'
        CHECK (mode IN ('disabled', 'allowlist', 'blocklist', 'open')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO chat_federation_policy (singleton, mode)
SELECT TRUE, CASE WHEN EXISTS (SELECT 1 FROM users) THEN 'open' ELSE 'allowlist' END;

-- Directional rules survive mode changes. `inherit` means the active mode's
-- default: deny in allowlist mode and allow in blocklist mode. Open mode
-- deliberately ignores rules, keeping it semantically distinct from blocklist.
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
