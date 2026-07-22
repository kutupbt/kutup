-- Atomic Phase C cut-over from the experimental Chat-only federation v1
-- transport to the shared federation v2 identity, trust, policy, and replay
-- stack. There is no mixed-replica or v1 fallback window.

-- These rows are authenticated by the removed v1 scheme. Local users,
-- devices, profiles, keys, conversations, and mailbox data are deliberately
-- untouched; only server-to-server transport state is reset.
DELETE FROM chat_federation_inbound_transactions;
DELETE FROM chat_federation_inbound_state;
DELETE FROM chat_federation_outbox;
DELETE FROM chat_federation_sequences;

DROP TABLE chat_federation_domain_rules;
DROP TABLE chat_federation_policy;

-- Persist only authenticated discovery metadata. The identity key/history and
-- operator trust state remain in their dedicated immutable Phase B columns.
ALTER TABLE federation_peer_identities
    ADD COLUMN current_api_base TEXT,
    ADD COLUMN capabilities JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(capabilities) = 'array'),
    ADD COLUMN discovery_expires_at TIMESTAMPTZ,
    ADD COLUMN last_discovery_error TEXT;
