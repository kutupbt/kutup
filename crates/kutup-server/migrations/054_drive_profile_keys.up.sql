-- Profile keys people hand each other through Drive shares
-- (docs/plans/unified-profile.md). Each row is one person's end of one pair:
-- the key they sent to someone ('sent', kept to know when it is stale) or the
-- key someone sent them ('received'). The envelope is HPKE-sealed to the
-- recipient and signed by the sender; the server only stores and forwards it.
CREATE TABLE drive_profile_keys (
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    direction        TEXT NOT NULL CHECK (direction IN ('sent', 'received')),
    peer_account     TEXT NOT NULL CHECK (length(peer_account) BETWEEN 3 AND 320),
    envelope         TEXT NOT NULL CHECK (length(envelope) <= 2048),
    profile_version  TEXT NOT NULL CHECK (profile_version ~ '^[0-9a-f]{64}$'),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, direction, peer_account)
);
