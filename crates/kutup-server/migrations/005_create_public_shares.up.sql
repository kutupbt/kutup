-- V1 public links share one collection. A single-file link can be added later
-- as a distinct purpose/format instead of overloading this record.
-- CRITICAL: The linkKey (needed to decrypt collection_key_envelope) is NEVER
-- stored server-side. It lives only in the URL #fragment.
CREATE TABLE public_shares (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    share_type  TEXT NOT NULL CHECK (share_type = 'collection'),
    target_id   UUID NOT NULL,
    -- Token is random URL-safe string (no embedded key)
    token       TEXT NOT NULL UNIQUE,
    -- Purpose-tagged DriveEnvelopeV1 under linkKey. Public header binds the
    -- target collection, owner and exact authenticated collection epoch.
    collection_key_envelope TEXT NOT NULL,
    collection_key_epoch INTEGER NOT NULL CHECK (collection_key_epoch > 0),
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_public_shares_token ON public_shares(token);
