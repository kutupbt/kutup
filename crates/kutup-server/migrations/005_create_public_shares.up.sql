-- share_type: 'collection' or 'file'
-- CRITICAL: The linkKey (needed to decrypt the encryptedCollectionKey) is NEVER
-- stored server-side. It lives only in the URL #fragment.
CREATE TABLE public_shares (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    share_type  TEXT NOT NULL CHECK (share_type IN ('collection', 'file')),
    target_id   UUID NOT NULL,
    -- Token is random URL-safe string (no embedded key)
    token       TEXT NOT NULL UNIQUE,
    -- Collection key encrypted with linkKey. Server stores this but cannot
    -- decrypt it without the linkKey (which is only in the URL fragment).
    encrypted_collection_key TEXT,
    encrypted_collection_key_nonce TEXT,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_public_shares_token ON public_shares(token);
