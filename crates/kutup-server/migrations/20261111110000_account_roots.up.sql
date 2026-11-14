-- The account's stored roots (docs/plans/identity-root.md): five random
-- secrets, each an account record sealed under the master key, so a new
-- master key changes nothing a peer sees. Purposes: 22 identity root and
-- 23 Drive root (one record per generation, the generation the object, u32
-- big-endian; every generation kept), 24 group pseudonym root, 25 call-link
-- root, 26 object-id key (one each, no object). Written at sign-up, at an
-- administrator-made account's setup and after a reset; the server only
-- adds rows (a master-key rotation re-wraps them in one transaction).
CREATE TABLE account_roots (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose smallint NOT NULL CHECK (purpose BETWEEN 22 AND 26),
    object bytea NOT NULL DEFAULT '',
    envelope bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, purpose, object),
    CHECK ((purpose IN (22, 23)) = (octet_length(object) = 4))
);
