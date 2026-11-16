-- The account's stored roots (docs/plans/identity-root.md): five random
-- secrets, each an account record sealed under the master key, so a new
-- master key changes nothing a peer sees. Purposes: 22 identity root,
-- 23 Drive root, 24 group pseudonym root, 25 call-link root, 26 object-id
-- key; each one record per generation (the object, u32 big-endian), every
-- generation kept. Written at sign-up, at an administrator-made account's
-- setup and after a reset; the server only adds rows (a master-key rotation
-- re-wraps them in one transaction).
CREATE TABLE account_roots (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose smallint NOT NULL CHECK (purpose BETWEEN 22 AND 26),
    object bytea NOT NULL,
    envelope bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, purpose, object),
    -- Every root's object is its generation, u32 big-endian.
    CHECK (octet_length(object) = 4)
);
