-- The account head chain (docs/plans/rollback-protection.md): each head
-- sealed by the account's clients, kept by sequence; the server reads only
-- the sequence (kutup_crypto::account_head::inspect) and keeps the newest
-- RETENTION (1,000). A new incarnation (a wipe) starts a new chain.
CREATE TABLE account_heads (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    sealed bytea NOT NULL CHECK (octet_length(sealed) BETWEEN 1 AND 16384),
    written_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, sequence)
);

-- A Pass vault secret is a listed value: it goes only when its owner forgets
-- it, under a head, never with its vault's file (a purge would drop it with
-- no head). It stays listed in the passSecrets index until then.
ALTER TABLE pass_vault_secrets DROP CONSTRAINT pass_vault_secrets_file_id_fkey;

-- A custom folder kept through an account reset (its messages stay) loses its
-- name with the old keys: null until its owner names it again (from revision
-- 0, under a head); left out of the mailNames index meanwhile.
ALTER TABLE mail_folders ALTER COLUMN name_sealed DROP NOT NULL;
