-- Kutup Pass vault secrets (docs/plans/pass.md, "Vault secrets").
--
-- What opens a vault (a KeePass file in Drive), sealed by its user under
-- their master key (an account envelope with purpose PassVaultSecret, bound
-- to the vault's file id), so Kutup Pass and `kutup sync` unlock it with the
-- Kutup sign-in. One per person and vault; the server cannot read it.
CREATE TABLE pass_vault_secrets (
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_id    UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    envelope   BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, file_id)
);
CREATE INDEX pass_vault_secrets_file ON pass_vault_secrets (file_id);
