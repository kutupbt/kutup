-- Pass vault secrets move to the account-records store (docs/plans/
-- account-records.md, slice 3): the scope `passSecrets`, keyed by the vault's
-- file id. No data moves (the wipe).
DROP TABLE pass_vault_secrets;
