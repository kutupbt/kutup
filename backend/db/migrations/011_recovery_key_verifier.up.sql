-- Stores a bcrypt hash of the recovery key entropy submitted at registration time.
-- Used to verify mnemonic possession during account recovery (S1-2 fix).
-- Empty string for accounts created before this migration — those accounts allow
-- recovery without proof (backward compat); new accounts always require proof.
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_key_verifier TEXT NOT NULL DEFAULT '';
