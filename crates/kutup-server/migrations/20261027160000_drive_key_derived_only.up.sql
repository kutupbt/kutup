-- The Drive X-Wing private key is derived from the master key and never
-- stored (docs/plans/w6-key-hierarchy.md §1): its account envelope
-- (purpose 3) goes. Accounts from before the wipe don't carry over.
ALTER TABLE users DROP COLUMN drive_private_key_envelope;
