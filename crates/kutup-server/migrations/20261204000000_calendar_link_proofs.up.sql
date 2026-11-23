-- Calendar sharing, after its security review (docs/plans/calendar-e3.md,
-- "Review fixes"):
-- - a keyed link's secret is its owner's own envelope (sealed to the
--   owner's account key, of no key generation, and larger than the copy
--   sealed under a passphrase it replaces);
-- - a keyed link's page proves it holds the secret: the server keeps the
--   proof's SHA-256;
-- - a calendar whose key someone left with is marked for rotation;
-- - an invitation remembers when its invitee first read it.
-- No server ever served keyed links before this (E3 was not released), so
-- the ones a development database holds, which have neither, go.
DELETE FROM calendar_links WHERE kind <> 'busy';

ALTER TABLE calendar_links DROP COLUMN secret_key_generation;
ALTER TABLE calendar_links DROP CONSTRAINT calendar_links_secret_check;
ALTER TABLE calendar_links
    ADD CONSTRAINT calendar_links_secret_check
    CHECK (octet_length(secret) >= 1 AND octet_length(secret) <= 4096);
ALTER TABLE calendar_links ADD COLUMN access_proof_hash bytea;
ALTER TABLE calendar_links
    ADD CONSTRAINT calendar_links_access_proof_hash_check
    CHECK ((kind = 'busy') = (access_proof_hash IS NULL)
           AND (access_proof_hash IS NULL OR octet_length(access_proof_hash) = 32));

ALTER TABLE calendars ADD COLUMN rotation_due boolean DEFAULT false NOT NULL;

ALTER TABLE calendar_invitations ADD COLUMN fetched_at timestamp with time zone;
