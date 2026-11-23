ALTER TABLE calendar_invitations DROP COLUMN fetched_at;

ALTER TABLE calendars DROP COLUMN rotation_due;

DELETE FROM calendar_links WHERE kind <> 'busy';
ALTER TABLE calendar_links DROP CONSTRAINT calendar_links_access_proof_hash_check;
ALTER TABLE calendar_links DROP COLUMN access_proof_hash;
ALTER TABLE calendar_links DROP CONSTRAINT calendar_links_secret_check;
ALTER TABLE calendar_links
    ADD CONSTRAINT calendar_links_secret_check
    CHECK (octet_length(secret) >= 1 AND octet_length(secret) <= 256);
ALTER TABLE calendar_links ADD COLUMN secret_key_generation integer;
ALTER TABLE calendar_links
    ADD CONSTRAINT calendar_links_check1
    CHECK ((secret IS NULL) = (secret_key_generation IS NULL));
