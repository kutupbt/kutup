-- Calendar keys on account-level keys (docs/plans/wipe-unification.md, W4).
-- A calendar's passphrase was a data packet and the owner's address-key
-- signature on the calendar, and a key packet to each member's address key
-- on the member's row: a rename or a removed address orphaned the member,
-- and nothing of it was post-quantum. Now each member's row holds a share
-- (`CalendarShareEnvelopeV1`): the passphrase sealed with X-Wing to the
-- member's account key and signed by the owner's account signing key,
-- bound to the calendar, its key generation and both accounts by id and
-- incarnation. The owner's own copy is a share to itself. Members no longer
-- name an address; events and the sealed name stay signed by address keys.
--
-- No passphrase can be converted on the server, so the calendars made
-- before go (kutup.dev is wiped with this release); the quota reconciler
-- gives their owners the storage back, as only `storage_pool` charges.
DELETE FROM calendars;

ALTER TABLE calendars
    DROP COLUMN passphrase_data_packet,
    DROP COLUMN passphrase_signature,
    -- The calendar key's generation: every share names the one it unlocks.
    -- A new key (E3, when a member is removed) takes the next.
    ADD COLUMN key_generation integer NOT NULL CHECK (key_generation >= 1);

ALTER TABLE calendar_members
    DROP COLUMN address_id,
    DROP COLUMN passphrase_key_packet,
    -- The member's share of the passphrase (an X-Wing encapsulation, two
    -- accounts with their servers, a signature).
    ADD COLUMN passphrase_share bytea NOT NULL
        CHECK (octet_length(passphrase_share) BETWEEN 1 AND 2048);
