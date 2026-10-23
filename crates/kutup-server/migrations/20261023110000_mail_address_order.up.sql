-- An account's addresses in the order it chooses, and disabled addresses
-- (Proton's address Order and Status; docs/plans/mail-custom-domains.md §5).
-- The first enabled current address with a key is the default: it sends when
-- a message names no From, and the composer offers it first.
ALTER TABLE mail_addresses
    ADD COLUMN position integer NOT NULL DEFAULT 0,
    -- Disabled (Proton's Status 0): it neither receives nor sends, its keys
    -- are no longer offered to senders, and they keep opening the mail it
    -- already received.
    ADD COLUMN disabled_at timestamptz,
    -- Deleted by its account (Proton's Delete address), not freed by a
    -- domain lost: taking it back would have to continue its key chain.
    ADD COLUMN deleted_at timestamptz;

-- Today's order: the account's own address first, then its addresses on
-- custom domains as they were made.
UPDATE mail_addresses a SET position = o.position
  FROM (SELECT id,
               row_number() OVER (PARTITION BY user_id
                                  ORDER BY domain_id IS NOT NULL, created_at) - 1 AS position
          FROM mail_addresses WHERE user_id IS NOT NULL) o
 WHERE a.id = o.id;
