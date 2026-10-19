-- Mail forwarding, as Proton has it (docs/plans/mail-forwarding.md).

-- One forwarding of an address: end to end to a Kutup address on this
-- server (proxy re-encryption), or outside (re-sent, the address's
-- end-to-end encryption off while any is on).
CREATE TABLE mail_forwardings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The forwarder's account and address.
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    forwarder_address_id uuid NOT NULL REFERENCES mail_addresses(id) ON DELETE CASCADE,
    forwardee_email text NOT NULL CHECK (length(forwardee_email) BETWEEN 3 AND 320),
    -- End to end only: the forwardee's address on this server.
    forwardee_address_id uuid REFERENCES mail_addresses(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('end_to_end', 'outside')),
    state text NOT NULL CHECK (state IN ('pending', 'active', 'outdated', 'paused', 'rejected')),
    -- Conditions as mail filters have them (all/any of sender, subject,
    -- attachments); none forwards everything.
    match text NOT NULL DEFAULT 'all' CHECK (match IN ('all', 'any')),
    conditions jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(conditions) = 'array'),
    -- While pending: the activation (end to end) or the hash of the
    -- confirmation link's token (outside), and when either expires. Dropped
    -- at accept, decline and expiry.
    activation text CHECK (activation IS NULL OR length(activation) <= 65536),
    confirmation_hash bytea CHECK (confirmation_hash IS NULL OR octet_length(confirmation_hash) = 32),
    expires_at timestamptz,
    -- Messages that couldn't be forwarded (shown to the forwarder).
    skipped bigint NOT NULL DEFAULT 0 CHECK (skipped >= 0),
    -- The outside budget and bounces, per day.
    day date NOT NULL DEFAULT current_date,
    sent_today integer NOT NULL DEFAULT 0 CHECK (sent_today >= 0),
    bounces_today integer NOT NULL DEFAULT 0 CHECK (bounces_today >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((kind = 'end_to_end') = (forwardee_address_id IS NOT NULL)),
    UNIQUE (forwarder_address_id, forwardee_email)
);
CREATE INDEX mail_forwardings_user ON mail_forwardings (user_id);
CREATE INDEX mail_forwardings_forwardee ON mail_forwardings (forwardee_address_id)
    WHERE forwardee_address_id IS NOT NULL;

-- The proxy factors of an end-to-end forwarding, one per forwarder
-- encryption subkey. k with the forwardee's secret key gives the
-- forwarder's, so it is sealed under the server's MAIL_FORWARDING_KEY
-- (its version beside it, the AAD bound to the forwarding and both
-- fingerprints), never returned, and deleted whenever the forwarding stops
-- being able to resume.
CREATE TABLE mail_forwarding_keys (
    forwarding_id uuid NOT NULL REFERENCES mail_forwardings(id) ON DELETE CASCADE,
    forwarder_fingerprint character(40) NOT NULL CHECK (forwarder_fingerprint ~ '^[0-9a-f]{40}$'),
    forwardee_fingerprint character(40) NOT NULL CHECK (forwardee_fingerprint ~ '^[0-9a-f]{40}$'),
    forwardee_public_key bytea NOT NULL CHECK (octet_length(forwardee_public_key) BETWEEN 1 AND 16384),
    proxy_parameter_sealed bytea NOT NULL CHECK (octet_length(proxy_parameter_sealed) BETWEEN 1 AND 256),
    secret_version smallint NOT NULL CHECK (secret_version > 0),
    PRIMARY KEY (forwarding_id, forwarder_fingerprint)
);

-- A forwardee's forwarding key is an address key that is never primary,
-- never encrypted to and left out of the signed key list. It outlives its
-- forwarding (mail already forwarded needs it) until its owner deletes it.
ALTER TABLE mail_address_keys
    ADD COLUMN is_forwarding boolean NOT NULL DEFAULT false,
    ADD COLUMN forwarding_id uuid REFERENCES mail_forwardings(id) ON DELETE SET NULL,
    ADD CONSTRAINT mail_address_keys_forwarding_check
        CHECK (NOT is_forwarding OR NOT is_primary),
    ADD CONSTRAINT mail_address_keys_forwarding_id_check
        CHECK (forwarding_id IS NULL OR is_forwarding);

-- A copy that reached its mailbox by forwarding: opened only with the
-- forwarding key (Proton's FLAG_AUTO_FORWARDEE), never forwarded again.
ALTER TABLE mail_messages
    ADD COLUMN forwarded_from text CHECK (forwarded_from IS NULL OR length(forwarded_from) <= 320);

-- The address owes a new signed key list (the last outside forwarding ended
-- from the server's side; only the owner's client can sign one).
ALTER TABLE mail_addresses
    ADD COLUMN key_list_owed boolean NOT NULL DEFAULT false;
