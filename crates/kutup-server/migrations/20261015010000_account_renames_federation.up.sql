-- Username renames across servers (docs/plans/username-renames.md, R2): the
-- chains this server has verified for other servers' accounts, and the
-- announces of its own accounts' renames still to be sent.

-- One verified chain per remote account incarnation: from an announce, a
-- chain lookup, or a peer's `409 renamed`. Kept only for the domain that
-- signed it (every address in the chain is on that domain).
CREATE TABLE remote_account_renames (
    domain               text NOT NULL CHECK (domain = lower(domain)),
    incarnation_id       char(64) NOT NULL CHECK (incarnation_id ~ '^[0-9a-f]{64}$'),
    authority_public_key text NOT NULL,
    sequence             integer NOT NULL CHECK (sequence BETWEEN 1 AND 1000),
    head_digest          bytea NOT NULL CHECK (octet_length(head_digest) = 32),
    -- The chain's last `current`, `username@domain`.
    current_address      text NOT NULL,
    -- What the peer said of it: current, held or gone.
    state                text NOT NULL CHECK (state IN ('current', 'held', 'gone')),
    chain                jsonb NOT NULL,
    -- Every address the chain names, folded: what lookups by address find.
    addresses            text[] NOT NULL,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (domain, incarnation_id)
);
CREATE INDEX remote_account_renames_addresses ON remote_account_renames
    USING gin (addresses);

-- One row per peer and statement, written in the rename's transaction.
CREATE TABLE rename_announce_outbox (
    destination     text NOT NULL,
    incarnation_id  char(64) NOT NULL CHECK (incarnation_id ~ '^[0-9a-f]{64}$'),
    sequence        integer NOT NULL CHECK (sequence BETWEEN 1 AND 1000),
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_error      text,
    PRIMARY KEY (destination, incarnation_id, sequence)
);
CREATE INDEX rename_announce_outbox_due ON rename_announce_outbox (next_attempt_at);
