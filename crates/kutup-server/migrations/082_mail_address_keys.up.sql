-- Mail address keys (docs/plans/mail-address-keys.md): each account's email
-- addresses, their OpenPGP keys (private parts only as master-key envelopes)
-- and each address's signed key list, Proton's model under the account
-- authority. Address rows are created on first use (`username@<server name>`
-- needs the configured server name), not here.

CREATE TABLE mail_addresses (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    address     TEXT NOT NULL UNIQUE CHECK (address = lower(address) AND length(address) BETWEEN 3 AND 320),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mail_addresses_user ON mail_addresses(user_id);

CREATE TABLE mail_address_keys (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address_id          UUID NOT NULL REFERENCES mail_addresses(id) ON DELETE CASCADE,
    fingerprint         CHAR(40) NOT NULL UNIQUE CHECK (fingerprint ~ '^[0-9a-f]{40}$'),
    sha256_fingerprint  CHAR(64) NOT NULL CHECK (sha256_fingerprint ~ '^[0-9a-f]{64}$'),
    public_key          BYTEA NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 16384),
    private_key_envelope BYTEA NOT NULL CHECK (octet_length(private_key_envelope) BETWEEN 1 AND 8192),
    is_primary          BOOLEAN NOT NULL,
    flags               INTEGER NOT NULL CHECK (flags BETWEEN 0 AND 15),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mail_address_keys_address ON mail_address_keys(address_id);
CREATE UNIQUE INDEX idx_mail_address_keys_one_primary ON mail_address_keys(address_id) WHERE is_primary;

-- Every signed key list an address has published, append-only; the highest
-- sequence is current. Readers verify the whole chain.
CREATE TABLE mail_key_lists (
    address_id  UUID NOT NULL REFERENCES mail_addresses(id) ON DELETE CASCADE,
    sequence    BIGINT NOT NULL CHECK (sequence >= 1),
    data        BYTEA NOT NULL CHECK (octet_length(data) BETWEEN 1 AND 8192),
    signature   BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (address_id, sequence)
);
