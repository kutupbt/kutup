-- Sealed-sender certificates a server provisions for itself when its
-- operator configures no offline root (docs/self-hosting.md, "Contacts-only
-- sealed sender"). Each row is one cycle: a root made in memory, used once to
-- sign an online certificate, and dropped; only its public key is kept here,
-- never its private key. The online private key is kept while the
-- certificate can issue and wiped once it expires; the row stays, so the
-- server can tell its own roots from an operator's.
CREATE TABLE sealed_sender_generated_certificates (
    certificate_id     BIGINT      PRIMARY KEY CHECK (certificate_id > 0 AND certificate_id <= 4294967295),
    root_id            TEXT        NOT NULL UNIQUE CHECK (root_id ~ '^[0-9a-f]{64}$'),
    root_public_key    TEXT        NOT NULL,
    certificate        TEXT        NOT NULL,
    online_private_key BYTEA       CHECK (octet_length(online_private_key) = 32),
    -- Unix seconds: when the root was published, when the certificate starts
    -- and stops issuing.
    published_at       BIGINT      NOT NULL,
    activates_at       BIGINT      NOT NULL CHECK (activates_at >= published_at),
    expires_at         BIGINT      NOT NULL CHECK (expires_at > activates_at),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
