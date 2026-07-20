-- Additive persistence foundation for unified federation v2.
--
-- Phase B deliberately does not alter or drop the experimental v1 Chat policy,
-- Chat transaction, or Drive share tables. Their destructive replacements are
-- atomic with the Phase C and D runtime cut-overs respectively.

CREATE TABLE federation_local_identity_documents (
    sequence       BIGINT      PRIMARY KEY CHECK (sequence >= 0),
    document_hash  TEXT        NOT NULL UNIQUE
        CHECK (document_hash ~ '^[0-9a-f]{64}$'),
    key_id         TEXT        NOT NULL
        CHECK (key_id ~ '^[0-9a-f]{64}$'),
    document       JSONB       NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE federation_peer_identities (
    domain                    TEXT        PRIMARY KEY,
    trust_state               TEXT        NOT NULL
        CHECK (trust_state IN ('tofu', 'verified', 'quarantined')),
    current_sequence          BIGINT      NOT NULL CHECK (current_sequence >= 0),
    current_document_hash     TEXT        NOT NULL
        CHECK (current_document_hash ~ '^[0-9a-f]{64}$'),
    current_key_id            TEXT        NOT NULL
        CHECK (current_key_id ~ '^[0-9a-f]{64}$'),
    current_public_key        TEXT        NOT NULL,
    first_seen_at             TIMESTAMPTZ NOT NULL,
    last_seen_at              TIMESTAMPTZ NOT NULL,
    verified_at               TIMESTAMPTZ,
    quarantine_reason         TEXT,
    pending_document          JSONB,
    pending_identity_chain    JSONB,
    pending_document_hash     TEXT
        CHECK (pending_document_hash IS NULL OR pending_document_hash ~ '^[0-9a-f]{64}$'),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (domain = lower(domain)),
    CHECK (length(domain) BETWEEN 3 AND 253),
    CHECK (domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CHECK (current_public_key ~ '^[A-Za-z0-9+/]{43}=$'),
    CHECK (
        (trust_state = 'quarantined'
         AND quarantine_reason IS NOT NULL
         AND pending_document IS NOT NULL
         AND jsonb_typeof(pending_document) = 'object'
         AND pending_identity_chain IS NOT NULL
         AND jsonb_typeof(pending_identity_chain) = 'array'
         AND jsonb_array_length(pending_identity_chain) > 0
         AND pending_document_hash IS NOT NULL)
        OR
        (trust_state <> 'quarantined'
         AND quarantine_reason IS NULL
         AND pending_document IS NULL
         AND pending_identity_chain IS NULL
         AND pending_document_hash IS NULL)
    )
);

CREATE INDEX federation_peer_identities_state_updated_idx
    ON federation_peer_identities (trust_state, updated_at DESC);

-- A composite key preserves same-sequence conflicting evidence without
-- mutating or discarding the previously accepted immutable document. The
-- partial unique index still permits only one accepted document per sequence.
CREATE TABLE federation_peer_identity_documents (
    domain          TEXT        NOT NULL REFERENCES federation_peer_identities(domain)
                                ON DELETE CASCADE,
    sequence        BIGINT      NOT NULL CHECK (sequence >= 0),
    document_hash   TEXT        NOT NULL
        CHECK (document_hash ~ '^[0-9a-f]{64}$'),
    key_id          TEXT        NOT NULL
        CHECK (key_id ~ '^[0-9a-f]{64}$'),
    document        JSONB       NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    acceptance      TEXT        NOT NULL
        CHECK (acceptance IN ('accepted', 'quarantined', 'superseded')),
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (domain, sequence, document_hash)
);

CREATE UNIQUE INDEX federation_peer_identity_one_accepted_sequence_idx
    ON federation_peer_identity_documents (domain, sequence)
    WHERE acceptance = 'accepted';

CREATE INDEX federation_peer_identity_documents_history_idx
    ON federation_peer_identity_documents (domain, sequence DESC, recorded_at DESC);

CREATE TABLE federation_request_replays (
    origin          TEXT        NOT NULL,
    request_id      TEXT        NOT NULL,
    request_hash    TEXT        NOT NULL
        CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    first_seen_at   TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (origin, request_id),
    CHECK (origin = lower(origin)),
    CHECK (length(origin) BETWEEN 3 AND 253),
    CHECK (origin ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CHECK (length(request_id) BETWEEN 1 AND 128),
    CHECK (request_id ~ '^[A-Za-z0-9._~-]+$'),
    CHECK (expires_at > first_seen_at)
);

CREATE INDEX federation_request_replays_expiry_idx
    ON federation_request_replays (expires_at);

CREATE TABLE federation_policy (
    singleton      BOOLEAN     PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    global_enabled BOOLEAN     NOT NULL DEFAULT TRUE,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO federation_policy (singleton, global_enabled) VALUES (TRUE, TRUE);

CREATE TABLE federation_feature_policies (
    feature        TEXT        PRIMARY KEY CHECK (feature IN ('chat', 'drive')),
    mode           TEXT        NOT NULL DEFAULT 'allowlist'
        CHECK (mode IN ('disabled', 'allowlist', 'blocklist', 'open')),
    minimum_trust  TEXT        NOT NULL DEFAULT 'verified'
        CHECK (minimum_trust IN ('tofu', 'verified')),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO federation_feature_policies (feature, mode, minimum_trust)
VALUES ('chat', 'allowlist', 'verified'), ('drive', 'allowlist', 'verified');

CREATE TABLE federation_domain_rules (
    domain             TEXT        NOT NULL,
    feature            TEXT        NOT NULL REFERENCES federation_feature_policies(feature)
                                   ON DELETE CASCADE,
    inbound_action     TEXT        NOT NULL DEFAULT 'inherit'
        CHECK (inbound_action IN ('inherit', 'allow', 'block')),
    outbound_action    TEXT        NOT NULL DEFAULT 'inherit'
        CHECK (outbound_action IN ('inherit', 'allow', 'block')),
    trust_requirement  TEXT        NOT NULL DEFAULT 'inherit'
        CHECK (trust_requirement IN ('inherit', 'tofu', 'verified')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (domain, feature),
    CHECK (domain = lower(domain)),
    CHECK (length(domain) BETWEEN 3 AND 253),
    CHECK (domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
);

CREATE INDEX federation_domain_rules_updated_idx
    ON federation_domain_rules (updated_at DESC, domain, feature);
