-- Atomic Phase D cut-over from the experimental unsigned Drive federation
-- protocol to the shared federation v2 identity, discovery, trust, policy,
-- replay, and signed transport stack. Kutup has no live federation deployment,
-- so the old bearer-in-path rows are deliberately discarded rather than
-- migrated into a weaker compatibility mode.

DROP TABLE federated_incoming_shares;
DROP TABLE federated_outgoing_shares;

-- The sharer's server stores only a verifier for the per-share capability.
-- Every capability use is also bound to the authenticated recipient domain.
CREATE TABLE federated_outgoing_shares (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id            UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    sharer_user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_username       TEXT NOT NULL,
    recipient_domain         TEXT NOT NULL,
    encrypted_collection_key TEXT NOT NULL,
    capability_hash          TEXT NOT NULL UNIQUE
        CHECK (capability_hash ~ '^[0-9a-f]{64}$'),
    can_upload               BOOLEAN NOT NULL DEFAULT false,
    can_delete               BOOLEAN NOT NULL DEFAULT false,
    upload_quota_bytes       BIGINT CHECK (upload_quota_bytes IS NULL OR upload_quota_bytes >= 0),
    upload_used_bytes        BIGINT NOT NULL DEFAULT 0 CHECK (upload_used_bytes >= 0),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (recipient_username ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    CHECK (recipient_domain = lower(recipient_domain)),
    CHECK (length(recipient_domain) BETWEEN 3 AND 253),
    CHECK (recipient_domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
);

CREATE INDEX federated_outgoing_shares_recipient_domain_idx
    ON federated_outgoing_shares (recipient_domain, created_at DESC);

-- The recipient server must retain the capability to exercise the remote
-- share, but stores only the canonical identity domain rather than a URL or
-- delegated API base. The duplicate verifier supports indexed de-duplication
-- without putting the secret itself in an index.
CREATE TABLE federated_incoming_shares (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    remote_domain            TEXT NOT NULL,
    remote_capability        TEXT NOT NULL,
    capability_hash          TEXT NOT NULL CHECK (capability_hash ~ '^[0-9a-f]{64}$'),
    encrypted_collection_key TEXT NOT NULL,
    encrypted_name           TEXT NOT NULL,
    name_nonce               TEXT NOT NULL,
    can_upload               BOOLEAN NOT NULL DEFAULT false,
    can_delete               BOOLEAN NOT NULL DEFAULT false,
    upload_quota_bytes       BIGINT CHECK (upload_quota_bytes IS NULL OR upload_quota_bytes >= 0),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, remote_domain, capability_hash),
    CHECK (remote_domain = lower(remote_domain)),
    CHECK (length(remote_domain) BETWEEN 3 AND 253),
    CHECK (remote_domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CHECK (length(remote_capability) BETWEEN 32 AND 256),
    CHECK (remote_capability ~ '^[A-Za-z0-9._~-]+$')
);

CREATE INDEX federated_incoming_shares_remote_domain_idx
    ON federated_incoming_shares (remote_domain, created_at DESC);

-- Shared replay reservation is short-lived transport protection. Mutating
-- Drive operations additionally retain their exact result for the lifetime of
-- the share so an uncertain retry cannot upload or delete twice.
CREATE TABLE drive_federation_mutations (
    origin                TEXT NOT NULL,
    request_id            TEXT NOT NULL,
    request_hash          TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    share_id              UUID NOT NULL REFERENCES federated_outgoing_shares(id) ON DELETE CASCADE,
    operation             TEXT NOT NULL CHECK (operation IN ('upload', 'delete')),
    response_status       SMALLINT NOT NULL CHECK (response_status BETWEEN 100 AND 599),
    response_content_type TEXT NOT NULL,
    response_body         BYTEA NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (origin, request_id),
    CHECK (origin = lower(origin)),
    CHECK (length(origin) BETWEEN 3 AND 253),
    CHECK (origin ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CHECK (length(request_id) BETWEEN 1 AND 128),
    CHECK (request_id ~ '^[A-Za-z0-9._~-]+$')
);

CREATE INDEX drive_federation_mutations_share_created_idx
    ON drive_federation_mutations (share_id, created_at DESC);

-- SHA-256 covers the exact encrypted object bytes. Existing objects are
-- backfilled independently and remain readable locally while their digest is
-- absent; federation never signs an unverified placeholder digest.
ALTER TABLE files
    ADD COLUMN ciphertext_sha256 TEXT
        CHECK (ciphertext_sha256 IS NULL OR ciphertext_sha256 ~ '^[0-9a-f]{64}$');

CREATE INDEX files_ciphertext_digest_backfill_idx
    ON files (created_at, id) WHERE ciphertext_sha256 IS NULL AND deleted_at IS NULL;
