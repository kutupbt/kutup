DROP INDEX files_ciphertext_digest_backfill_idx;
ALTER TABLE files DROP COLUMN ciphertext_sha256;

DROP TABLE drive_federation_mutations;
DROP TABLE federated_incoming_shares;
DROP TABLE federated_outgoing_shares;

-- Schema-only rollback for the removed experimental Drive federation
-- protocol. Its bearer capabilities and raw remote URLs were intentionally
-- destroyed by the forward migration and cannot be reconstructed.
CREATE TABLE federated_outgoing_shares (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id            UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    sharer_user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_username       TEXT NOT NULL,
    recipient_server         TEXT NOT NULL,
    encrypted_collection_key TEXT NOT NULL,
    access_token             TEXT UNIQUE NOT NULL,
    can_upload               BOOLEAN NOT NULL DEFAULT false,
    can_delete               BOOLEAN NOT NULL DEFAULT false,
    upload_quota_bytes       BIGINT,
    upload_used_bytes        BIGINT NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE federated_incoming_shares (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    remote_server            TEXT NOT NULL,
    remote_access_token      TEXT NOT NULL,
    encrypted_collection_key TEXT NOT NULL,
    encrypted_name           TEXT NOT NULL,
    name_nonce               TEXT NOT NULL,
    can_upload               BOOLEAN NOT NULL DEFAULT false,
    can_delete               BOOLEAN NOT NULL DEFAULT false,
    upload_quota_bytes       BIGINT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, remote_server, remote_access_token)
);
