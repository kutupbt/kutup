-- Always-on continuous E2EE Chat history. The server stores only typed account
-- envelopes, signed public manifests, opaque ciphertext, ordering metadata and
-- byte accounting. It never stores archive plaintext or conversation metadata.

ALTER TABLE users
    ADD COLUMN chat_storage_quota_bytes BIGINT NOT NULL DEFAULT 2147483648
        CHECK (chat_storage_quota_bytes > 0),
    ADD COLUMN chat_storage_used_bytes BIGINT NOT NULL DEFAULT 0
        CHECK (chat_storage_used_bytes >= 0);

-- Existing Chat-media becomes part of the dedicated Chat quota rather than
-- remaining charged to Drive/general storage.
WITH chat_usage AS (
    SELECT user_id, COALESCE(SUM(logical_bytes), 0)::BIGINT AS bytes
    FROM chat_media_references
    GROUP BY user_id
)
UPDATE users
SET chat_storage_used_bytes = chat_usage.bytes,
    storage_used_bytes = GREATEST(0, storage_used_bytes - chat_usage.bytes)
FROM chat_usage
WHERE users.id = chat_usage.user_id;

INSERT INTO site_settings(key, value)
VALUES ('default_chat_storage_quota_bytes', '2147483648')
ON CONFLICT (key) DO NOTHING;

CREATE TABLE chat_backups (
    user_id                       UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    backup_incarnation_id         UUID NOT NULL UNIQUE,
    suite                         SMALLINT NOT NULL CHECK (suite = 1),
    protection_domain             SMALLINT NOT NULL CHECK (protection_domain = 1),
    root_envelope                 TEXT NOT NULL,
    signer_authorization          JSONB NOT NULL CHECK (jsonb_typeof(signer_authorization) = 'object'),
    signer_authorization_digest   CHAR(64) NOT NULL CHECK (signer_authorization_digest ~ '^[0-9a-f]{64}$'),
    current_cursor                BIGINT NOT NULL DEFAULT 0 CHECK (current_cursor >= 0),
    current_generation            BIGINT NOT NULL DEFAULT 0 CHECK (current_generation >= 0),
    current_manifest_digest       CHAR(64) NOT NULL DEFAULT repeat('0', 64)
                                      CHECK (current_manifest_digest ~ '^[0-9a-f]{64}$'),
    current_manifest              JSONB CHECK (current_manifest IS NULL OR jsonb_typeof(current_manifest) = 'object'),
    current_base_object_id        UUID,
    latest_protected_at           TIMESTAMPTZ,
    provisioned_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (current_generation = 0 AND current_manifest IS NULL AND current_base_object_id IS NULL)
        OR
        (current_generation > 0 AND current_manifest IS NOT NULL AND current_base_object_id IS NOT NULL)
    )
);

CREATE TABLE chat_backup_provision_operations (
    user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    operation_id         UUID NOT NULL,
    request_digest       CHAR(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    backup_incarnation_id UUID NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, operation_id)
);

CREATE TABLE chat_backup_segments (
    user_id                 UUID NOT NULL REFERENCES chat_backups(user_id) ON DELETE CASCADE,
    cursor                  BIGINT NOT NULL CHECK (cursor > 0),
    operation_id            UUID NOT NULL,
    source_device_id        INT NOT NULL CHECK (source_device_id > 0),
    device_sequence         BIGINT NOT NULL CHECK (device_sequence > 0),
    previous_segment_digest CHAR(64) NOT NULL CHECK (previous_segment_digest ~ '^[0-9a-f]{64}$'),
    account_manifest_sequence BIGINT NOT NULL CHECK (account_manifest_sequence > 0),
    ciphertext_bytes        INT NOT NULL CHECK (ciphertext_bytes > 0 AND ciphertext_bytes <= 263168),
    ciphertext_sha256       CHAR(64) NOT NULL CHECK (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
    ciphertext              BYTEA NOT NULL,
    acknowledged_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, cursor),
    UNIQUE (user_id, operation_id),
    UNIQUE (user_id, source_device_id, device_sequence),
    CHECK (octet_length(ciphertext) = ciphertext_bytes)
);

CREATE INDEX chat_backup_segments_restore_idx
    ON chat_backup_segments(user_id, cursor);

CREATE TABLE chat_backup_device_heads (
    user_id                 UUID NOT NULL REFERENCES chat_backups(user_id) ON DELETE CASCADE,
    source_device_id        INT NOT NULL CHECK (source_device_id > 0),
    last_device_sequence    BIGINT NOT NULL CHECK (last_device_sequence > 0),
    last_segment_digest     CHAR(64) NOT NULL CHECK (last_segment_digest ~ '^[0-9a-f]{64}$'),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, source_device_id)
);

CREATE TABLE chat_backup_bases (
    user_id                 UUID NOT NULL REFERENCES chat_backups(user_id) ON DELETE CASCADE,
    object_id               UUID NOT NULL,
    generation              BIGINT NOT NULL CHECK (generation > 0),
    covered_cursor          BIGINT NOT NULL CHECK (covered_cursor >= 0),
    ciphertext_bytes        BIGINT NOT NULL CHECK (ciphertext_bytes > 0 AND ciphertext_bytes <= 134218752),
    ciphertext_sha256       CHAR(64) NOT NULL CHECK (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
    storage_path            TEXT NOT NULL UNIQUE,
    state                   TEXT NOT NULL DEFAULT 'staged' CHECK (state IN ('staged', 'committed')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    committed_at            TIMESTAMPTZ,
    PRIMARY KEY (user_id, object_id),
    UNIQUE (user_id, generation)
);

CREATE INDEX chat_backup_bases_staging_idx
    ON chat_backup_bases(state, created_at);

CREATE TABLE chat_backup_media_objects (
    user_id                 UUID NOT NULL REFERENCES chat_backups(user_id) ON DELETE CASCADE,
    media_id                BYTEA NOT NULL CHECK (octet_length(media_id) = 32),
    ciphertext_bytes        BIGINT NOT NULL CHECK (ciphertext_bytes > 0),
    ciphertext_sha256       CHAR(64) NOT NULL CHECK (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
    storage_path            TEXT NOT NULL UNIQUE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, media_id)
);

CREATE TABLE chat_backup_media_references (
    user_id                 UUID NOT NULL REFERENCES chat_backups(user_id) ON DELETE CASCADE,
    media_id                BYTEA NOT NULL,
    reference_id            UUID NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, reference_id),
    FOREIGN KEY (user_id, media_id)
        REFERENCES chat_backup_media_objects(user_id, media_id) ON DELETE CASCADE
);

CREATE TABLE chat_backup_media_operations (
    user_id          UUID NOT NULL REFERENCES chat_backups(user_id) ON DELETE CASCADE,
    operation_id     UUID NOT NULL,
    request_digest   CHAR(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    media_id         BYTEA NOT NULL CHECK (octet_length(media_id) = 32),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, operation_id),
    FOREIGN KEY (user_id, media_id)
        REFERENCES chat_backup_media_objects(user_id, media_id) ON DELETE CASCADE
);

CREATE TABLE chat_backup_media_reconciliations (
    user_id          UUID NOT NULL REFERENCES chat_backups(user_id) ON DELETE CASCADE,
    operation_id     UUID NOT NULL,
    target_generation BIGINT NOT NULL CHECK (target_generation > 0),
    reference_set_digest CHAR(64) NOT NULL CHECK (reference_set_digest ~ '^[0-9a-f]{64}$'),
    next_page        INT NOT NULL DEFAULT 0 CHECK (next_page >= 0),
    completed        BOOLEAN NOT NULL DEFAULT false,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, operation_id),
    UNIQUE (user_id, target_generation)
);

CREATE TABLE chat_backup_media_reconciliation_entries (
    user_id          UUID NOT NULL,
    operation_id     UUID NOT NULL,
    reference_id     UUID NOT NULL,
    media_id         BYTEA NOT NULL CHECK (octet_length(media_id) = 32),
    PRIMARY KEY (user_id, operation_id, reference_id),
    FOREIGN KEY (user_id, operation_id)
        REFERENCES chat_backup_media_reconciliations(user_id, operation_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id, media_id)
        REFERENCES chat_backup_media_objects(user_id, media_id) ON DELETE CASCADE
);

CREATE TABLE chat_backup_media_reconciliation_pages (
    user_id          UUID NOT NULL,
    operation_id     UUID NOT NULL,
    page_index       INT NOT NULL CHECK (page_index >= 0),
    request_digest   CHAR(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, operation_id, page_index),
    FOREIGN KEY (user_id, operation_id)
        REFERENCES chat_backup_media_reconciliations(user_id, operation_id) ON DELETE CASCADE
);

CREATE INDEX chat_backup_media_reconciliation_entries_order_idx
    ON chat_backup_media_reconciliation_entries(user_id, operation_id, reference_id);

CREATE INDEX chat_backup_media_references_media_idx
    ON chat_backup_media_references(user_id, media_id);

-- Device transfer is deliberately removed. Existing imported display-history
-- rows live in client-local stores and are not affected by dropping the relay.
DROP TABLE chat_history_transfer_frames;
DROP TABLE chat_history_transfers;
