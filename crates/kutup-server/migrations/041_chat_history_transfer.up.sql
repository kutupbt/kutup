-- Account-local opaque relay for one-time, two-device-authenticated Chat
-- history transfer. The server stores only signed public handshake objects and
-- XChaCha ciphertext frames; client archive plaintext and transfer keys never
-- enter these tables.

CREATE TABLE chat_history_transfers (
    transfer_id           UUID        PRIMARY KEY,
    user_id               UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requesting_device_id  INT         NOT NULL,
    responding_device_id  INT,
    manifest_sequence     BIGINT      NOT NULL CHECK (manifest_sequence > 0),
    request               JSONB       NOT NULL CHECK (jsonb_typeof(request) = 'object'),
    request_hash          CHAR(64)    NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    acceptance            JSONB       CHECK (acceptance IS NULL OR jsonb_typeof(acceptance) = 'object'),
    transcript_hash       CHAR(64)    CHECK (transcript_hash IS NULL OR transcript_hash ~ '^[0-9a-f]{64}$'),
    completion            JSONB       CHECK (completion IS NULL OR jsonb_typeof(completion) = 'object'),
    state                 TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (state IN ('pending', 'accepted', 'completed')),
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id, requesting_device_id)
        REFERENCES chat_devices(user_id, device_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id, responding_device_id)
        REFERENCES chat_devices(user_id, device_id) ON DELETE CASCADE,
    CHECK (
        (state = 'pending' AND responding_device_id IS NULL AND acceptance IS NULL
                           AND transcript_hash IS NULL AND completion IS NULL)
        OR
        (state = 'accepted' AND responding_device_id IS NOT NULL AND acceptance IS NOT NULL
                            AND transcript_hash IS NOT NULL AND completion IS NULL)
        OR
        (state = 'completed' AND responding_device_id IS NOT NULL AND acceptance IS NOT NULL
                             AND transcript_hash IS NOT NULL AND completion IS NOT NULL)
    ),
    CHECK (responding_device_id IS NULL OR responding_device_id <> requesting_device_id)
);

CREATE INDEX chat_history_transfers_pending_device_idx
    ON chat_history_transfers(user_id, state, requesting_device_id, expires_at);
CREATE INDEX chat_history_transfers_expiry_idx
    ON chat_history_transfers(expires_at);

CREATE TABLE chat_history_transfer_frames (
    transfer_id      UUID        NOT NULL REFERENCES chat_history_transfers(transfer_id) ON DELETE CASCADE,
    frame_index      INT         NOT NULL CHECK (frame_index BETWEEN 0 AND 1023),
    final_frame      BOOLEAN     NOT NULL,
    plaintext_bytes INT         NOT NULL CHECK (plaintext_bytes BETWEEN 0 AND 262144),
    nonce            TEXT        NOT NULL,
    ciphertext       TEXT        NOT NULL,
    ciphertext_hash  CHAR(64)    NOT NULL CHECK (ciphertext_hash ~ '^[0-9a-f]{64}$'),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (transfer_id, frame_index)
);

CREATE UNIQUE INDEX chat_history_transfer_one_final_idx
    ON chat_history_transfer_frames(transfer_id) WHERE final_frame = true;
