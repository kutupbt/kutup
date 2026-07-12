-- Federated E2EE chat ("ileti"), phase 2: device directory, prekey pools, mailboxes.
-- Design: docs/research/11-federated-chat.md §4. The server stores public keys and
-- opaque ciphertext only — nothing in these tables can decrypt a message.

-- One row per chat-capable client install. Distinct from `devices` (the collab
-- Ed25519 signing keys): a chat device carries libsignal state with its own
-- lifecycle (re-registration on reinstall wipes sessions). device_id is
-- libsignal's DeviceId: small per-user integer, 1..127, assigned by the server.
CREATE TABLE chat_devices (
    user_id          UUID     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id        INT      NOT NULL CHECK (device_id BETWEEN 1 AND 127),
    suite            SMALLINT NOT NULL DEFAULT 1,
    -- libsignal registration id (random u32 < 16384, chosen client-side at install).
    registration_id  BIGINT   NOT NULL,
    -- base64 serialized public IdentityKey.
    identity_key     TEXT     NOT NULL,
    -- Current signed EC prekey (only the newest is served; rotation replaces in place).
    signed_pre_key_id        BIGINT NOT NULL,
    signed_pre_key           TEXT   NOT NULL,
    signed_pre_key_signature TEXT   NOT NULL,
    -- Last-resort Kyber prekey: served when the one-time pool is empty so bundles are
    -- never non-PQ (reusable, unlike the one-time pool — the SPQR ratchet still heals).
    last_resort_kyber_pre_key_id        BIGINT NOT NULL,
    last_resort_kyber_pre_key           TEXT   NOT NULL,
    last_resort_kyber_pre_key_signature TEXT   NOT NULL,
    name             TEXT        NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ,
    PRIMARY KEY (user_id, device_id)
    -- Revocation is a hard DELETE: the cascades wipe the device's prekey pools and
    -- mailbox, and the freed device_id becomes reusable. (No soft-disable state —
    -- a revoked chat device has no meaningful half-life under E2EE.)
);

-- One-time EC prekey pool. Consumed (DELETE .. RETURNING) by bundle fetches;
-- unsigned by design (libsignal one-time EC prekeys carry no signature).
CREATE TABLE chat_one_time_pre_keys (
    user_id    UUID   NOT NULL,
    device_id  INT    NOT NULL,
    key_id     BIGINT NOT NULL,
    public_key TEXT   NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, key_id),
    FOREIGN KEY (user_id, device_id) REFERENCES chat_devices ON DELETE CASCADE
);

-- One-time Kyber prekey pool (always signed).
CREATE TABLE chat_one_time_kyber_pre_keys (
    user_id    UUID   NOT NULL,
    device_id  INT    NOT NULL,
    key_id     BIGINT NOT NULL,
    public_key TEXT   NOT NULL,
    signature  TEXT   NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, key_id),
    FOREIGN KEY (user_id, device_id) REFERENCES chat_devices ON DELETE CASCADE
);

-- Store-and-forward mailbox: one row per (message, recipient device). Content is an
-- opaque base64 libsignal ciphertext; rows are deleted on client ack. Sender columns
-- are plaintext in this phase (sealed sender across federation is a research
-- follow-up — docs/research/11-federated-chat.md §7).
CREATE TABLE chat_mailbox (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_user_id   UUID        NOT NULL,
    recipient_device_id INT         NOT NULL,
    sender              TEXT        NOT NULL,   -- local username; user@domain once federated
    sender_device_id    INT         NOT NULL,
    envelope_type       SMALLINT    NOT NULL,   -- 1 = preKey, 2 = message
    suite               SMALLINT    NOT NULL DEFAULT 1,
    content             TEXT        NOT NULL,   -- base64 ciphertext, opaque
    server_ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (recipient_user_id, recipient_device_id)
        REFERENCES chat_devices ON DELETE CASCADE
);

-- Drain order + fast per-device fetch.
CREATE INDEX chat_mailbox_recipient_idx
    ON chat_mailbox (recipient_user_id, recipient_device_id, server_ts, id);
