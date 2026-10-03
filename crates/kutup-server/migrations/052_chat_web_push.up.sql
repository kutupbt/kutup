-- Web Push wake-ups for Chat devices (docs/chat-notifications.md).
-- The server's VAPID signing key (P-256), made once.
CREATE TABLE chat_web_push_key (
    id          SMALLINT PRIMARY KEY CHECK (id = 1),
    private_key BYTEA NOT NULL CHECK (octet_length(private_key) = 32),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One browser push subscription per chat device; only its endpoint, since
-- wake-ups carry no payload.
CREATE TABLE chat_push_subscriptions (
    user_id    UUID NOT NULL,
    device_id  INT  NOT NULL,
    endpoint   TEXT NOT NULL CHECK (length(endpoint) <= 2048),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id),
    FOREIGN KEY (user_id, device_id) REFERENCES chat_devices (user_id, device_id) ON DELETE CASCADE
);
