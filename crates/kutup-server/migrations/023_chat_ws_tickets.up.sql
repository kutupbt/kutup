-- One-time browser WebSocket credentials. Only a SHA-256 token hash is stored;
-- successful upgrade atomically deletes the row before the socket is accepted.
CREATE TABLE chat_ws_tickets (
    token_hash TEXT        PRIMARY KEY CHECK (length(token_hash) = 64),
    user_id    UUID        NOT NULL,
    device_id  INT         NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (user_id, device_id) REFERENCES chat_devices ON DELETE CASCADE
);

CREATE INDEX chat_ws_tickets_expiry_idx ON chat_ws_tickets (expires_at);
