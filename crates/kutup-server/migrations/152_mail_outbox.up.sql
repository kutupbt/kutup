-- Undo send (docs/plans/mail-parity.md, P4), Proton's DelaySendSeconds: a
-- send is checked at once, then held this long before it goes, so it can be
-- taken back. What the browser sent waits in object storage (encrypted
-- copies, and the readable message for outside recipients that already went
-- that way) and is removed once sent, taken back or failed.
ALTER TABLE mail_settings ADD COLUMN delay_send_seconds INTEGER NOT NULL DEFAULT 10
    CHECK (delay_send_seconds IN (0, 5, 10, 20));

CREATE TABLE mail_outbox (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The draft being sent: it stays a draft until the send goes out.
    draft_id    UUID NOT NULL,
    is_admin    BOOLEAN NOT NULL,
    deliver_at  TIMESTAMPTZ NOT NULL,
    parts_key   TEXT NOT NULL,
    parts_version TEXT NOT NULL,
    -- pending, sending, sent, cancelled or failed.
    state       TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'sending', 'sent', 'cancelled', 'failed')),
    -- When sent: the recipients' statuses; when failed: the error.
    result      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);
CREATE INDEX mail_outbox_due ON mail_outbox (deliver_at) WHERE state = 'pending';
CREATE UNIQUE INDEX mail_outbox_one_per_draft ON mail_outbox (draft_id) WHERE state IN ('pending', 'sending');
