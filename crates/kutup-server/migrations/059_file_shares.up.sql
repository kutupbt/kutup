-- A single file shared by itself (docs/plans/drive-file-sharing.md), like
-- Proton Drive and CryptPad: the owner seals the file's current key to the
-- recipient (FileShareEnvelopeV1, bound to the file and key generation) and
-- signs it. A share left at an older generation (the file moved to a new key
-- by someone other than the owner) waits for the owner's app to re-seal it.
CREATE TABLE file_shares (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id            UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    sharer_user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    share_envelope     TEXT NOT NULL CHECK (length(share_envelope) <= 2048),
    key_generation     INTEGER NOT NULL CHECK (key_generation > 0),
    can_edit           BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (file_id, recipient_user_id),
    CHECK (sharer_user_id <> recipient_user_id)
);

CREATE INDEX file_shares_recipient_idx ON file_shares (recipient_user_id);
