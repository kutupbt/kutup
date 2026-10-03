-- Sharing one file with someone on another server
-- (docs/plans/drive-file-sharing.md, slice 2): a capability for that file
-- alone, used through the recipient's server, as folder invites are.

-- On the owner's server: the file's key sealed to the remote account
-- (FileShareEnvelopeV1) and the hash of the capability the invite carries.
CREATE TABLE federated_outgoing_file_shares (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id                  UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    sharer_user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_username       TEXT NOT NULL,
    recipient_domain         TEXT NOT NULL,
    recipient_incarnation_id TEXT NOT NULL CHECK (recipient_incarnation_id ~ '^[0-9a-f]{64}$'),
    share_envelope           TEXT NOT NULL CHECK (length(share_envelope) <= 2048),
    key_generation           INTEGER NOT NULL CHECK (key_generation > 0),
    capability_hash          TEXT NOT NULL UNIQUE CHECK (capability_hash ~ '^[0-9a-f]{64}$'),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (recipient_username ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    CHECK (recipient_domain = lower(recipient_domain)),
    CHECK (length(recipient_domain) BETWEEN 3 AND 253)
);
CREATE INDEX federated_outgoing_file_shares_file_idx ON federated_outgoing_file_shares (file_id);

-- On the recipient's server: the capability, and the owner as first seen
-- (a later answer from another owner identity is refused).
CREATE TABLE federated_incoming_file_shares (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    remote_domain            TEXT NOT NULL,
    remote_capability        TEXT NOT NULL,
    capability_hash          TEXT NOT NULL CHECK (capability_hash ~ '^[0-9a-f]{64}$'),
    remote_file_id           UUID NOT NULL,
    owner_user_id            UUID NOT NULL,
    owner_account            TEXT NOT NULL,
    owner_incarnation_id     TEXT NOT NULL CHECK (owner_incarnation_id ~ '^[0-9a-f]{64}$'),
    owner_signing_public_key TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, remote_domain, capability_hash),
    CHECK (remote_domain = lower(remote_domain)),
    CHECK (length(remote_capability) BETWEEN 32 AND 256),
    CHECK (remote_capability ~ '^[A-Za-z0-9._~-]+$')
);
