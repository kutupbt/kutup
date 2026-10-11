-- Drive identity (docs/plans/drive-identity-pins.md).
-- The account authority's signature over the account's Drive keys
-- (kutup-crypto drive_key_binding), checked before it is stored. NULL for an
-- account that has not signed one yet; its next sign-in adds it.
ALTER TABLE users ADD COLUMN drive_key_binding TEXT;

-- The account's pins on other accounts' authorities: one list sealed under a
-- key derived from the master key (kutup-crypto identity_pins), opaque here.
-- `revision` is authenticated inside the envelope; a write names the
-- revision it replaces.
CREATE TABLE identity_pins (
    user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    revision   BIGINT NOT NULL CHECK (revision > 0),
    envelope   BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
