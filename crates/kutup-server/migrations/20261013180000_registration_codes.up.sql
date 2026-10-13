-- Referral codes (docs/plans/registration-codes.md): what admits a sign-up
-- when the registration mode asks for one. The code itself is never stored,
-- only its HMAC under the server's own key, so a dump of this table gives no
-- usable codes; `hint` (its last characters) lets an admin recognise one.
CREATE TABLE registration_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash   BYTEA NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    hint        TEXT NOT NULL CHECK (length(hint) BETWEEN 1 AND 8),
    note        TEXT NOT NULL DEFAULT '' CHECK (length(note) <= 200),
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    -- NULL: as many sign-ups as come.
    max_uses    INTEGER CHECK (max_uses IS NULL OR max_uses BETWEEN 1 AND 100000),
    uses        INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
    revoked_at  TIMESTAMPTZ,
    revoked_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    CHECK (max_uses IS NULL OR uses <= max_uses)
);

CREATE INDEX registration_codes_created_at ON registration_codes (created_at DESC);

-- Which code each account signed up with (one at most).
CREATE TABLE registration_code_uses (
    code_id  UUID NOT NULL REFERENCES registration_codes(id) ON DELETE CASCADE,
    user_id  UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    used_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (code_id, user_id)
);

-- The open/closed switch becomes the registration mode (on, code, off).
DELETE FROM site_settings WHERE key = 'registration_enabled';

-- The server's own key for code hashes (server_keys::GeneratedKey).
ALTER TABLE server_generated_keys DROP CONSTRAINT server_generated_keys_purpose_check;
ALTER TABLE server_generated_keys ADD CONSTRAINT server_generated_keys_purpose_check
    CHECK (purpose = ANY (ARRAY['federation-identity', 'mls-control', 'mail-group-authority',
                                'fake-accounts', 'registration-codes']));
