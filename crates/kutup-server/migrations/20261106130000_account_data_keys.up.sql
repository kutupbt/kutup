-- Server-side personal data (docs/plans/server-personal-data.md, A2, slice L1):
-- each account's data key, wrapped under an entry of the server key list
-- (OPAQUE_SETUP_KEYS), in its own schema. The database dump leaves this schema
-- out and a separate dump keeps it only for a short time, so deleting a key
-- destroys every copy of the fields sealed under it (backups included).
CREATE SCHEMA account_keys;

CREATE TABLE account_keys.account_data_keys (
    user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    -- The server key list entry the key is wrapped under (its id): an entry
    -- can be retired only once no key uses it.
    sealing_key_id smallint NOT NULL CHECK (sealing_key_id >= 1),
    generation integer NOT NULL CHECK (generation >= 1),
    -- kutup_crypto::server_data::WRAPPED_KEY_LEN.
    wrapped bytea NOT NULL CHECK (octet_length(wrapped) = 86),
    created_at timestamptz NOT NULL DEFAULT now(),
    -- An account may hold two generations while its fields are re-sealed
    -- from one to the next; the newest seals, a field names the one it was
    -- sealed under.
    PRIMARY KEY (user_id, generation)
);

CREATE INDEX account_data_keys_sealing_key_id ON account_keys.account_data_keys (sealing_key_id);

-- The authenticator app's secret, sealed under the account's data key.
ALTER TABLE users DROP COLUMN totp_secret;
ALTER TABLE users ADD COLUMN totp_secret_sealed bytea
    CHECK (totp_secret_sealed IS NULL OR octet_length(totp_secret_sealed) BETWEEN 47 AND 200);
