-- Forwarding destinations are verified by a 6-digit code mailed to them and
-- entered by the forwarder (docs/plans/mail-forwarding.md, "Verification").
-- A forwarding forwards only once verified. Existing forwardings start
-- unverified: they pause until their forwarder enters a code.
ALTER TABLE mail_forwardings
    ADD COLUMN verified_at timestamptz,
    -- HMAC-SHA256 of the code under a key derived from MAIL_FORWARDING_KEYS
    -- version code_key_version; NULL when there is no live code.
    ADD COLUMN code_hash bytea,
    ADD COLUMN code_key_version smallint,
    ADD COLUMN code_expires_at timestamptz,
    ADD COLUMN code_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN code_sent_at timestamptz,
    ADD CONSTRAINT mail_forwardings_code_hash_length
        CHECK (code_hash IS NULL OR length(code_hash) = 32),
    ADD CONSTRAINT mail_forwardings_code_whole
        CHECK ((code_hash IS NULL) = (code_key_version IS NULL)
           AND (code_hash IS NULL) = (code_expires_at IS NULL));
