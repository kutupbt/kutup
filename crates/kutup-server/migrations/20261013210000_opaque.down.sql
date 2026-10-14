DROP TABLE account_security_events;
DROP TABLE auth_grants;
DROP TABLE opaque_login_states;
DROP TABLE opaque_server_setups;
ALTER TABLE users
    DROP CONSTRAINT users_opaque_record_check,
    DROP CONSTRAINT users_opaque_server_key_id_check,
    DROP CONSTRAINT users_opaque_suite_check,
    DROP CONSTRAINT users_opaque_check,
    DROP COLUMN opaque_server_key_id,
    DROP COLUMN opaque_suite,
    DROP COLUMN opaque_record,
    -- Accounts registered with OPAQUE have no login-key hash to go back to.
    ADD COLUMN login_key_hash text NOT NULL DEFAULT '',
    ADD COLUMN account_protection_salt text NOT NULL DEFAULT '',
    ADD COLUMN account_protection_suite smallint NOT NULL DEFAULT 0
        CONSTRAINT users_account_protection_suite_check CHECK (account_protection_suite = ANY (ARRAY[0, 1])),
    ADD COLUMN argon_memory_kib integer NOT NULL DEFAULT 0
        CONSTRAINT users_argon_memory_kib_check CHECK (argon_memory_kib >= 0),
    ADD COLUMN argon_iterations integer NOT NULL DEFAULT 0
        CONSTRAINT users_argon_iterations_check CHECK (argon_iterations >= 0),
    ADD COLUMN argon_parallelism integer NOT NULL DEFAULT 0
        CONSTRAINT users_argon_parallelism_check CHECK (argon_parallelism >= 0);
