CREATE TABLE pass_vault_secrets (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_id uuid NOT NULL,
    envelope bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (user_id, file_id)
);
CREATE INDEX pass_vault_secrets_file ON pass_vault_secrets USING btree (file_id);
