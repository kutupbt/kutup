UPDATE mail_folders SET name_sealed = '?' WHERE name_sealed IS NULL;
ALTER TABLE mail_folders ALTER COLUMN name_sealed SET NOT NULL;
DELETE FROM pass_vault_secrets s WHERE NOT EXISTS (SELECT 1 FROM files f WHERE f.id = s.file_id);
ALTER TABLE pass_vault_secrets
    ADD CONSTRAINT pass_vault_secrets_file_id_fkey FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE;
DROP TABLE account_heads;
