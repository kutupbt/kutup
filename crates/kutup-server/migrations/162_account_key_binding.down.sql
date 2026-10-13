-- Rolling back is not supported once any account has re-sealed its keys
-- (docs/plans/account-identity.md): older code reads envelopes by the
-- sign-in email, cannot decode accounts without one, and cannot restore a
-- voided temporary password. This undoes the schema only.
DROP INDEX IF EXISTS users_old_sign_in_email;
ALTER TABLE users DROP COLUMN envelope_binding;
ALTER TABLE users DROP COLUMN key_binding;
