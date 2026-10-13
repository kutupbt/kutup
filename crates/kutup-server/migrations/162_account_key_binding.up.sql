-- One identity per account (docs/plans/account-identity.md). Seals bind a
-- random, permanent key binding the browser draws at registration or first
-- sign-in, never a name; accounts sign in by username or Kutup address, so
-- the email is no longer required (a new account has none). Accounts made
-- before are not carried over: a server takes this only with no accounts
-- yet (the private beta is reset to an empty database and bucket), and
-- refuses to start otherwise rather than leave accounts that cannot sign in.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM users) THEN
        RAISE EXCEPTION 'migration 162 needs a server with no accounts: accounts made before one identity per account are not carried over (docs/plans/account-identity.md)';
    END IF;
END
$$;
ALTER TABLE users ADD COLUMN key_binding TEXT UNIQUE
    CHECK (key_binding ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
