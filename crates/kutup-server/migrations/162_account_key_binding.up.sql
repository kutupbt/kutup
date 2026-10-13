-- One identity per account (docs/plans/account-identity.md). Seals bind a
-- random, permanent key binding the browser draws, never a name; the string
-- an account's envelopes carry now is kept beside it: its sign-in email (as
-- every envelope carries today) until the browser re-seals them, then the key
-- binding. Sign-in moves to the username or the Kutup address, so the email
-- is no longer required; a new account has none.
ALTER TABLE users ADD COLUMN key_binding TEXT UNIQUE
    CHECK (key_binding ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');
ALTER TABLE users ADD COLUMN envelope_binding TEXT;
UPDATE users SET envelope_binding = lower(btrim(email));
ALTER TABLE users ALTER COLUMN envelope_binding SET NOT NULL;
-- An account made by an administrator has no keys until its first sign-in,
-- which sets both.
ALTER TABLE users ALTER COLUMN envelope_binding SET DEFAULT '';
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
-- An administrator's temporary password is derived in their browser now
-- (docs/plans/account-identity.md, review H1): an account still waiting for
-- its first sign-in under a password the server was sent as it is cannot
-- sign in any more (an administrator gives it a new one), and gets a salt
-- of its own, so preflight tells it from no other account.
UPDATE users
   SET login_key_hash = '',
       account_protection_suite = 1,
       account_protection_salt = encode(uuid_send(gen_random_uuid()), 'base64'),
       argon_memory_kib = 65536, argon_iterations = 3, argon_parallelism = 1
 WHERE is_first_login AND account_protection_salt = '';
