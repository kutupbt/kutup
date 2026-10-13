-- One identity per account (docs/plans/account-identity.md). Seals bind a
-- random, permanent key binding the browser draws, never a name; the string
-- an account's envelopes carry now is kept beside it: its sign-in email (as
-- every envelope carries today) until the browser re-seals them, then the key
-- binding. Sign-in moves to the username or the Kutup address, so the email
-- is no longer required; a new account has none.
ALTER TABLE users ADD COLUMN key_binding TEXT UNIQUE
    CHECK (key_binding ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');
ALTER TABLE users ADD COLUMN envelope_binding TEXT;
-- The binding exactly as the envelopes carry it, read from the password
-- envelope's header (magic 8, suite 2, purpose 1, reserved 1, a 2-byte
-- length, then the binding): no lowercasing rule here can differ from the
-- one that sealed it (Postgres's lower() is not ASCII-only).
UPDATE users
   SET envelope_binding = convert_from(
           substring(decode(master_key_envelope, 'base64') FROM 15 FOR
                     get_byte(decode(master_key_envelope, 'base64'), 12) * 256
                   + get_byte(decode(master_key_envelope, 'base64'), 13)),
           'UTF8')
 WHERE master_key_envelope <> '';
UPDATE users SET envelope_binding = '' WHERE envelope_binding IS NULL;
ALTER TABLE users ALTER COLUMN envelope_binding SET NOT NULL;
-- An account not re-sealed yet may still sign in with its old email.
CREATE INDEX users_old_sign_in_email ON users (lower(btrim(email))) WHERE key_binding IS NULL;
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
