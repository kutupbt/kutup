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
