-- Kutup Pass PIN lock (docs/plans/pass.md, "The PIN").
--
-- A six-digit PIN that opens vaults the app locked, as Proton Pass's PIN
-- lock. One per account, used on every device. The server keeps only its
-- bcrypt hash and checks it; setting or removing it takes the account
-- password.
CREATE TABLE pass_pins (
    user_id    UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    pin_hash   TEXT        NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Wrong PINs in a row, per sign-in (the root of a session tree): three end
-- that sign-in. Kept per sign-in so one sign-in's right PIN never gives
-- another more tries, and another's misses never take the owner's.
CREATE TABLE pass_pin_failures (
    sign_in_id UUID     PRIMARY KEY REFERENCES auth_sessions(id) ON DELETE CASCADE,
    user_id    UUID     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    failures   SMALLINT NOT NULL
);
CREATE INDEX pass_pin_failures_user ON pass_pin_failures (user_id);
