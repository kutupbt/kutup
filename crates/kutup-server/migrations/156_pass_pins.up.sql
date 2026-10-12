-- Kutup Pass PIN lock (docs/plans/pass.md, "Locking").
--
-- A six-digit PIN that unlocks vaults kept with the Kutup sign-in once the
-- app has locked them, as Proton Pass's PIN lock. One per account, used on
-- every device. The server keeps only its bcrypt hash and checks it; three
-- wrong PINs in a row end the sign-in that tried them. Setting or removing
-- it takes the account password.
CREATE TABLE pass_pins (
    user_id    UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    pin_hash   TEXT        NOT NULL,
    failures   SMALLINT    NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
