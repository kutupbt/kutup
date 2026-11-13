-- Append-only security and admin logs (docs/plans/server-personal-data.md, A8,
-- slice L2). The grants that make them append-only are set by the server at
-- start, as the owner role (DATABASE_OWNER_URL), not here: the app role's name
-- is the deployment's.

-- Sign-ins, sign-outs, session revocations and admin access join the kinds;
-- repeated failures fold into one row (`count`, the only column the app role
-- may update).
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_kind_check CHECK (kind = ANY (ARRAY[
    'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset', 'rename',
    'nameDropped', 'nameClosed', 'nameFreed', 'domainLost',
    'twoFactorOn', 'twoFactorOff', 'recoveryCodeUsed', 'recoveryCodesRenewed',
    'securityKeyAdded', 'securityKeyRemoved', 'securityKeyCompromised',
    'authenticatorOn', 'authenticatorOff',
    'orgJoined', 'orgLeft', 'orgRemoved', 'orgAccessGranted', 'orgAccessRevoked',
    'orgReset', 'orgSignIn',
    'signIn', 'signInFailedPassword', 'signInFailed2fa', 'signOut',
    'sessionRevoked', 'allSessionsRevoked', 'adminAccess']));
ALTER TABLE account_security_events
    ADD COLUMN count integer NOT NULL DEFAULT 1 CHECK (count >= 1);

-- A failure's count only grows, one at a time: the one update the app role
-- may make can't rewrite a row's count.
CREATE FUNCTION account_security_events_count_step() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.count <> OLD.count + 1 THEN
        RAISE EXCEPTION 'a security event''s count grows by one at a time';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER account_security_events_count_step
    BEFORE UPDATE OF count ON account_security_events
    FOR EACH ROW EXECUTE FUNCTION account_security_events_count_step();

-- A hash chain over the admin log: each row names the previous row's hash.
-- This lands with a database reset (the wipe), so every row is chained: one
-- without hashes reads as broken.
-- `chain_version` names how a row is hashed (1: SHA-256 under the
-- admin-audit-chain/v1 label over the fields below), so a later version can
-- join the chain without a reset.
ALTER TABLE admin_audit_log
    ADD COLUMN chain_version smallint NOT NULL DEFAULT 1 CHECK (chain_version >= 1),
    ADD COLUMN previous_hash bytea CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
    ADD COLUMN row_hash bytea CHECK (row_hash IS NULL OR octet_length(row_hash) = 32);

-- Where the retention job last cut the chain: the last row it deleted and its
-- hash. Only the owner role writes it (the server grants the app role
-- nothing more than reading it), so deleting more of the oldest rows than
-- retention did breaks verification.
CREATE TABLE admin_audit_anchor (
    only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    through_id bigint NOT NULL,
    through_hash bytea NOT NULL CHECK (octet_length(through_hash) = 32)
);
