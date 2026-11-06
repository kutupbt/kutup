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

-- A hash chain over the admin log: each row names the previous row's hash.
-- Rows from before the chain have none and are not verified.
ALTER TABLE admin_audit_log
    ADD COLUMN previous_hash bytea CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
    ADD COLUMN row_hash bytea CHECK (row_hash IS NULL OR octet_length(row_hash) = 32);
