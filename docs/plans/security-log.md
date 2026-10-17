# Security log: sign-ins and two-step changes

Status: draft for review by the main session (2026-10-17). No code before it
is accepted.

The account's security log (`account_security_events`,
`GET /api/user/security-events`, Account → Security) records today what
changed an account's sign-in: a password change, a recovery, a move to the
server's current OPAQUE setup, an administrator's reset, an account reset,
renames and held names. This note adds what Proton's log has and Kutup's
lacks: sign-ins, sign-outs and two-step changes, and Proton's choice of how
much is kept.

## What Proton does (copied)

`WebClients/packages/shared/lib/authlog/AuthLog.ts` and the user setting
`SETTINGS_LOG_AUTH_STATE` (`interfaces/UserSettings.ts:17-21`):
- **Events**: sign-in success, failure (wrong password), failure (second
  factor), success awaiting the second factor, sign-out, re-authentication
  success and failure, password and two-step changes, recovery changes, key
  changes, and revoking one session or all of them.
- **Each entry**: time, event, device (client and user agent), and, only in
  advanced mode, the IP address.
- **The setting**: `DISABLE`, `BASIC` (no IP) and `ADVANCED` (with IP),
  chosen by the account.

## The events added

| Kind | When | Written by |
| --- | --- | --- |
| `signIn` | a sign-in that completed (no second factor, or after it) | `opaque::login_finish` / `auth::login_two_fa` |
| `signInAwait2fa` | the password was right and a second factor is asked | `opaque::login_finish` |
| `signInFailedPassword` | the password was wrong for an existing account | `opaque::login_finish` |
| `signInFailed2fa` | a wrong second-factor code | `auth::login_two_fa` |
| `signOut` | the session signed itself out | `session_routes::logout` |
| `sessionRevoked` | another session of the account was ended (`DELETE /api/auth/sessions/:id`) | sessions |
| `allSessionsRevoked` | every other session was ended | sessions |
| `reauthFailed` | a wrong password when confirming an action | `opaque::login_finish` (`reauth`) |
| `totpOn` / `totpOff` | the account turned its authenticator on or off | `auth::verify_totp` / `auth::disable_totp` |
| `adminTotpOff` | an administrator turned it off (lost authenticator) | `admin::force_disable_2fa` |

Re-authentication *successes* aren't logged: each one precedes an action that
logs itself (a password change, a new recovery phrase), as Proton's list shows
the action rather than the confirmation. A refresh of an existing session isn't
a sign-in.

**Wrong passwords and non-accounts.** OPAQUE answers a name that is no account
with a fake login that can't finish, so `login_finish` knows a failure belongs
to an account only when the pending login names one. Only those are written;
the account's owner sees them, and an outsider learns nothing new (the answer
to the attempt is unchanged).

## How much is kept: the account's choice (Proton's three modes)

A new account setting, `securityLog`: `off`, `basic` (the default) or
`advanced`, changed in Account → Security.
- **basic**: every event, with time, client and user agent; no IP address.
- **advanced**: the same, plus the client's IP address (as the server already
  resolves it for rate limits, behind the proxy's `X-Real-IP`).
- **off**: sign-in, sign-out and session events aren't written.

**A deviation from Proton, with its reason.** Proton's `DISABLE` stops the
whole log. Here the events that already existed (a password change, a
recovery, an administrator's reset, a rename, two-step on or off) are written
in every mode: they record changes to how the account is protected, and an
owner who turned the log off must still be able to see that someone else
changed their password. Only the sign-in and session events follow `off`.

**IP addresses** are kept only while `advanced` is on. Leaving `advanced`
erases the IPs already stored for the account, in the same transaction.
Self-hosting documents that advanced mode stores IPs.

## Floods

Failed sign-ins are what an attacker can produce at will. So:
- repeated failures of the same kind, from the same client type and user agent
  (and, in advanced mode, IP), within 10 minutes fold into one row with a
  `count`;
- the existing limits stay: the newest 500 events or a year per account,
  whichever is less.
- The per-account and per-source sign-in limits
  (`LOGIN_ACCOUNT_CEILING`, `auth_check`) are unchanged; this only records.

## Storage (one migration)

On `account_security_events`:
- the new kinds in the `kind` check;
- `count integer NOT NULL DEFAULT 1`;
- `ip inet` (null unless the account was in advanced mode when it was
  written).

On the account's settings, `security_log text NOT NULL DEFAULT 'basic'`,
checked to the three values. The migration takes the next free number above
master and the open PRs at build time.

## API

- `GET /api/user/security-events` gains `count` and, when present, `ip`.
- `GET`/`PUT /api/user/security-log`: `{ "mode": "off" | "basic" | "advanced" }`.
  Changing it needs a fresh session (the account's existing re-authentication
  for sensitive settings) and is itself logged as `securityLogChanged`, in
  every mode.
- `docs/api.md` and the OpenAPI annotations are updated.

## Account → Security

- The list shows the new kinds, the fold count ("3 times") and, in advanced
  mode, the IP. Strings in en and tr.
- A "Security log" setting with the three modes, each with one line saying
  what it keeps, as Proton's does.
- Existing tests extend: the event labels, the setting, and the list with a
  folded failure.

## Tests

- Server live tests: a sign-in, a wrong password, a wrong second-factor code,
  a sign-out and a revoked session each write their event; a non-account
  writes nothing; folding; `off` writes no sign-in event but still writes a
  password change; leaving `advanced` erases the IPs.
- Frontend unit tests for the labels and the setting.

## Not in this note

- An administrator's view of all accounts' sign-ins (Proton's B2B log).
- Location or internet-provider lookups from IPs (Proton shows them in
  advanced mode). They need a GeoIP database; left for later.
- Notifying the owner of a new sign-in by email: it goes with system emails
  through Kutup's Stalwart (roadmap).

## Estimate

About 4–5 days: the migration and server events 2, the setting and API 1,
the UI 1, tests 1.
