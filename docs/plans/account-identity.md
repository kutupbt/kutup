# One identity per account

**Status:** plan (2026-10-12). Decided by the user: an account's identity is
its Kutup address; the email it signed up with becomes an optional recovery
email; keys are bound to the account's permanent id and re-sealed properly; no seal binds a name.

## Why

Every account has a Kutup address (`username@<domain>`, the mailbox Mail made
real) and, separately, the email it signed up with. Two emails per account
confuse people, and one string can name two people: user `dev` who signed up
as `admin@kutup.dev` beside user `admin` whose mailbox is `admin@kutup.dev`.

Worse for the long run, the sign-in email is part of the account's
cryptography: every account envelope (`KUTPAE1`, the password and recovery
wrappings of the master key, the Drive private key, the Chat backup root,
each mail address key, each Pass vault secret) carries it in its
authenticated header, and the recovery check derives from it. An email (or a
username) is a name, and names change.

## Decisions

1. **Sign in with the username or the Kutup address** (`dev` or
   `dev@kutup.dev`), as Proton. The account menu shows the display name and
   the Kutup address only.
2. **Keys are bound to a random, permanent key binding** of the account
   (`users.key_binding`: a random 128-bit value in UUID form, drawn by the
   browser at sign-up, never changed, never a name, not the database id, and
   carried with the account if it ever moves to another server). No seal
   binds a name. The envelope format stays as it is (its header's context
   string becomes the key binding; no format or suite change).
3. **The signup email becomes an optional recovery email** (Proton/Gmail):
   confirmed by a code, used for security notices and later password reset
   (encrypted data still needs the 24-word phrase). Emails on the server's own
   domain are dropped: such an address only ever names a mailbox.
4. **Existing accounts are re-sealed at their next sign-in** in the browser.

## Design

### Binding

How Proton does it: nothing is sealed to a name. Keys form a hierarchy (the
password unlocks the user key, the user key each address key), every key and
object has its own random id, and what keeps a secret in its place is the key
it is sealed under plus a fixed purpose string. CryptPad derives its login
keys from username and password, which is why a CryptPad username cannot
simply change. Kutup follows Proton: a seal binds the account's **key
binding**, the **purpose**, and the object's own **permanent id** where it has
one (a vault file, a mail key, a folder), under the account's own keys.

- `users.key_binding TEXT`: the random value the account's seals carry, and
  `users.envelope_binding TEXT NOT NULL`: the string its envelopes carry
  *now*, backfilled with `lower(email)` (what they carry today) and set to
  `key_binding` by the re-seal. Every server check that compares an envelope
  header with `users.email` (`validate_account_envelope`, Chat backup, mail
  keys, Pass vault secrets) compares with `envelope_binding` instead.
- **Registration** binds to the key binding from the start: the browser draws
  it (UUID v4 form) before it seals and sends it; the server stores it (a
  value already taken is refused and the browser draws again).
- The binding is returned by sign-in's preflight and kept in the session
  (`session.envelopeBinding`, CLI `Session.envelope_binding`); every seal and
  open uses it, never `session.email`, `session.username` or an address.
- Other at-rest formats that bound a name (found by the audit, below) move to
  the key binding in the same re-seal.

### Re-sealing (next sign-in)

When the envelopes do not carry the key binding yet, the account app, right after unlocking,
re-seals everything bound to the old string and sends it in **one request**
(`POST /api/user/rebind`), which the server applies in one transaction and only
whole: every envelope's header must name the key binding, every row of the account must
be covered (counts checked), then `envelope_binding = key_binding`.

| What | How the browser re-seals it |
|---|---|
| Password wrapping of the master key | from the master key and the password key it just derived |
| Recovery wrapping + recovery check | needs the 24 words: **asked once** ("Confirm your recovery phrase"); or **make a new phrase** (shown to write down), which replaces the old one |
| Drive private key | from the master key |
| Chat backup root | opened with the old binding, sealed with the key binding |
| Mail address keys (each) | opened with the old binding, sealed with the key binding |
| Pass vault secrets (each) | the same (Pass part by the third session, on this branch) |

Until it is done the account works as before (the server keeps the old
binding); the step can be put off ("Later") and comes back at the next sign-in.
The CLI never re-seals: it reads the binding from preflight and works with
either; if the binding changes while it is signed in, opening fails cleanly and
`kutup login` again fixes it.

Accounts that never sign in again keep their old binding indefinitely and
keep working. A **recovery** with the 24 words re-seals at once (the phrase is
known there).

### Sign-in

- `GET /api/auth/login/preflight?name=` takes the username or the address (the
  address must be on this server's domain); it answers the salt, the Argon2id
  parameters and the binding. For a name that is not an account it answers a
  deterministic fake salt **and a fake binding** (an id derived from the name
  under a server secret), so preflight does not tell which names exist.
- Login, recovery and reauth take `name` the same way. **Transition:** an
  account not yet re-sealed may still sign in once with its old email; after
  the re-seal the old email no longer signs in.
- The sign-in lockout (`LOGIN_LOCKOUT`) is keyed by the account id once the
  name resolves (by the name otherwise), so sign-in, reauth and the Pass PIN
  keep sharing one counter.

### Recovery email (second slice)

- `user_recovery_emails(user_id, address, verified_at, …)`, one per account;
  Settings → Recovery: add, change, remove; confirmed by a six-digit code sent
  to it (expires in 10 minutes, 5 attempts, rate-limited per account and per
  address), as Proton.
- The server needs a system sender for that mail (none exists today): mail
  from `no-reply@<domain>` through the outside-sending path, signed (DKIM) as
  the domain's own mail.
- Existing accounts: an outside signup email becomes an **unconfirmed**
  recovery email ("Confirm your recovery email" in Settings); one on the
  server's own domain is dropped.
- Uses now: security notices (a new sign-in, the recovery phrase replaced).
  Password reset by recovery email comes later (its own plan: Proton resets
  the password and keeps old data locked until the phrase is given).

### Everything else that reads `users.email`

- `/user/me` answers the Kutup address; `email` leaves the session.
- By-email lookup (Drive sharing, federation): by Kutup address only (it
  already tries the address first); the fallback to sign-in emails goes.
- Admin: users listed and searched by username and address; new users get a
  username and, optionally, a recovery email; break-glass and the bootstrap
  admin (`ADMIN_ACCOUNT`) by username.
- TOTP label: the Kutup address.
- CLI: `--username` (the address works too) on `register`, `login`, `recover`.
- Tests: `newAccount`/`signIn` fixtures sign in by username; specs that type
  an email change; live tests seal with the key binding.

## Security review

- **Re-binding:** the server accepts a rebind only whole (every row of the
  account, headers naming the key binding), in one transaction, from a fresh session;
  a partial or replayed request changes nothing. The old binding is not kept
  after the switch.
- **Recovery check:** the new check is derived only from the phrase the user
  typed or the new one shown; the server never sees the phrase.
- **Accounts that never sign in:** keep working with the old binding; nothing
  is re-sealed server-side (the server cannot).
- **Name enumeration:** preflight answers a fake salt and binding for unknown
  names (deterministic, so repeated asks look the same); sign-in failures are
  the same message; registration still says a username is taken (unavoidable,
  as Proton).
- **Recovery email:** codes hashed, short-lived, few attempts, rate limits per
  account and per target address; an unconfirmed address receives nothing but
  its code; changing it notifies the old one.
- **Client-drawn key binding:** random, UUID-shaped, checked for form and
  uniqueness; not secret and carries no authority (the server still owns
  sessions and roles); never shown as an identity.

## Slices

1. **Identity:** binding by id, sign-in by name, preflight with binding,
   rebind endpoint and the browser step (recovery phrase asked or replaced),
   session/CLI/tests by name, `/user/me` and the menus. Pass vault secrets'
   part by the third session on this branch.
2. **Recovery email:** the system sender, the table, Settings → Recovery,
   codes, notices, the backfill from sign-in emails.
