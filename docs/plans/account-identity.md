# One identity per account

**Status:** slice 1 built (PR #167, 2026-10-13). Decided by the user: an
account's identity is its Kutup address; the email it signed up with becomes
an optional recovery email; keys are bound to a permanent random key binding;
no seal binds a name. Accounts from before are not carried over: the private
beta starts again from an empty server (user, 2026-10-13).

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
   binds a name. Account envelopes move to suite 2 (a key per envelope; see
   the encryption review below).
3. **The signup email becomes an optional recovery email** (Proton/Gmail):
   confirmed by a code, used for security notices and later password reset
   (encrypted data still needs the 24-word phrase). Emails on the server's own
   domain are dropped: such an address only ever names a mailbox.
4. **No migration.** At first the plan re-sealed existing accounts at their
   next sign-in; that path carried most of the review's findings (a retry
   sealing under a wiped key, signup emails readable by username, a way to
   replace the recovery phrase with only the password). Since this is a
   private beta, the user chose a clean slate instead: kutup.dev starts from
   an empty database and bucket, and migration 162 refuses a server that
   still has accounts.

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

- `users.key_binding TEXT UNIQUE` (UUID v4 form): the value the account's
  seals carry. Every server check that compares an envelope header with the
  account (`validate_account_envelope`, Chat backup, mail keys, Pass vault
  secrets) compares with it.
- **Registration** and an administrator-made account's **first sign-in**
  bind to the key binding from the start: the browser draws it (UUID v4 form)
  before it seals and sends it; the server stores it (a value already taken
  is refused and the browser draws again).
- The binding comes only with a session (the login and 2FA responses, and
  `/user/me`), never from preflight, and is kept in the session
  (`session.envelopeBinding`, CLI `Session.envelope_binding`); every seal and
  open uses it, never an email, a username or an address.
- Other at-rest formats that bind a name (audit of 2026-10-12, every seal,
  derivation and store name) move to the key binding in the next PR (L2
  below), as new format versions only, there being nothing old to read:

| Bound to a name | What |
|---|---|
| Kutup address | identity pins (`identity_pins.rs` AAD) |
| Kutup address | contact cards and their summary signature (`contact_card.rs`) |
| Kutup address | mail folder, label and filter names (`mail_names.rs` AAD) |
| Kutup address | Chat's own copy of the account profile (`kutup-chat-core` `profile.rs`) |
| Kutup address | a Chat localStorage key (`pendingTimers.ts`, not sealed; renamed by account id) |

  Already bound to ids (no change): Chat's device store, sealed storage and
  backup (a hash of server and user id), the media cache, the Pass outbox,
  Drive's collection keyrings and public links, the account incarnation id.

  **Cross-party statements keep the address**, because the address is what
  they mean, and peers on other servers resolve people by it: the Drive key
  binding ("this address owns these keys"), safety numbers, named shares and
  profile key shares, the mail address key's own address, Chat profiles as
  peers check them, MLS credentials. If usernames become changeable later,
  renaming re-issues these (as a new OpenPGP user id would), a step of its
  own.

### Sign-in

- `GET /api/auth/login/preflight?name=` takes the username or the address (the
  address must be on this server's domain); it answers the salt and the
  Argon2id parameters, never the binding. For a name that is not an account
  it answers a fake salt (an HMAC of the name, its address form reduced to
  the username, under the server's own stored key), so preflight does not
  tell which names exist.
- Login, recovery and reauth take `name` the same way; an email never signs
  in.

### Sign-in checks

One check (`auth_check.rs`) serves sign-in, reauth (and with it the Pass
PIN's set and remove) and recovery:

- The secret is decoded before the name is looked up; the hash is checked
  next, at full cost when there is none (a name that is no account, a voided
  temporary password); only after a right secret does the answer say
  anything about the account (disabled, awaiting setup, 2FA). Every wrong
  secret is the same 401.
- **Lockout per account and client IP:** five misses in a row from one IP
  lock that account for that IP (`LOGIN_LOCKOUT_THRESHOLD`,
  `LOGIN_LOCKOUT_MINUTES`). A stranger elsewhere cannot lock a person out.
- **Ceiling per account for unknown clients:** attempts from every client
  the account does not know, together, are capped at `LOGIN_ACCOUNT_CEILING`
  (20) in the same window and `LOGIN_ACCOUNT_DAILY_CEILING` (200) a day,
  against guessing spread over many addresses. Rate limits and the lockout
  key an IPv6 client by its /64. Every attempt takes its slots first
  (parallel attempts get no more); a right secret gives them back.
- **Known clients:** a successful sign-in sets `kutup_known`, an HttpOnly
  cookie (`Path=/api`, `SameSite=Strict`, 90 days) holding the user id, the
  time and an HMAC under a key derived from the server's stored sign-in key.
  It is host-only, set on the account app's origin at sign-in and on each
  app's origin when it takes its session (fork consume), so reauth and the
  PIN from any app carry it; a parent-domain cookie was rejected because
  development hosts (`*.localhost`) cannot share one. A client with a valid
  cookie for the account is not held by the ceiling (still by its own
  per-IP lockout), so a distributed attack does not lock out the account's
  own devices. A caller already signed in to the account (reauth, the PIN's
  set and remove) counts as known too. The mark's HMAC also covers the
  account's current password hash, so a new password or a recovery retires
  every mark; signing out clears it on that origin. The CLI has no cookie:
  while an attack fills the ceiling, its sign-ins wait (documented risk).
- A source (an address or IPv6 /64) gets at most `LOGIN_SOURCE_DAILY_CEILING`
  (20) of an account's daily ceiling, so one source cannot use the day up
  alone. The daily counters live in a fixed-size table (memory does not grow
  with sprayed names). A refusal by a ceiling takes nothing from the
  client's own lockout.
- Accepted: a stolen session (signed in, so known) can guess the password
  past the ceiling at 5 per 15 minutes per /64. It could already fetch the
  account's key material, so the password adds little.
- Names that are no account meet the same lockout and ceiling on their
  canonical name, so a 429 says nothing about existence.
- The Pass PIN keeps its own limit (three per sign-in) and is checked at
  full cost even when malformed.

### Recovery email (slice 3, not in PR #167)

- `user_recovery_emails(user_id, address, verified_at, …)`, one per account;
  Settings → Recovery: add, change, remove; confirmed by a six-digit code sent
  to it (expires in 10 minutes, 5 attempts, rate-limited per account and per
  address), as Proton.
- The server needs a system sender for that mail (none exists today): mail
  from `no-reply@<domain>` through the outside-sending path, signed (DKIM) as
  the domain's own mail.
- Uses now: security notices (a new sign-in, the recovery phrase replaced).
  Password reset by recovery email comes later (its own plan: Proton resets
  the password and keeps old data locked until the phrase is given).

### Everything else that reads `users.email`

(Done: the clean-slate release dropped the `users.email` column, every
`email` field in API answers and audit payloads, and renamed the lookup to
`GET /api/users/by-address/:address`. A recovery email will get its own table.)

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

- **No old accounts:** nothing reads an email-bound seal or a suite-1
  envelope; migration 162 refuses a server with accounts.
- **Name enumeration:** sign-in preflight answers a salt and parameters only,
  for every account (one awaiting its first sign-in too) and, for a name that
  is no account, a fake one: the same each time, an HMAC under the server's
  own stored key, so no one without it tells it from a real one.
  The keys' binding comes only with a session. Recovery preflight has to
  answer a binding and an envelope (the phrase opens it offline); for unknown
  names both are faked the same way. Sign-in failures are the same message;
  registration still says a username is taken (unavoidable, as Proton).
- **Temporary passwords:** an administrator's browser makes the temporary
  password and derives it as any password is (a salt of its own, Argon2id
  V1): the server stores the login key's hash with that salt and never sees
  the password, for creating, rotating and wiping alike; the break-glass
  administrator from `ADMIN_ACCOUNT` is derived the same way once, at first
  start.
- **Recovery email (slice 3):** codes hashed, short-lived, few attempts, rate limits per
  account and per target address; an unconfirmed address receives nothing but
  its code; changing it notifies the old one.
- **Client-drawn key binding:** random, UUID-shaped, checked for form and
  uniqueness; not secret and carries no authority (the server still owns
  sessions and roles); never shown as an identity.

## Encryption review (2026-10-12)

The whole encryption design was reviewed while the identity changed.

| Item | What | State |
|---|---|---|
| H1 | No password sent to the server ever (temporary passwords derived in the administrator's browser) | done |
| H2 | Account envelopes suite 2: an AEAD key per purpose, binding and object (HKDF-SHA256), never the master key or recovery entropy used raw; the object id in the header (Pass vault secrets name their vault). Suite 1 is retired: neither read nor written | done |
| M4 | Fake preflight answers as HMACs under the server's own stored key | done |
| M5 | No binding before the password is proved (it comes with the session) | done |
| M6 | Re-sealed envelopes checked before sending | not needed: no re-seal |
| L2 | Identity pins, contact cards, mail folder and label names and Chat's own profile copy bound to the key binding instead of the address (new format versions only); signed statements about an address keep naming it | next PR |

Before v1, each separate: password change, raisable Argon2id parameters,
OPAQUE/SRP, key transparency. Master key rotation (authority succession, old
keys kept to decrypt only) has a plan of its own.

### Security review of PR #167 (2026-10-13)

Its findings about the re-seal (a retry sealing under a wiped key, signup
emails readable through recovery preflight, a password holder replacing the
recovery phrase, the backfill's lowercasing, Pass keys dropped silently)
went with the re-seal. Fixed in the PR: fake answers and the sign-in lockout
take `ada` and `ada@<this server>` as one name, under the server's own
stored key (not `JWT_SECRET`); the timing dummy is a real bcrypt hash and an
empty hash costs as much; a recovery checks the proof before anything else,
one 401 for every refusal; `ADMIN_ACCOUNT` is read in one place (a password
may hold colons, a bad username is refused); more suite-2 vectors.

Follow-ups:
- ~~The sign-in lockout per account lets anyone lock a known username out~~:
  per account and client IP, with a ceiling for unknown clients ("Sign-in
  checks").
- The web client takes the key binding from `/user/me` without checking it
  against anything it holds; a bad server could hand out another one (the
  seals would then fail to open, not leak). Pin it next to the keys.
- ~~Some refusals answer before the bcrypt check~~: the login key is decoded
  before the lookup and a disabled account is said only after the password
  ("Sign-in checks").
- The server could also require the object id where a purpose has one.

## Slices

1. **Identity:** the key binding, sign-in by name, the binding only with a
   session, account envelopes suite 2, derived temporary passwords,
   session/CLI/tests by name, `/user/me` and the menus (PR #167).
2. **Formats off the address** (L2): identity pins, contact cards, mail
   names, Chat's own profile copy.
3. **Recovery email:** the system sender, the table, Settings → Recovery,
   codes, notices.
