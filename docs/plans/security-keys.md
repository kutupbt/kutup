# Security keys as a second factor

Status: **approved** (the user, 2026-10-24; decisions below). Nothing here is
built yet.

**The request (the user, through the main session):** security keys (WebAuthn:
a YubiKey, a phone's or laptop's built-in authenticator used as a key) as a
second factor at sign-in, alongside the authenticator app, as Proton does it:
several keys per account, each named; added and removed in Account settings;
recovery codes still work; no passwordless passkey sign-in (Proton has none).

Proton's design is the reference throughout (WebClients:
`packages/components/containers/account/TwoFactorSection.tsx`, `fido/*`,
`packages/shared/lib/webauthn/*`, `login/loginActions.ts`).

## 1. What Proton does, and what Kutup has today

| | Proton | Kutup today |
|---|---|---|
| Authenticator app (TOTP) | yes | yes (`/api/auth/totp/*`, `users.totp_*`) |
| Security keys | up to **4**, named (≤ 128 chars), renamed, removed; a key marked compromised is shown so | none |
| Either factor alone | yes; with keys only, a warning that some apps may not support them | n/a |
| "Require PIN" on keys | an opt-in toggle (user verification required) | n/a |
| Recovery codes | **16**, shown once when TOTP is turned on; one replaces the second factor at sign-in | **none** |
| Lost the second factor | "Lost access to your 2FA device?": a recovery method (recovery phrase, email, SMS) turns 2FA off | the recovery phrase sets a new password, but **2FA stays on**; only an administrator's reset (`DELETE /api/admin/users/{id}/2fa`) gets the user in |

The request's "recovery codes still work" assumes something Kutup doesn't
have. §6 proposes adding them with this work (decision **D2**).

## 2. The crate (decision D1)

The relying-party side (verifying registrations and assertions) is a library
choice.

- **Recommended: [`webauthn_rp`](https://crates.io/crates/webauthn_rp)**
  (MIT/Apache, server-side only). It is pure Rust on the RustCrypto curves we
  already ship (`p256`, `ed25519-dalek`, `rsa`), so nothing new is linked.
  It covers what a second factor needs: non-discoverable credentials, ES256,
  EdDSA and RS256, user presence and verification flags, the signature
  counter, and attestation `none`.
  - Its verification code goes behind one adapter module in kutup-crypto,
    `webauthn` (W2's rule: an adapter names its standard). That adapter is
    the only place it is called, and it gets vectors (a recorded YubiKey and
    a virtual authenticator's registration and assertion).
- **The usual alternative: `webauthn-rs`** (Kanidm's, the most used). Its
  core requires **OpenSSL** (`openssl` and `openssl-sys`, not optional).
  W2's plan denies `openssl` outright (step 7), and the server image builds
  without it today. Taking it means lifting that ban and linking OpenSSL
  into the server.
- Younger pure-Rust options (`passki`, `caden`) are not mature enough to
  trust with sign-in.

## 3. Data

`user_security_keys`, one row per key:

| column | |
|---|---|
| `id` | uuid, the settings page's handle |
| `user_id` | FK, cascade |
| `credential_id` | bytea, unique per user; at most 1023 bytes (the spec's bound) |
| `public_key` | the COSE key, as registered |
| `algorithm` | the COSE algorithm id |
| `sign_count` | bigint; a counter that goes back marks the key compromised (§5) |
| `transports` | text[], passed back in `allowCredentials` |
| `aaguid` | bytea(16), shown nowhere; kept so a known-bad model can be flagged later |
| `name` | 1–128 chars, trimmed; not secret |
| `compromised` | bool |
| `created_at`, `last_used_at` | |

`users.security_keys_require_uv` (bool, default false) is Proton's "Require
PIN" toggle. Ceremony state (the challenge and the options it was issued
with) lives server-side for 5 minutes in `webauthn_ceremonies`, keyed by a
random handle, single use, and bound to the session or pre-auth token that
started it.

## 4. The ceremonies

The relying party id is the deployment's registrable domain
(`kutup.dev`, from `SERVER_URL`), so one key works on every app's host. The
accepted origins are the app origins the server already lists
(`ALLOWED_ORIGINS`). Both are configuration, read once at start and checked
by `check-config`.

**Adding a key** (Account settings → Security → Two-factor authentication):
1. `POST /api/auth/security-keys/register/start`: bearer, plus a grant from
   a reauth of this session, as turning TOTP on takes today (today's `totp`
   grant purpose, renamed `2fa` as it now covers both). It answers
   `PublicKeyCredentialCreationOptions`:
   - `attestation: "none"`; no vendor allowlist, as Proton's;
   - `authenticatorSelection.residentKey: "discouraged"` (not a passkey);
   - `userVerification` from the account's toggle;
   - `excludeCredentials` set to the account's keys;
   - algorithms ES256, EdDSA and RS256.
2. `POST …/register/finish { handle, name, credential }` verifies and stores
   the key. Refusals:
   - `409 securityKeyLimit` past the account's limit (§7);
   - `409 securityKeyExists` for a credential already registered;
   - `400` for a name out of bounds.

   A security-log entry is written, and the account's other sessions are
   told, as TOTP's change does today.

**Renaming:** `PATCH /api/auth/security-keys/{id} { name }`, bearer.
**Removing:** `DELETE /api/auth/security-keys/{id}`, bearer plus a `2fa`
grant; it writes a security-log entry. Removing the last factor turns 2FA off
and says so first, as Proton's modal does.

**Signing in.** OPAQUE's login stays as it is. Its finish answers with a
pre-auth token whenever the account has any second factor. `requires_totp`
becomes a list of the factors the account has:
`requires_second_factor: ["securityKey", "totp", "recoveryCode"]`.
1. `POST /api/auth/login/security-key/start { pre_auth_token }` answers
   `PublicKeyCredentialRequestOptions`, with `allowCredentials` set to the
   account's keys and their transports. The account's credential ids reach
   only someone who has already passed the password step.
2. `POST /api/auth/login/security-key/finish { pre_auth_token, handle,
   credential }` verifies:
   - the challenge, origin and RP id hash;
   - user presence, and user verification when required;
   - the signature under the stored key;
   - the counter (§5).

   On success it issues the session exactly as `/api/auth/login/2fa` does
   for a TOTP code.
- Failures share TOTP's attempt budget and block per pre-auth token (the
  `totp_attempts` and `totp_block_minutes` settings, relabelled "second
  factor").
- The sign-in page offers a security key first when the account has one,
  with "Use authenticator code" and "Use a recovery code" beside it, as
  Proton's does.

**Reauth** (password change, turning factors on or off, deleting the
account): the same second step, with either factor.

## 5. Policy

- **Attestation:** `none`. Kutup doesn't restrict models, and attestation
  certificates would tell the server which model each user owns. This is
  Proton's behaviour.
- **User verification:** `discouraged`, unless the account turned "Require
  PIN" on (then `required`, for adding and for signing in).
- **Counter:** a key reporting a counter at or below the stored one (both
  non-zero) is refused for that sign-in and marked `compromised`, shown so
  in settings as Proton shows its flag. Keys that always report 0 (many
  platform authenticators) are taken as they are.
- **Discoverable credentials (passkeys):** not asked for, and not offered
  for passwordless sign-in.
- **Apps that can't do WebAuthn:** the CLI, and native apps until they do.
  An account with keys and no authenticator app can't sign in there. The
  settings page warns of that, with Proton's wording adapted, when the
  authenticator app is off. The CLI says so when the server asks for a
  factor it can't offer.

## 6. Recovery (decision D2)

Proposed, following Proton:
- **Recovery codes:** 16 single-use codes, generated when the account's first
  second factor is turned on (either kind), shown and downloadable once,
  stored as MACs under a key the server makes for itself (see D2 below).
  - Regenerated on request with a `2fa` grant; the old set goes.
  - At sign-in, a code takes the second factor's place and is spent.
  - Settings show how many are left.
- **Lost 2FA:** the recovery phrase's path (`/api/auth/recover/*`) also turns
  every second factor off, deletes the keys and the codes, and writes it to
  the security log. Proton's "use a recovery method to disable your 2FA"
  works the same way, and today's phrase path otherwise leaves a user with a
  lost authenticator locked out.

If the user prefers, recovery codes can ship in a PR of their own before
the keys. Either way they should land before keys do, so "recovery codes
still work" holds from the first release.

## 7. Settings (administrators, site-wide and per account)

- `securityKeysPerAccount`: 10 at first (Proton allows 4). A higher default
  costs nothing and suits people with a backup key per device.
- The attempt budget: the existing `totp_attempts` and `totp_block_minutes`,
  renamed to the second factor's.
- `webauthnCeremonySeconds`: 300.

All three get admin fields with English and Turkish strings, as every limit
does.

## 8. The UI (en + tr)

- **Account settings → Security, "Two-factor authentication":**
  - the authenticator app toggle;
  - "Security keys", listing each key's name, when it was added and when it
    was last used, a compromised badge, and rename and remove actions;
  - "Add security key", asking for a name and then the browser's prompt;
  - the "Require PIN" toggle;
  - recovery codes: how many are left, and a regenerate action.
- **The sign-in page:** the security-key step with a waiting state (Proton's
  "Awaiting touch" banner), and the factor switch.
- **Errors:** cancelled, timed out, unknown key, a browser without WebAuthn.

## 9. Tests

- **Unit:**
  - the adapter's vectors (registration and assertion, each algorithm);
  - the counter rule;
  - the option builders (exclude/allow lists, UV);
  - the grant gating.
- **Live (server):** a software authenticator in the test crate drives every
  route:
  - register, sign in, rename, remove;
  - the limit, the duplicate, and a wrong origin or RP id;
  - a replayed or expired ceremony, and a counter going backwards;
  - recovery codes (spent once);
  - the phrase path turning 2FA off.
- **Browser:** Playwright's virtual authenticator (Chrome DevTools'
  `WebAuthn.addVirtualAuthenticator`) adds a key in settings and signs in
  with it. A spec in the account suite.

## 10. Order and size

1. Recovery codes and the phrase path turning 2FA off (D2): about 1.5 days.
2. The adapter, the data, and the server ceremonies, with tests: about 2
   days.
3. The settings and sign-in UI, with the browser spec: about 1.5 days.

About **5 days** in all, in two or three PRs. Migrations take the next
numbers above master and the open PRs at the time.

## Decisions (the user, 2026-10-24)

- **D1:** `webauthn_rp`, pure Rust, behind a kutup-crypto adapter, with
  vectors recorded from real browsers and YubiKeys.
- **D2:** as Proton: 16 one-time recovery codes when 2FA is turned on, and
  the recovery phrase's path turns every second factor off. This ships first,
  as its own PR. Built: codes are stored as MACs under a server-made key
  (`server_generated_keys`), not Argon2id hashes. With a salted hash, a
  sign-in would try every one of the account's codes; a keyed MAC finds the
  one typed. Their count is a site setting (`twoFactorRecoveryCodes`).
- **D3:** the key limit's default is 10, an administrators' setting, site-wide
  and per account.
