# OPAQUE sign-in

Status: agreed 2026-10-13, before the wipe release. The crypto layer
(`kutup_crypto::opaque`, its WASM objects and vectors) is built. The server
endpoints, storage, login state, lockout and limits, and the web and CLI flows,
land together on top of it.

This plan fixes everything a client and the server must agree on byte for byte.

## Today, and what goes

The client runs Argon2id(password, salt, params) to get a root, and HKDF splits it
into a KEK and a login key. The server stores `login_key_hash` and hands out the salt
and params in a preflight, with fakes for unknown names; the master key envelope is
sealed under the KEK.
- Anyone who reads the database can run an offline dictionary attack on
  `login_key_hash`.
- The preflight gives out the salt (and the key binding) before any proof.

OPAQUE (RFC 9807) removes both: the server stores a record that is useless without
an online exchange, and the client learns nothing it could test offline before the
server answers.

**Removed from `users`:** `login_key_hash`, `account_protection_salt`, the `argon_*`
columns, and the preflight. **Added:** `opaque_record` (bytea) and `opaque_suite`
(smallint, 1).

## 1. The suite (Rust, `kutup_crypto::opaque`)

The crate is `opaque-ke` 4.0.1. That is a final release: crates.io lists
4.1.0-pre.2 as the only pre-release. It is pinned with `=4.0.1`, with
`default-features = false` and exactly the features `ristretto255`, `argon2` and
`std` (serde is not needed: messages are serialized with the crate's own
`serialize()`/`deserialize()`). The repository has no `cargo deny` or `cargo vet`
set-up yet, so the pin plus `Cargo.lock` is the control; adding `cargo deny` is
a roadmap line, not part of this change. Suite 1:

| Part | Choice |
|---|---|
| OPRF | ristretto255-SHA512 |
| Key exchange | `TripleDh<Ristretto255, Sha512>` |
| KSF | Argon2id, m = 64 MiB, t = 3, p = 1 (today's V1 cost), output 64 bytes, salt-free as the RFC's KSF is |
| Identities | the defaults (client and server public keys), with no usernames |

- **Why no usernames:** an identity in the transcript would bind the record to a name,
  and a rename would break sign-in. The server key is pinned anyway (see 4).
- **The KSF parameters are part of the suite, not per account.** A future suite
  (stronger KSF) is a new `opaque_suite`, re-registered at the account's next
  sign-in from the password it just used. This keeps the CLAUDE.md rule (Argon2
  parameters are persisted per account, as the suite id) without a per-account
  parameter set the server could lower.
- **`Context`:** `"kutup/opaque/v1"`, bound into the transcript, so a record or
  message from another protocol or version cannot be replayed into this one.

## 2. Credential identifier: the key binding

The server derives each account's OPRF key from `oprf_seed` and a credential
identifier. That identifier must never change, so it is the account's
`key_binding` (random, fixed for the account's life, already what every sealed
record binds), never the username.
- **Registration:** the client draws the key binding, as today, and sends it with
  the registration request.
- **Sign-in by name:** the server maps the name to the key binding, then runs
  `ServerLogin::start`.
- **An unknown name:** `ServerLogin::start` with no record gives OPAQUE's fake
  answer. The identifier is then `"unknown:" ‖ canonical name`, keyed by the server's
  `oprf_seed`, so the same name always gets the same fake. The answer looks like a
  real one to the client, and lockout treats it the same .

## 3. Export key → master key

`export_key` (64 bytes) is the only thing the client takes away from a sign-in. It
never reaches the server.
- `kek = HKDF-SHA256(salt = "kutup/opaque/export/v1\0", ikm = export_key,
  info = "kutup/opaque/master-key-kek/v1\0" ‖ key_binding)`, 32 bytes.
- The master key envelope stays `AccountEnvelopePurpose::PasswordMasterKey`, sealed
  under `kek` and bound to `key_binding`, as today. Only where `kek` comes from
  changes.
- Any later use of the export key gets its own HKDF info.
- **The envelope comes back only after the client finishes the exchange.** The
  finish response carries the access session and the master key envelope (and the
  recovery envelope's metadata as today). Before that, the client holds nothing it
  could test a password guess against.
- **Recovery is unchanged:** the 24-word path seals the same master key under its
  own key (`RecoveryMasterKey`) and proves itself with the recovery proof.

## 4. Pinning the server

`ServerLogin` signs with the server's long-term OPAQUE key. The client has no prior
key to compare it with, so a malicious server is not stopped by OPAQUE alone. It
cannot read the password, but it could run a fresh registration under its own key.
- The client stores the server's OPAQUE public key at registration, in the
  registration record, which OPAQUE already binds through `server_public_key` in
  the envelope.
- On every sign-in, `ClientLogin::finish` verifies the server's key against the one
  in the user's envelope. A server that swapped its key fails the sign-in.
- **Rotating the server key** therefore means re-registering every account at
  its next sign-in. Each stored record keeps the key id of the setup that answers it.

## 5. Where the server keeps its secrets

**The setup is sealed under a secret outside the database.** OPAQUE only stops
offline attacks while the OPRF seed is out of reach. A database dump or backup
(nightly to R2) holding `ServerSetup` would give back today's offline Argon2
attack. So:
- `ServerSetup` (OPRF seed, server keypair, fake keypair) is stored in
  `opaque_server_setups (key_id smallint PK, sealed_setup bytea, created_at,
  retired_at)`, sealed with XChaCha20-Poly1305 under a key that is neither in the
  database nor in its backups. The AAD is
  `"kutup/opaque-setup/v1\0" ‖ key_id`.
- **The key** is `OPAQUE_SETUP_KEYS`: a comma list of `id:base64(32 bytes)`, in env
  or a secret file, loaded and checked like `JWT_SECRET` (`check-config`: present,
  well formed, at least one key). The highest id is the current one.
- **First start:** the server generates a setup and seals it under the current key.
- **Rotation:** add a key with a higher id. New registrations use it. Records keep
  their `opaque_server_key_id` and are re-registered at their next sign-in, and a
  retired setup is dropped once no record names it.
  - **If the rotation is because the old key leaked,** records still on the old
    setup stay attackable offline until each account signs in again and is
    re-registered. An admin can hasten that by ending those accounts' sessions.
    This trade-off is accepted and named; nothing more is built.
- **Never derived from `JWT_SECRET`:** rotating the JWT secret must not force every
  account to re-register.
- **Losing the key loses every password:** each account would then sign in with its
  recovery phrase and set a new password. `docs/self-hosting.md` says so, and says to
  back the key up separately from the database (and never in the same place).
- **Production:** kutup.dev needs this new secret in `/opt/kutup/.env`. The main
  session asks the user before the wipe deploy.

**The rest:**
- The login state between start and finish (`ServerLogin`) lives in
  `opaque_login_states (login_id uuid PK, credential: key binding or fake name,
  state bytea, purpose, client key, expires_at = now + 2 min)`. It is deleted at
  finish (single use) and swept on expiry. The client never holds the server's
  state.
- **`login/start` does work and writes a row:**
  - lockout and the per-source limits are checked before any OPAQUE computation;
  - pending login ids are capped at 5 per name and 20 per source;
  - past either cap, the oldest goes.
- The session version (`auth_check::credential_epoch`) becomes a hash of
  `opaque_record`, so a password change still ends the other sessions.

## 6. Messages (wire)

All binary values are canonical base64. OPAQUE messages are the crate's
`serialize()` bytes.

**Registration is stateless on the server.** `RegistrationResponse` is derived
from the OPRF seed and the credential identifier, so nothing is stored between
start and finish.

- **`POST /api/auth/opaque/register/start`** `{ keyBinding, registrationRequest, grant? }`
  → `{ registrationResponse, serverKeyId }`.
  - **A key binding that already has a record:** refused (`403 registrationNotAllowed`)
    unless `grant` is a re-registration grant for that account (see the grant list
    below).
  - **A new key binding:** must be unused (unique constraint on
    `users.key_binding`; a clash is `409 keyBindingTaken`, and the client draws
    another).
- **New account:** `POST /api/auth/register` carries `{ …the sign-up fields,
  keyBinding, opaqueRecord, opaqueServerKeyId }` instead of `loginKey`, the salt and
  the Argon2 fields. The server checks that the key binding is still unused, in the
  transaction that creates the account.
- **`POST /api/auth/opaque/register/finish`** (re-registration only)
  `{ grant, keyBinding, opaqueRecord, opaqueServerKeyId, masterKeyEnvelope }`.
  - It swaps the record and the password envelope in one transaction and consumes
    the grant.
  - The credential epoch changes, which ends other sessions except the caller's.
  - On recovery, the recovery envelope stays as it is.
- **`POST /api/auth/login/start`** `{ name, credentialRequest, purpose: "session" | "reauth" }`
  → `{ loginId, credentialResponse, suite: 1 }`.
  - A name that is no account, or one held after a rename, gets the fake answer.
  - `reauth` needs a signed-in caller and its name.
- **`POST /api/auth/login/finish`** `{ loginId, credentialFinalization }` → for `session`:
  `{ …the session as today, keyBinding, masterKeyEnvelope, … }`; for `reauth`:
  `{ grant, expiresAt }`.

**Grants** (`auth_check`): an opaque token, `kg1_` followed by
base64url of 32 random bytes, stored as its SHA-256.
- Each is bound to the session id, the account and one purpose: `pass`,
  `passwordChange`, `totp`, `deleteAccount`, `recovery`, `adminReset`.
- Single use: consumed by the action it was issued for.
- It expires in 5 minutes or less.
- It is never accepted as a session or a bearer token.
- Recovery issues a `recovery` grant from the recovery proof, unchanged.
- Re-registration takes `passwordChange`, `recovery` or `adminReset`, for that
  account's key binding only.

**Reauth** (sensitive actions, Pass PIN setup and unlock reset, today's
`verify_account_login_key`) is login start and finish with `purpose: "reauth"`,
counted against the account's ceiling like a sign-in.

**Password change:** a `passwordChange` grant, then register/start and
register/finish for the same key binding, with the master key re-sealed under the
new export key.

**Recovery:** a `recovery` grant from the recovery proof, then a re-registration.
The new password's export key seals the master key the phrase opened.

**Admin temporary passwords.** Today an admin reset is already an account reset:
`admin.rs` wipes the account's keys, shares, Chat manifest head, devices and
pins, and the next setup starts a new incarnation. OPAQUE keeps that:
- **Reset:** the admin's client registers the temporary password under a new
  random key binding with an `adminReset` grant, issued by the admin's own reauth
  for that target. The user signs in with it, sets up new keys, and re-registers
  under their own password and key binding at setup.
- **What the user loses:** what was encrypted under the old master key is gone.
  It can be recovered only with the old 24-word phrase, and only where the recovery
  envelope survives the reset. Today's reset deletes it, so nothing can be
  recovered.
- **The admin UI says this before the reset,** in en and tr: "Resetting erases
  this account's encrypted data (files, mail, chats, pins). The person starts again
  with a new identity; people who verified them will see a change. This cannot be
  undone." The current dialog's wording is checked against this.
- **`rotate_temp_password`** (an account that has not finished setup) is the same
  registration with a new temporary password. It changes nothing else.
- **The bootstrap admin** from `ADMIN_ACCOUNT` is registered by the server running
  the client half itself at startup: the only place the server ever sees a
  password. That is already true today.

**Renames:**
- **Signing in by an old name during the hold** is refused: the old name is only a
  mail alias then. The answer is the same fake as an unknown name.
- **Lockout** is keyed by the canonical name, through the hold and release and
  after a new account takes the name. The window is never reset by that change, so
  a name in its lockout window stays in it. Whether a name's answer is fake or real
  changes only when an account is created under it, as for any new name.

## 7. WASM and the web

- The client's OPAQUE state stays inside WASM objects: `OpaqueRegistration` and
  `OpaqueLogin`, with `start()` returning the request and `finish(response)`
  returning the record or finalization. JavaScript never sees the
  password-derived state, the export key or the KEK.
  - `openMasterKey(envelope, keyBinding)` returns the master key itself
    (canonical base64), as the session layer has always held it.
    `sealMasterKey(masterKey, keyBinding)` returns the password envelope.
  - Both wipe the export key once they succeed. `close()` wipes it in any case:
    a reauth opens nothing, and a sign-in given up is closed.
  - A finish runs once.
- Every OPAQUE message, record, login state and sealed setup is accepted only in
  its exact canonical encoding (opaque-ke's own parsers ignore trailing bytes).
- `OpaqueServer` (the server half) is in the WASM module for the vector tests
  and tools. It holds no secret a browser has, and a page has no setup key to
  open. Moving it behind a build feature would need a second WASM build for the
  tests: a roadmap line, not done.
- opaque-ke's `ServerSetup` does not wipe itself when dropped. The server wipes
  its own copies (the serialized setup, the export keys); the setup in the
  server process's memory is inside the server's trust boundary.
- Argon2id at 64 MiB runs in the existing crypto worker, as today, so the page
  doesn't freeze.
- **Web flows:** sign-in, the reauth dialog, password change, recovery and the
  admin temporary password, all through `@kutup/session` / the account app. The
  preflight disappears.

## 8. CLI

`kutup login`, `kutup register`, `kutup recover` and password change use the same
Rust module directly. `KUTUP_PASSWORD` still works. Profiles keep no OPAQUE state.

## 9. Vectors and tests

- **Vectors** (`opaque-v1.json`), with fixed seeds through the RFC's deterministic
  hooks (also a password change: the same key binding, a new record, the old export
  key no longer opens the new envelope):
  - registration request, response and record;
  - KE1, KE2, KE3 for the right password;
  - the export key and KEK;
  - the master key envelope;
  - a wrong password (KE3 fails, no export key);
  - a swapped server key (the client refuses);
  - the fake answer for an unknown name (stable per name).
- They run from Rust and WASM.
- **Live:**
  - sign-in, a wrong password, an unknown name (the same shape, the same timing
    class and lockout);
  - password change ending other sessions;
  - recovery;
  - an admin temporary password and the first sign-in;
  - reauth for Pass.
- **Browser:** the existing sign-in specs, with the preflight gone.

## Agreed (2026-10-13)

1. `users` gets `opaque_record`, `opaque_suite` and `opaque_server_key_id`. Setups
   are in `opaque_server_setups`, sealed (section 5).
2. The login state is a row under `loginId`: 2 minutes, single use, swept.
3. Reauth is login purpose `reauth`, through `auth_check`. It returns a grant and
   also closes #176 N5: reauth and PIN misses count against the account ceiling.
4. Lockout keys an unknown name by its canonical form, as the fake does.

**Native clients later:** 64 MiB Argon2id is fine on phones, and the suite table
handles a later bump.

