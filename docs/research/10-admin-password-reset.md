# Admin "password reset" under E2EE

Status: **decided + shipped** (see `docs/api.md` → Admin). This note records the design
and the reasoning so the constraint doesn't get re-litigated per support ticket.

## The constraint

kutup is end-to-end encrypted. A user's password feeds Argon2id (over `kdf_salt`) to
derive the key-encryption-key that unwraps `encrypted_master_key`; the master key in
turn unwraps every collection/file key. **The server only ever stores ciphertext and a
bcrypt hash of the *login key*** — it can verify a login, but it cannot decrypt or
re-encrypt the master key. Therefore an admin can never "reset a password" in the
Web2 sense: setting a new login hash without re-wrapping the master key would lock the
user out of their own data *while still letting them log in* — the worst of both worlds.

Who can recover what:

| Situation | Who can act | Mechanism |
|---|---|---|
| User knows their password | the user | normal login; change password in-app (re-wraps the master key client-side) |
| User forgot the password but has the 24-word recovery phrase | the user | `/auth/recover` — the phrase derives the recovery key, which unwraps the master key; the client submits a fresh bundle wrapped under the new password |
| User lost password **and** phrase | nobody | the data is cryptographically unreachable — by design |
| User never completed first-login setup (`is_first_login = true`) | an admin | no key material exists yet, so rotating the temp password is safe |

## The two admin actions

### 1. Rotate temp password — `POST /api/admin/users/:id/rotate-temp-password`

Scope: **only while `is_first_login = true`.** Such an account has an empty key bundle
(`kdf_salt = ''`) — the temp password gates nothing but the setup flow, so replacing
its bcrypt hash destroys nothing. Use case: the admin created the account, the temp
password never reached the user (lost email, typo), or expired policy-wise.

The endpoint returns `409` for an established account — the UI explains that the user
must self-serve via `/auth/recover` (or be wiped, below). Rotation does not extend to
established users **ever**; that would be a silent data-destruction path.

### 2. Destructive account wipe — `POST /api/admin/users/:id/wipe`

For the unrecoverable case. The admin supplies a new temp password; the server:

1. Purges every collection the user owns (files, versions, assets, S3 blobs, shares —
   the same machinery as a permanent trash purge), including anything they had in the
   trash.
2. Erases the key bundle (`encrypted_master_key`, `encrypted_recovery_key`,
   `encrypted_private_key`, `public_key`, `kdf_salt`, `login_key_salt`, nonces) and
   disables TOTP.
3. Revokes refresh tokens / devices, recomputes `storage_used_bytes` (files the user
   uploaded into *other people's* folders are the folder-owner's data and survive).
4. Resets the account to `is_first_login = true` with the new temp password — same
   state as a freshly admin-created user, keeping email/username/quota.

Guard rails: refused for the break-glass admin; behind an explicit type-the-email
confirmation in the UI; writes a `user.wipe` audit row. The wipe is **total and
irreversible** — that's the point: it's the honest version of "reset password" when
the keys are gone.

## What we deliberately did NOT build

- **Admin sets a new password on an established account** — see the constraint; this
  is cryptographically equivalent to the wipe but pretends not to be. Rejected.
- **Key escrow / admin recovery keys** — breaks the E2EE promise ("the server can
  never read your files"); a kutup with escrow is a different product. Rejected.
- **Emailing the rotated temp password** — deferred until SMTP lands (roadmap →
  SMTP integration); until then admins hand the temp password over out-of-band,
  exactly like at account creation.

## UI copy guidance

Surface the two actions separately — never as one "Reset password" button:

- *Rotate temp password* (enabled only for pending-setup accounts): "This account
  hasn't completed setup. Set a new temporary password and share it with the user."
- *Wipe account…* (destructive zone): "Erases **all** of this user's files and keys —
  this cannot be undone, and kutup's encryption means there is no backdoor. The
  account stays, reset to first-login with a new temporary password. Only for users
  who lost both their password and recovery phrase."
- Everywhere a "forgot password" support case lands first, point at `/auth/recover`:
  the user with a recovery phrase needs no admin at all.
