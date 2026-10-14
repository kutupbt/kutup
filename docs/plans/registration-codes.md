# Registration modes and referral codes

**Status:** built for the clean-slate release (October 2026). Beta testers
sign up on their own with codes administrators make. It replaced the old
open/closed setting (`site_settings.registration_enabled`). Decided with the
user: only administrators make codes, each code's number of uses is chosen when
it is made (a number, or unlimited), and the code each account signed up with
is recorded and shown to administrators.

## 1. Registration mode

A single site setting, `registration_mode`, replaces `registration_enabled`:

| Mode | Who can register | A code |
|---|---|---|
| `on` | anyone | optional; if given it must be valid, and it is recorded (who invited whom) and uses up one use |
| `code` | only with a valid referral code | required |
| `off` | nobody (the bootstrap admin comes from `ADMIN_ACCOUNT`, as today) | not accepted either |

- **Clean-slate default:** `off`. The admin signs in (`ADMIN_ACCOUNT`), switches to
  `code` and creates codes. With no row in the database, the mode is `off`.
- **Typed config:** an optional `REGISTRATION_MODE` env var sets the mode a fresh
  database starts in, so self-hosters can bootstrap `on`. It is validated in the
  boot-time Config, and written once at startup into a database that has no mode
  (`INSERT … ON CONFLICT DO NOTHING`); after that the stored mode is the only
  source, and a missing row reads as `off`.
- **The old switch:** the migration deletes `registration_enabled` and writes no
  mode, so the baseline folded from the chain seeds neither and a database takes
  `REGISTRATION_MODE` (default `off`) at its next start; nothing opens by itself.
  No database keeps the old switch across the wipe, so it is not translated. The
  down restores the switch as open only when the mode was `on`.
- **Public settings:** `GET /api/auth/settings` returns `registrationMode`
  (`on|code|off`) in place of `registrationEnabled`.
- **Admin:** a three-way choice on Server settings, replacing the switch.

## 2. Codes

- **Format:**
  - 20 Crockford base32 characters (100 bits), in groups: `7KQ2M-9XD4T-PAV3W-8HCNR`.
  - Input is case-insensitive. Spaces and dashes are ignored, and I/L read as 1, O
    as 0 (Crockford decoding), so a code read over the phone works.
- **Stored:** never the code itself.
  - The table keeps `code_hash = HMAC-SHA256(k, canonical code)`, unique. `k` is
    a key the server makes once and keeps in its database (`server_keys`,
    `registration-codes`), rotated with no other secret: a dump of the codes
    table alone gives no usable codes.
  - Looking up the hash is the comparison, so there is no timing oracle on a stored
    string.
  - A `hint` (the last 4 characters) lets the admin recognise a code in the list.
  - `k` comes from a `server_keys` label. Losing or rotating it makes every
    outstanding code invalid, which is acceptable: the admin makes new ones.
- **Shown once:** the code is shown only at creation, like an API token, with
  "Copy" and "Copy sign-up link".
  - The link is `https://account.<domain>/register#code=…`. The code is in the
    fragment, so it never reaches server or proxy logs.
  - The admin list shows only the hint. The plaintext code appears only in the
    create response.

## 3. Data (one migration, or folded into the baseline with the squash)

```
registration_codes (
  id uuid PK, code_hash bytea UNIQUE NOT NULL, hint text NOT NULL,
  note text NOT NULL DEFAULT '' (≤ 200 chars),
  created_by uuid REFERENCES users ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NULL,           -- NULL: no expiry
  max_uses integer NULL CHECK (max_uses BETWEEN 1 AND 100000),  -- NULL: unlimited
  uses integer NOT NULL DEFAULT 0 CHECK (uses >= 0),
  revoked_at timestamptz NULL, revoked_by uuid NULL REFERENCES users ON DELETE SET NULL,
  CHECK (max_uses IS NULL OR uses <= max_uses)
)
registration_code_uses (
  code_id uuid REFERENCES registration_codes ON DELETE CASCADE,
  user_id uuid UNIQUE REFERENCES users ON DELETE CASCADE,
  used_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (code_id, user_id)
)
```

Who invited whom is `registration_code_uses.user_id` → `registration_codes.created_by`.

## 4. Registration

- `POST /api/auth/register` takes an optional `registrationCode`.
- **Mode check:**
  - `off`: 403 `registrationClosed`.
  - `code` with no code: 403 `registrationCodeRequired`.
- **Redeeming a code** happens in the transaction that creates the user, right after
  the user row (the code row's lock orders concurrent sign-ups; a refusal rolls
  both back):
  ```sql
  UPDATE registration_codes SET uses = uses + 1
   WHERE code_hash = $1 AND revoked_at IS NULL
     AND (expires_at IS NULL OR expires_at > now())
     AND (max_uses IS NULL OR uses < max_uses)
  RETURNING id
  ```
  - No row: 403 `registrationCodeInvalid`, one answer for unknown, expired,
    revoked and used up (no oracle).
  - Otherwise: insert the user and the `registration_code_uses` row, then commit.
  - Any later failure rolls the use back.
  - The row lock on the code serialises redemptions, so with `max_uses = 1` and N
    parallel sign-ups exactly one succeeds.
- **Checking a code early:** `POST /api/auth/registration-code/check {code}` →
  204 or the same 403. The sign-up page uses it before the costly key derivation.
  It never consumes a use and shares the rate limit below.
- **Rate limits** (through the auth-check layer, second session's):
  - failed code attempts per IP, e.g. 20 per hour (`RATE_LIMIT_CODE_ATTEMPTS_PER_HOUR`,
    relaxed in test mode);
  - every call of the check endpoint per IP, valid or not, under a limit of its own;
  - the existing per-IP register limit stays.
- **CLI:** `kutup register` reads the server's mode first: `off` stops at once; `code`
  takes `KUTUP_REGISTRATION_CODE`, else asks for the code with a hidden prompt (no
  argument, which shell history and `ps` keep), and checks it before any key work;
  `on` sends `KUTUP_REGISTRATION_CODE` when set.

## 5. Admin

- **API** (admin only, audited):
  - `POST /api/admin/registration-codes {note, expiresAt|null, maxUses|null}` →
    `{id, code, hint, …}`. The only time the code is returned.
  - `GET /api/admin/registration-codes`: id, hint, note, createdBy, createdAt,
    expiresAt, maxUses, uses, revokedAt, and state (`active|expired|used_up|revoked`).
  - `POST /api/admin/registration-codes/{id}/revoke`, effective at once.
    "Expire now" is the same action.
  - `GET /api/admin/registration-codes/{id}/uses`: username and time.
  - A user's admin page shows "Invited with code …, created by …".
- **Audit log:**
  - `registration_code.created` {id, hint, maxUses, expiresAt};
  - `registration_code.revoked` {id};
  - signing up is not an administrator's action, so it is not in the audit log;
    `registration_code_uses` records it;
  - `site.setting_changed` for the mode.
- **UI** (Account app, Administration):
  - a "Referral codes" page: list, create dialog (note, expiry presets
    1 day/7 days/30 days/never, max uses 1/5/25/unlimited/custom), the code shown
    once, revoke, who used it;
  - Server settings gets the three-way mode.
  - Every string in en and tr (tr: "Davet kodu").
- **Sign-up page:**
  - mode `code`: a required "Referral code" field;
  - mode `on`: a collapsed "Have a referral code?";
  - mode `off`: the "registration is closed" message;
  - prefilled from `#code=`, checked on blur with the generic message.

## 6. Decided

- **Only administrators make codes.** There are no invites by regular users.
- **Who signed up with which code** is recorded (`registration_code_uses`) and
  shown to administrators: on the account's page, and in a code's "used by"
  list.
- **Uses** are chosen per code when it is made: one, a number (up to 100000), or
  unlimited (`max_uses` NULL).

## 7. Not affected

- **Federation:** codes are local to a server.
- **Mail:** the address is created at registration as today.
- **Chat, Drive, Pass:** nothing.
- **Stored formats:** none, so no wipe dependency beyond the release timing.

## 8. Tests

- **Live** (`registration_codes_live`):
  - redemption in each mode;
  - `max_uses = 1` with 8 parallel sign-ups gives exactly 1;
  - expired, revoked and used-up codes give the same 403 body;
  - mode `off` refuses even a valid code;
  - `check` consumes nothing;
  - uses are listed and audited;
  - a failed sign-up after redemption rolls the use back;
  - rate limit on wrong codes.
- **Unit:** code generation, canonical decoding (case, dashes, I/L/O), the HMAC.
- **Browser spec:** the admin creates a code, a new user signs up with the link
  (`#code=`), and the code shows 1 use. A wrong code shows the generic message.
- **CLI:** `register` with `KUTUP_REGISTRATION_CODE` against the live stack.

## 9. Who builds what (proposal)

- **Me:**
  - the codes module and migration;
  - admin API, UI and audit;
  - the redemption step;
  - the sign-up page field;
  - the CLI flag;
  - tests.
- **Second session:** reviews the touch points in their area:
  - the `register` handler (the mode check, and the redemption inside its
    transaction);
  - `REGISTRATION_MODE` in the typed Config;
  - the auth-check rate limiter for code attempts;
  - error codes in the shared list (`registrationClosed`,
    `registrationCodeRequired`, `registrationCodeInvalid`).
- **Base:** slate/integration.
