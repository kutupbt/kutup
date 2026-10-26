# One settings registry, with per-account values

Status: **proposed** (second session, 2026-10-26). This is a build note for
docs/plans/wipe-unification.md, "Not needing the wipe", item 4. It adds the
per-account values that the #359 review (the 8 Drive settings) and the #361
review (the security-key limit) asked for. It also follows the standing rule
that every limit is an administrators' setting, site-wide and per account.

## Today

- **Site settings.** 44 `NumericSetting`s (46 with #361) (`site_settings.rs`: key, field,
  default, min, max), each read with `.load()`, one query per read. There are
  no per-account values.
- **Rate limits.** 88 limits in their own registry (`ratelimit/registry.rs`),
  read from an in-memory snapshot that is reloaded every 30 seconds. They do
  have per-account values (`user_rate_limit_overrides`,
  docs/plans/admin-rate-limits.md §4), set on the account's admin page.
- **Admin UI.** The admin page copies each setting's min and max by hand
  (`ServerSettingsPage.tsx`), so the two lists can drift.
- **Drive limits.** `GET /api/drive/limits` answers the site's values only.

## Proposal

**1. The registry says which settings an account may have its own value
for.** `NumericSetting` gains three fields:
- `section`, for the admin page;
- `unit` (bytes, count or seconds), for showing the value;
- `per_account`, following rate limits §4: only where the setting limits one
  account.

**2. One table of per-account values.** `user_setting_overrides (user_id,
key, value, updated_at)` holds both registries. Rate limits are keyed
`rate_limit.<key>`, as `site_settings` already names them. The rows of
`user_rate_limit_overrides` move into it, and that table goes. The rate-limit
snapshot reads the new table.

**3. One accessor.** `setting.load_for(executor, account)` answers, in order:
- the account's own value;
- else the site's;
- else the default.

Each step is checked against the bounds, in one query. Every read that limits
one account goes through it. A test scans `src/` for `.load(` on a
per-account setting outside an allowlist, as `only_this_module_charges` does
for storage.

**4. Which settings, and whose account:**
- **Drive uploads.** `driveUploadMaxBytes` and `driveVersionMaxBytes` apply to
  the uploading account. A peer server's objects keep the site value
  (`max_drive_object_bytes`).
- **Drive streaming.** `driveStreamMaxBytes`, `driveStreamCacheBlocks`,
  `driveStreamReadaheadBlocks`, `driveStreamMaxConcurrent` and
  `driveStreamBlobFallbackMaxBytes` apply to the account reading. They reach
  its client through `/api/drive/limits`.
- **Range answers.** `driveStreamResponseMaxBytes` applies to the account
  reading, in this server's own range answers. Federated parts, and links
  opened without an account, keep the site value: the relay clamps to its
  own limit before signing (#359).
- **Security keys.** `securityKeysPerAccount` applies to the account.
- **Also per account, because the mechanism costs nothing more:**
  - `calendarsPerAccount`, `calendarAlarmsPerAccount` and
    `calendarPushSubscriptionsPerAccount`;
  - `chatLinkTokensPerAccount`, `chatMaxActiveDevices` and
    `chatProvisioningSocketsPerAccount`;
  - `twoFactorRecoveryCodes`.

  Settings that limit a request, a page, a batch or the server stay
  site-only.

**5. The admin API, fed by the registry:**
- `GET /api/admin/settings/registry` lists every numeric setting with its
  key, field, section, unit, default, bounds, `perAccount`, its value, and
  whether administrators set it. Server settings builds its numeric fields
  from this list, so there are no hand-copied bounds.
- `GET /api/admin/users/{id}/limits` lists what the account gets: each
  per-account setting and each per-account rate limit, with its value, the
  site's value, and whether the account has its own.
- `PUT /api/admin/users/{id}/limits/{key}` takes `{ value | null }`, checks
  the bounds, and is audited as `user.setting` or `user.rate_limit`. It
  replaces `/api/admin/users/{id}/rate-limits` (pre-production, so a
  breaking change is fine).

**6. The admin UI.** The account's admin page gets one "Limits" section: the
per-account settings and rate limits together, each with the site's value, a
field and a reset, in English and Turkish.

## Not in this PR (later slices of item 4)

- Moving the ad-hoc `site_settings` keys into `NumericSetting`: group link
  joins, the Pass vault size, name holds, avatar limits, delivery retention
  and outside sending.
- The server's 119 `const MAX_*`, each becoming a setting where it is a
  policy.
- The MLS limits, which the MLS removal deletes.
- Merging the three counter tables, at the squash.

Each later slice moves a group of limits and adds them to the registry.

## Also in this PR

`scripts/test-mail-domains-browser.sh` honours an existing
`KUTUP_HTTPS_PORT` (default 38443) for the app URLs, `--resolve` and
`E2E_APP_ORIGIN`, so it runs in any test lane.

## Tests

- **Unit:**
  - the precedence: own value, then the site's, then the default;
  - a bound-breaking value at any step falls through to the next;
  - the per-account scan;
  - the registry list matches `numeric_settings()`.
- **Live:**
  - an account with a lowered upload limit is refused a larger upload,
    while another account isn't;
  - `/api/drive/limits` shows the account's values;
  - a raised security-key limit lets that account add one more key;
  - a reset;
  - a value out of bounds, or a key that isn't per account: `400`;
  - each change in the audit log;
  - the moved rate-limit overrides still apply.
- **Browser:** the account's admin page sets and resets a limit (a spec in
  the account suite).

## Size

About 2 days. One migration (the table, and the rows moved), numbered above
master and the open PRs.
