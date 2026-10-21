# Rate limits administrators change

Status: proposal (second session, 2026-10-21), for the roadmap item from #297
and the user's standing rule: every limit is an administrators' setting in the
admin UI, never a constant.

## Today

- About 40 limits are environment variables read once at start
  (`RATE_LIMIT_*`, `LOGIN_*` in `ratelimit.rs`'s `LIMITS`), each building a
  process-local sliding-window limiter. `RATE_LIMITS_RELAXED` raises them on
  test stacks; an unknown `RATE_LIMIT_*` name stops the server.
- About 15 more are constants in their modules (`calls.rs`, `maps.rs`,
  `live_locations.rs`, `pass_icons.rs`, `mail_images.rs`,
  `chat_link_preview.rs`, `mail_forwardings.rs`, the MLS invite links and
  group calls, one in `middleware.rs`).
- The sealed single-send budgets are constants in the database counters
  (`capability_minute` 120, `capability_day` 10000, `recipient` 120,
  `federation_origin` 600).
- Group, mail-domain, multi-recipient and storage limits are already site
  settings; they stay as they are.

## Proposal

**1. One registry.** Every limit becomes an entry in one list in code: its
key, its environment variable (if it has one), its first value, its bounds,
its window, what it counts per (address, account, pseudonym, group, peer
server, link), the admin page's section and one line saying what it stops.
Every limiter, the module constants and the sealed-send constants included,
is built from its entry; a limit outside the registry is a review error.

**2. Values.** A limit's value is, in order: the administrators' (site setting
`rate_limit.<key>`), else its environment variable (now only its first value,
kept so deployments can seed it), else its default (raised on test stacks as
today). The bounds keep a typo from turning a protection off: at least 1,
never "off", and at most a generous ceiling per limit (100 times its default,
or the counter's own maximum). An unknown `RATE_LIMIT_*` still stops the
server.

**3. Reading them: a snapshot, not the database per request.** Limiters read
their limit from an in-memory snapshot of the current values, so a check
stays a lock and a vector as today.
- The backend that saves a change applies it at once.
- Every backend reloads the snapshot from `site_settings` every 30 seconds
  (one small query), so all agree within that.
- A lowered limit applies at the next check (the window is trimmed against
  it); a raised one at once.

**4. Per-account overrides, only where a limit counts per account.** Feedback,
chat key fetches per account, the groups relay per account, custom-domain
checks, account-head reads, device challenges and rename checks. They are
stored per account (`user_rate_limit_overrides`: user, key, value), read
through the same snapshot, and set on the account's admin page. Limits per
address, pseudonym, group or peer get none: there is no account to hang them
on. Overrides per peer server (federation budgets) can come later on the
federation page.

**5. Across backends.** The windows stay in each process's memory, as today:
with several backends behind a balancer, a client spread over them could get
up to that many times a limit. Kutup runs one backend per server, so this is
stated (self-hosting.md) rather than changed; scaling out later moves the
security-relevant ones (sign-in, registration, recovery) to database counters
like the anonymous budgets. The database budgets are shared already.

**6. The admin UI.** Administration → Rate limits: the limits by section
(sign-in and accounts, Drive and sharing, Chat, groups, Mail, calls and maps,
federation, administration), each with what it counts and per what, its value,
its first value and where that came from (environment or default), a field
and a reset. Every change is audited (`settings.rate_limit`).

**7. Tests.** Unit: the precedence (setting, environment, default, relaxed),
the bounds, every limiter built from the registry (a limiter built otherwise
fails a test). Live: a lowered limit refusing the next request without a
restart, a reset, an account's override, a value out of bounds refused.

## Order

1. The registry and the snapshot, with every existing limit moved into it (no
   behaviour change; the environment still sets them).
2. The site settings, the reload, the admin API and page.
3. The per-account overrides.
