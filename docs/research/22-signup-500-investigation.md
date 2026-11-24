# An intermittent 500 on sign-up in master CI (open, 2026-11-24)

**Status: cause not yet found.** This records the evidence, what was ruled
out and why, and the diagnostics added so the next failure names its cause.

## Symptom

Now and then a Mail browser spec on master fails in the shared sign-up helper
(`tests/e2e/fixtures/apps.ts`, the "Confirm and continue" step). The helper's
diagnostic line (added for exactly this) reads
`ACCOUNT DIAGNOSTIC submit button="Confirm and continue" attempt=1 path=/register … authStatuses=500`:
the first try of the request failed with a 500, not a 409 that the client
retries. Seen:

| Run | Spec | When |
|---|---|---|
| 44913523883, attempt 1 | 102 (undo send) | its third spec, shortly after start |
| 45252066193, attempt 1 | 102 | about 30 s after the backend started, after specs 100 and 101 |
| 45399061921, attempt 1 | 163 (forwarding) | about 3 minutes after start, after spec 113 |

Each passed on re-run. So the failure is not tied to start-up or to one spec.

## The request

The only `/api/v1/auth/*` call in that step is `POST /api/v1/auth/register`
(`registerAndSignIn` in `frontend/apps/account/src/features/auth/flows.ts`).
The server side is `register` in `crates/kutup-server/src/handlers/auth.rs`,
then `signed_in_answer` and `issue_tokens_and_respond`.

## Ruled out

By reading the code:
- duplicate keys: the accounts insert maps a unique violation to 409, and the
  username and address claims use `ON CONFLICT` and answer 409;
- the CHECK constraints on accounts and addresses (nothing depends on random
  input), `kutup_unb64`, the recovery-proof hash, the security-event insert
  and its CHECK lists, data-key creation and `server_keys::load_or_create`
  (both race-safe), quota and settings reads, and DDL at run time (none with
  the single database role CI uses);
- concurrency in the tests: browser specs run with one worker, so sign-ups
  never overlap.

Not yet read: `entitlements::set`, `legal::current`, `load_keyring`,
`account_roots::load`, `load_all_in`, `two_factor::factors`, `grants::issue`.

By running it (no 500 seen):
- 40 sequential sign-ups, a full Mail suite, and 11 fresh-stack cycles with
  the backend and Postgres capped at 1.5 and 0.5 CPU while `pg_stat_activity`
  was sampled every 0.5 s (no statement over 500 ms).

## What the diagnostics showed so far

CI's artifacts are sanitized: no message text, values or queries. #437 added
counted error classes; on run 45399061921 they read:
- backend: `status=unknown database_other count=1`;
- Postgres: `severity=ERROR other count=1`;
- activity: no deadlocks, no serialization conflicts, no waiting locks,
  6 rollbacks.

So one statement failed in Postgres with an error class the classifier did
not know (not a constraint, deadlock, serialization, lock or statement
timeout, or pool timeout). `status=unknown` was a collector bug: the server's
log puts colour codes between a field and its value.

## Diagnostics now in place (#446)

- The server logs a fixed label on a database 500: the SQLSTATE
  (`database error (sqlstate=XXXXX)`) or sqlx's error type when Postgres said
  nothing (`sqlx=PoolTimedOut`, `sqlx=RowNotFound`, …).
- CI's browser jobs run Postgres with `log_line_prefix` carrying `%e`
  (`docker-compose.ci-diagnostics.yml`, CI only, so no deployment's Postgres
  is recreated).
- The collector strips colour codes and writes, per failed request, the
  status, label and class, and per Postgres error the SQLSTATE, the
  statement's first keyword and its table (schema identifiers only).

## Next step

On the next failure, read `backend-request-failures.txt` and
`postgres-database-errors.txt` in the run's sanitized results: the
`sqlstate=` value and the statement's table should name the cause.
