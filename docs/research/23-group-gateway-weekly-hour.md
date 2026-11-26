# 23. Groups failed for the hour before each weekly gateway key change

Found 2026-11-26 while reproducing a master CI failure of
`38-chat-group-device-replaced.spec.ts` (run 45707348531, merge `c88b4c2fb`).
Fixed on `fix/group-gateway-last-hour`.

## Symptom

On a local CI-equivalent stack, every group creation failed between 23:40 and
23:57 UTC on Wednesday 2026-11-25 (specs 36 and 38, 8 of 8), and every run
after midnight passed (8 fresh stacks, 9 runs of spec 38). In the browser
nothing seemed to happen: "Create group" left the dialog open and the error
toast was gone before the test's 90-second wait ended. The trace's last
requests were two `GET /chat/groups/gateway-key` from the creator's page, and
no relay request followed.

## Cause

- A home's gateway key changes weekly, on Unix-epoch weeks
  (`chat_groups/keys.rs`, `EPOCH_SECS`): every **Thursday 00:00 UTC**. The
  served config is issued at the week's start and expires at its end.
- A client fetches the config again when it has less than an hour left
  (`group_client.rs`, `REFRESH_MARGIN_SECS`), to pick up the next one early.
  But it then **refused** the config it held, even when the fetch brought back
  the same one. The home has nothing newer until the change, so every group
  request (create, join, send, sync) failed with "group gateway key is not
  usable", from 23:00 to 24:00 UTC every Wednesday, on every server.
- The home itself still takes the key a day after the change
  (`KEY_OVERLAP_SECS`), so the refusal protected nothing.

## Fix

- **Client** (`kutup-chat-core`, `group_client::call`): the margin only
  triggers the fetch. If the fetch brings nothing newer, the held config is
  used while it verifies (`GatewayCache::valid`), up to its end.
- **Home** (`chat_groups/keys.rs`): the next week's config is served two
  minutes before the change (`SERVE_AHEAD_SECS`, below the format's 5-minute
  skew allowance), and its key is taken from then. A client whose clock runs
  a little ahead isn't left holding a config it finds expired while the home
  still serves it.
- **Not done, on purpose:** changing the configs themselves (a longer
  lifetime, an earlier `issued_at`). A config already seen with the same
  identity and `issued_at` but other content is an equivocation to clients
  (`accept_after`), so clients holding this week's config would have failed
  until the next one.

## Tests

- `group_client::tests::a_config_in_its_last_hour_is_used_until_the_home_rotates`
  and `…a_rotation_in_the_last_hour_is_taken_at_once`.
- `group_harness_tests::group_harness_groups_work_in_the_last_hour_before_a_rotation`:
  real engines create, join and message a group 30 minutes before the
  config's end.
- `chat_groups::keys::tests::every_minute_around_the_change_has_a_current_config_and_key`:
  minute by minute from two hours before the change to two hours after.

The client unit test and the harness test fail without the client change,
at the call and at `create_group`, as the browser did.

## What it does not explain

The CI failure itself was at 22:44 UTC, outside that hour. Its diagnostics show
no server errors, and the spec passes locally. See "CI failure" below.

## CI failure

Run 45707348531 failed in "a group member keeps the group after repairing
their browser" at 22:44 UTC: the group didn't appear in Bob's list on his new
device within 90 seconds of Alice's next message (`openGroup`, `chat.ts:281`).

- Not this bug: 22:44 is over an hour before the change.
- The job's sanitized diagnostics show no request failures, no server error
  lines and no database errors.
- Locally on a CI-equivalent stack it passed every time: 6 of 6 (both tests of
  spec 38, three times), then 10 of 10 (this test alone), then the whole
  `chat-backup` suite (18 of 18) with this fix.
- A possible cause, not shown: when the new device's first catch-up with the
  home fails, it retries after 10, 20, 40 seconds (`CATCH_UP_BACKOFF_MS`),
  which on a slow runner can outlast the test's 90 seconds. If it fails again,
  the numbers-only Chat diagnostics should record the device's catch-up
  attempts before anything is changed.
