# One federation outbox

Status: **approved** (main session, 2026-10-26): build on master now, in the
two PRs below, with these conditions:
- A rejected (final) row reaches the sender's client as a failed delivery of
  that message (Signal's "not delivered"), never a silent drop. Live tests for
  chat and for media.
- Order within a kind and destination is unchanged: a rejected row never lets
  a later row overtake an earlier pending one.
- The migration's sequence high-water marks are tested with rows mid-flight
  (pending and rejected) on both sides, in the two-server gate.
- Both servers deploy together: a receiver on the old code still answers 409
  to the gaps it doesn't record. The PRs say so. This is a build note for
docs/plans/wipe-unification.md, "Not needing the wipe", item 6. The survey
behind it reads master at b2b086a3.

## Today

Four outboxes deliver to peer servers. Each has its own sequences, worker,
backoff and states, and three have their own receiver tables.

| | Plain chat | Sealed chat | Chat media | Rename announces |
|---|---|---|---|---|
| Tables (out) | `chat_federation_outbox`, `_sequences` | `chat_sealed_federation_outbox`, `_sequences` | `chat_media_federation_outbox`, `_sequences` | `rename_announce_outbox` |
| Tables (in) | `chat_federation_inbound_state`, `_transactions` | `chat_sealed_federation_inbound` (`last` is `MAX(sequence)`) | `chat_media_federation_inbound_state`, `_transactions`, `_pending` (a pull lease) | none (applying a chain is idempotent) |
| Sequence | per destination; kept on correction | per destination; a new one on correction | per destination; never corrected | none: the chain's own |
| States | pending, mismatch, delivered | pending, delivered, rejected + class | pending, delivered, rejected + class | delete when done |
| Stored answer | `response` | `answer` | none | none |
| A mismatch | doesn't use up the sequence: **the destination's queue blocks** until the client resends | uses it up | (none) | (none) |
| Sending | the client's request, else a 5 s worker: one head per destination | an advisory-locked flush, batched (64 items, 4 MiB), from the client and the 5 s worker | the client's request, else a 5 s worker: **one row per tick for the whole server** | a 30 s announcer, 8 at once |
| Backoff | 2^n s, at most 300 s, with jitter | 2^n s, at most 300 s, no jitter | 5·2^n s, at most 900 s | 30·2^n s, at most 6 h; dropped after 7 days |
| Kept | delivered rows: `CHAT_SEND_RETENTION_DAYS` (env) | for ever, both sides (the receiver can't prune: its `last` is `MAX(sequence)`) | for ever, both sides | until delivered |
| Admin | counts and wake | none | none | none |

Two defects come from the split:
- **The media receiver records only final successes.** A media offer that the
  destination refuses for good is marked rejected at the origin, but the
  receiver never records its sequence. Every later offer to that server then
  gets a 409 gap, which is retried for ever.
- **A plain chat mismatch blocks the destination's queue**, because the
  receiver doesn't use up the sequence. Sealed chat already uses it up.

## Proposal

**1. One outgoing table, sequences per kind.**

```
federation_outbox (
  id uuid, kind text CHECK (kind IN ('chat','sealed','media','rename')),
  destination text, sequence bigint NULL,   -- NULL for rename (no transport sequence)
  idempotency_key text,                     -- the kind's own: sender+device+sendId,
                                            -- destination+recipient+sendId, user+operation,
                                            -- incarnation+chain sequence
  payload jsonb, state text CHECK (state IN ('pending','delivered','rejected')),
  error_class text, answer jsonb,
  attempts int, next_attempt_at timestamptz, created_at, updated_at,
  UNIQUE (kind, destination, sequence), UNIQUE (kind, idempotency_key))
federation_sequences (kind, destination, next_sequence)
```

- Sequences stay per (kind, destination), as every receiver checks today. A
  counter shared across kinds would leave gaps in each kind's stream and need
  a protocol version bump, so sequences keep their meaning on the wire. (What
  a plain chat mismatch does does change: §3, plain chat's wire version 2.)
- Each kind keeps its rules for `request_id` (the replay check needs new
  bytes to get a new id) and for which answers use up a sequence.

**2. One worker, the kinds as data.** One module:
- per destination, one flush at a time, with the advisory lock that sealed
  chat already uses;
- the kinds as a `Kind` enum, each flushed by its own module's function
  (what a batch is, the endpoint, and how an answer maps to a state), called
  by the one worker;
- one backoff (2^n seconds with jitter, a cap per kind) and one "peer can't
  yet" park (1 h).

The client's request still sends at once, and the worker takes what's left.
Media gets the per-destination flush, rather than one row per tick for the
whole server. The base, the cap, the park, the worker's tick and its heads
per tick are settings (`NumericSetting`), as every limit is.

**3. Every final answer uses up its sequence, and is recorded.** On both
sides, as sealed chat does already:
- **plain chat:** a mismatch is `rejected` (`device_mismatch`), and a
  resend after the client corrects goes out under a new sequence, so no
  queue blocks;
- **media:** the receiver records refusals too, so a refused offer no longer
  blocks the stream with gaps.

Both change how receivers act on things they already receive. All Kutup
servers are ours, so both sides ship together.

**4. One incoming table.**
- `federation_inbound (kind, origin, sequence, transaction_id, digest,
  status, answer, created_at)`, plus `federation_inbound_state (kind, origin,
  last_sequence)`. Sealed chat gets a state row too, so its records can be
  pruned.
- Media's pull lease (`_inbound_pending`) stays its own: it is a reservation,
  not a queue.

**5. Retention and admin.**
- Delivered and rejected rows, and inbound records, are pruned after one
  setting (`federationRecordDays`, 30). The state rows keep each high-water
  mark, so replays past it still answer "already applied".
- Administration → Federation shows pending, rejected and the oldest pending
  row per peer **and per kind**. "Retry now" wakes every kind.

**6. Migration.** One migration:
- creates the tables;
- copies the pending and rejected rows, and the inbound high-water marks,
  across with their sequences;
- drops the eight old tables.

The queues are small and transient, so this needs no wipe. Sequences carry
over unchanged, so peers mid-stream don't see a gap.

## Questions

1. ~~Is the plain (unsealed) chat path still needed?~~ Yes. The chat engine
   falls back to it when a sealed send isn't possible (`deliver_leg`,
   `kutup-chat-core/src/engine.rs`), as Signal does, so it is merged as the
   kind `chat`, not removed.
2. **Build it now on master**, rather than at the squash? It fixes the two
   defects now. I'd say yes.

## Tests

- **Unit:** each kind's answer-to-state mapping; the backoff; that the
  sequence rules match each receiver.
- **Live (the two-server gate):**
  - each kind delivered, replayed and refused;
  - a refused media offer followed by the next one (today it is stuck);
  - a plain chat mismatch no longer blocking the next send;
  - pruning keeps replays answered;
  - the admin counts per kind;
  - the moved rows still delivering after the migration.

## Size

About 4–5 days, in two PRs: (1) the tables, the worker and plain/sealed
chat; (2) media, renames, the admin view and pruning.
