# Chat ("ileti") — improvements to lock in while the feature is young

**Status:** proposal / working brief for chat phase 2b  
**Baseline:** branch `claude/chat-phase1` (spike ✅, server slice ✅, client
engine + UI not started), design note `11-federated-chat.md`  
**Written for:** the `kutup-chat-core` work and the native-client plans
(`kutup-android`, `kutup-ios`), which pin the chat wire contract

The phase-1/2 design is sound: pinned libsignal (PQXDH + Triple Ratchet,
PQ always-on), a dumb prekey-directory + mailbox server, REST drain/ack as
the source of truth with WS as a latency hint. Nothing below changes that
architecture. These are the things that are **cheap to fix now and breaking
to fix later**, ordered by how much future pain they remove — with three
clients (web/wasm, Android, iOS) about to freeze against this contract.

## 1. Define the inner content schema now (highest value)

Today nothing specifies what's *inside* the ciphertext. `content` is a
libsignal envelope around opaque plaintext — and three clients are about to
invent that plaintext independently. This is the single biggest
cross-client-compatibility risk in the whole feature.

Proposal: a versioned plaintext schema owned by `kutup-chat-proto` (new
`content` module, so server and clients share one definition even though the
server never sees plaintext):

```jsonc
{
  "v": 1,                      // content schema version, independent of suite
  "kind": "text",              // registry below
  "sentAt": "2026-07-13T…Z",   // SENDER clock — serverTimestamp is arrival time only
  "seq": 41,                   // per-sender monotonic counter → per-sender ordering
  "body": { "text": "…" }
}
```

Reserve `kind` values immediately, even though only `text` ships in 2b:

| kind | phase | body sketch |
|---|---|---|
| `text` | 2b | `{text}` |
| `receipt` | later | `{kind: "delivered"\|"read", ids: [seq…]}` — receipts are E2EE content, never a server feature |
| `typing` | later | `{state: "started"\|"stopped"}` (ephemeral; clients may drop) |
| `attachment` | 5 | `{fileId, key, digest, size, mimeType, name}` — pointer into the E2EE drive via tus, per design note §4.4 |
| `groupControl` | 4 | encrypted membership-blob operations |
| `sessionControl` | later | e.g. explicit session-reset notices |

Rules: unknown `kind` → render a "message from a newer client" placeholder,
never drop silently; unknown top-level fields → preserve/ignore; `v` bumps
only for incompatible shape changes. Use JSON now (everything else on the
wire is JSON; envelope bodies are ~100 B so size isn't the constraint);
protobuf can be revisited if attachments/groups make it worth it.

Ordering guidance for UIs: sort by (`sender`, `seq`) within a sender and
interleave by `sentAt` with `serverTimestamp` as tiebreak — never trust
`serverTimestamp` alone (it's arrival order, and federation will make it a
different server's clock).

## 2. Send idempotency (server change, small now)

There is no idempotency key: a client that times out on
`POST /api/chat/users/{username}/messages` and retries stores duplicate
mailbox rows. "Retry only on non-2xx" is not enough over mobile networks
(the request can succeed while the response is lost).

Proposal: client-generated `sendId` (UUID) on `SendMessagesRequest`; server
dedupes per `(sender_user, sender_device, sendId)` within a retention
window (unique index on the mailbox insert batch, `ON CONFLICT DO NOTHING`,
return the original 200). This makes the client's durable outbox (see §6)
safe to retry blindly — the property everything mobile wants.

## 3. Capability advertisement (server change, small now)

Native clients feature-flag chat per server. Today the only way to detect
chat support is probing routes. Add a `chat` block to `GET /api/auth/settings`
(already the public capability endpoint):

```jsonc
"chat": {
  "enabled": true,
  "suites": [1],
  "maxContentBytes": 65536,
  "protocolVersion": 1
}
```

`maxContentBytes` should also be **enforced** on send (today an envelope can
be arbitrarily large) — clients need the number anyway to budget
attachment-pointer payloads, and the cap closes a mailbox-abuse hole.

## 4. Rate-limit bundle fetches per account, not per IP

`GET /api/chat/users/{username}/keys` is authenticated but limited per IP
(30/min default). Mobile clients live behind CGNAT — one busy apartment
block can starve everyone, while a single hostile *account* can still drain
prekey pools from many IPs. Key the limiter on the authenticated user id
(the middleware already has it); keep an IP limiter only as a coarse outer
guard.

## 5. Keep JWTs out of WS query strings where possible

`/api/chat/ws?token=…` exists because browsers can't set headers on
WebSocket. But query strings land in nginx access logs. Two cheap steps:

- Native clients always use `Authorization: Bearer` (both hubs already
  accept it) — write this into the client plans (done).
- For browsers, add a one-time, short-TTL WS ticket
  (`POST /api/chat/ws-ticket` → opaque single-use token accepted only by
  the WS upgrade). Also fixes the same pattern in the collab WS. Until
  then, scrub `token=` in nginx log format.

## 6. `kutup-chat-core` architecture (the phase-2b deliverable)

One crate, three consumers (wasm, Android/UniFFI, iOS/UniFFI). Shape it so
platform differences stay at the edges:

- **Ports, not bindings, for I/O.** The engine depends on `ChatTransport`
  (HTTP + WS) and `ChatDb` traits. Native builds ship reqwest/tungstenite +
  SQLite implementations behind cargo features; wasm supplies fetch/
  WebSocket/IndexedDB adapters. The libsignal store traits are implemented
  *inside* the crate on top of `ChatDb` — never bridged individually across
  FFI (six chatty traits) or reimplemented per platform.
- **The engine owns the invariants.** Decrypt → persist ratchet state +
  plaintext atomically → then ack; dedupe by mailbox UUID; 409
  `DeviceListMismatch` recovery (re-fetch bundles, re-encrypt, resend)
  handled internally; prekey replenishment policy internal with a
  `NeedsAttention` event, not a caller checklist. Callers cannot violate
  ordering because the API doesn't expose the pieces separately.
- **Durable outbox.** Sends enqueue to `ChatDb` before any network; a
  drain loop retries with backoff. Combined with §2's `sendId`, retries are
  exactly-once from the recipient's perspective.
- **One event stream** as the entire read API:
  `MessageReceived | MessageSent | IdentityChanged | DeviceListChanged |
  ConnectionState | NeedsReplenish | SessionReset`. UniFFI exposes it as an
  async callback; wasm as a JS callback. UIs on all three platforms are
  renderers over the same event log.
- **Address type with federation built in.** `ChatAddress { user, domain:
  Option<…>, deviceId }`, parsed/printed as `user@domain` from day one —
  phase 3 then changes routing, not types.
- **Schema-versioned `ChatDb`** with a migrations table from the first
  release; ratchet state is unrecoverable, so botched migrations equal
  broken sessions.
- **libsignal quarantine.** No libsignal type in the public API; the pin
  (v0.97.2 / SPQR v1.5.1) upgrades behind the crate. Enforce
  `NotStale | EstablishedWithPqxdh | Spqr` centrally.
- **Golden fixtures in the crate**: bundle JSON, envelope JSON, content
  schema (§1) round-trips, and a scripted two-party conversation transcript
  — run in native CI *and* wasm CI so the three clients can't drift.

## 7. Forward-compatibility notes for the deferred phases

- **Sealed sender (phase 7):** `DeliveredEnvelope.sender` should be
  `Option<String>` in all client models now, so hiding it later isn't a
  breaking client change.
- **Mailbox retention + device expiry:** decide the policy early (e.g.
  mailbox rows expire after N days; devices unseen for 90 days are expired
  with their prekeys, Signal-style) and add it to the existing server
  sweeper family. Unbounded mailboxes for dead devices are both an abuse
  vector and a fan-out tax on every sender.
- **Push:** no push in the current design. When it comes, the
  self-hosted-friendly answer is UnifiedPush for Android and an opt-in
  hosted APNs relay for iOS, delivering content-free wake pings only
  ("mailbox has mail"). Reserve the concept — a future
  `POST /api/chat/push-subscriptions` — but build nothing yet; the
  drain-on-open model is the v1 story and the clients' plans say so
  honestly.
- **Groups (phase 4):** sender-keys ride the same mailbox; membership blobs
  are client-encrypted state — store them as drive objects (reusing the
  E2EE storage + quota machinery) referenced from `groupControl` messages,
  rather than inventing a new server surface.

## 8. Suggested order for phase 2b

1. Land §1 (content schema) + §2 (sendId) + §3 (capability block) on the
   server branch — three small diffs while nothing depends on the wire.
2. Scaffold `kutup-chat-core` with the ports/events shape from §6 and the
   golden fixtures; wire the spike's crypto flow into it (the spike is the
   reference implementation).
3. Native SQLite `ChatDb` + reqwest/tungstenite transport; wasm adapters
   after (web UI is upstream phase 2b's second half).
4. §4/§5 server hygiene (per-account limiter, WS ticket) any time before
   GA — they don't block clients.
