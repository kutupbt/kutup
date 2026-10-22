# Native chat bindings

**Status:** shared FFI boundary implemented. The native apps that will use it
are not started; each product (Drive, Chat, Mail …) will be its own app in its
own repository ([`mobile-build.md`](mobile-build.md)).

`kutup-client-ffi` is the stable Swift/Kotlin boundary around
`kutup-chat-core`. It is a standalone crate so libsignal, UniFFI, and the
mobile SQLCipher artifact do not become dependencies of the Kutup server or
CLI workspace.

## Ownership boundary

Rust owns:

- Signal registration, PQXDH/Triple Ratchet sessions, prekeys, and ciphertext.
- The account's Chat identity (linking, re-registration, the identity
  distribution), signed account manifests, complete hash-linked history,
  durable TOFU/verified/quarantined pins, and pair-bound safety numbers.
- Endpoint paths, request/response JSON, exact-device recovery, durable outbox,
  mailbox journal/decrypt/ack ordering, and history mapping.
- Note to Self routing and encrypted sent-transcript synchronization for all
  outgoing direct messages. Native UI code always uses the same `sendText` API;
  it never builds a transcript or chooses linked devices itself.
- The account-scoped SQLCipher connection and all ratchet/message state.

Swift/Kotlin owns:

- An authenticated `ChatHttpClient` implemented with URLSession or OkHttp.
  Its base URL is the selected server's `/api`; Rust supplies relative paths
  beginning with `/chat`. The adapter applies bearer authentication, the
  existing single-flight refresh policy, JSON content type, cancellation, and
  the normal TLS policy.
- A WebSocket hint connection. Connect/foreground/message events call
  `reconcile()`; REST drain is authoritative.
- Keychain/Keystore protection, lifecycle, notifications, and presentation.

No endpoint DTO or libsignal type is implemented in Swift or Kotlin. Unknown
content remains available as `ChatContentRecord.bodyJson` so a newer content
kind is not discarded.

## Threading model

The shared core intentionally uses `!Send` libsignal store futures so it can
also compile to browser WASM. UniFFI async exports require `Send` futures.
`NativeChatClient` bridges those constraints with one dedicated worker thread
per active account:

1. The worker exclusively owns the engine and SQLCipher connection.
2. Generated async/suspend methods submit typed commands and await one-shot
   responses.
3. Concurrent calls are serialized in arrival order; ratchets never run through
   multiple database connections or foreign executor threads.
4. `shutdown()` stops and joins the worker, dropping the engine and its
   authority key deterministically. Releasing the final native handle is a
   fallback that performs the same cleanup.

Foreign HTTP methods remain async. UniFFI starts URLSession/OkHttp work in the
platform runtime and completes the Rust worker's pending future through its
foreign-future callback.

## Secure opening lifecycle

Generate a random 32-byte chat database key at the first account unlock, wrap
it with the platform vault, and reuse it for that account installation. Call:

```text
openNativeChatClient(
  databasePath,
  databaseKey,
  account,            // aci:<uuid>@<server>
  accountMasterKey,
  keyBinding,
  authenticatedHttpClient
)
```

The account has one Chat identity shared by its devices
(docs/plans/account-identity-key.md). Opening opens the device this database
holds, finishes a registration it started, or re-registers when the account
has no Chat identity yet (its first device). When another device of the
account holds the identity it fails with `LinkRequired`: show "Link this
device" with a `NativeLinkingDevice` (`linkCode(address)` once the
provisioning socket gave its address), then call
`openLinkedNativeChatClient(linking, envelopeJson, …same arguments)` with the
envelope the socket delivers. `reregisterNativeChatClient(…)` is "I don't have
my other devices": a new identity, and the account's other devices leave.
The HTTP adapter sends `ChatHttpRequest.chatDevice`, when present, as the
`X-Kutup-Chat-Device` header.

`keyBinding` is the account's key binding (the session's `envelopeBinding`,
a UUID v4): the account's own seals, such as its synced identity pin list,
bind it, never the username or address.

`username` and `serverName` form the client's account, `username@serverName`;
the client runs as that canonical address (`user()` returns it) and every
account it names is fully qualified. The native store has one schema version
and refuses a database written with another one.

The FFI crate has only a SQLCipher feature and fails if SQLCipher is absent or
the key cannot unlock an existing database. Input vectors are zeroized in Rust
after SQLCipher unlock and account-authority derivation. The platform must
clear its temporary `Data`/`ByteArray` copies after the call.

The database must be app-private, excluded from backup, and protected as
documented in the native plans:

- iOS: `NSFileProtectionComplete`, backup exclusion, key wrapped by Keychain.
- Android: private app storage, backup exclusion, key wrapped by Android
  Keystore after biometric/device-credential unlock.

Opening is restart-safe. A partially registered install reuses its persisted
registration request; an installed device reopens without registering again.
The call publishes or confirms the account-signed local manifest before
returning. A server response can create only a gray TOFU pin. Native UI obtains
`safetyNumber(peer)` (libsignal's fingerprint over both account identity
keys, QR `kutup://verify/v4/`) and passes the scanned peer QR to
`verifySafetyNumber(peer, payload)`; Rust performs the exact comparison.
`setIdentityVerified(peer, identityKey, verified)` marks the compared identity
verified, or clears it, after the person compared the numbers by eye; it is
refused if the identity moved on meanwhile. There is no blind native
`verifyAuthority` operation.

## Generated API

The exported object currently covers the phase-2b native engine contract:

- `sendText`, `reconcile`, `history`, `pendingSendCount`
- `maintainPrekeys`, `setMailboxRetentionDays`, `syncManifest`
- `inboundAttention`, `quarantineInbound`, `resolveDeadLetter`
- `safetyNumber`, `verifySafetyNumber`, `setIdentityVerified`
- `linkDevice(code, settings)` (Linked devices → Link a new device),
  `resetIdentity(remove)` (remove a lost device and reset the identity)
- `shutdown` for logout/account-lock cleanup

Swift receives `async throws`; Kotlin receives `suspend` functions and typed
`KutupChatException` failures. `ChatHttpClient.execute` is also async/suspend.
Call `maintainPrekeys` at start, on reconnect and periodically (the web client
does so hourly): it tops up one-time prekeys and rotates the signed and
last-resort pair every two days (`docs/chat-protocol.md`, "Prekeys"). Pass the
server's `mailboxRetentionDays` from chat capabilities to
`setMailboxRetentionDays` first; until then replaced prekeys are kept 30 days
plus a margin.
`ChatReceiveReport.synced` contains logical send ids imported as outgoing
history from another linked device; callers normally refresh `history()` after
every reconcile, just as they do for newly received messages.

## Generate bindings

Host generation requires the pinned Rust toolchain and `protoc`:

```bash
scripts/generate-native-bindings.sh /tmp/kutup-native-bindings
```

This produces Swift source/header/modulemap and Kotlin source from the compiled
library metadata. Generated files are build artifacts and are not committed to
this repository.

Remaining packaging work is to cross-compile the same crate into:

- an XCFramework for `aarch64-apple-ios` and `aarch64-apple-ios-sim`, wrapped by
  the `KutupCore` Swift package;
- Android `.so` libraries for `arm64-v8a` and `x86_64`, bundled with the Kotlin
  source in an AAR and checked for 16 KiB page alignment.
