# Chat history transfer V1

Status: implementation contract for the V1 web-device-continuity blocker.

## Goal and boundary

A newly registered browser installation can receive a bounded copy of locally
readable Chat history from an existing active installation. The homeserver may
relay the exchange, but learns neither history plaintext nor a reusable history
key.

The transfer copies display history and attachment descriptors. It does **not**
copy libsignal sessions, MLS group state, prekeys, identity private keys,
mailbox cursors, pending outboxes, delivery capabilities, or account secrets.
The new installation remains an independent cryptographic device and joins
future direct and MLS delivery through the existing manifest workflows.

If no existing installation or separately designed E2EE backup survives, old
device-addressed ciphertext is unrecoverable. The client must say so; an empty
local database is not evidence that the account has no prior messages.

## Authentication and user consent

Both devices MUST appear in the same verified `AccountManifestV1` sequence.
The requesting device creates a fresh X25519 key pair, random 32-byte nonce and
UUID transfer ID, then signs the canonical request with its manifest-bound
libsignal identity key. An existing device verifies that signature and shows an
explicit approval prompt containing the requesting device label, device ID,
request age, and a short code derived from the request hash.

After approval, the existing device creates its own fresh X25519 key pair and
signs a canonical acceptance that commits to the exact request hash, both
device IDs, both ephemeral public keys, the manifest sequence and the selected
snapshot bounds. The requesting device verifies the responder signature
against the same manifest before accepting any frame.

Account login or possession of the password-derived master key alone does not
silently approve history release from an existing installation. The user must
approve on that installation. One accepted transfer ID can be consumed once.

## Key schedule and frames

The devices compute ephemeral X25519 DH and derive one transfer key:

```text
transcriptHash = SHA-256(canonicalSignedRequest || canonicalSignedAcceptance)
transferKey = HKDF-SHA256(
  salt = transcriptHash,
  IKM = X25519(requestPrivate, responsePublic),
  info = "kutup/chat/history-transfer-key/v1\0"
)[0..32]
```

Each frame is independently sealed with XChaCha20-Poly1305 under
`transferKey`, a fresh random 24-byte nonce, and canonical AAD binding the
transfer ID, transcript hash, frame index, final flag and plaintext length.
Frames must be strictly contiguous from zero. Repeated indexes are accepted
only when their nonce and ciphertext digest are byte-for-byte identical.

The final decrypted frame commits to the ordered plaintext-frame digest,
record count and media byte count. The importer verifies this commitment
before atomically exposing imported rows.

The relay stores only signed handshake objects and opaque frames. V1 bounds
are: 15-minute handshake/relay expiry, 256 KiB maximum plaintext per frame,
1,024 frames, 100,000 history records, and 256 MiB total plaintext. Servers may
configure smaller limits but may not advertise larger V1 limits.

## Snapshot contents and import

The first plaintext frame is a header binding the account, source device,
destination device, manifest sequence, transcript hash, creation time and
selected history/media cutoffs. Middle frames contain normalized records or
recent cached media chunks. A normalized record contains a stable source
record ID, typed conversation, canonical sender, sender device ID, direction,
canonical `ChatContent`, timestamp and delivery state.

Attachment descriptors already contain the keys required to retrieve immutable
Chat media. Cached media bytes are optional and bounded; absence does not make
the message record invalid.

Import is transactional and idempotent on `(transferId, sourceRecordId)`. Rows
land in an imported-history store, not the live ratchet/session tables. Normal
live and imported history are merged for display by timestamp and stable ID.
No imported row advances a mailbox cursor, creates a session, sends a receipt,
or triggers an MLS state transition.

## Relay lifecycle

1. The new installation posts its signed request.
2. Other live devices receive only a wake-up hint and fetch the request through
   an authenticated account-local route.
3. One existing device explicitly accepts; other acceptances conflict.
4. The existing device uploads opaque indexed frames. The new device drains
   and verifies them, then posts a signed completion receipt.
5. Completion or expiry deletes all relay frames and ephemeral handshake state.
   Revoking either device cancels every transfer involving it.

The server enforces account/device membership, expiry, size, frame-count and
single-responder constraints, but never validates archive plaintext.

## Implementation slices

1. **Implemented:** freeze canonical handshake/frame wire types and adversarial
   validation vectors in `kutup-chat-proto`.
2. **Implemented:** add bounded account-local relay tables/routes, expiry cleanup
   and device revocation cancellation.
3. **Implemented:** core signing, signature verification,
   X25519/HKDF/XChaCha framing, and the immutable normalized imported-history
   store for SQLite and IndexedDB.
4. Add WASM/transport bindings and the new/existing-device approval UI.
5. Extend the two-browser federation harness with success, denial, expiry,
   tampering, replay, interrupted-resume and no-surviving-device cases.
