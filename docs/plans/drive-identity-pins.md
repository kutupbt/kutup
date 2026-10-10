# Drive identity pins

**Status:** planned 2026-10-10; built on branch `fix/drive-identity-pins`.

## Problem

A named Drive share (a folder, or one file) is sealed to the recipient's
Drive encryption key and signed with the sender's Drive share-signing key
(`named_share`). Today both public keys come from the server, beside the
share or the person lookup, and nothing ties them to the account they claim
to belong to:

- A recipient checks a share's signature with whatever signing key the server
  sends with it. A compromised server can sign a share "from Alice" with a key
  of its own (an attacker's file that looks like hers).
- A sender seals to whatever encryption key the server returns for Bob. A
  compromised server can return a key of its own and read what is shared.

An account's identity is its **account authority** (an Ed25519 key derived
from the master key; the account's `incarnationId` is a hash of it). Chat
checks Drive keys through the authority-signed account manifest and pins
every peer's authority (`kutup-chat-core::manifest`), but only accounts that
opened Chat have a manifest, and Chat's pins live on Chat's origin, out of
Drive's reach. `docs/drive-security-threat-model.md` requires the Drive
signer and recipient keys to be bound to a pinned account; the code does not
do it.

## How Proton Drive does it (reference)

`kutup-references/WebClients` (2026-10): Drive trusts the keys Proton's key
server returns for an address (`getAllPublicKeys`, internal addresses,
falling back to unverified keys). It uses no Key Transparency, no pinned
contact keys and no fingerprint check. Signature failures never block:
the inviter's signature is not checked on accept in the legacy client, the
SDK path shows the *claimed* sharer instead of the verified one, a file with
a bad signature gets a lock icon and a Details explanation, and only a
download asks "Download anyway?". Trust rests on the server's directory.

Kutup goes further where its threat model asks for it (keys bound to an
account the client remembers) and follows Proton's handling of a failure
(warn, never block), as decided on 2026-10-10.

## Decisions

- **On a mismatch: warn, do not block.** A share whose sender cannot be
  verified, or whose identity changed, still opens, with a warning on the
  item, on the file page and in the share dialog. Sharing *to* someone whose
  identity changed or cannot be verified asks first.
- **Pins are synced in the account**, not kept per app or per browser: one
  encrypted list, readable by every app (Drive, Office, Photos; Chat later),
  surviving a new browser.

## Design

### 1. The Drive key binding (`kutup-crypto::identity`)

`DriveKeyBindingV1`: the account authority signs

```
"kutup/drive-key-binding/v1\0" ‖ len‖account ‖ incarnationId(32) ‖
authorityPublicKey(32) ‖ suite(u16) ‖ driveHpkePublicKey(32) ‖
driveShareSigningPublicKey(32)
```

`account` is the canonical `username@server`. Drive keys and the authority
derive from the master key, so a binding is made once per account lifetime
(an administrative wipe starts a new one). Verification is strict Ed25519
over these bytes, plus `incarnationId == hash(authority)`. Vectors in
`tests/vectors/drive_key_binding_v1.json`, exported to WASM.

### 2. Server

- `users.drive_key_binding` (signature, base64), required at registration and
  first-login setup, checked against the stored keys before storage.
- `PUT /api/auth/drive-key-binding`: an account made before this signs its
  binding at its next sign-in (the account app does it).
- Every response that hands out someone's Drive keys also hands out
  `accountAuthorityPublicKey` and `driveKeyBinding`: person lookups, named
  share rows (sender, owner), file share rows (sharer, owner), access lists
  (members), and the federated account lookup, whose remote server returns
  the remote account's binding (`kutup-federation-proto`).

### 3. Identity pins (`kutup-crypto::identity_pins`)

`IdentityPinsV1`: a canonical list of `{ account, incarnationId,
authorityPublicKey, state: seen | verified, firstSeen, previous[] }`, sealed
with XChaCha20-Poly1305 under a key derived from the master key
(`kutup/identity-pins/v1`), bound to the owner's account and a revision.
Stored by the server, opaque, at `GET / PUT /api/account/identity-pins`
with a compare-and-swap on the revision (two apps writing at once merge and
retry). Each browser remembers the highest revision it has seen, so the
server cannot quietly hand back an older list.

### 4. Checking a person (web)

`checkIdentity(person)` in `@kutup/drive-core/identity`:

| What the server gave | Result |
|---|---|
| No binding (an account that has not signed in since) | `unproven`: shown, not alarming ("keys not confirmed yet") |
| A binding that does not verify, or keys that differ from it | `invalid`: red warning |
| Valid, no pin yet | pinned as `seen`, then `ok` |
| Valid, matches the pin | `ok` (or `verified`) |
| Valid, a different incarnation than pinned | `changed`: red warning, until accepted |

Used where Drive trusts a key: opening a named share (the sharer's signing
key and the owner's), and sharing to someone (their encryption key). The UI:
a warning icon on the item in Shared with me and the Office home, a banner on
the file page, a notice and a confirmation in the share dialogs, and
"Accept new identity" to re-pin after a genuine reset (an administrator's
wipe).

### 5. Later

- Chat reads and writes the same synced pins instead of its origin's own.
- Comparing an identity in person (Chat's safety numbers) marks a pin
  `verified` for Drive too.
- The CLI checks bindings and uses the synced pins.

## Slices

1. Crypto: `DriveKeyBindingV1` and `IdentityPinsV1`, vectors, WASM.
2. Server: binding column, registration and setup, backfill endpoint, the
   fields on every key-carrying response, federation, pins storage.
3. Web: binding at registration, setup and sign-in; pins; checks; the UI in
   Drive, Office and Photos; strings in English and Turkish.
4. Tests: crypto vectors, server live tests (a forged signer and a swapped
   recipient key are caught), browser specs (a changed identity warns, a
   genuine reset is accepted).
5. Docs: threat model, architecture, API.
