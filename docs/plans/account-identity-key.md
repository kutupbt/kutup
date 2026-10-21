# One identity key per account (Signal's ACI model)

Status: design note for approval (2026-10-22). Docs only: nothing is built
before the main session and the user approve it. Client sections by the third
session, server and key endpoints by the second session.

## Why

Kutup Chat gives every device its own libsignal identity key. Signal gives an
account one identity key (the ACI identity), shared by all its devices, and
everything else per device. Two things now need Signal's model:

- **Multi-recipient group sends** (slice 2, docs/plans/pairwise-groups.md):
  libsignal's sealed sender v2 carries one key share per recipient account,
  sealed to that account's identity key. With per-device identities an
  account's second device can't open its copy.
- **Following the reference.** Copying Signal where it is right: sessions,
  safety-number semantics, re-registration and linking behave as people know
  them from Signal.

The user decided (2026-10-22): one identity key per account, as Signal
("reference signal").

## What stays

Kutup's **account authority** (an Ed25519 key derived from the account master
key, chat-protocol.md §4) stays the root of trust. It signs the account
manifest, safety numbers are computed over it (§5), identity pins and the QR
verification are per authority, and group bindings and pseudonyms derive from
the master key. None of that is tied to a device identity today, and none of
it changes. The authority now signs one more thing: which identity key the
account has.

## The model

| Item | Scope | Signed by | Today |
|---|---|---|---|
| Account authority (Ed25519) | account | (root; from the master key) | same |
| **libsignal identity key pair** | **account** | listed in the manifest the authority signs | per device |
| Registration id | device | — | same |
| Signed EC prekey, last-resort Kyber, one-time Kyber | device | the **account** identity key | the device's identity key |
| One-time EC prekeys | device | (unsigned, as libsignal) | same |
| Sessions | (account, device) | — | same |
| Sender certificate | device id + **account** identity key | server | device identity key |

The identity key pair is **random**, made once per account, and reaches other
devices only inside the provisioning message at linking, as Signal's does. It
is not derived from the master key (Q-a below): the master key unlocks the
account's data, the identity key speaks for it in Chat, and a compromise of
one is not silently a compromise of the other. As in Signal it is **not in
backups**: losing every device and restoring makes a new identity
("re-registration", below).

## Linking a device (Signal's provisioning)

Today a new device needs only the master key (it signs in) and adds itself to
the manifest. From now on a device of an account that has an identity is
**linked by one of its existing devices**, as Signal Desktop is linked by the
phone.

1. **The new device** signs in as today, finds the account has an identity
   (the manifest says so) and shows "Link this device": it opens the
   provisioning socket, gets a one-time address, makes an ephemeral X25519 key
   pair and shows both as a QR code and as a short link to copy (web devices
   often have no camera): `kutup://link?address=…&key=…`.
2. **An existing device** (Settings → Linked devices → Link a new device)
   scans or pastes it, shows the new device's name and asks to confirm, gets a
   one-time link token from its server, and sends the **provisioning
   message**, encrypted to the new device's ephemeral key.
3. **The new device** opens it, checks it (below), makes its registration id
   and prekeys, signs them with the account identity key, and registers with
   the link token. The existing device then signs the new manifest that lists
   it (the authority's signature; any device of the account can make it).

**The provisioning message** (Kutup's `ChatProvisionV1`, canonical JSON, the
fields Kutup needs of Signal's `ProvisionMessage`):

| Field | Signal's | Why |
|---|---|---|
| `account` (AccountRef) | `aci` | the new device checks it is its own account |
| `identityKeyPublic`, `identityKeyPrivate` | `aciIdentityKeyPublic/Private` | the account identity |
| `linkToken` | `provisioningCode` | one-time, from the server |
| `manifestSequence`, `manifestHash` | — | the manifest the identity is listed in (the new device verifies the key against it, under the authority it derives from the master key) |
| `profileKey` | `profileKey` | as Signal |
| `readReceipts`, `typingIndicators` | `readReceipts` | the account's settings, as Signal |
| `provisioningVersion` | `provisioningVersion` | 1 |

The master key is **not** in it (Signal sends `masterKey`/`accountEntropyPool`
because a linked Desktop has no other way to them; a Kutup device already has
the master key from signing in, and a provisioning message that carried it
would make a link stronger than a sign-in).

**The envelope**, Signal's `ProvisioningCipher` exactly: the sender's
ephemeral public key, then `0x01 ‖ IV(16) ‖ AES-256-CBC/PKCS7 ‖
HMAC-SHA256(32)` over version, IV and ciphertext, keys from
`HKDF-SHA256(ECDH(…), salt = 32 zero bytes, info = "Kutup Provisioning
Message v1")` (Signal's info string, with Kutup's name: the two protocols must
never accept each other's messages). The MAC is checked before anything is
decrypted. Implemented once, in `kutup-crypto` (with vectors), used by
chat-core, the web worker and client-ffi.

**What the new device checks before taking it:** the account is its own; the
identity public key matches the private key; the manifest at
`manifestSequence` verifies under the authority this device derives from the
master key and lists exactly that identity key. A provisioning message for
another account, or an identity the authority doesn't list, is refused, so a
server that relays a forged message gains nothing.

**Linking needs an existing device online.** A person whose only device is
gone has two ways, as in Signal: restore (re-registration, below), or, if
another device is only somewhere else, use it later. The "Link this device"
screen says so and offers "I don't have my other devices" (re-registration).

## Device removal

As Signal: removing a device (Settings → Linked devices, or the device signs
itself out of Chat) removes its row, its prekeys and its mailbox, and the
authority signs a manifest without it (`revoke_manifest_device`, as today).
**The identity is not rotated** (Signal doesn't). Peers learn lazily: their
next send gets `409` (extra device), and they drop that device's session; no
safety-number notice.

What a removed device keeps: the identity private key. Without a link token
and the account's sign-in it can't register a device, and the server refuses
its sends (no device row, no session token). It could still open the outer
sealed layer of envelopes that reach it, which none do any more. This is
Signal's exposure, accepted the same way, and said in the threat model. For a
stolen device the person can **reset the account identity** (re-registration
by choice, below), which makes every peer re-establish sessions and shows the
notice.

## Re-registration: a new identity

When the account's identity is lost (every device gone, the person restores
from the recovery phrase or a backup) or the person resets it after a theft:

- the device makes a new identity, re-registers its own keys under it, and
  publishes a manifest listing only itself with the new key; the authority
  signs it (the master key proves it is the account);
- the server takes it as the account's identity and drops the other device
  rows, as Signal's `reclaimAccount` unlinks every device;
- peers see the identity change. **The safety number does not change**: it is
  computed over the account authority, which the person still holds. Peers see
  Signal's notice wording adapted to that: "Ada's keys changed: she
  re-registered or reset them. The safety number is the same." Sessions with
  her are archived and re-established, her sender keys are reset in every group
  (as Signal's `addKeyChange`), and a verified contact stays verified (the
  verification is of the authority).

An identity change **not** signed by the same authority is today's authority
change: quarantined, as now (`quarantine_authority`).

## The manifest

`AccountManifestV2` (a new version and signing domain), signed by the same
authority: the account's `identityKey` (the 33-byte key itself, not a hash:
Q-c) once, and each device as `(deviceId, directChatSuite, registrationId,
mls)`. `verify()` checks the key's form and the signature as V1 does. The
client's trust rules:

- The identity key is pinned with the authority (`ManifestTrust` gains
  `identity_key`). Within one incarnation it changes only in a manifest that
  also removes every other device (re-registration); any other change is
  refused as equivocation.
- `verify_bundle_response` checks every bundle against the one manifest key.
- After an account's first V2 manifest, V1 manifests are refused for it.

## Sessions, sends and receipts in chat-core

- **Identity store:** stays keyed per address; every device of an account
  holds the same key. `save_identity` for a peer's device takes the manifest's
  account key; a different key on any device of the account is an account
  identity change (above), recorded once per account.
- **Reinstall detection** moves from "the device's identity changed" to "the
  device's registration id changed", as Signal: the server's `410
  staleDevices` (already sent on a registration mismatch) archives that
  device's session and fetches its bundle again. `session.rs`'s identity-based
  checks (`seal_device`, `prepare_sealed_session`, `has_sessions_with_all`, the
  stale amendment) follow.
- **`ChatEvent::IdentityChanged`** fires only for an account identity change,
  once per account. That also ends today's false "safety number changed"
  notices on a peer's reinstall (the safety number never changed).
- **Sender certificates** carry the account identity key; on receipt the key
  is checked against the manifest's account key and the device id against its
  devices.
- **Slice 2** then uses libsignal's `sealed_sender_multi_recipient_encrypt` as
  it is (one key share per account), and the server's parse stays libsignal's
  (#297). The `NamedIdentities` adapter stays (bare UUIDs to full names).

## Server and key endpoints

(Second session's section: tables, linking endpoints, key-upload checks, the
V2 manifest on the server, bundles and federation, migration on the server,
limits.)

**Today** (for the record):
- Every `chat_devices` row has its own `identity_key` (baseline migration,
  `chat_devices`), with `UNIQUE (user_id, identity_key)`.
- `POST /api/chat/device` checks only that the fields are base64: it never
  compares identity keys across an account's devices and never verifies a
  signed or Kyber prekey's signature (`handlers/chat.rs`: they are "stored and
  served verbatim for clients to verify").
- The only binding of a device to its account is `AccountManifestV1`, signed
  by the account authority, which the server verifies on publish and checks
  against the registered rows.
- The reserved `device_signature` field is never read.
- There is no linking or provisioning: a new device registers with the
  account's sign-in (JWT) alone.

**Tables** (one migration, `20261021170000`, no wipe):
- `chat_account_identities (user_id PK → users, identity_key text NOT NULL,
  established_manifest_version bigint, created_at)`: one row per account that
  has moved; no row is a legacy account (per-device keys, today's rules).
- `chat_link_tokens (token_hash bytea PK, user_id, issued_by_device int,
  expires_at, used_at)`: single use, only the hash stored.
- `chat_devices.identity_key` stays; for a moved account it must equal the
  account's key (enforced in the apply code, with a test: a cross-table CHECK
  isn't possible). `UNIQUE (user_id, identity_key)` goes, and the register
  call's retry key becomes the link token (or, while legacy, the registration
  id), not the identity key.

**Linking** (Signal's `/v1/devices/provisioning/code`, provisioning socket,
`PUT /v1/devices/link`):
1. The new device signs in (JWT) and opens `GET /api/chat/provisioning`
   (WebSocket); the server gives it a random provisioning address for the
   socket's life and relays exactly one envelope to it, nothing on disk.
2. An existing device of the same account calls `POST /api/chat/link-tokens`
   (device-bound: the JWT and a registered device id, as replenishing keys
   is) and gets a fresh link token.
3. It calls `PUT /api/chat/provisioning/{address}` with the opaque envelope
   (encrypted to the new device's ephemeral key from the QR code). The server
   checks only that both ends are one account and the size, relays it and
   forgets it; no socket listening is a `404`.
4. The new device calls `POST /api/chat/device` with `linkToken` and its keys.

**Key upload checks**, on `POST /api/chat/device` and `PUT /api/chat/keys`,
for a moved account:
- `linkToken` is required on register: unused, unexpired, the same account;
  consumed in the same transaction as the insert.
- `identityKey` equals the account's (33 bytes, a valid point).
- The signed prekey, the last-resort Kyber key and every one-time Kyber key
  verify against the account identity key (libsignal
  `IdentityKey::verify_signature`, as Signal's `PreKeySignatureValidator`);
  otherwise `400 badSignature`.
- `POST /api/chat/keys/check` (Signal's `/v2/keys/check`): a device confirms
  the server's copy of the identity and its repeated-use keys match its own.
- A legacy account: nothing changes until it moves.

**Manifest.** `AccountManifestV2` on publish:
- its identity key equals the `chat_account_identities` row, or establishes
  it on the account's first V2 manifest;
- every listed device row carries that key;
- unlisted rows are deleted, as today;
- after the first V2, V1 is refused for that account (no going back);
- a manifest that changes the identity key must list no other device than
  its publisher's (re-registration): the server then drops the others' rows,
  as Signal's `reclaimAccount` unlinks every device.

**Device expiry** (`jobs.rs`, today deleting rows without a manifest): for a
moved account the expiry only marks the device, and the account's next V2
manifest leaves it out (so the server never drops a device the authority
still lists; Q-b).

**Bundles.** `GET /api/chat/accounts/:id/keys` (local, federated,
anonymous) answers the account identity once, and each device's
registration id and prekeys (Signal's `GET /v2/keys`). A moved account never
has bundles with different identity keys. Federation: `fetch_remote_bundles`
verifies the attached manifest, as `fetch_remote_manifest` already does, and
the bundles' identity against it.

**Sender certificates.** `issue_sender_certificate` reads the account
identity for a moved account (the device row's, which equals it), with the
device id.

**Sends.** Unchanged; #297's multi-recipient route keeps libsignal's parse
(one key share per account), which now just works.

**The migration on the server.**
1. The migration adds the tables; every account starts legacy.
2. `PUT /api/chat/device/{id}/identity`: a device re-registers its own keys
   (identity, signed prekey, last-resort Kyber, one-time Kyber; all verifying
   against the new identity) while its account is legacy, for the caller's
   device only.
3. The account's first V2 manifest establishes the identity; devices it
   doesn't list are deleted (`DevicesChanged`), as today.

**Limits** (site settings): link-token lifetime (10 minutes) and outstanding
tokens per account (3); provisioning envelope size (64 KiB) and provisioning
sockets per address a minute; the migration's sync window (one minute); the
existing device cap (`chat_max_active_devices`).

**Server tests:**
- unit: prekey signature checks (good, bad, wrong key), link tokens (reuse,
  expiry, other account), the V2 publish rules (establish, mismatch, V1 after
  V2, re-registration drops the others);
- live: linking end to end (socket, token, envelope relay, register),
  `keys/check`, the migration's re-register then V2, two devices racing;
- two servers: federated bundles with the account identity, verified against
  the manifest.

## Migration without a wipe

Every existing account has per-device identities. It moves once, by its own
devices, and nothing keeps both formats afterwards.

1. **The first device of the account that opens the new version** (any one;
   the server serialises the step) makes the account identity, re-registers its
   own keys under it (`PUT /api/chat/device/{id}/identity`, allowed only while
   the account is legacy and only for the caller's device), and keeps the
   identity.
2. It sends the identity to **its other devices it already has sessions
   with**, as Signal's `PniChangeNumber` sync message pushes a new key pair to
   linked devices: a hidden pairwise `accountIdentity` sync message (never
   history) with the key pair, the account and the manifest sequence it will
   publish. Each of those devices checks it as a provisioning message, re-keys
   its own prekeys under the identity and re-registers them the same way.
3. After a short window (a site setting; one minute at first) or once all have
   answered, the first device publishes the account's first **V2 manifest**,
   listing itself and the devices whose rows now carry the identity. That
   establishes the account identity on the server; devices that didn't make
   it (offline, an old version) are left out and are linked again later
   through the provisioning flow, keeping their data (their history comes
   back through the encrypted backup, as a new device's does today).
4. Peers see one identity change per account (above), under the same
   authority: the notice, not a warning.

Two devices that start at once: the server takes the first V2 manifest; the
other's publish fails (sequence conflict), it reads the V2 manifest, and if
its own sync message has arrived it re-keys under that identity, otherwise it
waits for it or is linked.

## What changes where

- **kutup-crypto:** the provisioning cipher (with vectors).
- **kutup-chat-proto:** `ChatProvisionV1`, `AccountManifestV2`, the
  `accountIdentity` sync kind, the request types.
- **kutup-chat-core:** `keys::generate` takes the identity instead of making
  one; identity pinning and checks per account; registration-id-based
  reinstall detection; `IdentityChanged` per account; linking (both sides);
  the migration; slice 2 unparked.
- **kutup-client-ffi:** linking and the migration for native apps (not built
  yet; the API is in the bindings).
- **Web:** Settings → Linked devices (link, list, remove), "Link this
  device" (QR and link), the notice on a peer's identity change, the migration
  run on open.
- **Server:** the second session's section.
- **Backups:** unchanged format; docs/chat-backup.md says a restore is a
  re-registration (it was a new device identity before).
- **Groups:** nothing bound to device identities (pseudonyms, bindings and
  `VerifiedMember` derive from the account); sender keys reset on an account
  identity change.
- **Docs:** chat-protocol.md §4.1, §5, §6 and the threat model.

## Tests

- **Rust:**
  - the provisioning cipher against its vectors and against tampering (MAC
    first, wrong account, an identity the manifest doesn't list);
  - V2 manifest verification and the identity pin rules;
  - prekeys signed by the account key;
  - reinstall by registration id;
  - re-registration;
  - the migration with two devices, one offline, two starting at once.
- **Harness:** a three-device account messages and receives on the
  multi-recipient route; linking end to end; removal (`409`, no notice);
  re-registration (notice, sessions re-established, sender keys reset).
- **Browser:** spec 169 (Chat suite): link a second browser with the code,
  message from both, remove one, re-register the other after a reset. The
  two-server gate (spec 34) and the group specs.
- **Server:** the second session's section.

## Open questions

- **Q-a** (answered): random and provisioned, as Signal, not derived from the
  master key.
- **Q-b** (server): a moved account's device expiry goes through a V2 manifest
  too, so the server never drops a device the authority still lists.
- **Q-c** (answered): the manifest carries the key itself.
- **Q-d** (for approval): the identity-change notice wording when the
  authority is the same (above), and whether a verified contact stays verified
  (proposed: yes, verification is of the authority).
- **Q-e** (for approval): the migration's sync window (one minute) and that
  devices left out are linked again rather than kept as legacy.
