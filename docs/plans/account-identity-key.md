# One identity key per account (Signal's ACI model)

Status: design note for approval (2026-10-22), revised after the main
session's review against Signal-Desktop and Signal-Server. Docs only:
nothing is built before the main session and the user approve it. Client
sections by the third session, server and key endpoints by the second.

## Why

Kutup Chat gives every device its own libsignal identity key. Signal gives an
account one identity key (the ACI identity), shared by all its devices, and
everything else per device. Two things now need Signal's model:

- **Multi-recipient group sends** (slice 2, docs/plans/pairwise-groups.md):
  libsignal's sealed sender v2 carries one key share per recipient account,
  sealed to that account's identity key. With per-device identities an
  account's second device can't open its copy.
- **Following the reference.** Sessions, safety-number semantics,
  re-registration and linking behave as people know them from Signal.

The user decided (2026-10-22): one identity key per account, as Signal
("reference signal").

**No PNI.** Signal has a second identity per account, the PNI's, because
accounts have phone numbers that change and are shared with people who
shouldn't learn the ACI. Kutup has no phone numbers: an account is reached
by its permanent account id and username, so there is one identity (the
ACI's) and nothing of Signal's PNI machinery but the one pattern below (its
identity distribution), reused for the account identity.

## What stays, and what follows Signal

Kutup's **account authority** (an Ed25519 key derived from the account master
key, chat-protocol.md §4) stays the root of the account: it signs the
account manifest (now also which identity key the account has and each
device's registration id), the synced identity pins keep it (manifest
continuity, and Drive's sharing, which is per authority), and group bindings
and pseudonyms derive from the master key.

**Safety numbers and verification follow Signal** (the user, 2026-10-22:
"reference signal directly"): they move from the authority to the account
identity key. The safety number is libsignal's `NumericFingerprint` over each
side's account id and account identity key, as Signal's (which uses the ACI
and the ACI identity key); the QR code carries that fingerprint (a new
version of `kutup://verify`). A contact's verified state is kept with the
identity key it verified, and synced to the account's own devices in the
Chat contact record (docs/plans/chat-contacts-sync.md), as Signal keeps
`identityKey` and `identityState` in its `ContactRecord`. So an identity reset
changes the safety number and clears verified, exactly as in Signal; linking
or removing a device does neither.

## The model

| Item | Scope | Signed by | Today |
|---|---|---|---|
| Account authority (Ed25519) | account | (root; from the master key) | same |
| **libsignal identity key pair** | **account** | listed in the V2 manifest the authority signs | per device |
| Registration id | device | listed in the V2 manifest | per device, unsigned |
| Signed EC prekey, last-resort Kyber, one-time Kyber | device | the **account** identity key | the device's identity key |
| One-time EC prekeys | device | (unsigned, as libsignal) | same |
| Device credential | device | (a random secret, stored hashed by the server) | none (any session of the account) |
| Sessions | (account, device) | — | same |
| Sender certificate | device id + **account** identity key | server | device identity key |

The identity key pair is **random**, made once per account, and reaches other
devices only inside an encrypted provisioning or distribution message from a
device that has it, as Signal's does. It is not derived from the master key:
the master key unlocks the account's data, the identity key speaks for it in
Chat. As in Signal it is **not in backups** (below).

**The identity rule** (client and server, everywhere): the account identity
changes **only** with an authority-signed identity distribution (below), or
with a re-registration that drops every other device. A peer that sees any
other identity change refuses it as it refuses an authority change today
(quarantine); the server refuses every other way to set it.

**Any device links and removes.** Signal lets only the primary device link or
remove devices, because only the primary holds the account's registration
credentials. Every Kutup device holds the master key (it signs in with it),
so every device can sign the account's manifest; making one of them primary
would protect nothing and lose the account's Chat with that one device. So
any device of the account may link a new one, remove one, or distribute a new
identity.

## The manifest (V2)

`AccountManifestV2`, a new version and signing domain, signed by the same
authority, **replacing V1** (no account keeps a V1 manifest: the deploy below
starts every account's Chat afresh). It carries everything V1 carries, with
the identity moved up to the account:

| Field | From V1 | Note |
|---|---|---|
| `account` (AccountRef) | yes | |
| `incarnationId` | yes | an account reset is a new incarnation, as today |
| `sequence`, `previousHash` | yes | the chain: +1, linked to the previous manifest |
| Drive keys (as V1) | yes | unchanged |
| `issuedAt`, `authorityKeyId`, `selfAuthorityKey`, `signature` | yes | as V1, under the V2 domain |
| **`identityKey`** | new | the account's libsignal identity key (33 bytes) itself, not a hash |
| `devices[]`: `deviceId`, `directChatSuite`, **`registrationId`** | yes, without `identityKey` | the registration id is now part of what the authority vouches for |
| `devices[].mls` | yes | dropped if the MLS removal lands first |

V1 manifests are no longer accepted, by the server or by any client.

**Registration ids live in the signed manifest.** A bundle, or a server's
`409`/`410`, that disagrees with the manifest is refused, never silently
answered with a new session:

- peers send only to the devices the account's verified manifest lists, with
  their listed registration ids;
- a `409` naming a device the manifest doesn't list (missing) or omitting one
  it lists (extra) makes the client fetch the account's manifest; a newer
  verified one is taken and the send redone; a server that keeps answering
  against the verified manifest is refused (the send waits and fails with the
  usual "not delivered");
- a `410` (stale registration) is taken only if a newer verified manifest
  lists the new registration id; then that device's session is archived and
  re-established;
- a reinstall of a device is therefore a new manifest (the reinstalled device
  is linked again, with a new registration id, and the linking device signs
  the manifest that lists it).

## Linking a device (Signal's provisioning)

Today a new device needs only the master key (it signs in) and adds itself to
the manifest. From now on a device of an account that has an identity is
**linked by one of its existing devices**, as Signal Desktop is linked by a
phone.

1. **The new device** signs in as today, finds the account has an identity
   (the manifest says so) and shows "Link this device": it opens the
   provisioning socket, gets a one-time address, makes an ephemeral X25519 key
   pair and shows both as a QR code and as a code to copy (web devices often
   have no camera): `kutup://link?address=…&key=…`.
2. **An existing device** (Settings → Linked devices → Link a new device)
   scans or pastes it, shows the new device's name and asks to confirm, gets a
   one-time link token, and sends the **provisioning message**, encrypted to
   the new device's ephemeral key.
3. **The new device** opens it, checks it (below), makes its registration id,
   prekeys and device credential, signs the prekeys with the account identity
   key, and registers with the link token. The linking device then signs the
   manifest that lists it with its registration id (it learns it from the
   registration answer the new device sends back in a sync message, or from the
   server's device list, checked against the new device's signed prekeys).

**The pasted code.** The code carries the provisioning address and the new
device's ephemeral key, so whoever holds it can be sent the account identity
if the person confirms. The screen says: copy it only to your own other
device, typed by hand or sent to yourself over Kutup Chat or Mail, never
through another app or person. The new device's name shown on the confirming
device comes from the server; it is shown to help, never as proof. The QR code
needs no such care (it goes screen to camera).

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
| `profileSuite` | — | the profile key's suite, as every Kutup profile key carries |
| `provisioningVersion` | `provisioningVersion` | 1 |

Signal's `userAgent` is left out (the server already tells the linking device
the new device's name), and so are its backup keys (`ephemeralBackupKey`,
`mediaRootBackupKey`, `accountEntropyPool`): Kutup's Chat backup and media
keys come from the account master key, which every device has from signing
in.

The master key is **not** in it (Signal sends `masterKey`/`accountEntropyPool`
because a linked Desktop has no other way to them; a Kutup device already has
the master key from signing in, and a provisioning message that carried it
would make a link stronger than a sign-in).

**The envelope**, Signal's `ProvisioningCipher` exactly: the sender's
ephemeral public key, then `0x01 ‖ IV(16) ‖ AES-256-CBC/PKCS7 ‖
HMAC-SHA256(32)` over version, IV and ciphertext, keys from
`HKDF-SHA256(ECDH(…), salt = 32 zero bytes, info = "Kutup Provisioning
Message v1")` (Signal's construction, Kutup's info string: the two protocols
must never accept each other's messages). The MAC is checked before anything
is decrypted. Implemented once, in `kutup-crypto` (with vectors), used by
chat-core, the web worker and client-ffi.

**What the new device checks before taking it:** the account is its own; the
identity public key matches the private key; the manifest at
`manifestSequence` verifies under the authority this device derives from the
master key and lists exactly that identity key. A provisioning message for
another account, or an identity the authority doesn't list, is refused, so a
server that relays a forged message gains nothing.

**Linking needs an existing device online.** The "Link this device" screen
says so first: "Open Kutup on a device you already use and link this one".
Only behind that does it offer "I don't have my other devices", which is a
re-registration (below) and says what it costs.

## The identity distribution (Signal's PNI distribution, for the account identity)

One mechanism moves an account to a new identity while keeping its devices:
Signal's PNI identity-key distribution (`PhoneNumberIdentityKeyDistributionRequest`
to `AccountControllerV2`'s distribution route, with a `PniChangeNumber` sync
to each device), applied to the account identity. Kutup uses it for **"reset identity, keep
my devices"** (a lost or stolen device, or a device that wants a new
identity).

1. One device of the account makes a new identity key pair, and for **every**
   device it keeps (itself included): a signed prekey and a last-resort
   Kyber key, signed by the new identity, and a new registration id.
2. It sends one request (server section): the new identity, each device's
   keys and registration id, a `deviceMessages` sync for each other device,
   and the next **V2 manifest** listing the identity and every device it keeps
   with its new registration id (a lost device is simply not listed: the
   server drops it in the same transaction).
3. The sync to each device (`accountIdentity`, Signal's `PniChangeNumber`):
   the identity key pair, that device's signed prekey and last-resort Kyber
   key (private parts), its registration id, and the manifest's sequence and
   hash. It is sealed pairwise to the device, under its current session, as
   any sync message; hidden, never history.
4. The server checks every signature and the device set (the devices the
   manifest lists, all of them the account's: `409`/`410` otherwise), and in
   one transaction swaps every listed device's identity, keys and
   registration id, drops the unlisted ones, clears the account's one-time EC
   and Kyber keys, publishes the manifest and queues the syncs.
5. Each other device applies its sync when it next connects: it checks it as a
   provisioning message (the manifest lists exactly this identity and its own
   registration id), takes the identity, its keys and its registration id, and
   uploads its own one-time keys. Until it has, its peers fall back to the
   signed and last-resort keys, as for any device without one-time keys.

Peers see one account identity change (below).

## Device removal, and a lost or stolen device

**Removal** is Signal's: removing a device (Settings → Linked devices, or the
device signs itself out of Chat) removes its row, its prekeys, its mailbox and
its credential, and the device signs a manifest without it. The identity is
not rotated. Peers learn through the manifest (above); no notice.

**A lost or stolen device** keeps the identity private key, and, since every
Kutup device has it, the account master key. Removing it from the list stops
its credential, so it can't receive or send as a device; but with the identity
key it could open sealed envelopes that still reach it (none do once it is
removed) and impersonate the account to anyone who would accept a session from
it (no one: peers send only to listed devices). That is Signal's exposure on
unlink. So the remove-a-lost-device screen does both by default: **remove it
and reset the identity, keeping my other devices** (the distribution above),
with an option to only remove it (a device you still have, given away or
sold after you signed out). The new identity is useless to the lost device.

What the lost device still has is the **master key**: with it, it can sign
manifests, so it could re-register itself (below) and take the identity back,
which drops every other device (visible at once, never silent). **Full
revocation needs master-key rotation**, which is not built and has its own
plan (a roadmap item: a new master key re-wraps the account's data and
derives a new authority, an authority change peers verify). The threat model
says this plainly, and the screen points to "Change password" with that
caveat until then.

## Re-registration: a new identity, other devices dropped

When no device of the account has the identity any more (every device lost,
the person restores from the recovery phrase or a backup in a cleared
browser), or the person chooses "I don't have my other devices":

- the device makes a new identity and registers with a **re-registration
  manifest** in the same call (server section): the next V2 manifest, signed
  by the authority (the master key proves it is the account), with the new
  identity key, listing only this device; its prekeys verify against the new
  key;
- the server, in one transaction, inserts its row, swaps the account
  identity, publishes the manifest and drops every other device row, as
  Signal's `reclaimAccount` unlinks every device (Signal gates it on the
  number and the registration lock; Kutup on the authority, so on the master
  key).

## What peers see on an identity change

An identity change under the same authority (a distribution or a
re-registration):

- **Signal's notice:** "Your safety number with Ada has changed" in the
  conversation, as Signal shows it;
- the safety number is new (it is computed over the identity key), and a
  verified contact is **no longer verified** (Signal's VERIFIED to
  UNVERIFIED), synced so on every device of the account;
- sessions with every device of the account are archived and re-established;
- her sender keys are reset in every group she is in, and so are theirs
  toward her, as Signal's `addKeyChange` does;
- it is recorded once per account, never per device.

An identity change **not** signed by the same authority is today's authority
change: quarantined, as now (`quarantine_authority`).

## Sessions, sends and receipts in chat-core

- **Identity store:** stays keyed per address; every device of an account
  holds the same key. `save_identity` takes the manifest's account key; any
  other key is refused (the identity rule).
- **Reinstall detection** follows the manifest's registration ids (above),
  never a device's identity.
- **`ChatEvent::IdentityChanged`** fires only for an account identity change,
  once per account, and carries the new safety number. That also ends today's
  "safety number changed" notices on a peer's reinstall or new device (a new
  device doesn't change the identity, so it changes nothing, as in Signal).
- **Sender certificates** carry the account identity key; on receipt the key
  is checked against the account's verified manifest and the device id
  against its listed devices, also for a remote sender (the federated
  manifest).
- **Groups:** an identity change resets sender keys both ways (above).
- **Slice 2** then uses libsignal's `sealed_sender_multi_recipient_encrypt` as
  it is (one key share per account); the server's parse stays libsignal's
  (#297).

## Server and key endpoints

(Second session's section, revised after the review: the distribution
route, per-device credentials, link tokens and provisioning, key-upload
checks, the V2 manifest, bundles, federation, limits.)

**Today** (for the record):
- Every `chat_devices` row has its own `identity_key`, with
  `UNIQUE (user_id, identity_key)`.
- `POST /api/chat/device` checks only that the fields are base64: it never
  compares identity keys across an account's devices and never verifies a
  signed or Kyber prekey's signature ("stored and served verbatim for clients
  to verify", `handlers/chat.rs`).
- The only binding of a device to its account is `AccountManifestV1`, signed
  by the account authority, which the server verifies on publish and checks
  against the registered rows.
- Chat requests aren't device-authenticated: replenishing takes a `deviceId`
  any JWT holder of the account can name.
- There is no linking: a new device registers with the account's sign-in
  alone.

**Tables** (one migration, which clears Chat's transport state, below; its number is taken above master and the
open PRs when it is pushed):
- `chat_account_identities (user_id PK → users, identity_key text NOT NULL,
  manifest_version bigint NOT NULL, changed_at)`: one row per account with a
  Chat identity; no row means the account has no Chat device yet (its first
  device registers with a re-registration, below).
- The migration deletes every `chat_devices` row (and with them their
  prekeys, mailboxes and push subscriptions) and the manifests: the deploy
  above.
- `chat_devices` gains `credential_hash bytea` (Signal's `SaltedTokenHash`:
  SHA-256 over a per-row salt and a 32-byte random credential the device drew
  at registration; a high-entropy token needs no slow hash, as Signal) and
  `expired_at timestamptz` (Q-b); `UNIQUE (user_id, identity_key)` goes.
- `chat_link_tokens (token_hash bytea PK, user_id, issued_by_device int,
  expires_at, used_at)`: single use, only the hash stored.

**Device credentials** (Signal's per-device password):
- `POST /api/chat/device` takes `credential` (32 random bytes, unpadded base64url) and
  stores only its salted hash.
- Device-bound calls carry `X-Kutup-Chat-Device: <deviceId>.<credential>`
  beside the JWT: replenishing keys, `keys/check`, link tokens, identity
  distribution, manifest publish, revoke, sends. The server checks it in
  constant time against that device's row of the JWT's account; missing or
  wrong is `401` (Signal's `AccountAuthenticator`). A removed or expired
  device's credential dies with its row.
- The register call's retry key becomes the credential hash (the same
  credential again answers the row it made).

**Linking** (Signal's `/v1/devices/provisioning/code`, provisioning socket,
`PUT /v1/devices/link`):
1. The new device signs in (JWT) and opens `GET /api/chat/provisioning`
   (WebSocket); the server gives it a random address for the socket's life
   and relays exactly one envelope to it, nothing on disk.
2. An existing device calls `POST /api/chat/link-tokens`
   (device-authenticated) and gets a one-time token.
3. It sends the envelope with `PUT /api/chat/provisioning/{address}`
   (device-authenticated). The server checks the size and that the address is
   a socket of the same account; "no such socket" and "another account's
   socket" are the same `404`, so addresses can't be probed. It relays the
   envelope and forgets it.
4. The new device calls `POST /api/chat/device` with `linkToken`, its
   `credential`, its registration id and keys; the token is consumed in the
   insert's transaction. Then a device publishes the V2 manifest listing it.

**Key upload checks** (`POST /api/chat/device`,
`PUT /api/chat/keys`):
- `identityKey` is the account's (33 bytes, a valid point).
- The signed prekey, the last-resort Kyber key and every one-time Kyber key
  verify against the account identity key (libsignal
  `IdentityKey::verify_signature`, as Signal's `PreKeySignatureValidator`);
  otherwise `400 badSignature`.
- `POST /api/chat/keys/check` (Signal's `/v2/keys/check`): a digest of the
  identity key and the device's repeated-use keys, so the device learns
  whether the server's copy is its own.

**Identity distribution** (Signal's `PUT /v2/accounts/number` key part,
`PhoneNumberIdentityKeyDistributionRequest`): `PUT /api/chat/account-identity`,
device-authenticated, one request from one device:
- `identityKey`: the new account identity;
- per device the manifest lists (this one included): `signedPreKey`,
  `lastResortKyberPreKey`, `registrationId`;
- `deviceMessages`: exactly one sealed sync per other listed device (Signal's
  `PniChangeNumber`), carrying the identity's private key and that device's
  new private prekeys, encrypted on its existing session;
- `manifest`: the `AccountManifestV2` listing exactly these devices with
  these registration ids and this identity key, the next sequence, under the
  account's authority. It may leave out devices the account has (a lost
  device being reset away): those rows are dropped in the same transaction.

The server, in one transaction:
1. Device set: the per-device maps and `deviceMessages` name exactly the
   devices the manifest lists, all of them devices of the account (an unknown
   device is `409`, Signal's `MismatchedDevicesResponse`); a device message
   whose registration id doesn't match its stored row is `410`
   (`StaleDevicesResponse`). Nothing is stored either way.
2. Every signed prekey and last-resort key verifies against `identityKey`
   (`400 badSignature`); the manifest verifies, names this identity and these
   registration ids, and is the next sequence.
3. Swap: `chat_account_identities` set, every
   listed device row's identity, signed prekey, last-resort key and
   registration id replaced, unlisted rows deleted, every one-time EC and
   Kyber key of the account deleted (Signal's `deleteSingleUsePreKeys`;
   devices refill through `PUT /api/chat/keys`), the manifest stored as head
   and in history.
4. The `deviceMessages` queued to their devices' mailboxes in the same
   transaction; then `DevicesChanged`.

It serves "reset identity, keep my devices" (the lost device left out of the
manifest), and an account with one device re-keying itself.

**Re-registration** (after every device is lost, and an account's first Chat
device) is one registration call, `POST /api/chat/device` with
`registration: { type: "reregistration", manifest }` and no link token
(`RegisterChatDeviceRequestV2`, whose `registration` is exactly one of `link`
and `reregistration`, beside a required `credential`). The manifest is the
account's next V2 manifest (`AccountManifestV2::verify_successor`: sequence 1
with no `previousHash` when the account has none, otherwise the head's
sequence + 1 with `previousHash` the head's hash) and lists this device alone
as device 1 with the request's identity and registration id. In one
transaction the server deletes every other device row of the account, inserts
this one as device 1, sets the account identity and publishes the manifest
(Signal's `reclaimAccount`). The gate is the account authority, so the master
key.

**Manifest V2 on publish** (`POST /api/chat/manifest`): its identity key
equals `chat_account_identities` (a different one only through the
distribution route); its devices' registration ids equal the rows' (a
registration id changes only with a manifest that names it, at linking or a
distribution); unlisted rows are deleted, as today; V1 is refused.

**Registration ids:** bundles and `410` answers are built from rows equal to
the signed manifest; the server never answers a registration id the head
manifest doesn't carry, and clients refuse one that disagrees (client
section).

**Device expiry** (Q-b): `jobs.rs` sets `expired_at`
instead of deleting; an expired device leaves the send device set and the
bundles at once (sends never wait on it, as Signal), and any online device of
the account, on `DevicesChanged`, publishes the V2 manifest that drops it;
then the row goes.

**Bundles:** `GET /api/chat/accounts/:id/keys` (local, federated, anonymous)
answers the account identity once, and each listed device's registration id
and prekeys (Signal's `/v2/keys`).

**Federation:** `fetch_remote_bundles` verifies the attached manifest (as
`fetch_remote_manifest` does) and the bundles against it. A distribution or
a reset isn't pushed to peer servers: their clients learn it lazily, as
they learn of a revoked device, when their next send answers `409` or `410`
and they fetch the account's manifest and bundles again. A remote account's sender certificates carry its
identity key; receiving clients check them against the account's federated
manifest (client section); a server checks only that its own certificates
match the issuing account's current identity.

**Sender certificates:** `issue_sender_certificate` reads the account
identity and the caller's authenticated device id.

**Sends:** unchanged; #297's multi-recipient route keeps libsignal's parse
(one key share per account).

**Limits** (site settings; the request limits in the rate-limit registry):
link-token lifetime (10 minutes) and outstanding tokens per account (3); the
provisioning envelope size (64 KiB), provisioning sockets per address a
minute and relays per account a minute; distributions per account a day; the
`deviceMessages` size per device; the device cap (`chat_max_active_devices`).

**Server tests:**
- unit: prekey signature checks (good, bad, wrong key); credentials
  (missing, wrong, another device's, compared in constant time); link tokens
  (reuse, expiry, another account); the distribution's `409`/`410`, a bad
  signature, a manifest that disagrees, one-time keys cleared, an unlisted
  device dropped; the V2 publish rules; a registration id outside the
  manifest refused;
- live: linking end to end; `keys/check`; a reset as one distribution with
  the syncs drained by each device; a reset leaving a lost device out;
  re-registration from a new device; two distributions racing (the second
  gets a sequence conflict); expiry leaving the send set;
- two servers: federated bundles under the account identity, verified
  against the manifest; a reset seen by the peer.

## The deploy: no migration

Kutup has three accounts, all the user's (2026-10-22), so there is no
migration of old accounts, no per-device legacy path and no V1 manifest:

1. **The server's migration** deletes every account's Chat devices, their
   prekeys, their mailboxes and their manifests (Chat's transport state
   only). Accounts, contacts and the Chat contact list, group lists and the
   groups' state at their homes, Chat backups, Drive and the rest stay.
2. **The first device of an account that opens the new version** finds no
   identity for the account, discards its own old Chat transport state
   (identity, sessions, prekeys; never its history), and re-registers: a new
   account identity and a V2 manifest listing itself (the re-registration
   above).
3. **Each other device** finds the account has an identity it doesn't hold
   and shows "Link this device"; it is linked from the first one (QR or
   code), keeping its own local history.
4. **Peers** (here, the user's other accounts) see one "safety number
   changed" for the account and lose their verified state for it once, as
   after any re-registration; sessions are re-established and group sender
   keys handed out again with the next message.

**What is kept:** every device's local Chat history (only transport state is
replaced); a device that has lost its local data restores its display
history from the Chat backup, as a cleared browser does today
(docs/chat-backup.md, "Fresh-browser restore"); groups, contacts, settings;
messages waiting in a device's outbox, which go out again under the new
sessions.

**What is lost:** messages still waiting **unfetched in a device's server
mailbox** at the deploy (the migration clears the mailboxes): open every
device just before the deploy so its mailbox is drained. And anything of the
old MLS groups (their state is per device; MLS is being removed in any
case).

**Rollout.** The deploy that runs this migration deletes Chat device and
manifest data on kutup.dev. Per the standing rule, it waits for the user's
live "yes" right before it runs ("deleting Chat devices and manifests on
kutup.dev now, are you confirming?"), even with only the user's accounts;
the deploying session asks.

**What people are told.** The release notes say: "Chat now has one identity
key per account, as Signal. Your contacts will see your safety number change
once. If you had verified a contact, verify them again. Open each device
before updating, then link your other devices from the first one you open."

## Backups

Unchanged format, and as Signal the backup doesn't carry the account
identity. So **restoring into a cleared browser, with no other device to link
from, is a re-registration**: peers see the notice and every group resets its
sender keys. The restore screen says that and steers to "Link from another
device" first, restore only when there is none. docs/chat-backup.md says a
restore is a re-registration (it said a new device identity before).

## The CLI

The CLI has no Chat device and holds no identity. `kutup devices revoke` and
`kutup password` say, for a lost device, that the identity reset is done from
the Chat app ("remove it and reset the identity") and what a password change
does and doesn't revoke.

## What changes where

- **kutup-crypto:** the provisioning cipher (with vectors); the safety
  number moves to libsignal's `NumericFingerprint` over the account id and
  identity key (vectors against libsignal's own), and the verification QR gets
  a new version.
- **kutup-chat-proto** (`src/account_identity.rs`, in first and additive
  until the cutover): `AccountManifestV2` (domain `kutup/account-manifest/v2`,
  its chain starting at sequence 1) with its publication and history page;
  `AccountPreKeyBundlesResponse` (the identity once, checked against the
  manifest); `ChatProvisionV1`, `ProvisionEnvelopeV1`, the provisioning
  socket's messages, the relay request and the `kutup://link` code; the link
  token response; `AccountIdentityDistributionRequest` with its row-free
  checks (`400`, or `409` with the device lists); `DeviceRegistrationV1::Reregistration` (the
  manifest lists this device alone as device 1, the id left free once the
  other rows go); `RegisterChatDeviceRequestV2` (a required
  `credential`, and `registration`: exactly one of a link token and a
  re-registration manifest); `AccountManifestV2::verify_successor`, the one
  chain check every implementation uses; the `X-Kutup-Chat-Device` header; the `keys/check` digest; the
  `accountIdentity` sync body.
- **kutup-chat-core:** `keys::generate` takes the identity instead of making
  one; the safety number and verified state per identity key (the Chat
  contact record gains `identityKey` and `identityState`, as Signal's
  `ContactRecord`); the authority quarantine stays for manifest continuity; the identity rule and the registration-id rule; `IdentityChanged` per
  account; linking (both sides); the distribution (send and apply);
  re-registration; slice 2
  unparked.
- **kutup-client-ffi:** linking, the distribution, removal and reset for the
  native apps (not built yet; the API is in the bindings).
- **Web:** Settings → Linked devices (link, list, remove, remove a lost
  device and reset), "Link this device" (QR and code, with the pasted-code
  advice), Signal's "safety number changed" notice and the verified state
  cleared, the new safety number and QR, the first open after the deploy
  (re-register or link), the restore screen's steer.
- **CLI:** the lost-device and password texts.
- **Server:** the second session's section.
- **Docs:** chat-protocol.md §4.1, §5 (the safety number over the identity
  key), §6, chat-backup.md, docs/plans/chat-contacts-sync.md (the verified
  state in the contact record), the threat model (removal, lost devices,
  master-key rotation not built), and the release notes (the one-time
  "safety number changed" for every contact).

## Tests

- **Rust:**
  - the provisioning cipher against its vectors and against tampering (MAC
    first, wrong account, an identity the manifest doesn't list);
  - V2 manifest verification, the identity rule, the registration-id rule
    (a `409`/`410` that disagrees is refused);
  - the safety number against libsignal's fingerprint vectors; verified
    cleared by an identity change and kept by linking and removal;
  - prekeys signed by the account key;
  - the distribution (built and applied, a device offline applies it later);
  - re-registration; an account's first device; two devices of a fresh
    account starting at once (the second is told to link).
- **Harness:** a three-device account messages and receives on the
  multi-recipient route; linking end to end; removal (no notice); remove a
  lost device and reset ("safety number changed", verified cleared, sessions
  re-established, sender keys reset); linking a device changes nothing for
  peers;
  re-registration.
- **Browser:** spec 169 (Chat suite): link a second browser with the code
  (no notice at the contact), message from both, verify a contact, remove a
  lost device and reset (the contact sees "safety number changed" and is no
  longer verified), re-register after a cleared browser. The two-server gate (spec 34) and the group specs.
- **Server:** the second session's section.

## Decisions

- **Q-a:** the identity is random and provisioned, as Signal, not derived
  from the master key.
- **Q-b:** an account's device expiry marks it, it leaves the sends at
  once, and the next V2 manifest drops it.
- **Q-c:** the manifest carries the identity key itself.
- **Q-d** (the user, 2026-10-22, "reference signal directly"): safety numbers
  and verification follow the account identity key, as Signal's; an identity
  reset shows "safety number changed" and clears verified.
- **No migration** (the user, 2026-10-22: "only 3 users exist, all me"): no
  migration of old accounts, no per-device legacy path, no V1 manifests. The
  deploy clears Chat's transport state and every device re-registers or is
  linked, as a normal reset (above); Q-e and the legacy end date go with it.
