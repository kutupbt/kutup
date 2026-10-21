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

## What stays

Kutup's **account authority** (an Ed25519 key derived from the account master
key, chat-protocol.md §4) stays the root of trust. It signs the account
manifest, safety numbers are computed over it (§5), identity pins and the QR
verification are per authority, and group bindings and pseudonyms derive from
the master key. None of that is tied to a device identity today, and none of
it changes. The authority now also signs which identity key the account has
and each device's registration id.

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
authority. It carries everything V1 carries, with the identity moved up to
the account:

| Field | From V1 | Note |
|---|---|---|
| `account` (AccountRef) | yes | |
| `incarnationId` | yes | an account reset is a new incarnation, as today |
| `sequence`, `previousHash` | yes | the chain: +1, linked to the previous manifest (V1's last, for the first V2) |
| Drive keys (as V1) | yes | unchanged |
| `issuedAt`, `authorityKeyId`, `selfAuthorityKey`, `signature` | yes | as V1, under the V2 domain |
| **`identityKey`** | new | the account's libsignal identity key (33 bytes) itself, not a hash |
| `devices[]`: `deviceId`, `directChatSuite`, **`registrationId`** | yes, without `identityKey` | the registration id is now part of what the authority vouches for |
| `devices[].mls` | yes | dropped if the MLS removal lands first |

After an account's first V2 manifest, V1 manifests are refused for it, by
the server and by every client that has seen the V2.

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
| `provisioningVersion` | `provisioningVersion` | 1 |

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
to each device), applied to the account identity. Kutup uses it for the
**migration** and for **"reset identity, keep my devices"**.

1. One device of the account makes a new identity key pair, and for **every**
   device of the account (itself included): a signed prekey and a last-resort
   Kyber key, signed by the new identity, and a new registration id.
2. It sends one request (server section): the new identity, each device's
   keys and registration id, a `deviceMessages` sync for each other device,
   and the next **V2 manifest** listing the identity and every device with its
   new registration id.
3. The sync to each device (`accountIdentity`, Signal's `PniChangeNumber`):
   the identity key pair, that device's signed prekey and last-resort Kyber
   key (private parts), its registration id, and the manifest's sequence and
   hash. It is sealed pairwise to the device, under its current session, as
   any sync message; hidden, never history.
4. The server checks every signature and the device set (all of the account's
   devices, no more, no fewer: `409`/`410` otherwise), and in one transaction
   swaps every device's identity, keys and registration id, clears their
   one-time EC and Kyber keys, publishes the manifest and queues the syncs.
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

- the safety number **does not change** (it is computed over the authority);
- a notice in the conversation: "Ada's keys changed. Her safety number is the
  same." (exact wording and the verified state: Q-d, the user's decision);
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
  once per account. That also ends today's false "safety number changed"
  notices on a peer's reinstall.
- **Sender certificates** carry the account identity key; on receipt the key
  is checked against the account's verified manifest and the device id
  against its listed devices, also for a remote sender (the federated
  manifest).
- **Groups:** a member account still on the per-device model (legacy, below)
  gets its copies of a group message pairwise within the same send, while V2
  members get theirs on the multi-recipient route. An identity change resets
  sender keys both ways (above).
- **Slice 2** then uses libsignal's `sealed_sender_multi_recipient_encrypt` as
  it is (one key share per account) for V2 members; the server's parse stays
  libsignal's (#297).

## Server and key endpoints

(Second session's section, revised after the review: the distribution
route, per-device credentials, link tokens and provisioning, key-upload
checks, the V2 manifest, bundles, federation, limits.)

<!-- SERVER SECTION -->

## Migration without a wipe

Every existing account has per-device identities. It moves once, through the
identity distribution (above):

1. **The first device of the account that opens the new version** (any one)
   makes the account identity and sends the distribution for every device of
   the account, with the first V2 manifest. The server swaps everything in one
   transaction.
2. Each other device applies its sync when it next connects (offline ones
   later), and uploads its one-time keys.
3. Peers see one identity change per account, under the same authority: the
   notice, not a warning.

Two devices that start at once: the server takes the first distribution (the
manifest's sequence decides); the other's fails with a sequence conflict, it
reads the V2 manifest, and waits for its sync.

**Peers of a legacy account** (no device of which has opened the new version
yet): their manifest is still V1, so the multi-recipient route isn't used for
them; they get per-device copies (pairwise), as today, within the same group
send.

**The end of the legacy model:** a fixed date, no later than the release
after next and before v1 (the main session and the user set it; a roadmap
item). After it the per-device paths go; an account still on them re-registers
when its first device opens that release.

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

- **kutup-crypto:** the provisioning cipher (with vectors).
- **kutup-chat-proto:** `ChatProvisionV1`, `AccountManifestV2`, the
  `accountIdentity` sync kind, the distribution and registration request
  types.
- **kutup-chat-core:** `keys::generate` takes the identity instead of making
  one; the identity rule and the registration-id rule; `IdentityChanged` per
  account; linking (both sides); the distribution (send and apply);
  re-registration; the migration; group sends with legacy members; slice 2
  unparked.
- **kutup-client-ffi:** linking, the distribution, removal and reset for the
  native apps (not built yet; the API is in the bindings).
- **Web:** Settings → Linked devices (link, list, remove, remove a lost
  device and reset), "Link this device" (QR and code, with the pasted-code
  advice), the identity-change notice, the migration on open, the restore
  screen's steer.
- **CLI:** the lost-device and password texts.
- **Server:** the second session's section.
- **Docs:** chat-protocol.md §4.1, §5, §6, chat-backup.md, the threat model
  (removal, lost devices, master-key rotation not built).

## Tests

- **Rust:**
  - the provisioning cipher against its vectors and against tampering (MAC
    first, wrong account, an identity the manifest doesn't list);
  - V2 manifest verification, the identity rule, the registration-id rule
    (a `409`/`410` that disagrees is refused);
  - prekeys signed by the account key;
  - the distribution (built and applied, a device offline applies it later);
  - re-registration; the migration with two devices starting at once.
- **Harness:** a three-device account messages and receives on the
  multi-recipient route; linking end to end; removal (no notice); remove a
  lost device and reset (notice, sessions re-established, sender keys reset);
  re-registration; a group with a legacy member.
- **Browser:** spec 169 (Chat suite): link a second browser with the code,
  message from both, remove a lost device and reset, re-register after a
  cleared browser. The two-server gate (spec 34) and the group specs.
- **Server:** the second session's section.

## Open questions

- **Q-d** (the user's decision, asked by the main session): the notice
  wording when the authority is the same, and whether a verified contact
  stays verified (proposed: yes, verification is of the authority). Whoever
  has the master key could reset the identity with only that notice; that is
  no worse than today, where the master key already signs any manifest.
- **The legacy end date** (above).
