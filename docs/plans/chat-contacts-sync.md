# Chat contacts that survive device loss

Status: draft for review (2026-10-19). Third session (client and chat-core).
The server half reuses the group list's routes, so it's small; the second
session owns it. No code before the main session's review and the user's go.

- Gap: [`roadmap.md`](../roadmap.md), "contact states after total device
  loss"; found by spec 34 on #247.
- Copies: Signal's storage service, `ContactRecord`
  (Signal-Desktop `protos/SignalStorage.proto`).
- Built like: the account's Chat group list
  ([`pairwise-groups.md`](pairwise-groups.md) §5, `kutup_crypto::chat_group_list`).

## The problem

Who an account accepted, rejected or blocked in Chat lives only on its devices.
A change reaches the account's other devices as a contact control over Note to
Self (`flush_contact_syncs`). Nothing keeps it anywhere else, and the history
backup ([`chat-backup.md`](../chat-backup.md)) carries display records only.

So when every device is lost and a clean browser signs in:
- the history comes back, but every contact is unknown;
- people the account accepted show as message requests, and a request it sent
  stays pending;
- groups offer no one to invite (only contacts can be invited);
- **a block is gone**: someone the account blocked can write to it again;
- the contacts' profile keys are gone, so their names and avatars are missing
  until each one writes again.

Accepting everyone found in the restored history isn't a fix: it would undo
blocks too.

## What Signal does

Signal keeps this in the storage service, one encrypted record per contact
(`ContactRecord`), and a new device reads them before anything else. A record
carries, among others:
- `whitelisted` (profile sharing: the person is accepted);
- `blocked`, and since when;
- `profileKey` and `identityKey`, with `identityState` (verified or not);
- `archived`, `markedUnread`, `mutedUntilTimestamp`, `hidden`.

Records are written about half a second after a change (`runStorageServiceUploadJob`,
a 500 ms debounce). Each record gets a new random id on every change, and a
sealed manifest lists the current ids, so the server can't link one version of
a record to the next.

## What Kutup does

### The list

The account head gets one more scope, `chatContacts`, built exactly like
`chatGroups`:
- **Keys** from the account master key: HKDF-SHA256 with salt
  `kutup/chat-contact-list/v1\0`, infos `kutup/chat-contact-list/id-key/v1\0`
  and `kutup/chat-contact-list/seal-key/v1\0`. They are separate from the
  group list's keys.
- **Entry id**: `HMAC-SHA256(id key, "kutup/chat-contact-list/id/v1\0" ‖
  the contact's account, canonical form)`, base64url without padding.
- **Sealed entry**: the group list's layout with its own magic
  (`"KUTPCL1\0"`), suite 1, the revision in the authenticated header, and
  the AAD binding the account's key binding and the entry id. Every entry is
  one fixed size.
- **Routes**: `GET/PUT/DELETE /api/chat/contact-list[/{id}]`, the same bodies
  and codes as the group list, listed by the account head.

### An entry, `ChatContactEntryV1`

- `account`: the contact (`AccountRef`), never an address.
- `state`: `accepted`, `pendingOutgoing`, `rejected` or `blocked`.
  `pendingIncoming` is never written: a request someone else sent belongs to
  their messages, not to this account's choices.
- `previousState`: the state an unblock returns to, as now.
- `blockedAtMs` when blocked.
- `profileKey`: the contact's profile key as last received, so a new device
  shows their name and reaches them sealed at once (Signal's `profileKey`).
- `revision`, `sourceDeviceId` and `updatedAtMs`: the contact control's own
  fields, so the merge rule below is the one devices already use.

Not here:
- identity pins: they already live in the account's sealed pin list
  ([`drive-identity-pins.md`](drive-identity-pins.md)), shared with Drive;
- mute, archive, read state: device-local today, a separate decision.

### Writing

A device writes a contact's entry after each explicit transition (accept,
reject, block, unblock, and a sent request) and after a new profile key from
an accepted contact.

Signal writes within half a second. Kutup doesn't, for the same reason as the
group list: two accounts on the same server accepting each other write
entries at nearly the same moment, and the server would learn they are
contacts. Sealed sender hides exactly that. So, as for groups:
- each write waits a random 0–10 minutes, and writes due together go
  together;
- what is due is kept with the contact, so it survives a reload;
- a device flushes before it signs out or unlinks itself;
- the device-to-device contact control stays as it is, so the account's own
  devices still agree within seconds.

A block is the one exception to the delay. A blocked person must stay blocked
if the device is lost a minute later, so a block is written at once. It
leaks less: blocking is one-sided, so nothing on the other side lines up with
it.

### Reading

A device reads the list:
- when Chat starts on a device with no contacts (a clean browser), before it
  processes its mailbox, so nothing from a blocked person is shown first;
- every few minutes while it runs, and after a write was refused (409).

It merges each entry with the local record by the contact control's rule:
the higher `(revision, sourceDeviceId)` wins. A block is never lost to an
older accept.

### The server

It is the group list's server half with a second scope and its own routes,
following the main session's review of #252:
- the server reads the revision from the header;
- it refuses any size but the one;
- writes are listed by the account head;
- account reset clears it.

## Choices for the review

1. **Entry ids.**
   - Stable HMAC ids, as the group list has (proposed): the server sees which
     entry changed, never whose it is.
   - Signal's random id per version, with a sealed manifest: the server
     can't link versions either, but it needs a manifest object and its own
     conflict rule. If the review wants that, the group list should move with
     it.
2. **Profile keys in the entry** (proposed: yes, as Signal). Without them, a
   restored device shows contacts by address only, and can't send them a
   sealed message until they write first.
3. **The immediate write for a block** (proposed: yes).
4. **Rollout.** Every existing device uploads its contacts once, at random
   moments over the first hour after the update. kutup.dev's accounts keep
   their contacts with no wipe.

## Tests

- Vectors for the keys, the id and a sealed entry (`chat-contact-list-v1.json`).
- Harness:
  - a device that lost everything restores accepts and blocks;
  - a stranger's request stays a request;
  - a blocked person's message is dropped before the list is read;
  - concurrent transitions on two devices merge by revision.
- Browser: spec 34's restored pair is mutual contacts again with no
  re-accept, and a block made before the loss holds after it.

## Order

1. kutup-crypto `chat_contact_list` with vectors (third session).
2. The server scope and routes (second session).
3. chat-core: entries, the merge, the read before the mailbox, writes with
   their delay, and the flush at sign-out; WASM and TypeScript transport.
4. Spec 34 without its re-accept step; the roadmap gap closes.
