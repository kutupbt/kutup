# Chat contacts that survive device loss

Status: decided (2026-10-19): the main session's review, and the user's
answers (see Decisions). Third session (client and chat-core). The second
session built `kutup_crypto::chat_contact_list` (with vectors) and the server
half (`/api/chat/contact-list`, the `chatContacts` scope).

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
- the contacts' profile keys are gone, so names and avatars are missing until
  each one writes again.

Accepting everyone found in the restored history isn't a fix: it would undo
blocks too.

## What Signal does

Signal keeps this in the storage service, one encrypted record per contact
(`ContactRecord`), and a new device reads them before anything else. A record
carries, among others:
- `whitelisted` (profile sharing: the person is accepted);
- `blocked`, and since when;
- `profileKey` and `identityKey`, with `identityState`;
- `archived`, `markedUnread`, `mutedUntilTimestamp`, `hidden`, `nickname`,
  `note`.

Records are uploaded half a second after a change (`runStorageServiceUploadJob`,
a 500 ms debounce). A changed record gets a new random storage id, but the same
write deletes the old id and inserts the new one
(`storage.preload.ts`, around lines 242–262), so the server sees which record
replaced which. The rotating ids exist for manifest diffing and per-record
keys, not to hide linkage.

## What Kutup does

### The list

The account head gets one more scope, `chatContacts`. It is not the address
book's contacts (the Contacts app's own scope). It is built like `chatGroups`:
- **Keys** from the account master key: HKDF-SHA256 with salt
  `kutup/chat-contact-list/v1\0`, infos `kutup/chat-contact-list/id-key/v1\0`
  and `kutup/chat-contact-list/seal-key/v1\0`, separate from the group list's.
- **Entry id**: `HMAC-SHA256(id key, "kutup/chat-contact-list/id/v1\0" ‖
  AccountRef::bytes())`, exactly those bytes, base64url without padding.
- **Sealed entry**: the group list's layout with its own magic
  (`"KUTPCL1\0"`), suite 1, the write revision in the authenticated header,
  and the AAD binding the account's key binding and the entry id.
- **Size**: every sealed entry is exactly **2048 bytes**, padded as the group
  list's are.
- **Routes**: `GET/PUT/DELETE /api/chat/contact-list[/{id}]`, with the group
  list's bodies and codes, listed by the account head. They answer wherever
  Chat is on, not only with `CHAT_GROUPS`.

### An entry, `ChatContactEntryV1`

Fields and their budget (canonical JSON, before padding):

| Field | What | Bytes |
| --- | --- | --- |
| `version` | 1 | ~15 |
| `account` | the contact's `AccountRef` (server, account id) | ~120 |
| `state` | `accepted`, `pendingOutgoing`, `rejected` or `blocked` | ~30 |
| `previousState` | what an unblock returns to | ~35 |
| `blockedAtMs` | when blocked | ~30 |
| `profileKey` | the contact's profile key, base64 | ~60 |
| `control` | `{revision, sourceDeviceId, updatedAtMs}`, see below | ~80 |
| keys and punctuation | | ~100 |

That is about 500 bytes. 2048 leaves room for Signal's later fields (a
nickname, a note, mute and archive), each a few hundred bytes at most.

A device keeps the fields it doesn't know and writes them back as they were.
The plaintext type has no `deny_unknown_fields`: unknown fields are kept in
a flattened map and re-serialized canonically.

`pendingIncoming` is never written: a request someone else sent belongs to
their messages, not to this account's choices.

Not here:
- **Identity and verified state.** They already live in the account's sealed
  pin list ([`drive-identity-pins.md`](drive-identity-pins.md)), as
  `seen|verified`, shared with Drive. Not duplicated here; the pin list is
  read before the mailbox too (see Reading).
- **Mute, archive, read state.** Device-local today; a separate decision.

### Two revisions

They are two different things:
- **The write revision**, in the sealed header. Per entry, it rises by one on
  every write; it is what the server compares (`baseRevision`) and what the
  account head lists.
- **The control order**, `control` inside the plaintext. It is the contact
  control's `(revision, sourceDeviceId)`, which devices already use to agree.

A write is refused with 409 when another device wrote first. The device then
reads the entry, merges by the control order, and writes the result at the
stored write revision + 1. A change that leaves the control order as it was
(a new profile key; an implicit contact at control revision 0) is still a new
write revision.

### Merging: one order, blocks winning ties

One function orders contact states, and both the Note-to-Self contact control
and the list use it:

`order = (control.revision, state == blocked, control.sourceDeviceId)`

The higher order wins. At an equal revision a block wins, whatever device
wrote the other. An older accept never undoes a block.

### What is written

**Explicit transitions**, as now (accept, reject, block, unblock, a sent
request): the entry is written.

**Implicit transitions** are written too, with the same delay:
- `PendingOutgoing → Accepted` when the person replies
  (`stage_incoming_contact`). Without it, an accepted request would restore
  as pending forever.
- A contact first met through this account's own sent transcript
  (`stage_transcript_contact`, `sourceDeviceId` 0, revision 0), and its moves
  from `Rejected` or `PendingIncoming`.
- `Rejected → PendingIncoming` (the rejected person writes again) is **not**
  written: the entry keeps `rejected`, the account's last choice. A restored
  device shows their new message as a request again, as every device does
  today.

**Profile-key-only changes** (a contact's new key, as after a block rotates
it, `engine.rs` around 748) are written lazily: with the next write already
due, or after a long random delay (up to an hour).

### When it is written

Two accounts on the same server that accept each other would write entries at
nearly the same moment, and the server would learn they are contacts. Sealed
sender hides exactly that. So, as for the group list:
- each write waits a random 0–10 minutes, and writes due together go
  together;
- what is due is kept with the contact, so it survives a reload;
- a device flushes before it signs out or unlinks itself;
- the device-to-device contact control stays as it is, so the account's own
  devices still agree within seconds.

**A block's timing is a platform policy, one setting** (the user's decision).
On the web, a block is written at once: a blocked person must stay blocked
if the browser's data is lost a minute later, and a block leaks less, since
it is one-sided and nothing on the other side lines up with it. The future
native apps follow Signal's storage-sync timing for it (the upload debounce
above). chat-core takes the policy as one setting
(`ContactListTiming { block: Immediate | Debounced }`), chosen by each
platform's client, not scattered through the code.

**The pin list follows the same rule.** Today `identity_sync::record` writes
the pin list at once on first contact, with a millisecond timestamp as its
revision. That alone lines up two accounts meeting each other, and undoes the
delay above (it weakens the group list's reasoning in the same way). Pin
writes are delayed and batched the same way; verifying someone in person
stays immediate, since it is one-sided.

**Said honestly:** the delay is weaker on a small server. With few accounts
active, two writes ten minutes apart can still line up. The delay raises the
cost of the correlation; it does not remove it.

### Reading

On a clean device (no contacts, no highest-seen account head):
1. read the pin list and the contact list (`check_index` against the account
   head);
2. apply the contacts;
3. only then drain the mailbox and process transcripts. The mailbox is
   **held** until the list has been read, so nothing from a blocked person is
   taken first.

`bootstrap_contacts` goes. It marks every peer in the device's own message
tables as Accepted at revision 0, which would run before the list and accept
blocked people. It was an upgrade path from before contact states existed,
and pre-v1 needs no such shim. The web history restore writes to the
backup's display records, not to chat-core's message tables, so nothing else
reads restored history as contacts.

A running device reads the list every few minutes, and after a 409.

**Rollback limits.** The list is trust-on-first-use for a clean device: with
no highest-seen account head, it takes the head the server presents. From the
first read on, the account head stops the server from serving an older list
(as for the pin list and the group list).

### Size and deletion

At most **10,000** entries, as the pin list (`MAX_PINS`). Beyond that, the
oldest `rejected` entries go first, then the oldest `pendingOutgoing`. A
`blocked` entry is never evicted. Deletion happens only on eviction, and is
delayed like a write.

### Keeping the list in step: one standing rule

There is no separate migration. Every device runs the same rule, all the time:
any contact whose local state is missing from the list, or newer than the
list's entry by the control order, is due for a write, with the delay above.
That also covers the rollout: on the first start after the update, each
device finds its contacts missing from the list and writes them over the
following minutes; kutup.dev's accounts keep their contacts, with no wipe.

The rule is the references' own:
- **Signal** marks a record `needsStorageServiceSync` when it changes locally,
  and each upload writes every record that is flagged or has no storage id
  yet (`storage.preload.ts`, `storageNeedsSync`, around lines 226–240 and
  297).
- **Proton** clients reconcile through the server's event stream, from the
  last event id each has seen, with local changes pushed as they come
  (Proton Pass Android `SyncUserEventsImpl`, `lastEventId` and
  `eventsPending`); a new client version catches up the same way, with no
  separate migration step.

### The server

The group list's server half with a second scope and its own routes,
following the main session's review of #252:
- the server reads the write revision from the header;
- it refuses any size but 2048;
- writes are listed by the account head;
- account reset clears it.

## Decisions

The user's answers (2026-10-19, relayed by the main session):
1. **Profile keys in the entry: yes**, as Signal.
2. **A block's write timing**: immediate on the web; Signal's storage-sync
   timing in the future native apps; one platform setting (see "When it is
   written").
3. **Rollout**: the standing sync rule above, as Signal's `storageNeedsSync`
   and Proton's event-based catch-up; no wipe, no one-off migration.
4. **Entry ids**: fixed HMAC ids for now. The user asked why Signal rotates
   its ids if not for privacy; the main session is answering, and a change
   here would move the group list's ids too.

## Tests

- Vectors: the keys, an id from `AccountRef::bytes()`, a sealed 2048-byte
  entry (`chat-contact-list-v1.json`).
- Harness:
  - a device that lost everything restores accepts and blocks;
  - an accepted outgoing request restores as accepted (the implicit write);
  - the mailbox is held until the list is read, so a blocked person's
    message is never taken;
  - a block wins a tie with an accept at the same control revision, in the
    list and in the contact control;
  - a 409 merges and writes at the stored revision + 1;
  - a profile-key-only change is written without moving the control order;
  - unknown fields survive a rewrite;
  - a block, keyed by the account id, holds after the blocked person resets
    their account (a new incarnation of the same account);
  - eviction never drops a block.
- Browser: spec 34's restored pair is mutual contacts again with no
  re-accept, and a block made before the loss holds after it.

## Order

1. kutup-crypto `chat_contact_list` with vectors (second session, reviewed by the third).
2. The server scope and routes (second session).
3. chat-core:
   - the one order function, used by the contact control too;
   - the standing sync rule and the block-timing setting;
   - entries, implicit writes and their delay;
   - delayed pin writes;
   - the held mailbox and the read before it;
   - removing `bootstrap_contacts`;
   - the flush at sign-out;
   - the WASM and TypeScript transport.
4. Spec 34 without its re-accept step; the roadmap gap closes.
