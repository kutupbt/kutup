# Drive identity pins

**Status:** built 2026-10-10 on branch `fix/drive-identity-pins`, including one verification for every app (section 5).

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

### 1. The Drive key binding (`kutup-crypto::drive_key_binding`)

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
`tests/vectors/identity-pins-v2.json`, exported to WASM.

### 2. Server

- `users.drive_key_binding` (signature, base64), required at registration and
  first-login setup, checked against the keys sent before storage. An
  administrator's wipe clears it with the keys; the account's new setup signs
  it again. (The clean-slate release removed the later backfill,
  `PUT /api/user/drive-key-binding`.)
- The person lookups (`GET /api/users/by-address/:address`, and the federated
  `GET /api/drive/federation/users/:username`, whose remote server answers
  for its own account) hand out `accountAuthorityPublicKey` and
  `driveKeyBinding`. Share rows keep carrying only the keys they were made
  with: the client looks the person up and checks those keys against the
  binding, so one lookup per person serves every row.

### 3. Identity pins (`kutup-crypto::identity_pins`)

`IdentityPinsV1`: a canonical list of `{ account, incarnationId,
authorityPublicKey, state: seen | verified, firstSeen, previous[] }`, sealed
with XChaCha20-Poly1305 under a key derived from the master key
(`kutup/identity-pins/v1`), framed as `KUTIP2` suite 2 and bound
(`kutup/identity-pins/v2`) to the owner's key binding
(docs/plans/account-identity.md), never its address, and a revision. Suite 1
(`KUTIP1`, bound to the owner's address) is not read. The vectors list the
values that must be refused (another binding, the address, a changed header,
another revision, the suite-1 value).
The revision is in the list's authenticated header: a time in unix
milliseconds above every revision the writer has seen
(docs/plans/sealed-revisions.md). Stored by the server, opaque, at
`GET / PUT /api/user/identity-pins` with a compare-and-swap on the revision
the write started from (`baseRevision`; two apps writing at once merge and
retry). Each browser (`RevisionGuard`), the CLI and the Chat core remember
the highest revision they have seen, so the server cannot quietly hand back
an older list; a device with no history trusts the first list it reads.

**Renames** (docs/plans/username-renames.md). A pin also carries
`formerly` (the addresses the same incarnation had before `account`, oldest
first, at most 32, all on its server; when full the oldest goes, and that
address loses its "moved" warning) and `renames: { sequence, digest }`, the
head of the account's rename chain this list has verified. Former addresses
need the anchor; the anchor may stand alone (an account accepted back at a
name it had). Both are absent for an account that was never renamed. The anchor is the rollback guard on every
device of the account: a later chain is followed only if it holds that
statement at that sequence.

**An account is pinned once.** An incarnation (an authority key) appears at
most once in the whole list. Pins pushed off their address are kept in
`detached`, never dropped: by a rename landing on their address, or by the
user accepting another authority there. Their `account` is the last address
they were known at, and `detachedBy` says why they left it:
- **`rename`:** their own rename chain, or their return to that address,
  re-attaches them as they were.
- **`replaced`:** the user put another identity there. Replacing revokes its
  trust for good, because the usual reason is a reset or a lost key, which is
  the key an attacker may hold. Its state drops to `seen`. Wherever that
  authority turns up again (the same address, another one, or a rename chain
  it signs), it is `replacedIdentity` (record) or `replaced` (lookup): Drive
  and the CLI say `changed`, and Chat quarantines it. A chain moves its last
  known address but it stays `replaced`, and it never takes an address from a
  live pin. Only the user's explicit accept (`seen`) or in-person verification
  (`verified`) pins it again.

`detachedBy` is set on detached pins and only on them. At most 256 are kept;
past that, the oldest unverified go first, then the oldest.

**Fields added later (normative).** Every struct of the list (the list, a
pin, an anchor) keeps fields it does not know. They are read past, kept, and
written back unchanged, after the known fields and in name order. That is the
canonical form of any field added after V1, and the stored bytes must be
canonical. So an older app never strips a newer app's data, and a newer app
can add fields without a new suite. A writer that adds something older readers
would misread sets the list's `minReader` above their version (this reader is
version 1). Those readers then refuse the list ("needs a newer app") instead of
misreading it. `minReader` is never written as 1. Numbers in later fields are
integers or exactly representable values, since anything else could not
round-trip to the canonical bytes. JavaScript never re-serializes the list: the
browser holds the canonical text Rust wrote and hands that text back to Rust
(`PinsText`). Its parsed objects are read-only views.

**One set of rules for every app** (`identity_pins`, also through WASM), so
a pin one app writes is never undone or misread by another. Drive, Chat core
and the CLI all go through them:

- **`record(list, account, authority, update, since)`:**
  - `firstSeen` pins only an address and an account the list knows nothing
    of. It never replaces a pin.
  - An address some pin had before gives `formerAddressTaken`: not pinned.
    Drive and the CLI say `changed`, and Chat quarantines.
  - An account already pinned under another name gives `knownElsewhere`: not
    pinned twice. Its trust holds, and following its chain moves it. When the
    user tries to accept it at the new address, Drive says "someone you already
    know as …" and the CLI's `kutup identity trust` fails with that message.
    Fetching and applying the chain there needs the rename endpoints
    (docs/plans/username-renames.md); until they land it stays this message.
  - `accepted` and `verified` replace another authority at the address. The
    replaced pin is detached and its incarnation is kept in `replaced`.
  - The same authority keeps its history.
  - Whether the list changed is whether it differs from before.
- **`lookup(list, address, publishedAuthority)`:**
  - `pinned` (with whether the authority published there is still the
    pinned one);
  - `renamed` (the authority there is pinned, or detached, under another
    address: fetch its chain);
  - `returned` (a detached pin is back at its last address);
  - `moved` (pinned accounts had the address before, each with where it is
    now if known: whoever is there now is someone else);
  - `new`.
- **`apply_rename(list, authority, chain)`:**
  - Verifies the chain against that authority's pin (live or detached). The
    chain must hold the pin's address and extend its anchor; a rollback or a
    fork is refused.
  - Then moves the pin to the chain's current address. It keeps its trust,
    since the safety number did not change.
  - Its `formerly` comes from the chain, and its anchor is the chain's head.
  - The address's previous holder is detached and named in `replaced`, and
    the caller tells the user.
  - Applying the same chain twice changes nothing, and a refusal changes
    nothing.

The vectors (`identity-pins-v2.json`, `renames`) cover:
- one rename followed, and the rollback refused;
- each lookup kind and each record outcome;
- the lists the format refuses (a pin twice, `minReader`);
- non-canonical encodings;
- a list with later fields kept through an update.

They run from Rust and WASM.

### 4. Checking a person (web)

`checkIdentity(me, account, claimed)` in `@kutup/drive-core` (`identityPins.ts`):

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

### 5. One verification for every app

Built after the first slices, on the same list:

- **One safety number.** The number two people compare in person moved from
  Chat's core to `kutup-crypto::safety_number` (V2: the two authority keys,
  no address, so a rename keeps it; a vector pins it). Drive, Chat and the
  CLI derive the same digits and QR.
- **Verify in Drive.** Chat's verification dialog moved to `@kutup/ui`. Drive
  opens it beside who shared a file, on each person in the share dialogs and
  from the identity banner; scanning (or pasting) the other person's QR marks
  them `verified` in the list, which also accepts a changed identity compared
  in person. A verified person gets a green shield.
- **In Contacts.** A contact's Kutup address shows the same shield and opens
  the same dialog (`@kutup/drive-ui/IdentityShield`), for an address on this
  server or one already in the list; ordinary email addresses are not looked
  up, so no other server learns who is in the address book.
- **Chat on the list.** Chat's engine consults and writes the list
  (docs/chat-protocol.md, trust states): a contact the list knows by another
  authority is quarantined, one verified elsewhere is verified in Chat, Chat's
  verifications reach the list. The list never lifts a Chat quarantine.
- **The CLI.** `kutup identity list|show|verify|trust`; `kutup share` checks
  the recipient and stops on a doubt unless `--share-anyway`; the incoming
  list shows each sender's identity; `kutup login` signs a missing binding.
- **Lookups in batches.** `POST /api/users/drive-identities` answers for up to
  100 people of this server at once, so a page of shares from many people is
  one request under the user lookup limit.

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
