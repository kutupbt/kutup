# One device list per account (wipe W5)

Status: **approved** (third session, 2026-10-25; decisions in section 7). Lands
on the wipe-2 integration branch (it changes the account manifest and the
device tables). Nothing here is built yet. Item W5 of
[`wipe-unification.md`](wipe-unification.md); its open question 3 is settled
by events: #320 has merged, so this is the separate PR before the wipe.

**In one paragraph:** today an account has three device registries that know
nothing of each other: collab's `user_devices` (Ed25519 frame keys under
unchained, leased statements), Chat's `chat_devices` (under the hash-chained,
authority-signed account manifest), and the sign-ins in `auth_sessions`. No
action removes a device from all of them. And a collab frame's recipients
never check who sent it: only the server does, against keys it holds itself.
This note makes the **account manifest the one device list**, as Signal's
account record is: every device of the account (a Chat app, an editor, the
CLI) is an entry with its own keys; the server keeps one `devices` table; one
signed manifest adds, renews and removes devices for everything; peers and
the account's own clients verify every collab sender against that manifest.

## 1. Today

(Survey of master after #340; file references are to master.)

| Registry | Id | Keys | Lifecycle | Verified by |
|---|---|---|---|---|
| `user_devices` (collab) | global bigint | Ed25519 frame key, in a standalone authority-signed statement (`crypto/device_registration.rs`) | live while its sign-in is; 30-day lease counts toward a cap of 20; signed revocation numbered by a server sequence, permanent | the home server, at register, renew, revoke and per frame |
| `remote_collab_devices` (+ `remote_revoked_device_keys`, `remote_revocation_marks`, `collab_revocation_marks`) | (domain, bigint), `user_id text` | a copy of the statement | fresh under 30 days; swept after lease + 7 days; revocations forwarded by announce, tombstoned by key hash, acknowledged by a mark | the file's home server, per frame (`remote_devices::check_sender`) |
| `chat_devices` + `chat_device_manifests` (`AccountManifestV2`) | 1..127 per account | the account's libsignal identity, prekeys, registration id, a salted credential | idle expiry marks the row; the next manifest drops it; removal is a manifest without it | the server (`store_manifest_v2`) and every client and peer (TOFU pin, hash chain, gap recovery) |
| `auth_sessions` | uuid | refresh token | expires or is revoked | the server |

Side tables hang off these by id: Chat's mailbox, prekeys, push subscriptions
and tickets cascade from `chat_devices`; calendar push subscriptions hang off
`auth_sessions`; `file_update_log` names `user_devices.id` or a remote
(domain, device).

What follows from it:
- **Settings → Devices** shows three lists (sign-ins, Chat devices, editor
  keys); removing in one leaves the others.
- **Collab recipients don't authenticate senders.** `openCollabFrameV1`
  (`frontend/packages/collab/src/cryptoFrame.ts:51`) opens a frame with the
  file key and returns the sender device id unchecked. The Ed25519 signature
  is checked only by the server, with the key it stores. Anyone holding the
  file key, or the server, can write a frame that recipients take as any
  device's.
- **Two revocation models.** Collab revocations are separate signed
  statements ordered by a server sequence, forwarded to peers by announce;
  Chat's are manifest succession. Freshness is a 30-day lease on one side and
  the hash chain on the other.

## 2. What Signal does

One device list per account, in the account record
(`Signal-Server … storage/Account.java`, `Device.java`): each device has an id
(1..127), its registration id, its login credential, push tokens and
last-seen time. Every feature (messages, calls, sync) uses that list.
Removing a device (`AccountsManager.removeDevice`) deletes its pre-keys and
queued messages, drops its connections and writes the account in one locked
transaction; contacts learn the new set from `409`/`410` answers. Kutup's
manifest is the same list, but authority-signed and hash-chained, so peers
need not trust the server for it.

## 3. The design

### 3.1 The manifest gets one entry per device, of every kind

`AccountManifestV3` replaces V2 (the wipe empties every manifest, so nothing
reads V2 after it; V2 code goes):
- the same envelope: account, incarnation, sequence, previous hash, identity
  key and binding, Drive keys, issued at, authority key id, signature;
- **devices**, each:
  - `deviceId` (1..127, one id space per account);
  - `kind`: `chat` (a Chat app instance), `editor` (an editing app instance:
    Drive, Office, Maps, Pass), `cli`;
  - `chat`: `{ directChatSuite, registrationId }`, for a device that takes
    Chat messages (absent otherwise);
  - `frameKey`: the device's Ed25519 key for collab frames (and later for
    any other per-device signature), for a device that edits;
  - `session`: a hash of the sign-in it belongs to (`SHA-256(session id)`), so
    the account's devices group by sign-in without the server learning more
    than it does now;
- the legacy `mls` field is gone;
- the device count is a site setting (`devicesPerAccount`, default 32; the
  manifest format caps it at 127). One browser can hold several entries
  (Chat, Office, Maps), so the default leaves room for several browsers and
  the CLI.

**Why an entry per app instance, not per browser.** Each app lives on its own
origin, so its storage, and any key in it, is its own: the Chat app's
identity sessions and the Office app's frame key can't be the same
installation's without a cross-origin key store, which the browser model
(and Proton's) avoids. Signal Desktop is one app; Kutup in a browser is
several. Settings groups the entries by sign-in (`session`), so a person sees
"Firefox on this laptop: Chat, Office" and removes it as one.

### 3.2 One server table

`devices (account_id, device_id, kind, session_id, name, created_at,
last_seen_at, expired_at, credential_hash, credential_salt, frame_key,
chat columns…)` replaces `chat_devices`, `user_devices`,
`device_registration_challenges` and the four remote collab tables. Chat's
side tables (mailbox, prekeys, push subscriptions, tickets) reference it as
they reference `chat_devices` now. A row is live while its sign-in is live and
it is in the head manifest.

Every device authenticates with the device credential Chat uses today
(`X-Kutup-Chat-Device` becomes `X-Kutup-Device`), on top of its sign-in. The
collab routes take it in place of `?deviceId=`.

### 3.3 Adding, renewing and removing devices: manifest succession only

- **Add:** a new app instance registers its row (server-issued id, its
  credential), then publishes the next manifest with its entry. As for Chat
  today, a row not in the head manifest within a short window is dropped.
- **Renew:** gone. The lease existed because statements weren't chained; a
  manifest is current until it's superseded, and peers check it against the
  account's head (3.4). Idle devices expire as Chat devices do now: the
  server marks the row (`expired_at`), and the account's next manifest drops
  it.
- **Remove:** any device of the account (or the Account app) publishes a
  manifest without the entries, then ends their sign-ins. The server drops the
  rows and their side rows, and closes their connections. **Ending a sign-in**
  (sign-out, expiry, password change) marks its devices expired at once, and
  the next manifest drops them; until then the server refuses them, as it
  refuses collab devices of an ended sign-in today.
- The Account app needs to sign manifests. Re-signing with the head's identity
  binding needs only the authority key (`sign_manifest_with_binding`), so it
  moves from chat-core to `kutup-crypto` (it was in the code-item-1 move
  anyway), and the Account app signs through the crypto WASM.

### 3.4 Verifying collab senders against the manifest

- **Frames name their sender account.** The collab frame header carries the
  sender's account (`aci:<uuid>@<server>`) and device id, both bound into the
  signature; today it carries a server-global device id.
- **Recipients verify.** The editor fetches the sender's manifest (its own
  account's from its server; another account's through its server's
  federated manifest fetch, as Chat does), verifies it with the same pinning
  code as Chat (`verify_manifest_trust`: TOFU, rollback and equivocation
  detection), and checks each frame's signature against that device's
  `frameKey`. A frame from a device not in the pinned head is held, the
  manifest fetched again once, and the frame dropped if the device is still
  absent. This is the end-to-end check the recipients lack today.
- **The file's home server verifies too** (it still keeps out junk), against
  the same manifest, cached per account (`remote_account_manifests`) and
  refreshed when a frame names a newer manifest sequence than it holds or a
  device it doesn't know. Frames carry the sender's manifest sequence; a home
  never accepts an older head than one it has seen (the chain).
- **Revocation reaches peers** through the next manifest: no announce, no
  marks, no tombstones. How fast: at the next frame from the account (it names
  the newer sequence), or the next fetch. The sender's own server could delay
  that by serving an old head, as it can delay forwarding a revocation today.

### 3.5 Push subscriptions and sign-ins

- Web push subscriptions hang off the device (`push_subscriptions
  (account_id, device_id, apps)`, one VAPID key), replacing the Chat and
  calendar tables. That is the "after W5" item of `wipe-unification.md`
  (size S) and can follow in its own PR.
- `auth_sessions` stays the sign-in list; Settings shows each sign-in with its
  devices under it.

## 4. What changes

**Removed:** `user_devices`, `device_registration_challenges`,
`remote_collab_devices`, `remote_revoked_device_keys`,
`remote_revocation_marks`, `collab_revocation_marks`; the device registration
and revocation statements (`crypto/device_registration.rs`) and their
vectors; `/api/devices*`, the collab devices federation route and announce;
the 30-day lease and renewals (web `currentDevice.ts`, CLI
`collab_device.rs`); `AccountManifestV2` and its legacy `mls` field; three
Settings lists.

**Changed:** `chat_devices` becomes `devices`; the manifest becomes V3; the
collab frame header names the sender account and manifest sequence; the
device credential header is shared; the CLI registers as a `cli` device.

**Added:** recipients' sender verification in the editors and the CLI; the
home's manifest cache; one Devices page.

## 5. Slices (on `wipe-2`)

1. **Format and table:** `AccountManifestV3`, the `devices` table, Chat moved
   onto it; manifest signing in `kutup-crypto`. Chat behaves as now.
2. **Collab onto the manifest:** editor and CLI devices register through the
   manifest; frames name account and sequence; the home verifies against the
   cached manifest; the old collab tables, statements and announce go.
3. **Recipients verify senders** in the editors and the CLI.
4. **One Devices page** in Settings, grouped by sign-in; ending a sign-in
   ends its devices.
5. (After, own PR) device-keyed push subscriptions.

Size: L in all (1: M, 2: M, 3: S, 4: S). Each slice runs the Chat and
collab live tests and the two-server gate before it merges into `wipe-2`.

## 6. Tests

- Format: V3 vectors (Rust and WASM); a manifest without chat or frame keys
  for a device kind is refused; the cap is a site setting.
- Server: one removal ends a device for Chat, collab and push in one
  transaction; a device of an ended sign-in is refused at once; a row not in
  the head manifest is dropped.
- Collab: a frame signed by a device not in the head is refused at the home
  and by recipients; after a removal, the next frame from the account makes
  the home refetch, and the removed device's frames stop; a server that
  substitutes a frame key fails the recipients' check.
- Two servers: a peer sees a removal through the next manifest; an older head
  is never accepted after a newer one.
- Browser: one Devices page lists Chat and Office instances under one sign-in;
  removing it signs the account's devices out everywhere.

## 7. Decisions

The user approved the note on 2026-10-25 with these answers:

1. **One entry per app instance**, grouped by sign-in in Settings (3.1). A
   browser with Chat and Office open has two entries under one sign-in; no key
   store is shared across app origins.
2. **Recipients verify collab senders in W5** (3.4, slice 3), not later: the
   home and every recipient check a frame's sender against the manifest.
3. **Device cap 32 per account by default**, a site setting an admin can
   change site-wide and per user.

## 8. Build notes

### Slice 1 (format and table)

What the note leaves open, as built:

1. **Format.** `AccountManifestV3` replaces V2 in place in
   `kutup-chat-proto::account_identity`, with `AccountManifestDeviceV3` and
   the V3 publication and history page; the bundle and registration types
   keep their names. The signing domain follows the one label grammar:
   `kutup/account/manifest/v3\0`.
2. **Device entries.** `deviceId`; `kind` (`chat`, `editor`, `cli`);
   `chat: { directChatSuite, registrationId }`; `frameKey` (canonical base64
   of 32 bytes, a valid Ed25519 key); `session` (lowercase hex of 32 bytes).
   - A `chat` entry carries `chat`.
   - An `editor` or `cli` entry carries `frameKey`.
   - An `editor` entry never carries `chat`.
   - `frameKey` is optional on `chat` (for later per-device signatures), and
     `chat` is optional on `cli` (a CLI that takes Chat).
   - A manifest lists 1..=127 entries and may list no Chat device.
3. **Sign-in grouping.**
   - `session` is SHA-256 over `kutup/account/device-session/v1\0` and the
     device's root sign-in id: an app's session's parent, or the session
     itself for the CLI and native apps.
   - The server works it out at registration and returns it.
   - A publication whose entry names another session than that device's row
     is refused.
   - Contacts see only an unlinkable hash; the server learns nothing it
     doesn't hold already.
4. **Re-registration (a new Chat identity).**
   - Every Chat device goes, but the account's non-Chat entries stay.
   - The manifest lists the new Chat device and the head's other entries
     unchanged.
   - The new device takes the lowest id those entries leave free (1 while the
     account has only Chat devices).
5. **Table.**
   - `chat_devices` becomes `devices`, gaining `kind`, `session_id` (the root
     sign-in) and `frame_key`.
   - The Chat columns become nullable, with a CHECK by kind.
   - The account column keeps the schema's `user_id` name.
   - Every query that reads Chat columns or lists an account's Chat devices
     takes the rows with Chat keys (`suite IS NOT NULL`), since a CLI may
     take Chat too.
   - Publishing a manifest still prunes the rows it doesn't list at once.
     Slice 2, where editors register and then list themselves, gives an
     unlisted row a grace window first, so a concurrent publication by
     another device doesn't drop it.
   - The device header becomes `X-Kutup-Device`.
   - Registration picks the lowest id no row holds, expired rows included
     (an expired row keeps its id until the next manifest drops it).
6. **Caps.**
   - `devicesPerAccount` is a new `NumericSetting` (default 32, range
     1..=127) over all entries.
   - `chat.maxActiveDevices` stays as the Chat sub-cap, since each Chat
     device costs every sender one more sealed copy.
7. **Manifest signing in `kutup-crypto`.** This moves with the chat-core
   crypto move, which goes to master and lands before slice 4. Slice 4 is the
   first to need it (the Account app signing removals), so slice 1 leaves it
   in chat-core.

### Slice 2 (collab onto the manifest)

What the note leaves open, as built:

1. **Frame format V3** (`KUTPCF3\0`, in `kutup-crypto::envelope`).
   - The 80-byte header becomes 88 bytes:
     - `deviceId` u32 at 36 (1..=127);
     - 4 reserved zero bytes;
     - `manifestSequence` u64 at 44: the sender's manifest when it sealed;
     - then `sequence`, nonce and length, as before.
   - The signature covers `kutup/collab/frame/v3\0`, the sender's account
     (`AccountRef::bytes`), the header and the ciphertext.
   - The account travels beside the frame on every transport (`{ sender,
     frame }`) rather than in it, so the frame stays fixed-size. A server
     that lies about the sender breaks the signature.
   - The signed bytes hold the file id, the key generation and the
     per-device `sequence` (all in the header). So a valid frame can't be
     replayed into another file. A replay into the same file is refused,
     because the log keeps each sender's sequence once. The AEAD binds the
     file id too, under the file key. But a key holder can re-encrypt, so
     the binding that counts is the signature's.
2. **Registering an editor or CLI device.**
   - `POST /api/devices` with `{ kind, name, frameKey, credential }` gives a
     row with the lowest free id under the caller's sign-in, within
     `devicesPerAccount`.
   - The device then publishes the account's next manifest listing itself
     (`POST /api/chat/manifest`, device-authenticated as `X-Kutup-Device`).
   - Signing needs only the authority key, so `AccountManifestV3::sign`
     moves into `kutup-chat-proto`. The crypto WASM exposes "add this device
     to this head", which builds and signs it.
   - The editors never load the Chat runtime. The rest of the chat-core
     crypto move is unchanged.
3. **No leases or statements.** A device's frames count while:
   - its row is live;
   - its sign-in is live;
   - the head manifest lists it with that frame key.
   Publishing prunes an unlisted row only once it is older than
   `deviceListingGraceSeconds` (a site setting, default 600). The grace is
   for a device between registering and listing itself. It only delays row
   pruning: an unlisted device's frames are refused throughout, by the home
   (here) and by recipients (slice 3).
4. **Sockets.** A browser can't set headers on a WebSocket, so a device asks
   for a single-use ticket first: `POST /api/device-ticket`, as Chat's
   `ws-ticket`.
   - Chat's `chat_ws_tickets` becomes the one `device_tickets`, used by the
     Chat and collab sockets.
   - The HTTP collab routes take `X-Kutup-Device`; `?deviceId=` goes.
5. **The home checks frames.**
   - A local sender: its row's frame key.
   - A remote sender: the account's manifest, cached in
     `remote_account_manifests` (domain, account id, sequence, manifest).
     - It is fetched through the federated manifest route the first time,
       and again when a frame names a newer sequence or an unknown device.
     - It goes through `verify_successor` over the history, never back to
       an older head.
     - It is fetched at most once a minute per account.
     - A frame on a head older than `remoteManifestMaxAgeSeconds` (a site
       setting, default 300) waits for a fetch first, so a device removed
       on its own server stops counting here within that time. When that
       fetch fails, the cached head still decides until the next try.
     - A failed first fetch, with nothing cached, is recorded in
       `remote_manifest_failures`. The frames after it wait out the minute
       instead of each starting a fetch.
   - `remote_collab_devices`, the revocation tables, the announce route and
     its rate limit all go.
6. **The update log** names a sender as (`sender_domain`, '' for this
   server; `sender_account` uuid; `sender_device` 1..=127), unique with
   `sender_seq` per file. The old `sender_device` bigint and
   `remote_domain`/`remote_device` columns go. The log is cleared by the
   migration, as the wipe clears every file.
   - Trimming the log (a saved version, a new session's base, the daily
     prune of old office frames) would delete the rows that make a counter
     a replay. So every trim records, in the same statement, each sender's
     highest trimmed counter per prefix in `file_sender_floors`.
   - The prefix is the high 32 bits, drawn per editing session. A frame at
     or below its prefix's floor is refused as a replay, and a new session's
     prefix starts clean.
   - A local device's next counter (`mySenderSeqHigh`) is above its floors
     too.
7. **Presence** keys a peer by `account#device`. The hub's peers and
   `close_device` take (account, device).
8. **Removing a device.**
   - It is a manifest without the entry; the server prunes the row and
     closes its sockets.
   - Closing marks the connection shut for good, and its read loop checks
     that before each frame. So a frame read after the removal is never
     applied, even when the loop was busy with another frame at the time.
     The wakeup is a `notify_one`, whose permit waits for that loop.
   - Every 15 seconds a collab socket (local or bridged) also checks its
     device again: listed with the same frame key, its sign-in live. A
     definite no closes it, which catches a close it missed.
   - Signing out publishes the account's manifest without its own device
     (best effort, as the signed revocation was).
   - Account → Devices lists every editor and CLI device
     (`GET /api/devices`: kind, name, sign-in, last seen) and removes one the
     same way. Slice 4 groups that list by sign-in.
9. **The CLI** registers as a `cli` device, keeps its credential and frame
   seed, and publishes its own entry.
10. **Recipients verify every frame** (slice 3, the user's decision). Each
    client checks each frame's signature against the sender's head manifest:
    - the frame key is listed;
    - the device id matches;
    - the manifest sequence is not older than the one it has seen.
    A removed device is refused at once, because the head no longer lists
    it. Slice 3's tests include a home relaying a forged frame that the
    recipient refuses. Slice 2 builds the frame and the home's checks that
    this rests on.
    - Open for slice 3: device ids are reused, and the head decides. So a
      logged frame from a device since removed, or from an earlier holder
      of a reused id, needs a rule of its own. One option is to check it
      against the manifest its `manifestSequence` names, from the account's
      history, rather than against the head.
11. **An account without Chat has a manifest too.**
    - `identityKey` and `identityBinding` are optional and come together.
      The signed bytes carry a presence flag.
    - A manifest without them lists only devices that don't take Chat; an
      editor of an account that never used Chat publishes the account's
      first one.
    - The first Chat device sets the identity by re-registration, which
      continues that chain and keeps the editors' entries.
    - A publication keeps the identity the account has, or none while it
      has none; a distribution or a re-registration names one.
12. **A device's frames go through one gate everywhere.** The server names
    the sender of every delivered frame (`envelope::deliver`): on its
    sockets, in the log, and on the federation wire as `{ sender, frame }`.
    - The home takes a remote frame only from the share's recipient and
      from that recipient's server.
    - Signing is by a frame key that the recipient's cached manifest lists,
      under the incarnation the share was made to.
    - The old `remote_collab_devices` route, its announce and its rate limit
      go; `device_challenges` becomes `device_registrations` (20 a minute
      per account).
13. **A client pins its own account's head** (`OwnManifestPinV1` in
    `kutup-chat-proto`, the same check in the CLI and in the browser's
    crypto WASM).
    - It keeps the newest manifest of its own account it has seen
      (account, incarnation, sequence, hash): the CLI in its profile store,
      a web app per origin in localStorage.
    - Before listing itself or signing a successor, it checks the head the
      server gives. The head must verify under the account's own authority
      and incarnation. It must be no older than the pin, and at the pin's
      sequence it must be the same manifest. Once a head has been seen,
      "no manifest" is refused.
    - So a server can't have a client sign a stale head (bringing a removed
      device back, or dropping the Chat identity), or start a new chain over
      the account's.
    - A reset account's new keys make a new incarnation, which the old pin
      doesn't cover.
    - The CLI also checks that what it signed follows the head
      (`verify_successor`), as the WASM path does.
14. **Pending rows don't fill the cap.** A registration first drops the
    account's rows that its head doesn't list and that are older than the
    listing grace. Only listed rows and rows within their grace count
    toward `devicesPerAccount` and the Chat cap. So a stolen access token
    can't fill the account with registrations that never list themselves.
    `devicesPerAccount` is a per-account setting.

### Slice 3 (recipients verify senders)

Approved by the main session on 2026-10-27, with decisions (a) to (c) below.

Every client that applies a collab frame checks its sender against the
sender account's manifest: the web editors (notes, maps lists, Office,
whiteboards) and the CLI's sync. Until now they took whatever the home
relayed. The home's checks stay, but a home can no longer have its clients
apply a frame the sender's devices didn't sign.

1. **One check, in Rust.** `SenderManifests` in `kutup-chat-proto`, shared
   by the crypto WASM and the CLI. It holds what a client knows of one
   sender account and, for a frame, answers one of:
   - take it;
   - fetch the head, or the manifest at a sequence, first;
   - refuse it.
   The clients only fetch, store and apply.
2. **Rollback pins** (`AccountManifestPinV1`: account, incarnation,
   sequence, hash). One per account a client has met, its own included,
   with one rule for all:
   - A newer head is taken only when the history from the pin to it
     verifies link by link (`manifest-history`), never an older one.
   - A fresh browser or profile with no pin trusts the first head that
     verifies under the account's authority (trust on first use), then
     holds it to that chain.
   - Web: in memory per page. When the origin keeps the sign-in, also
     sealed in localStorage (local-state purpose `ManifestPins`, under a key
     derived from the master key, profile = the client and account), never
     plain. This replaces slice 2's plain own-account pin.
   - CLI: in its profile store.
3. **Live frames** (after `replayed`): the head must list the frame's
   device with the key that signed it. A frame naming a later sequence than
   the head makes the client fetch the head and check once more. So a
   removed device's frames stop at the recipients as soon as they hold the
   head without it.
4. **Logged frames** (the replay on join, the CLI's log reads): device ids
   are reused, and a removed device's past edits are part of the document.
   So a logged frame is checked against the manifest its
   `manifestSequence` names, from `manifest-history`, fetched once per
   sender and sequence. That manifest must verify, be no later than the
   pin, name the pinned account and incarnation, and list the device with
   the signing key.
5. **A reset account.** The account's identity pin (the synced list Drive
   and Mail use, docs/plans/drive-identity-pins.md) names another authority
   than the sender's head: `changed`. Then the sender's frames are refused,
   and the editor shows "Edits from <name> can't be verified: their
   account was reset" (en and tr) until the share is made again to the new
   incarnation. This matches Chat's quarantine and the share's incarnation
   binding. An account the list doesn't know is trusted on first use, as in
   item 2.
6. **Refused frames** are dropped, never applied. The editor shows that
   once per session and sender ("Some edits from <name> couldn't be
   verified"). The CLI prints a warning and `sync` exits non-zero.

**What slice 3 covers and what it doesn't.**
- Covered: a home (or anyone between) can't have a client apply a frame
  that the sender account's devices didn't sign. It can't replay a removed
  device's key into live editing once the recipient holds the head without
  it, can't roll a sender's manifest back, and can't pass off a reset
  account as the old one.
- Not covered: someone who holds a removed device's key, together with a
  home that takes its frames, can add a frame that claims an earlier
  `manifestSequence`. Recipients take it as history (item 4). An honest
  home refuses it (slice 2), so this needs both a stolen key and a
  dishonest home.
- Closing that is the roadmap item **"rotate document keys when a device is
  removed"**, after Signal's practice of new sender keys after a removal.
  When a device leaves an account that edits a file, the file's next
  document key excludes it, and frames under an older document key count
  only up to the rotation's log position.
  - Every frame already signs its `doc_key_id` and key generation (V3).
  - The log keeps each frame's document key.
  - Nothing in slice 3 ties verification to a single key.
  So the rotation needs no format change and no wipe.

Tests:
- Rust: the check's rules: listed or not, key mismatch, a later sequence, a
  reused id with an earlier holder's history, a rolled-back or forked head,
  a reset incarnation.
- vitest: the session's `onFrame` with a fake home relaying a frame of a
  device the head doesn't list, or under another key: dropped, not applied.
- Live (two servers): a removed remote device's frame injected into the log
  by SQL, standing in for a home that takes it: refused at the recipient.
- Browser: spec 04 and the collab suites stay green.
