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
