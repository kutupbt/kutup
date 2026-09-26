# One profile for the account

**Status:** agreed 2026-09-26, done (slices 1–3). Branch `feat/frontend-rewrite`.

## Problem

"You" is spread over three places with no rule:

| Where | Holds |
|---|---|
| Account → Account | email, username, storage for Drive and Chat, presence colour (Drive editing), file-version retention (a Drive setting) |
| Chat → Profile | display name, picture, "about" (end-to-end encrypted, Signal-style), chat address and QR |
| Drive | nothing: people appear by username |

There are also three device lists: Account → Sessions, Account → Editor
devices, and Chat → Devices.

## Decisions (product owner, 2026-09-26)

1. **One profile, in the account app; each app keeps only its own
   preferences.** This is what Proton and Google do.
2. **The profile stays end-to-end encrypted, and Drive uses it too.** The
   server never sees names or pictures. The people you chat or share files
   with do. There is no server-side display name.
3. **One "Devices & sessions" list** in the account app (the default
   proposed; nobody objected).

## Target layout

**Account app (`account.`):**
- **Profile:** name, picture, about, presence colour; your address and QR
  code, read-only.
- **Account:** email, username, storage for Drive and Chat together, delete
  account.
- **Security:** password, recovery phrase, two-factor.
- **Devices & sessions:** web sessions, chat devices, editor devices and the
  CLI in one list, each labelled and revocable.

**Drive → Settings (new):** file-version retention (moved from Account),
default view and sort.

**Chat → Settings:** Notifications, Privacy, Backup, Storage. Profile and
Devices become links to the account app.

## How the profile moves out of the chat engine

The server already holds everything:
- the encrypted name, picture and "about" envelopes;
- the profile key, wrapped under a key derived from the account master key
  (`PutChatProfileRequest.wrappedKey`).

Any signed-in client with the master key can open and re-seal the profile.
The account app has it. What changes:

- **Crypto stays in Rust.** Pure functions (no chat engine, no device) open
  the own profile and seal the next revision or a first profile:
  `accountProfileOpen` and `accountProfileSeal`. The account app reaches them
  through the chat WASM, loaded only on the Profile page.
- **The account app as a source.** Profile writes name a source device for
  ordering. The account app, which is not a chat device, writes with the
  reserved source id `128`: outside the chat device range 1–127 (the
  envelope format refuses 0). The server accepts `128` from the account
  itself (migration 053).
- **Chat devices adopt newer revisions.** They take a newer revision from
  the server as they do from another chat device. Key rotation (on
  blocking) stays in Chat: it has to reach contacts through messages.

## Drive sees profiles

People who share a folder, either way round, give each other their profile
key in a `ProfileKeyEnvelopeV1`: sealed to the other's Drive HPKE key and
signed with their own Drive signing key, like a named share. Differences from
the first sketch (a key per share):
- The envelope is bound to the two accounts and incarnations, not to a
  folder. The server keeps one per pair (`drive_profile_keys`: a "sent" row
  for the giver, a "received" row for the recipient), so ten shared folders
  mean one key, and rotating a folder does not touch it.
- It is not part of the share request. Whenever Drive is open, the client
  lists everyone it shares with (`GET /api/drive/people`), gives its current
  key to anyone whose "sent" version is not current (a new share, a first
  profile, a new key after blocking in Chat), and opens the keys it got.
  The same path handles old shares; nothing needs a backfill.
- Across servers the giver's server forwards the envelope
  (`PUT /api/fed/drive/profile-keys`); each server checks that a share
  exists between the two people and that the envelope names them.

A recipient fetches the profile with the key (version and access key both
come from it; federated like chat) and Drive shows the name and picture in
"Shared with me" and the share dialog's access list. Anyone who has not
given their key yet, or whose key is out of date, shows as their address.

## Slices

1. (done) The profile functions in Rust/WASM (`accountProfileOpen`,
   `accountProfileSeal`), source id `128` on the server, the Profile page in
   the account app (with the presence colour and your address), and Chat's
   Profile settings becoming a preview with "Edit profile". The avatar
   helpers moved to `@kutup/ui`.
2. (done) Settings layout:
   - **Account:** details and storage only.
   - **Devices & sessions:** one page with sign-in sessions, chat devices
     (listed; removing one opens Chat, which re-signs the device list and
     takes the device out of groups) and editor keys. `/settings/sessions`
     redirects there.
   - **Drive → Settings:** file-version retention (moved from Account) and
     this browser's default view (list/grid, folders first, previews).
   - Every app's "Settings" menu item opens the Profile page.
3. (done) Drive shows profiles: `ProfileKeyEnvelopeV1` in kutup-crypto (and
   WASM), `drive_profile_keys` with `GET /api/drive/people`,
   `PUT /api/drive/profile-keys` and the federated delivery (migration 054),
   the chat WASM's `accountProfileKey`, `profileLookup` and
   `profileOpenPeer`, and names and pictures in Drive's "Shared with me" and
   access list. Covered by the Rust envelope tests, the two-server live test
   (both directions, a stranger and a forged sender refused) and a browser
   run on one server.
