# One profile for the account

**Status:** agreed 2026-09-26, in progress. Branch `feat/frontend-rewrite`.

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

A share carries the sharer's profile key, encrypted to each recipient the
way the folder key already is. A recipient's client:
- fetches the profile (version and access key both come from the profile
  key; federated like chat);
- shows names and pictures in "Shared with me", the share dialog and the
  file details.

The owner learns members' profiles the same way: a recipient's client
returns its own profile key when it accepts the share. A member without a
profile shows as their username, as today.

## Slices

1. (done) The profile functions in Rust/WASM (`accountProfileOpen`,
   `accountProfileSeal`), source id `128` on the server, the Profile page in
   the account app (with the presence colour and your address), and Chat's
   Profile settings becoming a preview with "Edit profile". The avatar
   helpers moved to `@kutup/ui`.
2. Settings layout: Account (storage), Security, one Devices & sessions
   list, and Drive → Settings with version retention.
3. Drive shows profiles: profile keys in shares, names and pictures in the
   Drive UI, both ways and across servers.
