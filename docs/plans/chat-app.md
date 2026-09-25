# Chat app — design

**Status:** implemented 2026-09-24, branch `feat/frontend-rewrite` (phase 4 of
docs/plans/multi-app-web-rewrite.md): all six slices, checked in the browser
with two accounts (requests, replies, reactions, edits, deletes, receipts,
disappearing messages, search, files, the viewer, voice notes, groups,
settings, phone width). The Playwright chat specs port in phase 5.

## Why

Chat used to be one 4.3k-line page inside the Drive shell. It moves to its own
origin (`chat.<domain>`), built on the shared design, with the protocol code
it already has (`@kutup/chat-core`: `ChatService`, MLS, backup, media) and no
protocol changes.

## Reference

Signal Desktop: a conversation list on the left, the thread in the middle, and
everything about the conversation (safety number, members, disappearing
messages, block) in a details panel on the right instead of header buttons.
One pane at a time on a phone.

## Structure

```
apps/chat/src/
  app/        Boot (session fork), ChatShell, ChatProvider (service lifecycle)
  state/      derived view models over history(): conversations, requests,
              messages with edits/reactions/receipts/timers folded in (pure,
              unit-tested — lifted from the old page's inline selectors)
  features/
    list/         conversation list, new chat, requests, note to self
    thread/       message list, bubbles, composer, reactions, replies,
                  edits/deletes, receipts, typing, disappearing timer, search
    media/        attachments, voice notes, viewer, local media cache
    details/      contact (safety number, block), group (members, roles,
                  owners, policies, security, close/recover)
    groups/       create, invitations, owner approvals
    settings/     profile, devices, read receipts, backup, media storage
```

- **Service lifecycle.** One `ChatService.open(...)` per signed-in tab, held
  by a provider; `subscribe` drives a snapshot refresh (the history,
  contacts, profiles, groups, invitations, approvals and backup status in one
  load, stale results discarded), exposed to components through
  `useSyncExternalStore`. `dispose()` on sign-out and unmount.
- **Failure states** before the shell: browser without Web Locks, a server
  without Chat, a device that cannot open (offer the local device reset the
  old page had).
- **Routes:** `/` (list; on a wide screen the most recent conversation), `/c/:key`
  (a conversation, `key` = `conversationKey`), `/requests`, `/settings/*`.
  Chat has its own settings pages: devices, backup and media live in this
  origin's service and local store.
- **Strings** under `chat.*` in the app's own locales, en + tr, recovered
  from the old page where they fit; the old hard-coded English MLS strings
  become keys.
- **Test ids** of the old page are kept where the element still exists, so
  the Playwright chat specs port with path changes only (phase 5).

## Slices

1. Foundation: boot, provider, shell, failure states, view models.
2. Conversations: list, new chat, note to self, requests (accept, reject,
   block).
3. Thread: messages, composer, replies, edits and deletes, reactions,
   receipts, typing, disappearing messages, search.
4. Media: attachments, camera, voice notes, viewer, save and clear.
5. Details: contact and safety number verification, block; groups (create,
   invitations, members, administrators, owners and approvals, policies,
   security details, close and recover).
6. Settings: profile, devices, read receipts, backup status, media storage.

## Not in scope

No protocol or server changes, with one fix in `chat-core`: a socket hint
that arrived while a mailbox drain was running was folded into it, so a
message landing just after that drain read the mailbox waited for the next
hint; the service now drains once more. Things chat-core could not yet provide
(group names, leaving a group) are in
docs/roadmap.md rather than faked. Signal parity beyond this app's first
version is tracked in docs/plans/chat-signal-parity.md.
