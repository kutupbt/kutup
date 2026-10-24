# Chat — Signal feature parity

**Status:** in progress (started 2026-09-25), branch `feat/frontend-rewrite`.
Required before deployment (phase 5 of docs/plans/multi-app-web-rewrite.md).

## Scope

What Signal Desktop does for messaging, rebuilt in Kutup's protocol and the
Chat app's look. Decided with the product owner:

- **In:** everything below, including voice/video calls and Web Push.
- **Out:** Stories and payments.
- **Groups move to Signal's model.** Sender keys over one-to-one sessions,
  with the group state on the group's own server. This replaces MLS
  ([`pairwise-groups.md`](pairwise-groups.md), in review). Until it ships,
  groups are off in the beta.
- **Group info:** administrators may always change the name, picture and
  description; a group setting ("who can edit group info": administrators /
  all members, changed by owners) can open it to members, as in Signal.

## Slices

Done:

1. **Connection status.** Heartbeat over the chat socket, a notice above the
   list, Retry.
2. **Account state across devices** (docs/chat-protocol.md §6 "Account state
   across devices"). Read position, pin (max 4), archive (back on a new
   message unless muted), mute (Signal's durations), mark unread, delete for
   me (a message or a whole chat), all synced through hidden Note-to-Self
   controls and kept in the backup.
3. **Group info** ([`pairwise-groups.md`](pairwise-groups.md)): name,
   description and picture sealed in the group state on its home, changed by
   a signed change; the "who can edit" access rule. (Built first for MLS
   groups, removed with them.)
4. **Group timeline notices**, written locally from each accepted group
   change; a local-only content kind that no path can send or accept.
5. **Leave group**: a member's own `Leave` change; the last administrator
   names a successor first.

Next, in order:

6. **Message features** (done): mentions, forwarding, profile "about", link
   previews (fetched by the sender's server), view-once media, polls, and
   personal stickers (made from any picture, synced with `stickerSaved` /
   `stickerRemoved`; Signal's sticker packs are not carried over).
7. **Invite links** (done for MLS groups, `chat-invite-links.md`, removed with
   them; pairwise groups have group links, pairwise-groups.md slice 3):
   the secret rides in the group information and the link fragment; a
   sealed mailbox on the host server holds the preview and requests;
   administrators approve, or their clients add people when approval is
   off; the requester's client accepts the invitation by itself.
8. **Notifications** (done, [`chat-notifications.md`](../chat-notifications.md)):
   in-tab notifications (one tab notifies; what they show; sound; muted
   chats only for mentions; unread count in the title), and opt-in Web Push
   wake-ups for closed browsers. Pushes are empty, since the server cannot
   read messages, so they say only that something may be new.
9. **Calls.** 1:1 voice and video (done, [`chat-calls.md`](../chat-calls.md)):
   WebRTC with signals over the Direct session, coturn shared-secret TURN,
   "always relay", call history, ringing across devices and tabs. Group
   calls through the starter's LiveKit SFU were done for MLS groups and
   removed with them; for pairwise groups they are slice 4 of
   pairwise-groups.md.
10. **Smaller things** (done):
    - **Drafts:** they persist per conversation in the browser, show as
      "Draft:" in the list, and are cleared on sign-out.
    - **Sending:** a message still going out shows a clock, then "Not sent"
      with Retry. Group messages already encrypted into the group outbox count
      as queued, not failed, so the composer is not refilled (resending it
      would duplicate the message), and they show in the thread until
      delivered.
    - **Offline:** reloading keeps showing local history.
    - **Typing indicators:** a switch that stops both sending and showing
      them.
    - **Default timer for new chats:** a new direct chat is a message request
      until accepted, so its messages carry the timer meanwhile and the
      conversation timer is set on acceptance.
    - **Keyboard shortcuts:** Ctrl/⌘K search, Alt+N new chat, Alt+↑/↓
      between chats, and Ctrl/⌘/ or ? for the list.
    - **Export:** a conversation as a plain-text transcript, after a warning
      that the file is not encrypted.
