# Chat — Signal feature parity

**Status:** in progress (started 2026-09-25), branch `feat/frontend-rewrite`.
Required before deployment (phase 5 of docs/plans/multi-app-web-rewrite.md).

## Scope

What Signal Desktop does for messaging, rebuilt in Kutup's protocol and the
Chat app's look. Decided with the product owner:

- **In:** everything below, including voice/video calls and Web Push.
- **Out:** Stories and payments.
- **Groups stay MLS.** Signal's sender-key groups with a central group server
  do not fit federation, and MLS already gives agreed membership and cheaper
  removal.
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
3. **Group info** (docs/chat-mls.md "Group information"). Name at creation,
   description and picture in the MLS private control state, changed by a
   `GroupInfoChange` Commit; the owners' "who can edit" rule.

4. **Group timeline notices** (docs/chat-mls.md "Timeline notices"),
   written locally from each applied Commit; a local-only content kind that
   no path can send or accept.
5. **Leave group** (docs/chat-mls.md "Leaving"): a `leaveRequest` control,
   removal committed by the first staying administrator, successor choice
   for the last administrator.

Next, in order:

6. **Message features** (done): mentions, forwarding, profile "about", link
   previews (fetched by the sender's server), view-once media, polls, and
   personal stickers (made from any picture, synced with `stickerSaved` /
   `stickerRemoved`; Signal's sticker packs are not carried over).
7. **Invite links.** A join capability carried in the link fragment,
   optional administrator approval.
8. **Notifications.** In-tab notifications with per-chat and global
   settings, then Web Push with a service worker.
9. **Calls.** 1:1 voice and video over WebRTC with TURN, then group calls
   through an SFU; end-to-end encrypted media frames.
10. **Smaller things.** Persistent drafts, failed-send retry,
    typing-indicator setting, default disappearing timer for new chats,
    keyboard shortcuts, chat export.
