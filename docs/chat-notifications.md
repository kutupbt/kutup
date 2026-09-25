# Kutup Chat notifications

Chat notifies in two ways: while it is open in a browser tab, and, when the
person turns it on, through Web Push while the browser has no Chat open.

## While Chat is open

The chat app decides from the decrypted history, as Signal Desktop does.

- **What notifies:** a new incoming message; a reaction to one of your own
  messages; a group invitation; for administrators, someone asking to join
  through a group link.
- **What doesn't:**
  - messages from blocked people;
  - a chat already read up to that message (also on another device);
  - a muted chat, unless the message mentions you;
  - what was already there when the chat opened.
- **Focus:** while any tab of the chat has focus there are no system
  notifications, only the sound, and only for messages in chats other than
  the one on screen.
- **Tabs:** one tab per account shows notifications (the holder of a Web
  Lock; another takes over when it closes). Tabs tell each other over a
  BroadcastChannel whether they have focus and which chat they show.
- **Settings (Chat settings → Notifications, kept per browser):**
  - on or off;
  - what a notification shows: name and message, name only, or nothing;
  - a short Web Audio chime;
  - a test notification.
  A one-time prompt above the chats asks the browser for permission.
- **Grouping:** notifications for one chat share a tag, so a new one
  replaces the last. More than three at once become one summary.
- **Tab title:** it counts unread messages in chats that aren't muted, as
  "(3) Kutup Chat".

## Web Push, while Chat is closed

Messages are end-to-end encrypted and usually sealed-sender, so the server
cannot say who wrote or what. A push is therefore **empty**. It wakes the
browser's service worker (`/push-sw.js`), which shows one generic
notification ("You may have new messages."). Clicking it opens Chat, which
then shows what arrived.

- **Opt-in:** "Notify me when Chat is closed" subscribes the browser
  (`PushManager.subscribe`, `userVisibleOnly`) with the server's VAPID key
  (`/api/auth/settings` → `chat.webPushPublicKey`). It then registers the
  endpoint for this chat device (`PUT /api/chat/push-subscription`).
  - Each start renews the registration, for a new server key or a new
    language of the worker's words, which travel in its registration URL.
  - Signing out removes it.
- **When the server pushes:** after it stores a Direct, sealed, federated or
  MLS mailbox row for a device that has no live WebSocket. It then:
  - waits five seconds, so a page reload doesn't cause a push;
  - pushes at most once a minute per device;
  - sends `TTL: 86400`, `Urgency: high` and `Topic: kutup-chat`, so the push
    service keeps only the latest wake-up;
  - never pushes for this account's own sent transcripts or notes to self.
- **What else wakes a device:** MLS mailbox rows are anonymous, so group
  controls and your own group messages also wake your other closed browsers.
- **Signing:** pushes carry an RFC 8292 VAPID token (ES256, P-256). The
  server makes the key once and keeps it in `chat_web_push_key`.
- **Stale subscriptions:** when the push service answers `404` or `410`, the
  subscription is forgotten.
- **No arbitrary URLs:** the server sends only to https endpoints on port
  443 whose host is in `CHAT_WEB_PUSH_HOSTS`. By default that is Chrome and
  Edge (FCM), Firefox, Safari and Windows. Other endpoints are refused when
  registered, and dropped if the list later changes.
- **Off switch:** `CHAT_WEB_PUSH=false` turns it off.

## What servers learn

- **Kutup server:** nothing new beyond the push endpoint of each subscribed
  device and when it pushed.
- **Push service** (Google, Mozilla, Apple or Microsoft, chosen by the
  browser): which server wakes this browser, and when. The setting says so.
- **Neither** learns who wrote or what.

Browsers can't take part in private or incognito windows (Chrome refuses the
Push API there). They then keep only the in-tab notifications.
