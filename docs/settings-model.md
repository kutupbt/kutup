# Settings: per account or per device

Every user setting in Kutup lives in one of two places. This page gives the
rule, lists where each setting is today, and names the ones that do not follow
the rule yet (tracked in [`roadmap.md`](roadmap.md), "Settings model").

## The rule

- **Per account** (stored by the server, readable or sealed): a setting that
  changes **what leaves the device** or **how well the account is protected**.
  A person who turns such a setting off once should not find it on again on the
  next browser or phone they sign in to. Signal syncs these (read receipts,
  typing indicators, link previews) through its storage service, and Proton
  keeps them in the account (remote images, the image proxy, link
  confirmation). Kutup does the same.
- **Per device** (localStorage or IndexedDB on that device): **ergonomics**,
  where each screen may want its own (pane sizes, sort order, an editor's
  mode), and things that **only mean something on that device**: its push
  subscription, a local search index, the browser's notification permission.
- **Security posture across devices: the account sets the floor.** When a
  security setting has a device side (how soon a vault locks), the account
  value applies everywhere, and a device may only make it **stricter**: a
  shorter auto-lock, never a longer one.
- **Following Proton where it syncs ergonomics.** Mail's appearance and
  composer defaults (layout, density, view mode, page size, composer
  font/size/direction) are per account because Proton Mail keeps them in the
  account and Mail follows Proton ([`plans/mail.md`](plans/mail.md)). That is
  the one deliberate exception to "ergonomics are per device".
- **Theme and language** are per account (`/api/account/ui-preferences`) with
  a per-origin copy in localStorage only for the first paint; the account value
  wins on load and when a tab comes back into view.

A setting that would be per account but must not be readable by the server
(it says something private) is stored sealed under the master key or end to
end encrypted (Chat's per-conversation state, Photos' library flags, a
contact's PGP preferences).

## Where each setting is

### Per account (server)

| App | Settings | Storage |
|---|---|---|
| Account | theme, language | `user_ui_preferences` |
| Account | two-factor sign-in | `users.totp_*` |
| Account | presence / cursor colour | `users.color` |
| Account | identity pins | `identity_pins` (sealed; highest revision seen also kept on each device against rollback) |
| Chat | profile (name, avatar, about) | `chat_profiles` (end to end encrypted) |
| Chat | per-conversation pinned, archived, muted, read | hidden Note to Self messages (end to end encrypted) |
| Mail | every option on its settings pages: auto-delete, sign outside mail, public key attachment and PGP scheme, link confirmation, spam action, remote images, image proxy, embedded images, image metadata, undo-send delay, layout, density, view and composer modes, page size, composer defaults | `mail_settings` |
| Mail | senders whose images load, block/spam/allow lists, filters, folder notify and expanded, auto-reply, identity and signature | their own tables |
| Pass | site icons (through Kutup or off) | `pass_settings` |
| Pass | PIN | `pass_pins` (bcrypt) |
| Drive | version retention, folder colours | `users.version_retention_days`, `collections.color` |
| Photos | upload and library folders; favourites, archived, hidden | `photos_preferences`; `photos_library` (sealed) |
| Maps | on/off, provider, through proxy, save folder | `user_map_preferences` |
| Contacts | per-contact encrypt, sign, scheme | inside the encrypted contact card |

### Per device (browser)

| App | Settings | Storage |
|---|---|---|
| Chat | notifications on, sound, prompt dismissed | `kutup:chat:*` localStorage |
| Chat | Web Push on (with its server subscription row) | `kutup:chat:web-push` + `chat_push_subscriptions` |
| Mail | list pane size, dismissed banners | `kutup.mail.*` localStorage |
| Mail | message body search and its index | IndexedDB (encrypted records) |
| Drive | default view, sort, folders first, grid thumbnails | `kutup-drive-view` |
| Notes | source mode; Markdown mode per file | `kutup.notes.sourceMode`, `kutup-md-mode-<fileId>` |
| Photos | viewer info panel | `kutup-photos-info` |
| Chat, Mail | dismissed "not in contacts" banners: dismissals, not policy, so they stay on the device (keyed by user id, cleared on sign-out) | per app localStorage |

## Not following the rule yet

These are stored per device although the rule puts them in the account. Each
is a follow-up, not a bug in a single app.

1. **Chat privacy options**: read receipts, typing indicators, link previews
   (the server fetches the address), always relay calls (hides the IP),
   the default disappearing-message timer, and notification content. A new
   browser starts with link previews on and calls not relayed, whatever was
   chosen elsewhere. They move into the account, sealed, as Signal does.
   Notification content stays per device as the stricter-only override: a
   phone's lock screen may show less than the account default, never more.
2. **Pass auto-lock and unlock mode**: the PIN is per account but whether it
   is used, and the auto-lock delay, are per device; a new device falls back
   to 15 minutes and the password. Both move into `pass_settings` as the
   floor; a device may lock sooner.
3. **Showing the account when joining a meeting link** (and the name shown in
   calls): an identity disclosure, per device and on by default. It moves into
   the account, off by default.
4. **Which devices keep a Mail search index** is known only to each device. The
   account should list them so a person can see where a searchable copy of
   their mail is kept.

There is no user-chosen session lifetime: sessions last a fixed 30 days and
each can be revoked from the account's sessions page.

## Adding a setting

Decide with the rule above before choosing storage, and say which side it is
on in the PR. A per-account setting gets a column in that app's settings table
(or a sealed record if it is private), a typed `GET`/`PUT` route, and the same
default on every client. A per-device setting gets a namespaced localStorage key
(`kutup.<app>.<name>`), read inside `try`/`catch` so that a browser without
storage still works with the default.
