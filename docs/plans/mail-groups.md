# Mail groups

**Status:** agreed 2026-10-10 (two kinds, group quotas, storage owner; the server vouches for group keys, role groups are distribution lists, member lists are not secret). G1a and G1b done; G1c–G1d next. Follows Mail C1–C3
([`mail.md`](mail.md)); its own pull request after #87 → #88 → #90.

## Goal

Addresses that belong to a team rather than one person, in two kinds the
person creating the group chooses between:

- a **distribution list** (`team@`, `all@`): each member gets the message in
  their own inbox and reads, files and deletes it on their own;
- a **shared mailbox** (`hr@`, `support@`): one mailbox the members work in
  together; once someone has read an application, it is read for everyone,
  and members answer as `hr@`.

The role addresses (`postmaster@`, `abuse@`, `security@`, `hostmaster@`)
become groups too, so they reach a team instead of one administrator, and
can never bounce.

## How others do it

| | Distribution | Shared | Roles | Who may post | Storage and price |
|---|---|---|---|---|---|
| **Exchange / Microsoft 365** | distribution groups, mail-enabled security groups | shared mailboxes (Full Access, Send As, Send on Behalf); Microsoft 365 groups (a group mailbox members subscribe to) | owners, members | everyone, the organisation only, listed senders; moderation | shared mailbox 50 GB free, no licence |
| **Google Workspace** | groups | collaborative inbox (assign, resolve) | owner, manager, member | anyone, organisation, members, managers; moderation | groups free; the archive counts against no one |
| **Proton for Business** | groups with their own address and key | none (members get copies) | owner flag; per-member SEND (send as) and LEAVE | nobody, members, everyone | storage from the organisation's pool |

Proton delivers group mail end to end with OpenPGP proxy re-encryption: the
server turns a message encrypted to the group key into one per member key
without reading it. Kutup encrypts mail from outside on arrival anyway, and
Kutup senders already encrypt one key packet per recipient, so distribution
lists need no group key; only the shared mailbox does.

## Decisions (agreed 2026-10-10)

- Both kinds, chosen when the group is created; a group does not change kind.
- **Storage:** group mail is charged to the group's own quota, set by an
  administrator, never to its members. A distribution list stores a message
  once (one data packet, one small key packet per member), however many
  members it has.
- **Storage owner:** every group records who its storage belongs to. Today
  that is always the server (the quota an administrator sets). When Kutup
  gets organisations (Phase E: aliases, custom domains), the owner becomes
  the organisation and the group's storage counts against its pool; billing
  then attaches to the organisation (see "Storage and pricing").
- Moderation is G2; assigning messages, marking them done and tags are G3.

## Kinds

### Distribution list

- **Mail from outside** arrives in clear and is encrypted once to every
  member's primary key (`encrypt_split`): one data packet, stored once in
  the group's storage; one key packet per member, kept in the member's row.
  Each member has their own row (folder, read, starred, deleted) pointing at
  the shared data packet; the data packet goes when the last row does.
- **Mail from a Kutup user:** `GET /api/mail/keys?email=team@…` answers that
  this is a group and lists its members with their keys (each member's
  signed key list, checked as for any Kutup address). The browser encrypts a
  key packet per member, as for any recipient list; the server stores it as
  above. A Kutup user sending to the list does not learn more than its
  membership, which members may see anyway (see "Who sees members").
- **New members** receive mail from when they join (as at Exchange); a
  removed member keeps what they already received.
- The message keeps its `To: team@…`; Kutup adds `List-Id: <team.kutup.dev>`
  so members' filters and Mail's label can tell group mail apart.
- No group key, so nothing for WKD to publish: OpenPGP users outside send to
  the list in clear and it is encrypted on arrival, like other mail (Proton
  does the same for lists without a group key).

### Shared mailbox

- **A group address key** (OpenPGP, the same shape as personal address
  keys), made in the creating administrator's browser. Its secret part is
  stored once per member, encrypted to that member's address key (an OpenPGP
  message, like Proton's activation tokens); a member's browser opens it with
  their own address key. The server never holds it in clear.
- **The group's key list** is signed by the server's identity key (the
  federation identity every Kutup server has), since a group has no account
  of its own. Kutup senders and WKD use the primary group key. This trusts
  the server for group keys, as distribution lists trust it for membership;
  members' browsers check that the key they hold is the published one and
  warn when not. Key transparency would remove that trust later.
- **Mail from outside** is encrypted on arrival to the group key and stored
  once. **Mail from Kutup users** is encrypted by their browser to the group
  key. **OpenPGP users outside** find the group key through WKD and write end
  to end, as to a person.
- **One row per message**, owned by the group: folder, read, starred and
  deleted are shared. Mail shows each shared mailbox the person belongs to
  under their own folders, with its unread count.
- **Sending as the group:** members with the "send as" right write from
  `hr@…`; the message is signed with the group key and the copy lands in the
  group's Sent. Members without it can read and file only.
- **A member leaves or is removed:** the browser of the manager who removes
  them makes a new group key, primary from then on, and seals it (and the
  older keys, so old mail still opens) for the remaining members only. The
  removed member keeps whatever they already opened; nobody can take that
  back, as at Proton. They cannot read new mail.
- **Members join:** a manager's browser seals every group key for the new
  member's address key, so they read the whole mailbox, as at Exchange.

## Roles and rights

| | Owner | Manager | Member |
|---|---|---|---|
| Read the group's mail | yes | yes | yes |
| Send as the group (shared mailbox) | yes | yes | when granted |
| Add and remove members, change rights | yes | yes (not owners) | no |
| Who may post, description | yes | yes | no |
| Add owners, delete the group | yes | no | no |
| Quota | administrators only | | |

Administrators can do everything on every group, and only they create
groups and set quotas. A group always has at least one owner; system groups
are owned by the administrators.

## Who may post

Per group: **anyone** (including outside), **Kutup users** of this server,
**members** only, or **owners and managers** only (announcement lists).

- Kutup users send through Kutup, signed in, so these rules hold exactly.
- Mail from outside is refused at RCPT (`550 5.7.1 this group accepts mail
  only from …`) unless the group takes anyone. Outside mail claiming to come
  from a Kutup address is not trusted for this (it would be a forgery: the
  domain's DMARC policy covers it).
- Role groups always take anyone: `abuse@` must hear from the world.

## Role addresses

`postmaster@`, `abuse@`, `security@` and `hostmaster@` are system groups,
distribution lists that exist from the start, cannot be deleted or renamed,
and take mail from anyone. An administrator adds members; while a role group
has no active member with a key, its mail goes to every active
administrator. `mailer-daemon@` stays refused. Members answer from their own
address (sending as `abuse@` comes with turning a role group into a shared
mailbox, later).

`/.well-known/security.txt` (RFC 9116) on the apps' hosts names
`mailto:security@<domain>`, with `Expires` a year ahead and
`Preferred-Languages: en, tr`.

## Addresses

A group's address is `name@<server name>`, in the same namespace as
usernames: a group cannot take a username, and registration and username
changes refuse a group's name. Group names follow the username rules.

## Who sees members

Members see the member list of their groups. Kutup users sending to a
distribution list receive the member keys their browser needs, so the list
is not secret from them. A "hidden membership" setting would need the
server to fan out from a group key instead; it is not in G1.

## Storage and pricing

- A group has `quota_bytes` and `storage_owner`. The group's storage is
  counted by the same pool code as an account's (`storage_pool`), with its
  own row; distribution list data packets and shared mailbox messages are
  charged to it. A full group refuses new mail with a temporary failure
  (452), like a full account.
- Members' quotas are never touched by group mail (their rows and key
  packets are small and counted to the group too).
- `storage_owner` is `server` in G1: an administrator sets the quota from the
  server's storage. With organisations (Phase E) it becomes the
  organisation, whose pool funds its groups, so pricing needs no migration.
- How the others price it, for when kutup.dev sells plans: Microsoft gives
  shared mailboxes 50 GB free and prices the users who read them; Google
  does not count group archives; Proton draws group storage from the
  organisation's pool and limits addresses per plan. The fitting model for
  Kutup is Proton's: groups come with organisation plans, their storage
  comes from the organisation's pool, and plans limit how many groups there
  are. Self-hosters set quotas freely.

## Data (migration 089)

- `mail_groups`: id, address (unique, shared namespace), display name,
  description, kind (`list`, `shared`), post policy (`anyone`, `local`,
  `members`, `managers`), system role (null or one of the four), quota bytes,
  storage owner (`server`), created by, created at.
- `mail_group_members`: group, user, role (`owner`, `manager`, `member`),
  can send as, added by, added at; primary key (group, user).
- `mail_group_keys` (shared mailboxes): group, fingerprint, sha256
  fingerprint, public key, primary, flags, created at.
- `mail_group_key_shares`: group key, user, the secret key encrypted to the
  user's address key, the user's address key fingerprint it was made for.
- `mail_group_key_lists`: group, sequence, data, signature (by the server
  identity), as `mail_key_lists`.
- `mail_messages` gains `group_id` (a shared mailbox's rows, and a
  distribution list member's row) and `key_packet` (a list member's own key
  packet; the object then holds the shared data packet alone).
- `mail_group_objects`: object key, version, size, group, row count; the
  object is removed when the count reaches zero.
- `storage_pool` gains group pools.

Every change to members, rights, keys and policy is written to the audit
log.

## API

- `GET/POST /api/admin/mail/groups`, `GET/PATCH/DELETE /api/admin/mail/groups/{id}`
  (administrators: create with kind, address, quota; system groups refuse
  delete and rename).
- `GET /api/mail/groups` (the caller's groups, with role and rights),
  `GET/PUT /api/mail/groups/{id}/members`, `PATCH /api/mail/groups/{id}`
  (owners and managers: description, post policy, members, rights).
- `POST /api/mail/groups/{id}/keys` (a new group key with its shares and the
  next list, signed by the server once checked) and
  `GET /api/mail/groups/{id}/key-shares` (the caller's shares).
- `GET /api/mail/keys?email=` answers a group: `kind` `list` with members'
  keys, or `shared` with the group's key list.
- Mail listing, reading, flags and moving take an optional group: a shared
  mailbox's folders are `?group={id}`.
- `POST /api/mail/send` takes `fromGroup` for sending as a shared mailbox.

## Apps

- **Account → Administration → Mail → Groups:** create (kind, address, name,
  quota), see usage, members, and delete; role groups listed first with
  their purpose ("delivery problems", "spam and abuse complaints",
  "vulnerability reports", "DNS") and "Goes to all administrators" while
  empty.
- **Mail:** shared mailboxes under the person's folders, each with Inbox,
  Sent, Archive, Spam and Trash and unread counts; the composer's From picks
  the person or a group they may send as; distribution list mail shows the
  group as a label. **Mail → Settings → Groups:** the groups the person
  manages, with members (user picker from the server's users), rights and
  who may post.
- **Contacts** suggestions include groups.
- en and tr strings for all of it.

## Out of scope

- Outside members (forwarding to other providers needs SRS and harms
  deliverability), hidden membership, moderation (G2), assigning and tags
  (G3), Proton-style proxy re-encryption, groups across federated servers.

## Slices

1. **G1a data and delivery:** migration 088, group pools, distribution list
   delivery from outside and from Kutup users, role groups with the
   administrator fallback, RCPT rules for who may post, security.txt. Done:
   migration 089 (088 is another branch's); `mail/groups.rs` (find,
   receivers with the administrator fallback, post policies, group storage,
   one stored data packet per message with a key packet per member,
   chunks of 1000, release of copies nobody holds); the RCPT hook and LMTP
   answer for groups (550 5.7.1 for a sender the group does not take, 452
   when full, 550 5.2.1 with nobody to receive); sending from Kutup with a
   key packet per member (`GET /api/mail/groups/recipients`, `409
   groupChanged`, members reached directly get one copy); list copies
   charged to the group in usage, reconcile and deletion; the groups API
   for administrators, owners and managers with audit entries; usernames and
   group names kept apart; `security.txt`. The mail gate covers creation and
   names, member rights, delivery from outside and from Kutup, duplicates,
   post policy, a full group, release on delete, the role fallback and
   security.txt.
2. **G1b shared mailboxes:** group keys, shares, server-signed lists, WKD,
   delivery, shared rows, sending as the group, key rotation on removal. Done: the
   group key is the address key shape for the group's address, its shares
   OpenPGP messages to members' address keys (`seal_group_key_share`,
   `open_group_key_share`; WASM `generateMailGroupKey`,
   `reshareMailGroupKey`, `openMailGroupMessage`,
   `encryptMailMessageAsGroup`, `encryptMailPgpAsGroup`, the secret never in
   JS); key lists signed by a server key of their own
   (`server_generated_keys` `mail-group-authority`), so groups do not
   depend on federation being on; `mail_messages.owner` (the account, or the
   group for a shared mailbox's rows) scopes every read, filing and delete;
   `sent_by` and `sender_account` keep the sending limits on the member who
   sent as the group; delivery from outside encrypted to the group key,
   from Kutup with a key packet for it; deleting a shared mailbox deletes its
   messages. The gate covers creation with a key, the signed list, shared
   read state, joining with shares, sending as the mailbox (and the right
   to), writing to it from Kutup, leaving with a new key the leaver never
   gets, and deletion.
3. **G1c apps:** the administration page, Mail's shared mailboxes, From
   picker and group settings, Contacts suggestions.
4. **G1d gates:** the mail gate (a list with three members from outside and
   from Kutup, a full group, a role group's fallback, a shared mailbox read
   by two members, a removed member who cannot read new mail, GnuPG writing
   to a shared mailbox through WKD), browser specs, docs.

## Tests

- Rust: fan-out with one data packet and per-member key packets, the last
  row removing the object, group quota (full → 452), post policies at RCPT
  and at send, role fallback when empty or all inactive, shared mailbox
  shares and rotation, server-signed group key lists.
- Browser: an administrator creates `hr@` (shared) and `team@` (list), adds
  members; outside mail to each arrives for the right people; one member
  reads in `hr@` and the other sees it read; a member answers as `hr@`; a
  removed member loses new mail.
