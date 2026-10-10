# Mail folders, labels and filters

**Status:** agreed 2026-10-11: names sealed, folders as their own section, filters on sent mail too, blocking as Proton, slices in the order below. After Mail C1–C3
([`mail.md`](mail.md)); its own branch (`feat/mail-filters`) and pull
request. A step towards Proton Mail parity ([`mail-parity.md`](mail-parity.md)).

## Goal

Your own places for mail and rules that put it there:

- **folders** you make (and folders inside them), in the sidebar under the
  fixed ones; a message is in one folder at a time;
- **labels**, coloured tags; a message can have several, and keeps them
  wherever it is filed;
- **filters**: "when a message matches, do this": move it to a folder,
  label it, mark it read or starred. They run on the server as mail
  arrives, so they work with Mail closed, and can be applied to the mail
  you already have;
- **block, spam and allow lists** for senders and domains.

## How Proton does it

From `WebClients` (the server is not public, so delivery-time behaviour is
read from the client and its texts):

- **One model.** Folders, labels, contact groups and the system folders are
  all *labels* with a type (`LABEL_TYPE` in `packages/shared/lib/constants.ts`):
  Inbox, Archive, Spam, Trash, Starred, Scheduled, Snoozed and All mail have
  fixed ids; a message carries a set of label ids, and moving it to a folder
  replaces its folder id. Fields: name, colour, order, parent (folders),
  expanded, notify, display (`interfaces/Label.ts`, `Folder.ts`).
- **Limits:** folders nest at most `MAX_FOLDER_NESTING_LEVEL = 2` below the
  top; free plans get 3 folders, 3 labels and 1 active filter; names must be
  unique among siblings, checked by the server (`labels/available`).
- **Managing** (`packages/components/containers/labels`): Settings →
  Folders and labels: "Add folder", "Add label", drag to nest and reorder,
  "Sort" alphabetically, "Use folder colors", "Inherit color from parent
  folder", a notification switch per folder. The sidebar shows collapsible
  *Folders* and *Labels* sections with unread counts, a "+" (create) and a
  per-item menu (edit, delete); messages are dropped onto them.
- **Move to / Label as** (`MoveDropdown.tsx`, `LabelDropdown.tsx`; keys
  `M` and `L`): a searchable list, "Create folder "…"" from the search text,
  and the checkboxes **"Always move sender's emails"** / **"Always label
  sender's emails"**, which make a filter for those senders (undoable), and
  "Also archive" when labelling.
- **Deleting:** a label leaves its mail where it is; a folder (and its
  subfolders) leaves its mail in All mail.
- **Filters** (`packages/sieve`, `containers/filters`): stored as Sieve and
  run at delivery, on incoming and sent mail, never on spam. The simple
  builder is a four-step wizard (Name, Conditions, Actions, Preview):
  conditions on *the subject, the sender, the recipient, the attachment*;
  comparators *contains, is exactly, begins with, ends with, matches*
  (wildcards) and their negations; *all* or *any*; actions *move to*
  (Inbox, Archive, Spam, Trash or a folder), *label as* (several), *mark as*
  read or starred, and a paid *auto-reply*. An advanced Sieve editor checks
  the script on the server. Filters are ordered by drag, switched on and
  off, and **"Apply to existing messages"** runs them over the whole mailbox
  in the background ("No auto-reply emails will be sent").
- **Block, spam, allow** ("incoming defaults"): an address or a domain sent
  to Spam, blocked, or always allowed; "Block sender" in the message's
  sender menu, the list's right click and the toolbar.

## How Kutup does it

### Folders

- `mail_folders`: the account's folders, nested three deep at most (a top
  folder and two levels inside, as Proton), with a colour, an order among
  siblings, expanded, and a notify switch (used by web push later).
- A message's place stays the existing `folder` column, which gains the
  value `custom` with `custom_folder` naming the folder; the fixed folders
  stay as they are, so nothing that exists changes. A message is in exactly
  one place.
- They appear in the sidebar as their own *Folders* section under the fixed
  ones (as Proton, not inside Inbox): mail moved or filtered there leaves
  the Inbox. Unread counts per folder; collapsible parents; drop mail on
  them; "+" to make one; a menu to rename, recolour, move or delete.
- **Deleting a folder** moves its mail (and that of its subfolders) to
  Archive, which is Kutup's All-mail-without-a-place, and removes it from
  filters that move there (they keep their other actions, or are switched
  off when nothing is left), saying so before.
- Trash and Spam empty after 30 days (C2f) regardless; moving to Spam or
  Trash takes mail out of its folder.

### Labels

- `mail_labels` (colour, order) and `mail_message_labels`. A label stays on
  a message wherever it goes, Trash included; deleting a label removes it
  from messages and filters, never the mail.
- Shown as coloured chips in the list and the reading pane (removable
  there), and as a *Labels* section in the sidebar, each a view of its mail
  with unread counts. Search by label comes with advanced search (P6).
- Starred stays a flag, as now (Proton's Starred is a label; the behaviour
  is the same).

### Names are sealed

Folder, label and filter names are written in the browser and **sealed
with the account's master key**, as Drive file names are: the server
stores ids, colours, order and the tree, never "Lawyer — divorce" or
"Job search". The server needs no names: filters point at ids, and the
sidebar opens names in the browser. Uniqueness among siblings is checked
in the browser (the server cannot). Proton stores names readable.

What stays readable is what the server must match: a filter's conditions
(the sender address, the words in the subject), as Proton's Sieve is; its
name and the names of the folders and labels it files into do not.

### Filters

- `mail_filters`: name (sealed), enabled, order, `all`/`any`, conditions and
  actions (JSON, below), and where it came from (made by hand, or by
  "Always move/label sender's emails").
- **Conditions** (readable by the server, which runs them, as Proton's
  Sieve is): *sender* (address and name), *recipient* (To and Cc, and the
  address it came to, which matters with aliases), *subject*, *has
  attachments*; comparators *contains, is, begins with, ends with,
  matches* (`*` and `?`), each with *not*; case and accents folded. Bodies
  are encrypted, so no filter can look into them; Proton is the same.
- **Actions:** move to Inbox, Archive, Spam, Trash or a folder; add labels;
  mark read; star. Auto-reply comes with the vacation responder, forwarding
  with the rules forwarding we left for later (aliases plan); both are new
  actions here, not new machinery.
- **When they run:** inside `insert_message` (`crates/kutup-server/src/mail/mod.rs`),
  the one place every stored copy goes through, mail from outside (LMTP),
  mail from Kutup users (`mail_send.rs`) and list and shared-mailbox copies
  (mail groups), for incoming mail and the sender's own sent copy (as
  Proton), in order, all matching filters' labels and flags adding up and
  the first move winning. Never on mail Stalwart filed as spam, except
  through the allow list.
- **Apply to existing messages:** a background job on the server over the
  account's messages in batches, with progress in the app ("Filters are
  being applied…"); it never sends anything.
- **Made from the list:** "Always move sender's emails" in *Move to* and
  "Always label sender's emails" in *Label as* make a filter for the chosen
  senders, with Undo, as Proton.
- **Sieve:** not stored. An advanced editor that imports and exports a Sieve
  subset (the parts that map to these conditions and actions) is the last
  slice, for people moving from Proton, Fastmail or a Sieve server.

### Block, spam and allow lists

- `mail_sender_rules`: an address or a domain, with *spam*, *block* or
  *allow*. Checked before filters.
- *Spam* files it in Spam. *Allow* keeps a sender out of Spam, **only when
  the message passed DMARC** for that domain, so a forged From cannot use
  someone's allow entry (Proton does not say it checks this).
- *Block*, as Proton ("New emails from … won't be delivered and will be
  permanently deleted", `BlockSenderModal.tsx`): the message is still
  accepted at SMTP (refusing it would tell the sender) and then dropped,
  never stored, counted on the entry ("12 blocked"). The block dialog says
  so before.
- "Block sender" in the person card, the list's right click and the reading
  pane; "Not spam" offers "Always allow this sender"; Settings lists all
  three, by address or domain.

### Shared mailboxes

Folders, labels and filters here belong to an account's own mailbox. A
shared mailbox (mail groups) gets its own, kept by its owners and
managers, in a later slice; until then its mail uses the fixed folders.

### Limits

`MAIL_FOLDERS_PER_ACCOUNT` (default 500), `MAIL_LABELS_PER_ACCOUNT` (500),
`MAIL_FILTERS_PER_ACCOUNT` (200 enabled), `MAIL_SENDER_RULES_PER_ACCOUNT`
(5000): the levers a priced kutup.dev would use, as Proton's plans do.

## Decisions (2026-10-11)

1. **Names sealed in the browser.** The server works with ids; filter
   conditions stay readable, because the server matches them.
2. **Blocked mail** is accepted and deleted, never stored, as Proton.
3. **Folders are their own sidebar section**, as Proton.
4. **Filters run on sent mail too**, as Proton.
5. **Slices** in the order below, which builds each layer on the one
   before: places first, then what files mail into them.

## Data (migration 112)

110 and 111 are taken by the aliases plan (A0, A1).

- `mail_folders` (id, user_id, parent_id, sealed name, colour, position,
  expanded, notify), depth checked on write.
- `mail_messages.folder` adds `custom`; `custom_folder` UUID (set exactly
  when `folder = 'custom'`), indexed with the date for the list.
- `mail_labels` (id, user_id, sealed name, colour, position),
  `mail_message_labels` (message_id, label_id).
- `mail_filters` (id, user_id, sealed name, enabled, position, match,
  conditions JSONB, actions JSONB, source).
- `mail_sender_rules` (id, user_id, address or domain, kind).
- `mail_filter_runs` (id, user_id, filter ids, progress, started, finished)
  for "apply to existing".

## API

- `GET/POST /api/mail/folders`, `PATCH/DELETE /api/mail/folders/{id}`
  (rename, recolour, move, reorder, expanded).
- `GET/POST /api/mail/labels`, `PATCH/DELETE /api/mail/labels/{id}`.
- `PATCH /api/mail/messages` takes `folder: {custom: id}`, `addLabels`,
  `removeLabels`; the list and counts take a folder or a label.
- `GET/POST /api/mail/filters`, `PATCH/DELETE /api/mail/filters/{id}`,
  `PUT /api/mail/filters/order`, `POST /api/mail/filters/apply` (and its
  progress).
- `GET/POST /api/mail/sender-rules`, `DELETE /api/mail/sender-rules/{id}`.

## Apps

- **Sidebar:** Folders and Labels sections (tree, colours, unread counts,
  collapse, "+", menu, drop targets).
- **List and reading pane:** label chips; *Move to* (`M`) and *Label as*
  (`L`) menus in the toolbar and the right click, searchable, creating from
  the search, with "Always move/label sender's emails" and "Also archive".
- **Mail → Settings:** Folders and labels (drag to nest and reorder, sort,
  colours), Filters (the four-step builder with preview, order, on/off,
  apply to existing), Block and allow.
- en and tr strings.

## Slices

1. **F1 folders and labels:** migration 112 (folders, labels), the server,
   sealed names (`kutup-crypto` `mail_names`), the sidebar, Move to and
   Label as (toolbar, right click, `M`, `L`, dropping), Settings → Folders
   and labels, counts. Built on `feat/mail-filters`.
2. **F2 filters:** the matcher in `insert_message`, the builder, order,
   on/off, apply to existing, "Always move/label sender's emails".
3. **F3 block, spam and allow** lists, with DMARC for allow, and their
   menus.
4. **F4 Sieve** import and export of the subset; folders, labels and
   filters for shared mailboxes.

## Tests

- Rust: folder depth and cycles, deleting a folder with mail and filters,
  labels surviving moves, every comparator (with Turkish case folding:
  `İ`/`i`, `I`/`ı`), all/any, filter order, spam skipped, allow needing
  DMARC, block dropping, apply to existing in batches, limits.
- The mail gate: a filter files mail from outside and from a Kutup user;
  a blocked sender's mail is accepted and not stored.
- Browser (specs 82, 83): make folders and labels, nest, drag mail,
  "Always move sender's emails", build a filter and apply it to existing
  mail, block a sender.
