# Mail body search in the browser

**Status:** built (2026-10-12), docs/plans/mail-parity.md P6.
**Model:** Proton Mail's "Search message content" (`applications/mail/src/app/helpers/encryptedSearch/`,
v1; `contentSearch/`, v2) and Kutup Chat's search index
([research 16](../research/16-browser-storage-architecture.md), Phase 3).

Message bodies are end-to-end encrypted, so the server cannot search them.
As Proton does, the browser downloads and opens each message once, keeps an
encrypted index of its words and its list row in IndexedDB, and answers
keyword searches from it: found, filtered by place and criteria, sorted and
paged in the browser, so the server never learns which messages matched. The
server's change feed keeps the rows current.

## What the reader sees (Proton's)

- Advanced search: **Search message content**, off until turned on. Turning
  it on asks first ("Mail downloads a copy of your messages to this browser,
  encrypted, to search their text").
- While it builds: "Message download status: X of Y", the estimated time
  left, Pause and Resume; it carries on after a reload.
- When done: a switch (on), and a notice. If the browser runs out of room:
  "For messages newer than <date>".
- Turned off: searches go back to subjects and addresses; the index stays
  and is kept current. **Delete local search data** in Settings → General
  removes it (Proton's Clear browser data).
- A search with the switch on shows "Results include message text, searched
  in this browser".

## What is indexed

Each message the reader can open (all folders but Drafts;
Spam and Trash too, as Proton's All mail): its subject and body text. HTML
becomes text as Proton's `cleanText` makes it: comments, styles, scripts and
hidden elements removed, blocks as line breaks, the quoted earlier message
left out. Attachments are not indexed (neither are they in Proton). Sender
and recipients (names and addresses) are indexed with the text, so a keyword
finds them too, as Proton's `testKeywords`.

**Drafts** change while written and take a new time when sent, so they are
not in the word index: their rows are kept in one sealed record beside it
and matched by subject and people with the index's own rule
(`kutup_search::matches`), so a search in Drafts, All mail or Starred finds
them as the server's would, without sending the keyword anywhere.

With its words, each message keeps its **list row** (what the list shows:
folder, labels, flags, people, time, size, files), as Proton's `ESMessage`
keeps its metadata, to filter and show hits without asking the server.

## Engine

The index layout of Chat's `search.rs`: words folded (İ/I/ı/i → i, accents
removed, lowercase), an inverted index sharded by a word's first three
characters and a 30-day period, sealed records listed in a directory; a
query word matches the words it begins, every query word must match.

`fold` and `words` live in a small shared crate, `kutup-search`, with the
period-sharded index over named records the caller stores; each document is
an id, a time, its text and the caller's own data (Mail's list row, without
the thread's references), which a hit returns and `update_meta` replaces
without indexing the text again. A period's documents are kept in 32 tables,
each document in the one its id hashes to (FNV-1a, fixed), its number
naming its table: no table grows past what a record holds, and a change
finds a document from its id alone. A query reads the shards first, then
only the tables its matches are in. Mail uses it through
`kutup-mail-search-wasm`; Chat keeps its own index for now and moves to the
shared one in a later, separate change.

## Storage

Research 16's design (`kutup_crypto::mail_search`, vectors in
`tests/vectors/mail-search-v1.json`), bound to no name, as Proton's keys:

- **Database:** one per account and browser, named
  `kutup-mail-search:<HMAC(locator key, "database")>`, the locator key from
  the master key (HKDF-SHA256, salt `kutup/mail-search/wrap/v1`): it names
  no one and is found before anything is read.
- **Store key:** random, kept in the database wrapped under a second
  master-derived key (XChaCha20-Poly1305, `KUTMSW1`). Deleting the database
  destroys it, so copies left behind (disk remnants, a profile backup) stay
  unreadable even to someone who later has the master key.
- **Records:** stored under `HMAC(name key, name)`, values
  XChaCha20-Poly1305 bound to their purpose and that hashed name (record
  and name keys from the store key). A record that does not open is read as
  missing and the index is built again.

Unlike Proton's v1, nothing decrypted is kept in memory beyond the records a
query reads. Signing out closes it and leaves it (encrypted, per account),
as Proton's; Delete local search data deletes the database, and its key.

## Building

- Before the first page, the change feed's cursor is taken (so nothing
  changed during the build is missed). Pages of rows come from
  `GET /api/mail/search-index`, newest first (its total on the first page
  only). A page is read under the lock and its rows wait in a sealed list
  (`pending`, Drafts aside); its messages are downloaded and opened outside
  the lock, four at a time, then stored under it again, each only if it is
  still pending and with its row as the list holds it then. The feed keeps
  that list current under the same lock, so a message moved or deleted
  while it downloads is stored as it is now, or not at all.
- **Locks:** every change, in any tab, holds one exclusive Web Lock
  (`<database>:write`) and reads the stored state again inside it; a second
  lock lets one tab build at a time. Other tabs hear of each change on a
  BroadcastChannel and read the index again; deleting the database closes
  their connections first.
- Out of room (or a record past what one may hold): what is indexed stays,
  the index becomes "limited" to a date.
- **Damage:** a record that does not open, a directory that does not (or is
  of another version), or progress that does not: nothing more is written
  over it; the database is deleted and the index built again.
- Searches use the server until the index is built (and while paused).

## Keeping it current: the change feed

`GET /api/mail/search-index/changes?since=` (migration 163), Proton's event
loop for its local search. Each change of a message (any column, a label put
on or taken off) records the transaction that made it; a deletion leaves a
tombstone with the message's time. The feed answers, in (transaction, id)
order, changes of transactions below the snapshot's xmin only, so one that
commits late is never skipped; without `since` it answers where the feed is
now. Tombstones are kept 30 days; a cursor older than that gets `resync`
and the index is built again.

On Mail's poll and before every search the browser follows it: gone
messages are removed, changed ones get their new row (a waiting one too),
Drafts are kept or dropped by their rows, and those not held (new mail) wait
to be indexed. While building, one the build has yet to reach is left to it.
A cursor ahead of the server (a restored database) also gets `resync`.

## Searching

The keyword goes to the local index, every period, newest first, and to the
Drafts kept beside it; each hit carries its row, which is filtered by the
place and the other criteria (the server's list rules, `contentFilter.ts`),
grouped by conversation when the list is, sorted and paged in the browser.
Only the reader's own mailbox is indexed: shared mailboxes search on the
server. With the switch off, search stays on the server as today.

## Follow-ups

- The change trigger rewrites `change_xid`, an indexed column, on every
  update, so no update of `mail_messages` is HOT any more, and a label
  trigger updates once per label row: a statement-level trigger with a
  transition table would write once per message.
- Label changes now take a row lock on `mail_messages`: order those updates
  by id (or retry on deadlock) when the trigger becomes statement-level.
- A list row's `groupAddress`, `scheduledAt`/`outboxId` and `sentBy` change
  in other tables, without a change recorded on the message.
- Local filtering takes the account's address as "every message", which no
  longer holds once accounts have aliases; it folds case as JavaScript does,
  not as `ILIKE`; the server cuts criteria at 200 characters, the browser
  does not.
- Tombstones outlive a deleted account until they age out, and
  `mail_change_floors` has no foreign key.

## Pieces

1. `kutup-search` crate (fold, words, the sharded index) with Chat's
   `fold`/`words` moved there; native tests and a benchmark.
2. Index storage and building in Mail: the wasm package, the sealed IndexedDB
   store with its wrapped store key, the builder with progress, pause/resume
   and the Web Locks; the advanced-search switch and its dialog.
3. Searching: the change feed, the list made in the browser, the notice;
   Delete local search data.
