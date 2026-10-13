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

Each message the reader can open (all folders but Drafts; Spam and Trash
too, as Proton's All mail): its subject and body text. HTML becomes text as
Proton's `cleanText` makes it: comments, styles, scripts and hidden elements
removed, blocks as line breaks, the quoted earlier message left out.
Attachments are not indexed (neither are they in Proton). Sender and
recipients (names and addresses) are indexed with the text, so a keyword
finds them too, as Proton's `testKeywords`.

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
an id, a time, its text and the caller's own data (Mail's list row), which a
hit returns and `update_meta` replaces without indexing the text again.
Mail uses it through `kutup-mail-search-wasm`; Chat keeps its own index for
now and moves to the shared one in a later, separate change.

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
  changed during the build is missed). The messages come from
  `GET /api/mail/search-index`, newest first, in pages; each is downloaded
  and opened as the reader would open it, four at a time, and indexed in
  batches of 50, stored with its progress in one IndexedDB transaction.
- **Locks:** every change, in any tab, holds one exclusive Web Lock
  (`<database>:write`) and reads the directory and progress again inside it;
  a second lock lets one tab build at a time. Pages are downloaded outside
  the write lock and stored only if the progress is still where the page
  began. Other tabs hear of each change on a BroadcastChannel and read the
  index again; deleting the database closes their connections first.
- Out of room: what is indexed stays, the index becomes "limited" to a date.
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
messages (and any now in Drafts) are removed, changed ones get their new
row, and those not held (new mail) are downloaded and indexed.

## Searching

The keyword goes to the local index, every period, newest first; each hit
carries its row, which is filtered by the place and the other criteria
(the server's list rules, `contentFilter.ts`), grouped by conversation when
the list is, sorted and paged in the browser. Only the reader's own mailbox
is indexed: shared mailboxes search on the server. With the switch off,
search stays on the server as today.

## Pieces

1. `kutup-search` crate (fold, words, the sharded index) with Chat's
   `fold`/`words` moved there; native tests and a benchmark.
2. Index storage and building in Mail: the wasm package, the sealed IndexedDB
   store with its wrapped store key, the builder with progress, pause/resume
   and the Web Locks; the advanced-search switch and its dialog.
3. Searching: the change feed, the list made in the browser, the notice;
   Delete local search data.
