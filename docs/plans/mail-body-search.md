# Mail body search in the browser

**Status:** built (2026-10-12), docs/plans/mail-parity.md P6.
**Model:** Proton Mail's "Search message content" (`applications/mail/src/app/helpers/encryptedSearch/`,
v1; `contentSearch/`, v2) and Kutup Chat's search index
([research 16](../research/16-browser-storage-architecture.md), Phase 3).

Message bodies are end-to-end encrypted, so the server cannot search them.
As Proton does, the browser downloads and opens each message once, keeps an
encrypted index of its words in IndexedDB, and answers keyword searches from
it; the server still checks every hit against the place and the other
criteria, so a result is never a message that was moved, deleted or does not
match.

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
recipients stay searched on the server.

## Engine

The index layout of Chat's `search.rs`: words folded (İ/I/ı/i → i, accents
removed, lowercase), an inverted index sharded by a word's first three
characters and a 30-day period, sealed records listed in a directory; a
query word matches the words it begins, every query word must match.

`fold` and `words` move from `kutup-chat-core` into a small shared crate,
`kutup-search`, with a generic period-sharded index over a key-value store
(documents are a message id and a time). Mail uses it through
`kutup-mail-search-wasm`; Chat keeps its own index for now and moves to the
shared one in a later, separate change.

## Storage

One IndexedDB database per account and browser,
`kutup-mail-search:<user id>`. A random index key, wrapped under a key derived
from the account master key (HKDF-SHA256, `kutup/mail-search/wrap/v1`) as the
chat store's; records under `HMAC(index key, name)`, values
`XChaCha20-Poly1305` bound to their name (research 16's design). Unlike
Proton's v1, nothing decrypted is kept in memory beyond the shards a query
reads. Signing out leaves it (encrypted, per account), as Proton's;
Delete local search data removes it.

## Building

- The list of message ids and times comes from the server, newest first, in
  pages; each message is downloaded and opened as the reader would open it,
  four at a time, and indexed in batches of 50 with its progress saved.
- One tab builds at a time (Web Locks); another tab waits, and searches what
  is built.
- Out of room: the oldest period goes first, the index becomes "limited" to
  a date.

## Keeping it current

There is no event stream: on Mail's poll the index adds messages that
arrived after the newest it holds. Moves and labels need no update (the
server checks the place). A deleted message stays in the index, never shown:
the server's check leaves it out. An edited draft is not indexed (Drafts are
left out).

## Searching

The keyword goes to the local index, which answers candidate ids newest
first; `POST /api/mail/messages/lookup` returns those that are still in the
place and match the other criteria, in the list's shape; the list shows them
with "Load more" until the index has no more. With the switch off, search
stays on the server as today.

## Pieces (one PR each)

1. `kutup-search` crate (fold, words, the sharded index over a store trait)
   with Chat's `fold`/`words` moved there; native tests and a benchmark.
2. Index storage and building in Mail: the wasm package, the sealed IndexedDB
   store, the builder with progress, pause/resume and the Web Lock; the
   advanced-search switch and its dialog.
3. Searching: the lookup endpoint, the list's local-search mode, the notice;
   keeping current on the poll; Delete local search data.
