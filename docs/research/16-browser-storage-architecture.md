# Browser storage: encrypted blobs in IndexedDB

**Status:** decided (October 2026); Phases 1, 2 (2a, 2b) and 3 done; Phase 4 next. Builds on
[15-client-side-search-index.md](15-client-side-search-index.md), whose
Phase 2 (SQLite with full-text search in the browser) this document replaces
for the web. Entries in [`../roadmap.md`](../roadmap.md) track the work.

**Method:** three research passes in October 2026, kept beside the
repository under `research_notes/Browser SQLite architecture/`: Proton's
code (WebClients at `4c408125`, ProtonDriveApps/sdk at `df3a717`), the state
of SQLite in the browser and the apps that use it, and an inventory of
everything Kutup's web apps store today.

## Decision

**On the web, Kutup stores data the way Proton does: IndexedDB holding
encrypted records, under one random key per account and store wrapped by the
account master key. Native clients keep SQLite with SQLCipher, unchanged.**
Search is a Rust engine of our own over encrypted index shards, not SQLite.

## What others do

| | Web | Native | Web data encrypted at rest |
|---|---|---|---|
| Proton (Drive, Mail, Pass) | IndexedDB, encrypted blobs; a Rust/WASM search engine over them; no SQLite on the web | SQLite in the Drive SDK and CLI, each value encrypted (HKDF + AES-GCM) | Yes, per blob, key wrapped by the account key |
| Matrix (matrix-rust-sdk), Element | IndexedDB, values encrypted | SQLite | Yes, per value |
| Wire | IndexedDB for messages; SQLite (sqlite-wasm-rs + SQLite3 Multiple Ciphers) for the MLS keystore | SQLCipher | Yes |
| XMTP | SQLite (sqlite-wasm-rs, OPFS) for messages | SQLCipher | No |
| Notion | SQLite WASM on OPFS | SQLite | No |
| WhatsApp, Telegram, Linear | IndexedDB | — | Varies |
| Signal | no web client | SQLCipher | — |

Proton's details, verified in code: Drive's web SDK keeps node data in
memory only (`MemoryCache`); the search index is one IndexedDB database per
user of AES-GCM blobs, each bound to its identity as associated data
(`drive.search.blob.{indexKind}.{blobName}`), under a random key
OpenPGP-wrapped by the user key; the engine (`@proton/proton-foundation-search`,
not published on the public npm registry) runs in one SharedWorker, guarded
by a Web Lock, capped at 50,000 documents and at 20 decoded blobs in memory
after a WASM out-of-memory crash at about 500 MB. Pass web stores one
encrypted snapshot of its state.

SQLite in the browser was the alternative: `sqlite-wasm-rs` 0.6.1 (September
2026) brings SQLite 3.53.4 with FTS5 and optional encryption (SQLite3
Multiple Ciphers) to a Rust core on OPFS. It was set aside because OPFS needs
the engine in a dedicated worker, gives one connection at a time (a frozen
tab can keep the files), is missing in Firefox and Safari private windows,
and adds about 1 MB; the Proton model needs none of that and works with the
engine lock Kutup already has.

## Kutup today (October 2026)

- Only Chat stores data in the browser: its engine store
  (`kutup-chat-v2:<scope>`, 25 object stores), the backup mirror
  (`…:continuous-backup`) and the media ciphertext cache. The other apps keep
  a few settings in localStorage.
- **Nothing in the chat store is encrypted at rest**: message text, Signal
  and MLS private keys, contacts and profiles are plaintext, and record keys
  include contact addresses. The backup mirror's records are plaintext too.
  Drafts, joined meetings (with the link secret to rejoin), live-share
  secrets and read positions sit in plain localStorage.
- Every update reads the whole history about five times (each store a full
  scan, then the backup mirror), merges and sorts it in JS, and renders every
  message of the open conversation. Search is a linear scan over all of it.

## Design

1. **Keys.** A random 256-bit store key per store, wrapped with
   XChaCha20-Poly1305 under a key derived from the account master key
   (HKDF-SHA256, `kutup/chat-store/wrap/v1`), bound to the store's name; the
   wrapped key sits in the store's `meta`. From it, HKDF derives a value key
   and an index key. The master key is the same across password changes, so
   the store survives them; it can only be opened by someone who can unlock
   the account.
2. **Records.** Each record is stored under `HMAC-SHA256(index key, store ‖
   original key)`, so no address or id is readable from the database. Its
   value is `XChaCha20-Poly1305(value key, nonce, CBOR(original key, value))`
   with associated data binding the store name and the hashed key: a record
   moved to another key or store fails to open.
3. **Format marker.** A plaintext `meta` entry names the format. A store in
   the old plaintext format is converted on first open: everything is read,
   then written encrypted and the plaintext deleted in one durable
   transaction, so a crash leaves either the old store or the new one.
4. **A timeline per conversation (Phase 2).** Phase 2a removes repeated
   work: history is loaded once per change and not at all when a reconcile
   committed nothing (the stores count their commits). Phase 2b adds a
   per-conversation index in the Rust core, written in the same transaction
   as the messages it indexes:
   - a sealed header per conversation (activity time, latest entry, the list
     of chunks) and sealed chunks of up to 256 references (time, store, id),
     with a reverse entry per record so a delete finds its chunk;
   - message content stays in its existing record, read by point lookups, so
     a conversation's entries are built by the same code as today;
   - controls that travel in Note to Self but act on another conversation
     (read position, delete for me, view-once opened, conversation state,
     disappearing expiry start) are indexed under the conversation they act
     on;
   - stored in one generic sealed key-value store in both backends, which the
     search shards of Phase 3 reuse; an existing store is indexed once on
     first open, behind a format marker.
   The core then answers `conversations()` from headers,
   `conversationHistory(key, before, limit)` newest-first by chunk (edits,
   reactions and receipts come after their targets, so they are included),
   and which conversations each commit touched, so the UI reloads only those.
   The web client keeps a live window (`liveTimeline.ts`): each
   conversation's newest and unread entries, its timer and the account's
   controls, read again only for the conversations a change touched. The
   list, unread counts, notifications, receipts and ringing work on it; the
   conversation on screen reads its older pages as it scrolls, and only its
   thread view sees them.
   The work that follows the history reads only what the journal names:
   the attachment ledger the newest page of each changed conversation
   (everything once per session), the backup's collection step each changed
   conversation whole, plus those with an entry due to leave the backup and
   those whose media protection changed, with the mirror's records kept in
   memory behind a revision. Another tab's write, which this tab's journal
   cannot know, makes the next pass read everything.
   Rendering: each timeline row has `content-visibility: auto`, so the
   browser lays out and paints only rows near the screen while every row
   stays in the document (find in page, anchors, assistive technology);
   older pages read in are let go when the reader returns to the newest
   messages, as Element does, so the rows rendered stay bounded. A
   JavaScript virtual list was set aside: variable heights, prepends that
   keep their place, jumps to a quoted message and the disappearing-message
   visibility start all depend on rows being in the document.
5. **Search (Phase 3, done).** A Rust inverted index from Turkish-folded words
   (İ/I/ı/i → i, accents removed) to history entries (`search.rs`), sharded by
   a word's first three characters and the entry's 30-day period (a write
   rewrites only the current period's shards, however long the history or
   common the word) into sealed records beside the chunks,
   listed in a directory and updated in the same write; built once on open;
   word-start queries, every word required; at most 20 decoded shards kept
   between queries, dropped on any commit. Each entry is also indexed under
   its own message id and an edit or deletion under its target, so a query
   returns with its hits what edits or deletes them; the client applies
   those, the disappearing deadlines and the same matching before showing a
   hit, and matches restored backup history (in memory) the same way. The
   browser and native clients fold identically (shared vectors). Matching is
   by word start, not substring, as in Signal and Proton.
   Compact layout (October 2026, after the first version): SQLite FTS5's,
   as in Signal Desktop, on sealed records. In each period an entry gets a
   small number and is stored once in a document chunk (256 per record:
   conversation as a position in the directory's list, record, time,
   message id, target); a shard maps each word to the ascending numbers
   holding it as LEB128 differences, a byte or two per occurrence. Queries
   read periods newest first and stop once they have enough hits; decoded
   records are kept within 4 MB, dropped on any commit. The first version
   repeated each entry's full identity under every one of its words.

   Measured with one workload (`search::bench`: 50,000 messages over two
   years, eight words each), natively (`search::tests::scale`, release,
   SQLite backend) and in headless Chromium on encrypted IndexedDB
   (`scripts/bench-search-index.sh`), before and after compaction:

   | | Browser before | Browser after | Native before | Native after |
   |---|---|---|---|---|
   | Index size | 37.4 MB | 3.5 MB | 37.4 MB | 3.5 MB |
   | 50,000 written in batches of 100 | 105 s | 69 s | 4.2 s | 2.3 s |
   | One new message with its index | 12 ms | 6.6 ms | 2.1 ms | 1.3 ms |
   | Whole history indexed on open | 3.0 s | 1.8 s | 0.56 s | 0.31 s |
   | "bir" (very common) | 65 ms | 9.5 ms | 12.6 ms | 2.0 ms |
   | "bi" (two letters) | 197 ms | 4.9 ms | 27 ms | 1.3 ms |
   | a rarer word (128 hits) | 15 ms | 60 ms (2.7 warm) | 3.5 ms | 7.9 ms |
   | two words | 60 ms | 33 ms | 10.7 ms | 3.9 ms |

   Query times are cold (a fresh cache) and include fetching what edits or
   deletes the hits. A word with fewer hits than the limit reads every
   period, and each hit now needs its document chunk: slower than before
   on a cold cache, 2.7 ms once cached (as while typing). Larger chunks
   (1,024) made it slower still, decoding outweighing the reads saved.
6. **Tabs.** The existing engine lock (one holder, take-over after 30 s of
   silence) and the writer generation checked in every write.
7. **Sign-out keeps the encrypted store**, so the same browser stays the same
   device; it is unreadable without the account password.

## Phases

| Phase | What |
|---|---|
| 1 | Encrypted chat store (keys, records, conversion of existing stores); the backup mirror's records, drafts and read positions sealed (`SealedStorage`, `sealLocalData`). Not sealed, on purpose: the meeting hand-off list (written by a page with no account key, moved into the account's encrypted list and deleted) and live shares in `sessionStorage` |
| 2 | Chunked messages, conversation headers, paging, windowed rendering |
| 3 | Search engine with Turkish folding, replacing the linear scan |
| 4 | Office and Drive catalog and name search in their own origins (needs a server change feed, see document 15) |
