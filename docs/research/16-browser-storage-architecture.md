# Browser storage: encrypted blobs in IndexedDB

**Status:** decided (October 2026); Phase 1 in progress. Builds on
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
4. **Messages in chunks (Phase 2).** Messages grouped per conversation into
   encrypted chunks of about 100, with a small encrypted header per
   conversation (last message, unread count, list of chunks), keyed by an
   HMAC of the conversation id. The conversation list reads headers; a
   conversation opens on its newest chunks and pages older ones in.
5. **Search (Phase 3).** A Rust inverted index from Turkish-folded words
   (İ/I/ı/i → i, accents removed) to message ids, sharded by word prefix into
   encrypted blobs beside the chunks and updated in the same write; prefix
   queries; at most 20 decoded shards in memory; rebuildable from the chunks.
6. **Tabs.** The existing engine lock (one holder, take-over after 30 s of
   silence) and the writer generation checked in every write.
7. **Sign-out keeps the encrypted store**, so the same browser stays the same
   device; it is unreadable without the account password.

## Phases

| Phase | What |
|---|---|
| 1 | Encrypted chat store (keys, records, conversion of existing stores); the backup mirror, drafts, joined meetings, live-share secrets and read positions moved into encrypted storage |
| 2 | Chunked messages, conversation headers, paging, windowed rendering |
| 3 | Search engine with Turkish folding, replacing the linear scan |
| 4 | Office and Drive catalog and name search in their own origins (needs a server change feed, see document 15) |
