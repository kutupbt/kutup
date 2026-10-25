# Drive block format: streaming with seeking

**Status:** approved 2026-10-22 with the answers in §11. Slice 1 (the
crypto core) is built: `kutup-crypto` `blocks.rs`, `drive_blocks.rs`,
`chat_media_blocks.rs`, `chat_backup_media_blocks.rs`, `FileMetadataV2`,
the revision-bound thumbnail context, vectors (`blocks-v1.json`), the
`block_object_parsers` fuzz target, the WASM `BlockEncryptor` and
`BlockReader`, and the benchmark (§9). Nothing uses them yet: clients switch
in slices 3–6. The suite id 2 is a constant of each family for now:
`DriveObjectSuiteId` and `ChatMediaSuiteId` (a wire type in descriptors and
federation offers) gain it in the slice that switches their protocol, so
nothing that parses suite 1 accepts suite 2 before the server checks it.
When they do, the suite-1 parsers must still refuse suite 2 under the old
magics (`KUTPDB2`, `KUTPCM1`), with a test each. The user's decision: "follow proton drive". Reference:
Proton's web client, `kutup-references/WebClients`. Its new
`@protontech/drive-sdk` is not checked out there, so the in-repo upload and
download code (`packages/drive-store`,
`applications/drive/src/app/modules/fileSaver`, `modals/preview`) is the
source for what follows.

## Today

- A file is one XChaCha20-Poly1305 secretstream (`crates/kutup-crypto`
  `stream.rs`, `drive_object.rs`):
  `[32-byte Drive header][24-byte stream header][5 MiB + 17 frames]`, the last
  frame `TAG_FINAL`. The header (magic `KUTPDB2\0`, suite 1, purpose, file-key
  generation, file UUID) is the HKDF info for the stream key and the AAD of
  every frame.
- Frames have no index. Their order comes from the stream's ratchet, so
  reading frame *k* means decrypting frames 0 to *k*−1 first. Nothing can
  seek.
- So a video in Photos plays only once it is fully downloaded and decrypted
  into a Blob URL, up to 1 GiB (`PhotoViewer.tsx:34`, `MAX_VIDEO_BYTES`).
  Drive's preview and Chat do the same.
- The server streams whole objects only: no Range on any route and no ranged
  S3 GET (`handlers/mod.rs` `octet_stream_response`, `storage.rs`).
- The header binds the file and the generation, but not the version
  (`v1-format-inventory.md`, the `KUTPDB2` paragraph). Two versions sealed
  under the same generation could be swapped by the server, and nothing stops
  it from serving an older version as the current one.
- `FileMetadataV1.sha256` (`file_metadata.rs:93-96`) is optional and covers
  the whole file, so a player cannot check a block on its own.
- Thumbnails are bound to the file and its key generation, but their
  revision is fixed at 1 (`v1-format-inventory.md`, thumbnails). A stale
  thumbnail of older content still opens.
- The same 5 MiB secretstream framing is used by:
  - Chat attachments (`KUTPCM1`, `chat_media.rs:21`; docs/chat-media.md),
    so Chat videos cannot seek either;
  - Chat backup media (`KUTPBM1`, `chat_backup_media.rs:11`);
  - Drive versions and the text, office and whiteboard snapshots;
  - public links, the CLI and federation copies.
- In the browser the frames run through libsodium (`streamEncryptor.ts`,
  `streamDecryptor.ts`; the roadmap's "remaining libsodium primitives"). Rust
  only gives out the header and the derived key.

## 1. Goal and non-goals

**Goal:** video and audio of any length that Drive accepts (10 GiB today)
start playing at once and seek anywhere in Photos, Drive's preview and Chat.
A client can read any byte range of a file by fetching and decrypting only
the blocks it covers. **One shared seekable block framing** replaces
secretstream for every large object: Drive blobs (originals, versions,
snapshots), Chat attachments and Chat backup media. Each keeps its own
header, suite and keys. The same change closes the audit's integrity gaps:
- content is bound to its revision;
- the sealed metadata commits to the current revision;
- thumbnails are bound to the revision they show;
- sealing moves from libsodium to WASM.

Proton Drive's model is used: fixed-size blocks, each
sealed on its own; a manifest of block hashes signed by the uploader; the
browser's `<video>` element fed by a service worker that answers Range
requests; and decryption in the page, not in the worker.

**Non-goals:**
- server-side transcoding or HLS/DASH renditions (the server never sees
  plaintext);
- deduplication (Proton has none across files; neither does Kutup);
- moving thumbnails into the block object. They stay `DriveEnvelopeV1`
  purpose 7 in their replaceable slot and only gain the revision binding
  (§2);
- Mail attachments, which are OpenPGP (docs/plans/mail.md);
- partial writes. A new version is still a full new upload, as in Proton.

## 2. The format: a new suite

### What Proton does

- **Blocks:** 4 MiB of plaintext (`FILE_CHUNK_SIZE = 4 * MB`,
  `packages/shared/lib/drive/constants.ts:9`), numbered from 1. Each block is
  its own OpenPGP message under the revision's session key (the
  `ContentKeyPacket`).
- **Block signatures:** each block has a detached signature by the
  uploader's address key over the plaintext. The signature is encrypted to
  the node key and sent as `EncSignature`
  (`store/_uploads/worker/encryption.ts:117-170`).
- **Block hash:** SHA-256 of the encrypted block (`encryption.ts:133`).
- **Manifest:** `ManifestSignature` is a detached signature by the address
  key over the raw concatenation of the thumbnail hashes and then the block
  hashes, in index order (`worker/buffer.ts:192-200`, `worker.ts:147`).
- **Commit:** `PUT …/revisions/{id}` with `ManifestSignature`,
  `SignatureAddress` and `XAttr`. The commit carries no block list; the
  server already holds the blocks with their hashes.
- **Sizes:** `XAttr` (encrypted and signed) carries `Size` and `BlockSizes`.
  Those sizes are only "claimed" (the SDK's `getClaimedSizeInBytes`). The
  block count and the end of the file are authenticated by the signed hash
  list. Before signing, the uploader checks that it sent
  `ceil(size / 4 MiB)` blocks.
- **Verifier:** a per-block verification token. The server hands out a
  code, and the client proves it can decrypt each block before upload, which
  guards against a corrupt encryption.

### What Signal does, compared

Signal encrypts an attachment whole with AES-256-CBC and HMAC-SHA256. For
streaming it adds an **incremental MAC** (libsignal `incremental_mac`;
`Signal-Desktop/ts/AttachmentCrypto.node.ts`, `app/attachment_channel.main.ts`):
- an HMAC over each ciphertext chunk;
- a chunk size inferred from the file's size, so the list stays small;
- the list sent inside the E2EE attachment pointer (`incrementalMac`,
  `chunkSize`).

Desktop then plays a video while it downloads, and checks each chunk as it
arrives.

The idea is the same as Proton's hash list: authenticate pieces, and commit
to the list in something already authenticated. Signal can put the list in
the message because a message carries one immutable attachment. Drive files
have versions and owners but no message to carry it, so the list lives in a
manifest inside the object, as in Proton.

Kutup's Chat attachments use the same object as Drive. The E2EE descriptor
commits to the manifest's digest, the role Signal's pointer plays. That keeps
one framing for both, with no second "chat" construction. Signal's CBC also
needs the previous ciphertext block to start mid-file; per-block AEAD does
not.

### What Kutup does

**One framing, three families.** `kutup-crypto` gets one generic block
module (`blocks.rs`): blocks, nonces, the manifest and the trailer. Each
family supplies its header and its HKDF labels. The families stay apart: no
key, header or suite is shared between them.

| Family | Header | Suite | Revision in header | Manifest signed |
|---|---|---|---|---|
| Drive blob (original, version, text/office/whiteboard/Yjs snapshot) | `KUTPDB3\0` | `DriveObjectSuiteId` 2 | yes | yes, by the uploader |
| Chat attachment | `KUTPCM2\0` | `ChatMediaSuiteId` 2 | no (immutable; the attachment id) | no: the E2EE descriptor commits to it |
| Chat backup media | `KUTPBM2\0` | backup media suite 2 | no (the media id and incarnations, as today) | no: the backup's sealed index commits to it |

The Drive family is described in full below. The other two differ only in
their header fields and labels.

The same structure, in Kutup's own Rust construction (`kutup-crypto`:
XChaCha20-Poly1305, HKDF-SHA256, SHA-256, Ed25519; no new dependency).
OpenPGP buys Proton nothing a typed AEAD does not do here. It also lacks
what this format needs: it cannot bind a block's index or the revision in
associated data, and that is why Proton relies on the signed hash list. Kutup
keeps that hash list *and* binds the index, so a block is refused on its own,
before the manifest is even compared.

New suite: `DriveObjectSuiteId::KutupDriveBlocksV1 = 2`, purpose `FileBlob`.

**Header, 48 bytes, in clear.** It is the HKDF info and part of every AAD.

```text
magic           8   "KUTPDB3\0"
suite           u16 2
purpose         u8  1 = file blob
reserved        u8  0
generation      u32 file-key generation, non-zero
file_id         16  file UUID
revision_id     16  random UUID the client picks for this content object
```

`revision_id` is new. The original upload and every version is a revision
with its own id, chosen by the client before it encrypts. Blocks can
therefore no longer move between versions, even under the same generation.

**Keys.** Each is `HKDF-SHA256(ikm = file key, salt = label, info = header)`:

| Key | Label |
|---|---|
| block key | `kutup/drive-object/blocks/block-key/v1\0` |
| nonce key | `kutup/drive-object/blocks/nonce-key/v1\0` |
| manifest key | `kutup/drive-object/blocks/manifest-key/v1\0` |

The header contains the revision id, so every revision has its own keys.

**Blocks.** The block size is fixed at 4 MiB (B = 4,194,304), Proton's value.
- The block count is n = max(1, ceil(size / B)). Block *i* holds bytes
  `[i·B, min((i+1)·B, size))`.
- An empty file is one empty last block, so n ≥ 1 always. This is what
  `TAG_FINAL` does for an empty file today, and it avoids Proton's
  trailing-zero `BlockSizes` quirk.
- Each block is sealed:

```text
nonce  = HMAC-SHA256(nonce key, u32 index ‖ u8 last ‖ SHA-256(plaintext))[0..24]
AAD    = header ‖ u32 index ‖ u8 last        (last = 1 only for i = n−1)
block  = nonce(24) ‖ XChaCha20-Poly1305(block key, nonce, AAD, plaintext) ‖ tag(16)
```

- A block's ciphertext is B + 40 bytes; the last one is shorter.
- **The nonce is synthetic** (SIV-style). Re-encrypting the same plaintext
  gives the same bytes, so a tus upload can resume from any offset, as it
  does today. A different plaintext at the same index gets a different
  nonce, so a file that changes during an upload never reuses a nonce. (The
  uploader still restarts when the file's size or modified time changes.)
- **The block hash** is h_i = SHA-256(block), over the ciphertext, as in
  Proton.

**Manifest.** It is written after the last block.

```text
manifest plaintext:
  u32 block size ‖ u32 n ‖ u64 plaintext size ‖ h_0 … h_{n−1}
  ‖ signer: u8 kind (1 = Drive signing key) ‖ 16-byte account id
  ‖ 64-byte Ed25519 signature
signed message = "kutup/drive-block-manifest/v1\0" ‖ header ‖ 16-byte account id
                 ‖ u32 block size ‖ u32 n ‖ u64 size ‖ h_0 … h_{n−1}
sealed manifest = nonce(24 random) ‖ XChaCha20-Poly1305(manifest key, nonce,
                  AAD = header ‖ "manifest", plaintext) ‖ tag(16)
trailer         = u32 sealed-manifest length ‖ "KUTPDBM\0"
```

- **Size and end of file.** The manifest gives the exact plaintext size and
  the block count. The reader checks n = max(1, ceil(size / B)). This is the
  `TAG_FINAL` of the new format, and it is stronger: the reader knows the
  end before it reads a single block. The `last` flag in block n−1's AAD is a
  second check that needs no manifest.
- **The signature** is Proton's manifest signature. Kutup signs with the
  uploader's Drive share-signing key (Ed25519), the key the account manifest
  and key binding already vouch for (docs/plans/drive-identity-pins.md).
  It proves who wrote the content: someone else who holds the file key, such
  as a co-editor, can seal blocks but cannot sign as you. It is checked
  against pins and warns, never blocks, as Drive's other signatures do.
- **Where the signature lives.** It sits inside the sealed manifest, so the
  server never sees which key signed. Proton's is in clear, but Kutup's
  server already knows the uploader.
- **Not in Kutup's manifest:**
  - per-block signatures: the manifest signature covers every block's hash,
    and Proton also skips per-block checks when it seeks;
  - thumbnail hashes: Kutup's thumbnails sit in a replaceable slot, so they
    are not part of a revision.

**The object, as stored:**

```text
[header 48][block 0]…[block n−1][sealed manifest][trailer 12]
```

The overhead is 72 bytes per 4 MiB (the nonce, tag and hash) plus about 150
bytes. For given plaintext sizes, the ciphertext size is exact, which tus
needs: `Upload-Length` is computed before encryption.

**Reading.** The reader makes three range reads.
1. It reads the first 48 bytes and checks the header against the expected
   file, generation and revision.
2. It reads the trailer, then the manifest. It opens the manifest, checks the
   sizes and verifies the signature.
3. For any byte range it fetches blocks ⌊a/B⌋ to ⌊b/B⌋. For each block it
   checks the hash against h_i, then opens it with its index and `last`
   flag.

Plaintext is released only after both checks pass. Unlike Proton's legacy
`downloadSlices` ("we do not care of signature issues on random blocks"),
nothing reaches the player unverified.

**Whole-buffer helpers.** `encrypt_file_blocks` and `decrypt_file_blocks`
serve everything that seals a whole buffer, using the same construction, so
there is one format, not a "small" one. These callers come along:
- note (Yjs) snapshots;
- office and whiteboard saves and versions (`packages/collab`,
  `editors/src/content.ts`);
- Maps place lists;
- Pass vault sync;
- the CLI's `versions`, `sync` and `share`.

**Sealing in WASM.** Every block is sealed and opened in Rust, through
`kutup-crypto-wasm` in the browser, not by libsodium's secretstream. The JS
stream adapter goes. The benchmark in §9 is the check the 10× rule in
docs/cryptographic-dependencies.md asks for.

### Binding the current revision and the thumbnails

The header's revision id stops splicing between versions. On its own it
does not stop the server from serving an older revision as the current one.
Two more bindings close that:

- **The sealed metadata commits to the current content.**
  `FileMetadataV2` (`FileMetadata` envelope, revision-bound as today) gains a
  required `content: { revisionId, manifestSha256 }`. `manifestSha256` is the
  SHA-256 of the sealed manifest. Every new current revision (an upload, a
  saved version, a restore) seals the next metadata revision with it, in the
  same request that commits the content.
  - A reader opens the metadata first, then refuses any object whose header
    revision or manifest digest differs. Every reader takes the committed
    digest as an argument and compares it before it opens anything: the
    Drive reader takes `content` and the metadata's size, the Chat
    attachment reader the descriptor's digest, the backup media reader the
    index's. None can open a manifest without one, so a key holder (a
    co-editor, a group member) can't have the server hand others a valid
    object of their own making under the same header.
  - Older content under newer metadata therefore fails.
  - The block hash list is thus committed twice: in the sealed metadata
    through the manifest digest, and by the uploader's signature, as Proton
    does.
  - The optional whole-file `sha256` stays only for Photos' duplicate check.
- **Freshness of the metadata itself.** Each client remembers the highest
  metadata revision it has seen per file. This is `RevisionGuard`
  (docs/plans/sealed-revisions.md), extended to Drive file metadata, and
  inside the account head where the file's owner lists it
  (docs/plans/rollback-protection.md). Serving old metadata together with
  old content is then refused on any device that saw newer.
- **Thumbnails are bound to the revision they show.** The thumbnail
  envelope's parent commitment becomes
  `SHA-256(label ‖ variant ‖ content revision id)` instead of the variant
  alone. Its revision slot then means something. A thumbnail of older
  content fails to open and is drawn again from the current content.

Versions in the history list open by their own revision id: the header must
name the version the listing asked for. The server can still mislabel an old
version's date in the list. It cannot change what opens.

## 3. Server and storage

**One object per revision, read with HTTP Range.** Proton stores each block
as its own object, with per-block upload URLs and tokens. Kutup keeps one
object per revision:
- tus, S3 multipart, quota reservation, deletion by prefix and the
  federation digests all work on whole objects today and stay unchanged;
- R2 and SeaweedFS serve ranged GETs natively;
- 2,560 objects for a 10 GiB file would multiply R2 class-A writes and
  listing cost.

The cryptography follows Proton exactly. Only the storage layout differs,
and it can change later without touching the bytes (open question 2).

**Storage keys.** Content objects become `files/{id}/revisions/{revisionId}`
for the original and for every version. The `original` and
`versions/{vid}` keys go away. `file_versions.id` becomes the client's
revision id: the server checks that it is unique and that it matches the
header. `files.content_revision_id` names the original's.

**tus.** The protocol is unchanged.
- `Upload-Metadata` adds `revisionId`.
- On the first PATCH the server validates the 48-byte header (suite 2, the
  file, the generation and that revision).
- On the final PATCH it reads the trailer with one ranged GET and checks the
  structure: the manifest length fits n, and n fits the total length. This
  catches a broken client early. It cannot check the AEAD.
- Quota counts ciphertext bytes, as today.
- Multipart uploads and `POST /files/{id}/versions` validate the same way.

**Range GET on every content route:**
- `GET /api/files/:id/download`, `/original` (renamed to the revision
  route), `/api/files/:id/versions/:vid/download`;
- `GET /api/share/:token/download/:fileId`;
- the Chat media download route and the federated proxies below.

Each route takes one `bytes=a-b` range, or `a-`, or `-k` (the last k bytes).
It answers `206` with `Content-Range` and `Accept-Ranges: bytes`, or `416`.
The ETag is the revision id, and `If-Range` is honoured. A request with no
Range header gets the whole object, as today. `storage.rs` gains
`get_object_range`. nginx passes `Range` through and does no caching or
slicing of its own.

**Federation.**
- A full copy is unchanged: the whole-object SHA-256 (`ciphertext_sha256`)
  is checked before release.
- Ranges are new. The receiving server forwards `Range` in the signed
  request. The origin answers `206`, signed over an RFC 9530
  `content-digest` of that part. The receiver checks the signature and
  digest before it releases the part.
- Parts are capped by `drive.stream.response_max_bytes`, so a part can be
  spooled whole.
- End-to-end integrity comes from the manifest in any case.

**Versions and quota.** Versions stay full copies (docs/plans/drive-versions-v2.md).
Retention and accounting are unchanged. Each version's object is a revision
with its own id.

**Server learns.** Ranged reads show the server which parts of a file were
read, for example where a video was seeked to. Proton's server learns the
same from block fetches. This is listed in §8.

## 4. Browser streaming

**Method: a service worker answering Range requests, as Proton does.**

Proton's current preview (`modals/preview/streaming.ts`, `downloadSW.ts`
route `/sw/stream/{id}`) works like this:
- The video's `src` is a virtual same-origin URL.
- The service worker parses `Range` and caps the answer at 4 MiB. Safari asks
  for the whole file in one range, and a shorter `206` is valid HTTP.
- It asks the page for those bytes over a MessageChannel.
- It answers `206` with `Content-Range`.

The service worker holds no keys; the page decrypts. Proton also has an MSE
path, but only for fragmented MP4, to avoid Chrome scanning fMP4 through the
worker (`mseStreaming.ts`), and a full download as the last resort. Kutup
builds the service worker path, which plays every container the browser
supports (MP4, WebM, MOV/H.264, MP3, M4A, Opus, FLAC). MSE for fMP4 waits
until a test shows the Chrome problem (open question 5).

**Pieces:**
1. **Block reader, in a dedicated Worker** that the page starts
   (`@kutup/files` `blockReader`).
   - The page gives it the file key, the file id, the generation and the
     revision id. Those are the same keys the page holds today.
   - It runs the WASM block reader: header, then manifest, then blocks, as in
     §2.
   - It fetches with `fetch(url, { headers: { Range } })`, which `connect-src
     'self'` already allows.
   - It keeps a small LRU of verified plaintext blocks (default 3, about
     12 MiB, Proton's `MAXIMUM_BLOCKS_CACHE`) and reads ahead one block.
2. **Service worker** `kutup-sw.js` at scope `/` on each app host that plays
   media: `drive.`, `photos.`, `chat.`.
   - Chat already has `push-sw.js` at `/`. One origin can have only one
     worker per scope, so push and streaming become one script there.
   - Route `/sw/stream/{streamId}`. The `streamId` is 128 random bits.
   - The page registers a stream with `{streamId, size, mimeType, port}`.
     The worker answers only fetches whose `clientId` is the document that
     registered the stream. It answers them one at a time per stream (as
     Proton does).
   - It caps each answer at `drive.stream.response_max_bytes` (4 MiB) and
     drops the stream when the page closes the viewer or goes away.
   - Responses carry `Content-Type`, `Content-Range` and `Accept-Ranges`,
     plus a strict CSP and `nosniff`, as Proton's do.
3. **Page glue.** On a request, the page asks the block reader for
   `[a, b]` and posts the plaintext to the worker over the port as a
   transferred `ArrayBuffer`.

**Seeking.** When the element seeks, it opens a new range request. The
reader computes ⌊a/B⌋ and fetches only that block (and the next one, if the
range crosses into it). A 2-hour film at 4 Mbit/s is about 3.6 GB; a seek
costs one 4 MiB fetch. For an MP4 whose `moov` box is at the end, the browser
first asks for the tail, which is one more block.

**Memory.** Bounded by the cache (blocks × 4 MiB), the readahead and one
capped response in flight per stream, and at most
`drive.stream.max_concurrent` streams per tab (default 3). Nothing grows with
the file's size.

**Cancelling.** When the viewer closes, the page aborts the reader's
fetches with an `AbortController`, clears the cache and unregisters the
stream. If the browser cancels a request, the worker tells the page, and the
page drops the pending read.

**The keys stay in the page.** The file key and the plaintext blocks live in
the page and its dedicated Worker, as they do today. The service worker sees
only the plaintext ranges of a stream the page registered. It is
same-origin, so it has the same trust, but it is longer-lived and shared by
every tab of the origin. That is why it never gets keys. Keys there would
outlive the viewer and be reachable from other tabs.

**CSP and scope.**
- The existing policy already allows a same-origin worker
  (`worker-src 'self' blob:`) and same-origin media (`media-src 'self'`), so
  nothing is loosened.
- The script is served at `/kutup-sw.js` with `Cache-Control: no-cache`.
- nginx answers `/sw/*` with 404, so a request that no worker controls never
  falls through to the app.
- The worker calls `clients.claim()`, so the first visit is controlled
  without a reload.

**When there is no worker,** the viewer falls back to today's path: a full
download into a Blob, up to `drive.stream.blob_fallback_max_bytes`. This
happens with Firefox private windows, Shift+reload (which bypasses the
worker) and browsers with service workers disabled.

**Safari and iOS.**
- Safari probes with `bytes=0-1` and then may ask for the whole file. The
  4 MiB cap handles both.
- It needs exact `Content-Range` and `Content-Length` on every `206`.
- iOS gives a tab little memory, so the default cache there is 2 blocks.
- Lock screen and background playback are best-effort: iOS may suspend the
  page that supplies the bytes.
- The e2e suite runs on WebKit to cover this.

**Downloads to disk** keep File System Access, with a Blob fallback. Proton
also streams downloads through its worker (`/sw/{id}` with
`Content-Disposition`). That would lift the 1 GiB Blob limit on Firefox and
Safari. It is a follow-up on the same worker, not part of this plan (open
question 7).

## 5. Other clients

- **CLI.** It switches with the web; it is the same Rust code.
  - Upload: tus with `revisionId`; resume re-encrypts from the offset.
  - Download: the manifest first (one ranged read), then blocks in order. It
    can also fetch blocks in parallel, and resume after an interruption at a
    block.
  - `versions`, `sync`, `share` and `vaultsync` use the same functions.
- **Native apps, later.** `kutup-client-ffi` exposes the block reader (open
  header, open manifest, open block *i*). An app plugs it into
  AVAssetResourceLoader or an ExoPlayer `DataSource`, the native equivalents
  of the service worker.
- **Chat attachments switch too.** Long videos and voice notes in Chat then
  stream the same way.
  - New `ChatMediaSuiteId` 2 with the same block construction. The header
    is `KUTPCM2\0` with the attachment id; there is no revision, since
    attachments are immutable.
  - The E2EE attachment descriptor carries the sealed manifest's SHA-256.
    The message is already authenticated by the Signal session, so the
    manifest needs no signature (`signer kind` 0).
  - Server admission and federation still bind the whole-object SHA-256.
- **Chat backup media switches as well** (`KUTPBM2\0`, same construction).
  It is only read for restore and does not need seeking. Switching it lets
  secretstream and the browser's libsodium stream code leave the codebase.
  That also closes part of the roadmap's "remaining libsodium primitives"
  item.
- **Thumbnails, whiteboard assets and envelopes** are single AEADs and stay
  as they are.

## 6. Migration

### (A) Background conversion, no wipe

- New uploads use suite 2 from the release onward.
- Each client converts its account's files in the background: download,
  re-encrypt as a new revision, upload. Versions are either converted too or
  dropped.
- Readers keep suite 1 until every account reports it is done, then suite 1
  is removed before v1 (no two formats at the tag).
- This needs:
  - a conversion engine for Drive, Photos, Chat media and backup media that
    resumes, shows progress, survives tabs closing and handles quota while
    old and new copies coexist;
  - a server-side "converted" state per object;
  - both readers in every client for weeks;
  - and then a removal PR.
- Shared files and Chat attachments held by other people's servers can only
  be converted by their owner or sender, so some objects may never convert.

### (B) A clean-slate wipe when the block format ships

- kutup.dev is reset, database and bucket, in the same release that switches
  every writer and reader to suite 2.
- There is no conversion code, no suite 1 reader and no dual format. The
  secretstream file path is simply deleted.
- There are three accounts, all the user's.

### Recommendation: (B)

It is simpler and safer: there is no conversion code to build, review and
then remove, no window with two readers, and no objects that cannot be
converted. The user allowed another wipe for this ("we can also do another
wipe if needed and if its easier"). This replaces, for this change, the
roadmap's "no second wipe is planned".

- **Timing.** A wipe also clears Chat, Mail, Pass, Calendar and Contacts. It
  should be the same wipe as the next one already needed, so the plan aims to
  ship with the Chat identity deploy if both are ready together.
- **Confirmation.** Per the standing rule, the wipe happens only after the
  user confirms live ("wiping kutup.dev now, are you confirming?").

**Before the wipe the user exports:**
- **Drive and Photos:** everything to keep. Use a folder download from the
  web (ZIP), or `kutup download` / `kutup sync` to a local folder. Photos are
  Drive files, so they come along. Album membership, favourites and
  archive/hidden marks do not.
- **Pass:** each vault, as the `.kdbx` file (it is a Drive file) or as a CSV
  export.
- **Contacts:** a vCard export. **Calendar:** an `.ics` export.
- **Mail:** the mail to keep, copied out through the IMAP bridge into a
  desktop mail client.
- **Chat:** history cannot be exported, as in Signal. Save any attachments
  worth keeping to Drive first, then download them.
- **Admin:** a note of the site settings and per-user quotas, to enter
  again.
- **After the wipe:** the accounts are made again, with new recovery
  phrases.

### Bundled with the wipe

These are other changes that are easier with a wipe. They ship in the same
release and are not designed here:
- **Chat, one identity.** PR #320, approved and nearly ready.
- **The X25519 identity suite-1 upgrade path goes** (pq-shares.md, step 6):
  1216-byte keys are enforced, and the upgrade endpoint and `keysPendingUpgrade`
  are removed.
- **The migrations are squashed** into a new baseline.
- **The MLS tables are dropped,** if the MLS removal has landed by then.

Mail and Calendar post-quantum work is not in the bundle. It is blocked on
rPGP, and it is additive anyway.

**Landing order under (B).**
- Slices 1 and 2 (crypto, server Range) only add things, so they can merge
  to master at any time.
- Slices 3 to 7 switch the format. They merge into an integration branch
  `feat/drive-blocks` and land on master together, just before the wipe
  release. Until then, master can still be deployed to kutup.dev without
  changing its data.

## 7. Limits as site settings

The block size is **not** a setting. It is a fact of suite 2, like the 5 MiB
chunk of suite 1, and changing it changes the bytes. The limits around it
are site settings (`site_settings.rs` `NumericSetting`, in the admin UI, per
the standing rule). The client reads them from the site config.

| Setting | Default | Bounds |
|---|---|---|
| `drive.stream.max_bytes` (largest file streamed rather than downloaded) | the Drive upload limit (10 GiB) | 0 = never stream, up to the upload limit |
| `drive.stream.cache_blocks` (verified blocks kept per stream) | 3 (2 on iOS) | 1–16 |
| `drive.stream.readahead_blocks` | 1 | 0–4 |
| `drive.stream.max_concurrent` (streams per tab) | 3 | 1–8 |
| `drive.stream.response_max_bytes` (per answer, also the federation part size) | 4 MiB | 256 KiB–16 MiB |
| `drive.stream.blob_fallback_max_bytes` (no service worker) | 1 GiB | 0–4 GiB |

The Drive upload and version limits (`DRIVE_UPLOAD_LIMIT_BYTES`,
`DRIVE_VERSION_LIMIT_BYTES`) are constants in `main.rs` today. They become
site settings in slice 2 too, since streaming depends on them.

## 8. Security analysis

**What the server learns:**
- the ciphertext length, which gives the exact plaintext size and the block
  count, as today;
- **new:** which ranges are read and when. For a video that is roughly
  where it was played and seeked to. Proton's server learns the same.

It learns nothing of the content, the manifest or who signed it (the signer
is inside the sealed manifest). The signature covers the account id it
names, so a holder of the file key can't move it onto another name.

**Key commitment.** XChaCha20-Poly1305 is not key-committing: a ciphertext
can be crafted to open under two keys. Two things make an object single-key
here. The committed digest (in the metadata or descriptor) pins the sealed
manifest's ciphertext. And the manifest's hash list names every block by the
SHA-256 of its sealed bytes, checked before the block's AEAD: another object
behind the same manifest under a second key would need blocks with those
hashes, a SHA-256 preimage.

**Integrity.** Any change to one block's bytes fails its hash and its AEAD.
A wrong manifest fails its AEAD, its AAD (header and revision) and its
signature.

**Attacks covered:**

| Attack | Stopped by |
|---|---|
| Reorder or duplicate blocks | the index in each block's AAD and nonce; h_i in the manifest |
| Splice blocks from another file | the file id in the header, so in every key and AAD |
| Splice from another version of the same file | the revision id (per-revision keys) |
| Splice from an older key generation | the generation in the header |
| Truncate (drop the last blocks) | n and the size in the manifest; the `last` flag on block n−1 |
| Extend (append blocks) | n in the manifest; the trailer and the server's structure check; no block after `last` opens |
| Swap the manifest | the manifest's AAD (header), keys per revision, `manifestSha256` in the metadata |
| Serve an older revision as current | the metadata's `content` commitment; `RevisionGuard` on the metadata revision |
| Show an older revision's thumbnail | the content revision id in the thumbnail's binding |
| Forged content by another holder of the file key | the manifest signature (warns per identity pins) |
| Serve a different range than asked | the reader checks the indices it receives; each block opens only at its index |
| Nonce reuse on a resumed upload of a changed file | the synthetic nonce over the plaintext hash |

**Rollback to an older revision.** Older content under newer metadata fails
the metadata's content commitment. Old metadata with old content is refused
by any device that has seen a newer metadata revision (`RevisionGuard`, the
account head). A stale thumbnail fails its revision binding.

**Not covered:**
- A device with no history of a file trusts the first metadata revision it
  reads. These are the limits of sealed revisions.
- A deleted file can be held back.
- Availability: the server can refuse to serve.

**Failure mode.** A block that fails mid-playback stops the stream with an
error. The player never shows unverified bytes.

## 9. Tests and vectors

- **Rust vectors** (built in their own file, `tests/vectors/blocks-v1.json`):
  - the header bytes, the three derived keys and a block nonce;
  - a 3-block object (B + B + 17 bytes of plaintext from a fixed pattern),
    with full bytes for the header, the trailer, the manifest and the last
    block, and SHA-256 for the whole object;
  - an empty file;
  - a size that is an exact multiple of B;
  - the same set for Chat media suite 2 and backup media suite 2.
- **Rust negatives:**
  - each row of the §8 table as a test, including an older revision served
    under newer metadata and an old revision's thumbnail;
  - flipping any header byte; a wrong revision;
  - a short trailer, a manifest length that does not fit, n and size
    mismatches, and bytes after the trailer.
- **Fuzzing:** a `fuzz` target for the reader's header, trailer and manifest
  parsing.
- **WASM vectors:** the same JSON, run through `kutup-crypto-wasm` in vitest.
- **Benchmark:** WASM XChaCha20-Poly1305 throughput against libsodium on
  desktop Chrome, Firefox, Safari and an Android phone. If WASM is within 10×
  (the rule in docs/cryptographic-dependencies.md), libsodium's stream path
  goes.
  - Measured 2026-10-25 (`packages/crypto/src/blocks.bench.ts`; the median
    of 25 runs, one 4 MiB block, on the dev VM):

    | | WASM block | libsodium, same work | libsodium secretstream |
    |---|---|---|---|
    | Seal, Node 22 (V8) | 19.6 ms | 21.6 ms | 5.5 ms |
    | Open, Node 22 (V8) | 13.9 ms | 13.3 ms | 5.3 ms |
    | Seal, Chromium | 20.4 ms | 21.3 ms | 5.6 ms |
    | Open, Chromium | 14.4 ms | 13.4 ms | 5.5 ms |

  - "Same work" is what a block costs in either library: SHA-256 of the
    plaintext (the synthetic nonce), XChaCha20-Poly1305 and SHA-256 of the
    sealed block (the manifest's hash). WASM is level with libsodium, far
    inside 10×, so the libsodium stream path goes in slice 7.
  - A block costs about 3× a secretstream chunk because of the two hashes:
    about 200 MiB/s sealing and 290 MiB/s opening on one core, which is
    above a fast connection.
  - Still to measure: Firefox, Safari and an Android phone. WebKit doesn't
    start on the dev VM, which lacks its system libraries. These figures
    can't change the decision unless WASM there is 10× slower than
    libsodium on the same engine.
- **Server tests:**
  - Range parsing (`a-b`, `a-`, `-k`, multiple ranges refused, 416);
  - `If-Range`;
  - tus header and structure checks;
  - the federated range proxy, with a wrong part digest.
- **e2e spec** (next free number in the block):
  - upload a 2-hour, low-bitrate test video of a few hundred MB, made with
    ffmpeg in the fixture step;
  - open it in Photos, seek to 1:30:00 and check that `currentTime` advances
    within a few seconds;
  - check from the network log that only a few blocks were fetched;
  - the same in Drive's preview, and for audio;
  - Chromium and WebKit; a run with no service worker covers the fallback.
- **CLI round trip:** `kutup upload` then `kutup download` of a file of
  B·k ± 1 bytes; an interrupted upload resumed; a web upload read by the CLI
  and the reverse.

## 10. Slices

Each slice is a PR.

1. **Crypto core.**
   - `kutup-crypto` `blocks.rs` holds the construction.
   - Drive suite 2, Chat media suite 2 and backup media suite 2 build on it.
   - `FileMetadataV2` with the content commitment.
   - The thumbnail binding to the content revision.
   - Vectors, negatives, a fuzz target and WASM exports (block encryptor,
     reader). The benchmark.
2. **Server.**
   - Range on every content route.
   - `get_object_range`.
   - Revision ids (a migration) and the new storage keys.
   - tus, multipart and version header and structure checks.
   - The federated range proxy.
   - The site settings from §7.
3. **Upload.**
   - Web `streamUpload` / `encryptedSource` on blocks, with resume.
   - Versions and editor snapshots through the whole-buffer helpers.
   - The metadata is sealed with the content commitment, in the same commit
     as the content.
   - Thumbnails are drawn bound to the new revision.
   - `RevisionGuard` for Drive file metadata.
   - The CLI upload.
4. **Download and streaming.**
   - The block reader Worker and `fetchDecrypt` on blocks.
   - The CLI download.
   - `kutup-sw.js` (merged with Chat's push worker) and the stream registry.
5. **Players.** Photos' viewer and Drive's preview stream video and audio.
   `MAX_VIDEO_BYTES` gives way to `drive.stream.max_bytes`. The e2e spec.
6. **Chat.** Attachments and backup media on suite 2; Chat's viewer streams.
7. **Removal.**
   - `stream.rs`, suite 1, `KUTPDB2`/`KUTPCM1`/`KUTPBM1`, the JS
     `streamEncryptor`/`streamDecryptor` and the libsodium stream path all
     go.
   - Docs: `architecture.md`, `v1-format-inventory.md`, `chat-media.md`,
     `chat-backup.md`, `cryptographic-dependencies.md`.
   - `FileMetadataV1`, the thumbnail context without a revision
     (`DriveEnvelopeContextV1::thumbnail`) and their callers: until the
     switch, both sit side by side, the V2 ones unused.
   - CLAUDE.md's V1 fact "secretstream uses 5 MiB chunks and authenticated
     `TAG_FINAL`" becomes "large objects use 4 MiB AEAD blocks bound to
     their index and revision, with a sealed, signed manifest of block hashes
     that fixes the size and the end".

Under (B), slices 3–7 land together with the wipe (§6). Under (A), a
conversion slice comes between 6 and 7, and slice 7 waits for every account.

## 11. Decisions

The user's answers, 2026-10-22:

1. **Wipe (B).** Slices 3–7 land with the wipe (§6).
2. **One object per revision, read by Range.**
3. **Ed25519 now.** A post-quantum hybrid signature comes as a new suite,
   with the rest of Drive's signatures under the PQ plan.
4. **4 MiB blocks**, as Proton.
5. **MSE only if needed later**, if Chrome's fMP4 scanning proves a problem.
6. **Chat backup media moves to suite 2 too**, so secretstream leaves
   entirely.
7. **Downloads through the service worker are in scope** (slice 4).

The questions as asked:

1. **Wipe (B) or conversion (A)?** The plan recommends (B). When: with the
   Chat identity deploy?
2. **One object with Range, or one object per block as Proton stores them?**
   The plan recommends one object. The bytes are the same either way, so
   this can change later.
3. **The manifest signature: Ed25519 now?** It would get a hybrid
   post-quantum signature with the rest of Drive's signatures under the PQ
   plan.
4. **Block size 4 MiB (Proton), or keep 5 MiB?** 5 MiB would line up with
   S3's minimum part size, but nothing needs that alignment, since tus parts
   are independent of blocks.
5. **MSE for fragmented MP4 now, or only if Chrome's fMP4 scanning proves a
   problem?**
6. **Chat backup media to suite 2 as well,** so secretstream leaves
   entirely? The plan says yes.
7. **Is downloading through the service worker** (lifting the 1 GiB Blob
   limit on Firefox and Safari) part of this, or a follow-up?
