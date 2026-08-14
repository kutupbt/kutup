# Unified media preview, in-app open, and save plan

**Status:** partially implemented; shared preview generation, Chat presentation,
and private ciphertext cache landed, while Drive sidecars and native export
hardening remain planned

**Written:** 2026-08-11

**Scope:** authenticated Chat and Drive clients on Web and Tauri

**Primary references:** Signal Desktop, Matrix encrypted thumbnails, Wire asset
previews, Kutup's existing Chat-media and Drive object formats

## Implementation record

Commit `fd1948e` landed the common bounded preview/safety modules, worker,
account-isolated encrypted cache, concurrent request deduplication, Chat image/
waveform presentation, in-app viewer, download/open/save/clear states, and unit
coverage. It did not complete this entire plan: Drive preview sidecars, the
unified Drive viewer integration, Tauri streaming export/quarantine attributes,
cache settings UI, and the complete cross-browser/two-server matrix remain
open. The slice lists below are therefore retained as the source for that
remaining work rather than being marked complete wholesale.

## Target outcome

Kutup will use one user-facing attachment state machine and one shared preview
policy across Chat and Drive:

```text
preview/card -> Download into Kutup -> Open/Play in Kutup -> Save to device
                         |                       |
                         +---- Clear local copy-+
```

`Download` means fetching an authenticated encrypted object into Kutup's private
local cache. `Save to device` means deliberately exporting plaintext outside
Kutup. These actions must never be presented as equivalent.

Chat and Drive share preview generation, validation, rendering, cache state,
progress UI, file-safety classification, and viewer components. They do not
share ciphertext, keys, object identifiers, storage references, or KDF labels.
Saving a Chat attachment to Drive continues to decrypt and re-encrypt it as a
new Drive object.

## Locked product decisions

1. The server never receives a plaintext thumbnail, waveform, filename, MIME
   type, page image, slide image, or preview classification.
2. Preview generation happens on the sender/uploader's client. Preview
   rendering and full-content decryption happen on the viewing client.
3. Chat uses a small preview carried inside the existing E2EE attachment
   descriptor. The current 32 KiB decoded limit remains.
4. Drive uses a separately encrypted preview sidecar referenced only by
   encrypted file metadata. Directory listing must not download the full file.
5. A full attachment fetched for in-app use is stored persistently only as
   ciphertext. Plaintext is transient and must not be placed in Downloads or a
   user-visible filesystem location until `Save to device` is chosen.
6. The initial release remains manual-download as required by
   `docs/chat-media.md`. Auto-download preferences are a later, separately
   gated feature.
7. Safe preview is allowlist-based. Sender MIME and filename extension are
   hints, not authority. Unsupported or conflicting input becomes a generic
   file card.
8. Raw SVG, HTML, XML, executable content, scripts, and macro-enabled Office
   documents are never embedded as active content.
9. Chat blocks known dangerous file types both on send and on plaintext export,
   following Signal Desktop. Drive may store arbitrary encrypted files, but
   dangerous files have no preview and require an explicit warning before
   export.
10. Disappearing-media expiry removes Kutup's cached copy. A copy explicitly
    exported to the operating system cannot be revoked. View-once media, when
    added, has no Save, Forward, Save to Drive, or persistent-cache action.
11. Message requests do not fetch full media or allocate destination media
    before acceptance. Preview bytes are not rendered until the request is
    accepted.
12. No server endpoint or database column may branch on a plaintext media kind.

## Current baseline

### Chat

- `ChatAttachmentDescriptorV1` already has an optional
  `ChatMediaPreviewV1 { mimeType, data }`, validated as non-empty canonical
  base64 with a maximum decoded size of 32 KiB.
- Upload currently leaves `preview` unset.
- The message bubble shows a generic filename/size card.
- Its Download button calls `downloadChatMediaV1`, which decrypts and writes
  directly to an OS/browser save sink. There is no private in-app media cache
  or inline viewer.
- Chat media is immutable, descriptor-bound, digest-verified, streamed through
  secretstream, federated durably, and covered by the shared account quota.

### Drive

- Image, video/audio, and PDF viewers already exist.
- `FileEditorPage` currently downloads and decrypts the full object into tab
  memory, creates a plaintext Blob URL, and caps preview at 100 MiB.
- PDF currently uses the browser's native PDF iframe rather than the pinned
  PDF.js runtime.
- Office documents are opened with Kutup's CryptPad-pinned OnlyOffice/x2t
  integration, but Drive listings have no page/slide preview sidecar.
- `FileMetadataV1` contains only name, MIME type, and size; its decoder requires
  exactly those keys.
- Drive's explicit download path already decrypts into a streaming save sink
  on File System Access API and Tauri, with a whole-Blob fallback on browsers
  without a streaming save API.

### Constraint exposed by the baseline

The current Chat and Drive secretstream formats authenticate sequential
frames; they are not random-access media containers. Kutup cannot promise
Signal Desktop-style arbitrary encrypted byte-range seeking merely by adding a
viewer. The first implementation must support bounded full decrypt and
progressive playback where the browser container and MediaSource permit it,
and must fall back safely for large or non-streamable media. A future
random-access object suite requires a separate protocol design and migration;
it is not hidden inside this UI work.

## Target interaction model

Every full attachment is represented by the following UI states:

| State | Primary action | Secondary actions |
|---|---|---|
| `PreviewOnly` | Download | Details |
| `Queued` | Cancel | Details |
| `Downloading` | Cancel | Progress, details |
| `Verifying` | None | Progress |
| `AvailableInKutup` | Open or Play | Save to device, Clear local copy |
| `Opening` | None | Close |
| `Open` | Viewer controls | Save to device, Save to Drive in Chat |
| `FailedRetryable` | Retry | Details, error summary |
| `Unavailable` | None | Details |
| `Expired` | None | Expired label |

The state is scoped by authenticated account incarnation, product domain,
object ID, suite, ciphertext length, and ciphertext digest. A cached object
must not be reused when any binding differs.

### Chat presentation

- Image: inline tiny raster preview; tap downloads full content; tap again or
  automatic transition opens the lightbox.
- Video: inline raster poster with play/download overlay and duration; full
  content is fetched before or progressively while opening.
- Voice/audio: waveform/duration card; Download changes to Play when available.
- PDF/Office: first-page/first-slide raster if the sender generated one within
  resource limits; otherwise a generic document card.
- Other safe files: generic filename/type/size card with Download, then
  `Save to device` when available. They are not automatically opened.
- Dangerous files: blocked at composition. A dangerous attachment received
  from history or a newer/hostile client remains a warning card and cannot be
  exported from Chat.

### Drive presentation

- List and grid views lazily load encrypted preview sidecars only for visible
  rows.
- Opening a file fetches its full ciphertext into Kutup if it is not cached,
  then uses the same viewer shell as Chat.
- The three-dot menu uses `Save to device`, never ambiguous `Download`, for
  plaintext export.
- `Clear local copy` removes only the device cache, not the Drive object.
- A safe non-previewable file opens a details page with `Save to device`.
- A dangerous file opens a warning/details page and requires a second explicit
  confirmation before export.

## Shared preview model

Create an internal, versioned `PreviewManifestV1` used by generation,
validation, cache, and rendering. This is a shared logical model, not a shared
cryptographic envelope.

```ts
type PreviewManifestV1 = {
  version: 1
  kind: 'image' | 'video-poster' | 'pdf-page' | 'office-page' | 'audio-waveform'
  contentType: 'image/webp' | 'application/vnd.kutup.audio-waveform.v1'
  width?: number
  height?: number
  durationMs?: number
  blurHash?: string
  waveform?: Uint8Array
  raster?: Uint8Array
  source: {
    product: 'chat' | 'drive'
    objectId: string
    contentRevision: number
    ciphertextSha256?: string
  }
}
```

The validator enforces exact keys per kind, safe integers, canonical strings,
bounded dimensions, bounded decoded pixels, bounded payload length, fixed
waveform sample count, and product-specific source binding. Decoders must reject
unknown manifest versions and kinds without rejecting the parent file/message.

### Chat wire adapter

Do not change `ChatAttachmentDescriptorV1` merely to introduce the shared
internal type. Encode the initial Chat profile through the existing
`ChatMediaPreviewV1` fields:

- raster previews use `mimeType = image/webp` and raw WebP bytes in `data`;
- audio uses a registered Kutup waveform MIME and a compact canonical binary
  payload in `data`;
- full width/height/duration remain in the existing descriptor fields;
- decoded payload remains at or below 32 KiB;
- older clients that do not render previews continue to show their generic
  attachment card.

If BlurHash or additional authenticated fields later require wire changes,
introduce a capability-gated descriptor V2. Do not add non-optional or unknown
fields to V1 while older strict decoders exist.

### Drive wire adapter

Introduce a Drive metadata V2 decoder rather than weakening V1's exact-key
validation. V2 adds an optional encrypted preview reference with:

- opaque preview object ID;
- preview suite and purpose;
- exact ciphertext length and digest;
- source content revision/digest binding;
- preview format, width, height, and optional BlurHash inside the encrypted
  metadata envelope.

The sidecar has its own typed public object header and purpose-separated key:

```text
KDF label: kutup/drive-preview/object-key/v1
AAD: suite || purpose || preview_id || file_id || collection_id || epoch
```

The preview key is derived from the Drive file key and complete sidecar
context. The sidecar is never a Chat object, never uses a Chat attachment key,
and is invalid after its bound content revision changes. Rename-only metadata
revisions should not regenerate it; content replacement or restored content
must.

## Preview generation policy

Create one worker-owned preview pipeline with product profiles:

| Input | Output | Chat profile | Drive profile |
|---|---|---:|---:|
| Safe raster image | Re-encoded WebP | max edge 384 px, <=32 KiB | max edge 768 px, <=256 KiB |
| Video | Rasterized poster + duration | <=32 KiB | <=256 KiB |
| PDF | Rasterized first page | <=32 KiB when bounded/cheap | <=256 KiB |
| DOCX/XLSX/PPTX | Rasterized first page/sheet/slide | best effort | <=256 KiB |
| Audio/voice | Normalized unsigned waveform + duration | 64 samples | 100 samples |

Final constants should be benchmarked on low-memory mobile hardware and then
locked in code and tests. The values above are ceilings for implementation,
not permission to allocate unbounded decoder input.

Generation rules:

1. Inspect magic bytes and bounded headers before trusting MIME or extension.
2. Decode in a Web Worker wherever the library permits it.
3. Enforce input byte, pixel, frame/time, page, recursion, and wall-clock
   budgets. Timeout produces no preview, not an upload failure.
4. Draw supported images/video frames onto a bounded canvas and export WebP.
   Never copy sender bytes directly into a raster preview.
5. Do not decode SVG as an image. Do not fetch external fonts, images, links,
   or media referenced by a document.
6. PDF uses the pinned PDF.js worker with scripting, forms, launch actions, and
   external resources disabled.
7. Office generation uses the pinned x2t/OnlyOffice assets in an isolated
   worker/iframe. Macro-enabled formats are excluded in V1.
8. Strip EXIF and other source metadata by raster re-encoding.
9. Preview failure never prevents sending/uploading a safe full file.
10. The receiver validates and bounds the preview again before rendering it.

## File-safety policy

Implement one tested `classifyFileForKutup` module. It returns:

- `previewable`: type is in the safe viewer allowlist and signature agrees;
- `safe-download-only`: archive or unsupported inert file;
- `dangerous-active`: executable, installer, script, shortcut, active web
  content, or other blocked extension/signature;
- `mismatch`: filename, claimed MIME, and detected signature materially
  disagree; treat as generic and never preview.

The Signal Desktop dangerous-extension list is the initial minimum, including
APK, BAT, CMD, COM, DLL, DMG, EXE, HTA, JAR, JS/JSE, LNK, MSI, PIF, PS1,
REG, SCR, VB/VBS, and WSF. Matching is case-insensitive and ignores trailing
dots and whitespace. Add ELF, Mach-O, PE, script shebang, and common shortcut
magic detection so renaming is not sufficient to bypass classification.

Product behavior:

| Classification | Chat send | Chat export | Drive store | Drive export |
|---|---:|---:|---:|---:|
| Previewable | allow | allow | allow | allow |
| Safe download only | allow | allow | allow | allow |
| Dangerous active | block | block | allow | confirm warning |
| Mismatch | allow as generic unless dangerous signature | policy of detected type | allow | confirm warning |

On Tauri, exported files should receive operating-system origin/quarantine
metadata analogous to Signal Desktop: macOS quarantine attributes and Windows
Mark-of-the-Web. The Web client must rely on the browser's save path and must
not claim it can set these attributes itself.

## Encrypted local cache

Add an account-scoped, chunked ciphertext cache backed by IndexedDB on Web and
an app-private directory on Tauri.

Each cache record contains only:

- version and product domain;
- opaque local cache ID;
- suite, object binding, ciphertext length, and digest;
- chunk count and received/verified state;
- last access time and lifecycle/expiry deadline.

It must not contain plaintext filename, MIME, conversation name, recipient, or
decryption key in its index. Those remain in the E2EE message or encrypted
Drive metadata. Cache writes become `AvailableInKutup` only after exact length,
digest, public header, framing, final tag, and AEAD verification succeed.
Partial data is resumable only when the server/object protocol authenticates
the resumed binding; otherwise retry from zero.

Required cache behavior:

- deduplicate concurrent requests for the exact same binding;
- expose progress and cancellation to multiple UI subscribers;
- enforce a configurable local-device cache limit independent of server quota;
- evict least-recently-used non-pinned entries, never an open entry;
- purge on logout/account switch, clear-local-copy, disappearing expiry,
  delete-for-everyone receipt, view-once close, and object binding change;
- clean crash-left partial entries at startup;
- never log object keys, digests, filenames, or conversation relationships.

## Full-content viewer pipeline

Build a shared `AttachmentViewerShell` around the existing viewers. It owns
Open, Close, Save to device, Save to Drive, Clear local copy, error state, and
temporary plaintext lifetime.

### Images

- Verify detected format against the allowlist before constructing a Blob.
- Decode to bounded dimensions; large/decompression-bomb images fail closed.
- Revoke the Blob URL on close/unmount/account change.
- Raw SVG remains unsupported; a future SVG feature must rasterize in a
  sandbox first.

### PDF

- Replace the native iframe with the pinned PDF.js viewer/worker.
- Disable document JavaScript, launch actions, automatic external navigation,
  and external resource loading.
- Do not expose PDF.js's built-in Download control as a hidden second export
  path; route export through `Save to device`.

### Office

- Drive retains editable OnlyOffice behavior where already supported.
- Chat opens Office attachments read-only.
- Page/slide list previews use the generated sidecar/inline raster rather than
  booting the full OnlyOffice runtime.
- Any OnlyOffice download/export affordance must delegate to Kutup's explicit
  save action.

### Audio and video

- Voice notes and supported small audio/video may use a bounded transient Blob.
- Use MediaSource progressive append where the detected container and browser
  support it; otherwise finish verified download before Play.
- Never accumulate an object above the bounded Blob limit in renderer memory.
- For a large unsupported container, show `Available in Kutup` with
  `Save to device`; do not OOM attempting an in-app preview.
- Seeking beyond already decrypted data is not guaranteed in the V1 object
  suite. Specify and implement a random-access V2 media suite separately if
  Signal-class arbitrary seeking becomes a release requirement.

### Plaintext lifetime

- Prefer a decrypting stream feeding a viewer over a complete plaintext Blob.
- Blob URLs are created only after full authentication for non-progressive
  viewers and are revoked deterministically.
- Do not put plaintext in Cache Storage, IndexedDB, localStorage, OPFS, or an
  app-private persistent file merely to make a preview convenient.
- Tauri temporary plaintext, if a platform decoder strictly requires a path,
  must use a protected temporary directory, random name, restrictive mode,
  startup cleanup, and deterministic deletion on close.

## Save and Save-to-Drive workflows

### Save to device

1. Re-run the shared safety classification using filename, authenticated
   metadata, and detected content.
2. Enforce the product policy table above.
3. Ask for the destination before starting a new network transfer when the
   platform save API permits it.
4. Stream verified plaintext from the encrypted cache or network into the File
   System Access/Tauri sink. Keep the whole-Blob fallback bounded and display a
   browser limitation for files above that bound.
5. Sanitize the suggested filename and prevent path traversal/reserved device
   names.
6. Apply native quarantine metadata in Tauri.
7. Show completion only after the sink is closed successfully.

### Save Chat attachment to Drive

1. Verify/decrypt the Chat object under the Chat-media descriptor.
2. Create a fresh Drive file ID/key and Drive metadata.
3. Generate or reuse only the decoded logical preview; encrypt a new Drive
   preview sidecar under the Drive preview domain.
4. Stream re-encryption into the Drive object format and verify finalization.
5. Commit the encrypted attachment-ledger transition before releasing the Chat
   reference when the user chooses to move rather than copy.
6. Never adopt Chat ciphertext, key, digest, retrieval token, storage row, or
   preview ciphertext as a Drive object.

## Implementation slices

Each slice is independently testable and should be committed only after its
acceptance gates pass.

### Slice 1 — Shared policy and preview foundation

- Add the versioned internal preview manifest and strict validator.
- Add file signature detection, dangerous-extension normalization, and the
  product policy matrix.
- Add the worker protocol, cancellation, resource budgets, WebP raster output,
  and audio waveform encoding.
- Add fixture-based tests for benign, malformed, mismatched, oversized, SVG,
  executable, and polyglot inputs.

**Gate:** no UI change; deterministic generation and rejection tests pass in
Chromium and the unit-test DOM environment.

### Slice 2 — Chat inline previews

- Generate preview data before Chat upload finalization and populate the
  existing descriptor only after bounded validation.
- Render images, video posters, document posters, and waveforms in message
  bubbles.
- Keep message-request previews hidden until acceptance.
- Preserve the generic card when preview generation/decoding fails.
- Add linked-device/history-transfer and direct/MLS serialization tests.

**Gate:** Alice on A sends each supported type to Bob on B; Bob sees the same
bounded preview after login/restart without either server learning its type or
bytes.

### Slice 3 — Private ciphertext cache and Chat open flow

- Implement the chunked encrypted local cache and request coordinator.
- Split current `downloadChatMediaV1` into fetch-to-cache, open-from-cache, and
  export-to-device operations.
- Add Download/Downloading/Cancel/Available/Open/Clear state to Chat bubbles.
- Add shared image, audio, and video viewer shell paths.
- Wire disappearing-message expiry and delete controls to cache purge.

**Gate:** Download does not trigger an OS save; Save to device does. Offline
reopen works from verified cache; logout and expiry remove the cached object.

### Slice 4 — Drive preview sidecars

- Specify and implement Drive preview header/KDF/AAD in canonical Rust/WASM.
- Add metadata V2 compatibility, server-opaque preview storage/reference
  endpoints, upload finalization, deletion/refcount, quota accounting, and
  migration behavior.
- Generate the preview during Drive upload and content replacement.
- Lazy-load sidecars in list/grid views with concurrency and memory bounds.
- Invalidate previews on content revision changes, not rename-only changes.

**Gate:** directory listing transfers only bounded encrypted sidecars; old V1
files still open without previews; corrupt/swapped sidecars fail to a generic
icon.

### Slice 5 — Unified Drive and Chat viewer shell

- Reuse the cache state machine and viewer shell from both products.
- Replace Drive's eager full-arraybuffer preview path.
- Replace native PDF iframe with pinned PDF.js.
- Add read-only Chat Office viewing and first-page/slide rendering.
- Route every viewer export affordance through `Save to device`.

**Gate:** one viewer behavior matrix passes for Chat local, Chat federated,
Drive owned, and Drive named-share content.

### Slice 6 — Dangerous-file and platform export hardening

- Block dangerous Chat composition and Chat export.
- Add Drive warning/confirmation and generic-only rendering.
- Add filename sanitization and mismatch downgrade.
- Add Tauri macOS quarantine and Windows Mark-of-the-Web support with platform
  tests; document Web limitations.

**Gate:** renamed executables, trailing-dot/space tricks, mixed-case
extensions, script shebangs, and MIME mismatches cannot reach a preview or
unwarned export path.

### Slice 7 — Lifecycle, settings, and polish

- Add local cache usage/limit/clear controls.
- Add accessibility labels, keyboard controls, progress announcements, focus
  restoration, reduced-motion behavior, and mobile touch/safe-area handling.
- Add an opt-in auto-download design for photos, video, audio, and documents,
  but do not enable it or change the V1 manual-download rule in this slice.
- Add view-once cache isolation when view-once itself is scheduled.

**Gate:** state survives restart where intended, never crosses accounts, and is
usable by keyboard and screen reader.

## Verification matrix

### Unit and property tests

- preview manifest exact decoding and size/pixel/sample limits;
- WebP and waveform deterministic fixtures;
- signature/MIME/extension agreement and dangerous-name normalization;
- cache key binding, partial cleanup, LRU behavior, concurrent deduplication,
  cancellation, and account isolation;
- descriptor and Drive metadata backward compatibility;
- expiry/delete/view-once purge ordering;
- Blob URL creation/revocation and no-export-on-Download behavior.

### Adversarial tests

- truncated, extended, reordered, swapped, wrong-key, wrong-revision, and
  wrong-digest preview/full objects;
- image decompression bombs, huge dimensions, malformed WebP, hostile PDF,
  SVG with script/external references, Office external relationships, archive
  recursion, and polyglot files;
- preview claims safe while full file is executable;
- cache rollback/substitution and stale preview after content replacement;
- cancellation/crash during cache write, viewer decrypt, and device export;
- disappearing expiry racing an active download or viewer.

### Browser and platform tests

- Chromium File System Access streaming;
- Firefox/Safari bounded Blob fallback and oversized-file messaging;
- Tauri streaming sink, temporary-file cleanup, and quarantine attributes;
- image, audio, video, PDF, and Office behavior on desktop and mobile widths;
- low-memory test demonstrating no renderer allocation proportional to a large
  ciphertext except where an explicitly bounded Blob path is selected.

### Two-server end-to-end gate

Use Alice/Admin A on server A and Bob/Admin B on server B:

1. Send photo, video, voice note, audio, PDF, PPTX, ZIP, and malformed/mismatch
   fixtures from Alice to Bob.
2. Verify preview visibility, manual Download, cancel/retry, Open/Play, Save to
   device, and Clear local copy.
3. Restart both servers and both browsers; verify durable server ciphertext and
   intended device-cache behavior.
4. Repeat through direct Chat and MLS group delivery.
5. Save selected Chat items to Bob's Drive and verify fresh Drive object/header,
   key, digest, preview sidecar, quota/ledger transition, and independence from
   Alice's Chat object.
6. Verify `.exe`/script send and Chat export are blocked; Drive storage remains
   possible but preview is absent and export warns.
7. Verify disappearing expiry removes Bob's cache and reference while an
   already exported OS file remains explicitly outside Kutup's control.
8. Inspect server logs, database fields, object paths, metrics, and federation
   messages for forbidden plaintext media metadata.

## Documentation and rollout

Before advertising the feature:

- update `docs/chat-media.md`, both Chat/Drive threat models, architecture,
  API documentation, and roadmap status;
- document preview limits, unsupported formats, dangerous-file policy, local
  cache semantics, and the difference between Download and Save;
- add admin guidance for preview-sidecar quota/cleanup without revealing media
  kinds;
- ship behind advertised client/server capabilities for Drive preview sidecars
  and any future descriptor version;
- retain generic cards and direct Save behavior as compatibility fallback;
- record benchmark hardware, peak memory, generation time, and transfer sizes
  used to lock release limits.

## Explicit non-goals

- Server-side plaintext thumbnailing, transcoding, virus scanning, or Office
  conversion.
- Reusing a Chat media object as a Drive object or vice versa.
- Rendering arbitrary browser-supported MIME types without an allowlist.
- Promising revocation of files already saved outside Kutup.
- Adding view-once media as part of preview implementation.
- Claiming arbitrary large-media seeking with the current sequential V1 object
  suites.
- Enabling automatic full-attachment download by default.

## Reference implementation notes

Signal Desktop is a behavioral reference, not a format dependency:

- it separates app download state from OS Save;
- it exposes NeedsDownload, Downloading, and ReadyToShow states;
- it stores modern local attachments encrypted and decrypts them through a
  private range-capable attachment protocol;
- it uses a strict image/video allowlist and intentionally excludes SVG;
- it blocks dangerous extensions on composition and Save;
- it marks exported native files with platform quarantine metadata; and
- it removes Save/Forward from view-once media and deletes its temporary copy.

Kutup should preserve these product/security properties while using its own
Rust/WASM suites, Web/Tauri storage abstractions, federation rules, and separate
Chat/Drive cryptographic domains.
