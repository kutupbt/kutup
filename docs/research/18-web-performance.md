# Web performance: where the apps are slow and how to make them fast

**Date:** 2026-10-09. **Code:** master at `39b1537`. **Status:** Tier 1 and most of Tier 2 implemented on branch `perf/web-performance` (see §6); Tier 3 open.

**Method.** Four investigations, run in parallel:
1. **Browser measurements** with Playwright and Chromium on the local stack. Its asset hashes match production, so the byte counts apply to kutup.dev. Runs covered cold and warm loads, link speeds from unthrottled down to slow 4G, and CPU throttling.
2. **Bundle analysis** of the deployed `dist/` with source-map-explorer.
3. **A code trace** of the client data path.
4. **A server and delivery review:** nginx, the Axum handlers, `EXPLAIN` on the list queries, and anonymous `curl` against production.

The raw data (JSON results, header dumps, scripts) is in the session scratchpad. The previous baseline is `perf-baseline-2026-05-06.md`.

## Summary

- **The server is not the problem.** Every endpoint on the Office and Drive load path answers in 1–5 ms, and the list queries are indexed (0.3 ms execution).
- **Pages are slow for three reasons:**
  1. **Bytes:** nothing is compressed and the OnlyOffice assets are huge and partly unminified.
  2. **Caching:** the editor assets have no `Cache-Control`, and the WASM files are `no-cache`.
  3. **Serial round trips:** a session restore takes 5 requests one after another before the first data request. Opening a document crosses origins and does everything in sequence.

| Page (local stack, same assets as production) | Unthrottled | 40 Mbps / 40 ms | 40 Mbps + CPU 4× | Slow 4G (1.6 Mbps / 150 ms + CPU 4×) |
|---|---:|---:|---:|---:|
| Office home, cold / warm | 227 / 223 ms | 1.33 s / 658 ms | 1.81 s / 1.08 s | 19.2 s / 2.25 s |
| Drive root, cold / warm | 257 / 291 ms | 1.48 s / 625 ms | 1.94 s / 1.13 s | 21.5 s / 2.45 s |
| Note editor, cold / warm | 392 / 405 ms | 2.36 / 1.02 s | 3.14 / 1.81 s | 35.8 / 3.5 s |
| **.docx open, cold** | 1.76 s | **19.5 s** | 21.2 s | **fails** |
| .docx open, warm (same browser session) | 1.23 s | 13.4 s | 15.6 s | – |
| .docx open, warm (on-disk cache) | 1.2 s | 1.66 s | – | – |

- **Opening a .docx on slower links:** 71.6 s at 10 Mbps, and it fails at 5 Mbps.
- **What a cold .docx open downloads:** 276 requests and 89 MB (41.5 MB JS, 40.9 MB WASM, 4.9 MB fonts). Main-thread time is 1.1 s, or 6.0 s at CPU 4×.
- **What a cold Office home downloads:** 27 requests and 3.54 MB. With brotli it would be about 0.85 MB.

## 1. What is slow, and why

### 1.1 Opening an office document: 89 MB, uncompressed, revalidated

| File (editor origin) | Raw | brotli (`.br` already in the image) | Notes |
|---|---:|---:|---|
| `onlyoffice/dist/x2t/x2t.wasm` | 36.0 MB | 6.8 MB | fetched for every open, PDFs included (they don't need conversion) |
| `sdkjs/word/sdk-all.js` | 28.7 MB | 3.25 MB | **unminified**: 847,109 lines, license header ×388. Not a duplicate: `sdk-all-min.js` is the shared first part and its `loadSdk()` loads and runs this one, the Word editor itself. cell 32.4 MB, slide 28.3 MB |
| `fonts.wasm` | 3.6 MB | – | |
| `sdkjs/word/sdk-all-min.js` | 3.5 MB | 0.47 MB | the shared first part, despite its name; not minified either |
| `web-apps/.../code.js`, `app.css`, locale | 2.3 MB + 0.6 MB + 0.3 MB | 0.22 + 0.06 + ~0.05 MB | web-apps is an unbuilt RequireJS layout: hundreds of requests |
| 18 TTF fonts | 4.9 MB | not precompressed | |

- **Compression:** the frontend image already contains 1,080 `.br` files, but the stock `nginx:alpine` has no brotli module and `gzip_static` is off. Neither `nginx/nginx.conf` nor `frontend/docker/40-kutup-hosts.sh` has `gzip on`.
- **Edge to origin is HTTP/1.0:** the edge proxies to the frontend without `proxy_http_version`, and `gzip_static` only answers HTTP/1.1 by default.
- **No `Cache-Control` on the editor host:** browsers fall back to heuristic freshness and dozens of 304s. A private window re-downloads 64.8 MB on each open. Paths carry only `v9` and `dist/x2t/` has no version, so they cannot be marked immutable today.
- **The 7-second remount timer makes documents unopenable on slow links.**
  - `frontend/apps/editor/public/onlyoffice/inner.html:662` sets `APP_READY_TIMEOUT_MS = 7000`. An editor not ready after 7 s is destroyed and mounted again, which aborts the in-flight downloads (`net::ERR_ABORTED`). After three mounts it gives up.
  - On slow 4G it failed at 46.6 s with only 5.3 MB received. The timer also once stretched an unthrottled cold pptx open to 8 s.
- **The open is one long sequential chain.**
  1. Office links to the editor on the **Drive origin** (`apps/office/src/features/home/documents.ts`), so the browser does a cold Drive load.
  2. Session restore.
  3. Folders.
  4. A full listing of the document's folder (`FileEditorPage`).
  5. The versions list.
  6. The whole blob, downloaded into memory with axios `arraybuffer`.
  7. Decrypt (`crypto/src/fileBlob.ts:144-180`, about 3× the file size in peak memory).
  8. The lazy `OfficeEditor` chunk.
  9. The editor iframe.
  10. x2t load, compile and convert (`inner.html:824-855`).
  11. Only then `api.js`, web-apps and the SDK.

  None of the ~80 MB of editor assets depends on the document. Today's time is the data path **plus** the editor boot; it could be the **max** of the two.

### 1.2 Nothing is compressed anywhere

There is no gzip at the edge, none on the frontend nginx, and no compression layer in Axum. Production returned the Office JS as 1,917,596 bytes even when the request accepted gzip and br.

| Response | Raw | gzip -6 |
|---|---:|---:|
| Office main JS | 1.92 MB | 0.61 MB |
| crypto WASM | 1.28 MB | 0.47 MB |
| chat WASM | 9.3 MB | 2.8 MB (br 1.76 MB) |
| `GET /api/collections` (20 folders) | 20.8 KB | 8.3 KB |
| One file listing (41 files) | 44.1 KB | 17.7 KB |

### 1.3 App start-up code: heavier than it needs to be

| App | Start-up JS raw / br | Biggest avoidable parts |
|---|---|---|
| office | 1,873K / 470K (one chunk) | libsodium ~990K, bip39 212K |
| drive | 2,268K / 566K | libsodium, bip39, yjs |
| chat | 3,024K / 711K | libsodium, bip39, **livekit 508K** |
| photos | 3,116K / 737K | libsodium, bip39, **maplibre 940K** (static `PlacesPage` import in `App.tsx`) |
| maps | 3,080K / 731K | libsodium, bip39 |
| account | 1,101K / 287K | zod and admin pages |

- **libsodium-sumo** is in every app's start-up code except account, about 990K including a 520K base64-embedded WASM. Its WASM also initialises when the module is imported (`crypto/src/sodium.ts:3`).
- **bip39 with all 10 wordlists** reaches every app through the `packages/crypto/src/index.ts` barrel (`./mnemonic`). Only account and the KDF worker need it, and only the English list.
- **Drive and Maps load the 9.3 MB chat WASM at start.**
  - The path: `usePeople` → `loadPeople` → `ownLookup` → `loadChatWasm()`, only to compute `accountProfileKey` (`packages/drive-core/src/people.ts:94`).
  - Opening a document from Office therefore pulls the chat WASM on the Drive origin as well.
- **Large lazy chunks** (they load only when needed, but are worth trimming):
  - Excalidraw: 2.7 MB.
  - libheif: 1.9 MB, in 4 apps.
  - pdf.worker: 1.2 MB, in 4 apps.
  - The note editor: 1.1 MB, of which 646K is syntax grammars bundled together.
- **Rust WASM builds:**
  - The release profile is `opt-level = 2` (`Cargo.toml:108`), with no LTO and no wasm-opt.
  - The chat-core WASM keeps a 1.19 MB name section.
- **Source maps:** `sourcemap: true` publishes 85 MB of maps.

### 1.4 The same files, downloaded once per app hostname

- **Duplicated files:** each app hostname is its own origin and serves its own copy of the crypto WASM, chat WASM, libheif, pdf.worker, `cities.json` and the IBM Plex fonts. Identical files across the six origins total **67 MB raw / 15.5 MB br**.
- **Duplicated vendor code:** the shared vendor code (libsodium, React and so on) is bundled again in each app, about 1.6 MB per extra app.
- **WASM URLs:** they are fixed paths (`/crypto-wasm/...?runtime=2`) served `no-cache`, so every load revalidates them. Hashed `/assets/*` files are correctly `immutable`.

### 1.5 Serial round trips before anything shows

- **Session restore** (`session/src/childBoot.ts:64-83`, `persist.ts:154-199`) runs one request after another: `GET /auth/settings` → `POST /auth/refresh` (under a Web Lock) → `GET local-key` → crypto WASM JS and WASM (revalidated) → `GET /user/me`.
- **Then the Office home goes on to:** settings again plus ui-preferences, then `/collections` plus four sharing endpoints, then one listing per folder, then thumbnails.
- **Why warm visits still cost something:** the chain is 9–11 steps deep, so a warm visit takes 658 ms at 40 ms round-trip time and 2.25 s at 150 ms. Production's round-trip time from Turkey was about 84 ms, with time to first byte about 260 ms.
- **First paint** waits for the whole main bundle: 0.6–0.7 s at 40 Mbps, 10.5–12.9 s on slow 4G.
- **No Argon2 on restore:** it runs only at sign-in, about 150 ms, in a worker. The first Office open right after sign-in bounces through the account app (three page loads, about 14 serial round trips).
- **Production transport:** HTTP/2, no HTTP/3 (the module is built in but not enabled), no CDN and no `ssl_session_cache`. Upstreams are proxied through a variable, so there is no keepalive (a new HTTP/1.0 connection per request).

### 1.6 Everything is decrypted again on every visit

- **Office home:** one `GET /collections/:id/files` per readable folder (`documents.ts:228-283`), then every file record is opened, documents or not.
  - Each record costs 3 WASM calls, about 10 base64 conversions and 2 JSON parses, all on the main thread.
  - Measured cost is about 2.3 ms per document, or 4.7 ms at CPU 4×.
- **Request count:**
  - With 20 folders it was 21 listings, 40 thumbnail requests and 72 API calls in total, against 9 API calls for a 4-document account.
  - With 50 folders and 3,000 files, it works out to about 142 requests and over 9,000 WASM calls per visit.
- **What is cached:** only in-memory Maps and TanStack Query (`staleTime` 30 s). Nothing survives a reload, and each origin repeats all of it. The persisted catalog is Phase 4 of `16-browser-storage-architecture.md`, not done.
- **The editor page also lists the whole folder and all folders** to open one file (`FileEditorPage` `OpenFile`).
- **`deriveAccountIdentityKeys` runs once per owned folder** (`crypto/src/ownedCollection.ts:114`): 3 HKDFs and 3 key generations each time.
- **Render waste on the Office home:**
  - `documents` is a new array on every render, so the `useMemo` in `HomePage.tsx:400-403` never hits.
  - Every card fetches and decrypts the **large** thumbnail at once (`HomePage.tsx:346-361`), with no IntersectionObserver and no virtualization.
- **Invalidation fan-out:**
  - `useDriveMutation` invalidates six key families after any change.
  - The file-share poller (60 s) invalidates all `['files']`.
  - `useSharedFiles` makes one federation request per remote file share, and the Office home waits for all of them, so a slow remote server blocks it.

### 1.7 What is fine

- **API latency:** 1–5 ms per call (auth/settings 2 ms, collections 2–5 ms, a 41-file listing 2–5 ms, epochs 1 ms). The DB pool (16) and auth (one primary-key join) are fine.
- **Database:** no missing index on the list path.
- **Thumbnails:** already `private, max-age=31536000, immutable`.
- **Hashed app assets** are `immutable`.
- **Icons:** Lucide is tree-shaken (13–29K per app).
- **Duplication within an app** is negligible.

## 2. Improvements, ranked by effect for effort

Rough effect assumes 40 Mbps and production's ~85 ms round-trip time.

### Tier 1: configuration and build only (days, low risk)

1. **Serve compressed files.**
   - **Editor origin:** use a brotli-capable nginx (e.g. `fholzer/nginx-brotli` or an `ngx_brotli` build) with `brotli_static on`, or generate `.gz` siblings and turn on `gzip_static on`.
   - **App dists:** have Vite emit `.br` and `.gz` (e.g. `vite-plugin-compression2`) and serve them the same way.
   - **Dynamic responses:** `gzip on` at the edge for `application/json`, JS, CSS, `application/wasm` and SVG. Not for `application/octet-stream`, which is encrypted and incompressible.
   - **The HTTP/1.0 trap:** set `proxy_http_version 1.1;` at the edge, or `gzip_http_version 1.0;` at the origin.
   - **Effect:** cold .docx 89 MB → about 11–15 MB. Office home 3.5 MB → about 0.9 MB. Drive cold 13 MB → about 2.7 MB.
2. **Version and cache the editor assets.**
   - Serve OnlyOffice from a versioned path (`/onlyoffice/<fork-version>/…`, including `dist/x2t/`) with `Cache-Control: public, max-age=31536000, immutable`, and keep `inner.html` `no-cache`.
   - Load the crypto and chat WASM through Vite `?url` imports so they are content-hashed and immutable, instead of `no-cache` with `?runtime=`.
   - **Effect:** warm opens make about zero network requests, even after a browser restart (today 13.4 s warm in-session at 40 Mbps).
3. **Fix the 7-second remount.**
   - Measure progress, not wall time: restart the timer while x2t or the SDK is still downloading or compiling, or raise the limit to about 60 s once the iframe has signalled "loading assets".
   - Never abort downloads in flight.
   - **Effect:** documents open on 5–10 Mbps links at all (today they fail or take 72 s).
4. **Ship release builds of OnlyOffice in the `kutupbt/onlyoffice-editor` fork.**
   - Run Closure (or esbuild) over `sdk-all.js` for every editor; esbuild alone takes word from 28.7 MB to 14.1 MB / 2.52 MB br.
   - Minify `sdk-all-min.js` too: despite its name it is not minified (esbuild: 3.5 → 2.0 MB). Both files are needed; neither is a duplicate.
   - Build web-apps with grunt/r.js, so hundreds of module requests become a few.
   - Precompress the fonts.
   - **Effect:** about −30 MB raw per open, much less parse time, and fewer requests.
5. **Edge transport.**
   - Use `upstream` blocks with `keepalive 32` and HTTP/1.1 to upstreams.
   - Add `ssl_session_cache shared:SSL:10m`.
   - Enable HTTP/3 (`listen 443 quic` plus `Alt-Svc`).
   - **Effect:** a few ms locally, and fewer handshakes on mobile.
6. **Hide source maps** (`sourcemap: 'hidden'`) and stop shipping the unused woff fallbacks and `.d.ts` files.

### Tier 2: small code changes (days, low risk)

7. **Overlap the editor boot with the data path.**
   - As soon as `FileEditorPage` sees an office file name, import the `OfficeEditor` chunk and mount the iframe, or a hidden warm-up iframe. Post `init` when the bytes are ready.
   - In `inner.html`, start `api.js` and the SDK alongside `x2tConvert`, not after it.
   - Do not load x2t at all for PDFs.
   - Add `<link rel="preconnect">` to the editor and Drive origins on the Office home, and prefetch on hover.
   - Transfer `initialBytes`; it is cloned today.
   - **Effect:** open time becomes max(data, editor) instead of their sum; seconds on any link.
8. **Stop loading the chat WASM in Drive and Maps.**
   - Compute `accountProfileKey` lazily (on share, or when profiles are needed), or move it into the crypto WASM.
   - **Effect:** −9.3 MB raw / −1.76 MB br and about 9 MB of compile per Drive load, which includes every document open from Office.
9. **Trim start-up code.**
   - Remove libsodium from the start-up code (use the Rust crypto WASM, or lazy-load it): −990K per app.
   - Keep `mnemonic` out of the crypto barrel and ship only the English bip39 list: −212K per app.
   - Make Photos' `PlacesPage` lazy (maplibre −940K) and Chat's livekit lazy (−508K).
   - Split syntax grammars per language in the note editor (−550K).
10. **Shrink the Rust WASM.**
    - Use `opt-level = "s"` or `"z"`, `lto = true` and `codegen-units = 1` for the WASM crates.
    - Run `wasm-opt -Oz` and strip the name section in `scripts/build-crypto-wasm.sh` and `scripts/build-chat-wasm.sh`.
    - **Effect:** stripping alone is −1.19 MB on chat-core; likely another 20–30% from the rest.
11. **Parallelise session restore.**
    - Start `getCryptoWasm()` at module load, with `<link rel="modulepreload">` and a `preload as="fetch"` for the WASM.
    - Run the settings request alongside the refresh, and `/user/me` alongside opening the local state.
    - Cache `/auth/settings` (it is public: `Cache-Control: public, max-age=60`) and reuse it in `useDriveIdentity`.
    - Optionally have `/auth/refresh` return the local key and the profile, so restore is one request.
    - **Effect:** 2–3 fewer round trips per app load (about 150–400 ms on production).
12. **Office home render fixes.**
    - Memoise documents on `dataUpdatedAt`, as Photos' `library.ts` does.
    - Load thumbnails only when visible, and use `sm` in the grid.
    - Virtualize beyond a few hundred cards.
    - Render progressively instead of waiting for the slowest folder.
    - Take remote file shares out of the loading gate, or give them a timeout.
13. **Smaller fixes.**
    - Memoise `deriveAccountIdentityKeys` per master key, or pass the authority key in.
    - Invalidate only the keys a mutation touched.
    - Add `unicode-range` to the font faces and preload the regular woff2.

### Tier 3: structural (weeks, medium risk)

14. **One request for "my files" instead of one per folder.**
    - **(A) Cross-folder listing:** `GET /api/drive/files?cursor=` reuses the existing list query over owned and shared folders with keyset pagination. It ran in 1.1 ms on the test account and replaces about 22 requests. No migration.
    - **(B) Change feed:** `GET /api/drive/changes?cursor=` needs a `change_seq` column with an index, plus tombstones; about 1–2 days on the server. It is what (16) needs.
    - **(C) Without any server change:** refetch only folders whose `updatedAt` moved (check that deletes and moves bump it).
    - The server cannot filter "documents" (names are encrypted). Any kind hint would need a leakage review.
15. **An encrypted local catalog** (Phase 4 of `16-browser-storage-architecture.md`).
    - Store decrypted file and folder records sealed under a local store key in IndexedDB, filled by the change feed: show the cached copy, then revalidate.
    - Warm Office home, Drive and Photos would render from local data with about one request, and decrypt each record once per change instead of once per visit.
    - Ente does this (a local DB with `sinceTime` diffs); Proton uses an in-memory node cache fed by an events loop.
16. **A crypto worker with batch, byte-array APIs.**
    - Batch calls such as `openFileRecords(rows, key)` and `openOwnedCollections(rows)` that take `Uint8Array` instead of base64 per field.
    - Stream downloads with `fetch` plus `openFileBlobStreamV1` into a preallocated buffer in the worker, transferring the result.
    - **Effect:** no long tasks while lists load, 2–3× less marshalling, and a third of the peak memory when opening a file.
17. **One cache for the shared files.**
    - **Option A, a static origin:** serve WASM, libheif, pdf.worker, fonts and a common vendor chunk from one same-site origin, e.g. `static.kutup.dev`. Browsers key the HTTP cache by site (eTLD+1), so all `*.kutup.dev` apps would share one copy, saving about 1.5–2 MB br per extra app visited. It needs CSP (`script-src`, `connect-src`, `font-src`) and CORS changes, same-origin workers (or a blob shim), configurable WASM URLs, and a fallback for self-hosters on separate sites.
    - **Option B, a CDN:** put Cloudflare's proxy in front of `editor.kutup.dev` first (static, about 1.2 GB). Fronting the API hosts needs `CF-Connecting-IP` instead of the PROXY protocol, and uploads kept under 100 MB per request (`client_max_body_size` is 10G today). TURN must stay DNS-only.
18. **Serve the editor route on the Office origin too.** Office would keep its warm query cache and session when opening a document, instead of a cold Drive load.
19. **Cache converted documents.**
    - **The idea:** keep the x2t output per version id as an encrypted IndexedDB record, so a reopen skips x2t and its download.
    - **The longer route:** store documents in OnlyOffice's native binary format, as CryptPad does; then x2t is needed only for import and export.
20. **Downloads.**
    - Support `Range` (a `bytes=0-99` request returns the full 20 MB today), and serve versioned blobs as immutable.
    - Consider presigned R2 GETs behind a switch, so SeaweedFS deployments keep proxying. The comment in `storage.rs:8-10` no longer holds with R2. It needs CORS on R2 and a CSP change, and R2 would see client IPs: a policy call.

## 3. Suggested order and expected outcome

| Step | Items | Cold .docx at 40 Mbps | Warm .docx | Office home cold, slow 4G |
|---|---|---:|---:|---:|
| today | – | 19.5 s, 89 MB | 13.4 s in-session | 19.2 s |
| 1 | compression, editor caching, remount fix | ~4–5 s, ~12–15 MB | ~1.5 s | ~5–6 s |
| 2 | OnlyOffice release build, overlap the editor boot, no chat WASM on Drive | ~2–3 s | ~1.2 s | ~4 s |
| 3 | trimmed start-up code, parallel restore, render fixes | – | – | ~3 s |
| 4 | cross-folder listing, local catalog, crypto worker | – | – | flat with folder count; warm ≈ one request |

These are estimates scaled from the measured bytes and round trips. Remeasure after each step with the scripts in the scratchpad (`b-measure.spec.ts`, throttle profiles), and add the Office home and docx open to `perf-baseline` as tracked numbers.

## 4. Open questions

- **Upstream minifier:** the fork's OnlyOffice build may need upstream's Closure setup; check what produces `sdk-all-min.js`, which ships unminified.
- **CDN and R2:** a CDN or presigned R2 downloads change what third parties see (client IPs, timing). That needs a product decision, beyond performance.
- **Hosting split:** a shared static origin and a same-origin editor both affect self-hosters who put apps on separate sites; whichever is chosen needs a fallback.

## 5. How Proton handles the same problems

Read from the local WebClients clone (`kutup-references/WebClients`). Drive now runs on `@protontech/drive-sdk`, and neither it nor `@protontech/crypto` is in the clone. Where SDK internals matter, the in-repo legacy store (`applications/drive/src/app/legacy/store`, `packages/drive-store`) shows the same patterns.

| Kutup problem | What Proton does | Evidence (WebClients) | Take for Kutup |
|---|---|---|---|
| Office documents need a 36 MB converter on every open | .docx, .odt and .xlsx are converted **once, at import**, in pure JS inside the editor (docx-preview → Lexical; RowsnColumns for sheets). Documents then live as encrypted Yjs commits, so opening never converts. | `docs-editor/src/app/Conversion/*`, `CommitInitialConversionContent` | Long term: keep a native or cached converted state per version (§2 item 19). Short term: cache the x2t output per version in encrypted IndexedDB. |
| Editor starts only after the data path | The sandboxed editor iframe (its own origin, **no session**) renders immediately, in parallel with `DocLoader.initialize()`. Node, keys and commit are fetched with `Promise.all`, then the commit and the realtime token concurrently. | `docs/.../DocumentViewer.tsx:260,705`, `docs-core/lib/UseCase/LoadDocument.ts`, `FetchMetaAndRawCommit.ts` | §2 item 7: mount the editor early and fetch in parallel. |
| Everything decrypted again on every visit, nothing persisted | **Shared models** (user, settings, addresses) are persisted as encrypted Redux state in IndexedDB under the session ClientKey; thunks return the cache and refetch in the background (stale-while-revalidate). **Drive nodes are not persisted**: an in-memory SDK cache is fed by events. **Docs** caches node and document keys (localStorage) and raw commits (IndexedDB), encrypted, so reopening the same commit downloads nothing. | `account/persist/*`, `redux-utilities/asyncModelThunk/promiseStore.ts`, `docs-core/lib/Services/CacheService.ts` | A persisted encrypted state for boot models; a commit/blob cache for reopening documents; the catalog (§2 item 15) goes further than Proton. |
| Refetching lists after changes, plus polling | One **event loop** (`/events` cursor, 30 s, visibility-aware, Fibonacci backoff), shared by the app and the SDK. Events patch single nodes: rename updates the name, trash removes it, create or move fetches that one node. Legacy marks nodes stale and re-decrypts lazily. | `shared/lib/eventManager/eventManager.ts`, `drive/modules/busDriver/internal/BusDriver.ts`, `sections/folders/subscribeToFolderEvents.ts` | The change feed (§2 item 14B), with per-item patching instead of invalidating `['files']`. |
| Crypto on the main thread, one item per call | A **worker pool** behind `CryptoProxy`, sized to `hardwareConcurrency` (2–6 for Drive on Firefox), started lazily. Legacy decrypts in pages of 50, 5 concurrent, and deduplicates in-flight key decryption. | `shared/lib/helpers/setupCryptoWorker.ts`, `account/bootstrap/cryptoWorkerOptions.ts`, `legacy/store/_links/useLinks.ts` | §2 item 16: a crypto worker with batch APIs. |
| Big lists rendered at once | Listing streams through an async iterator, flushed to the store **every 30 ms**. Lists and grids are virtualized (`@tanstack/react-virtual`). Thumbnails are batched every 100 ms in chunks of 10, ordered by viewport distance, SD before HD, with an encrypted IndexedDB thumbnail cache (35 MB FIFO). | `sections/folders/useFolder.tsx`, `DriveExplorer/use*Virtualizer.ts`, `drive/modules/thumbnails/*` | §2 item 12, plus a persisted thumbnail cache. |
| Downloads through the server, whole file in memory | 4 MB blocks fetched **directly from storage servers** with a per-block token (`credentials: 'omit'`), in parallel, reassembled in order, at most 10 buffered. A byte-budgeted scheduler (40 MiB per file, 60 MiB total). Saves go to memory, then OPFS, then a streaming service worker; video uses SW Range serving or MSE. | `drive-store/store/_downloads/download/downloadBlocks.ts`, `modules/download/DownloadScheduler.ts`, `modules/fileSaver/*` | §2 item 20: Range support and presigned R2 GETs, plus streaming decrypt into a worker. |
| Session restore takes 5 serial round trips | Resume is **one parallel round** (`GET sessions/local/key` alongside `GET users`), then a local decrypt. Bootstrap fires user, settings, features and crypto-pool loading in parallel. The main UI chunk is `webpackPreload` with `fetchPriority: high`, loaded alongside auth. | `shared/lib/authentication/persistedSessionHelper.ts:82`, `drive/src/app/bootstrap.ts`, `drive/src/app/App.tsx:33` | §2 item 11: parallel restore and a preloaded main chunk. |
| Each subdomain re-downloads shared files | **Same as Kutup:** every app ships its own copies (`publicPath '/'`), with no shared static origin or CDN. | `packages/pack/webpack.config.ts` | Not an industry norm; a shared origin is an optional extra, not a must. |
| No compression or caching | No precompressed files from the build; compression is left to the server. HTML and `version.json` are `no-store`. Drive gives js/css a 14-day lifetime and wasm 30 days, all content-hashed under `assets/static/`. `version.json` polling reloads idle tabs after a deploy. | `applications/*/src/.htaccess`, `shared/lib/busy/busy.ts` | Kutup must at least compress at the server and hash and cache its WASM and editor files (§2 items 1–2). |
| Heavy start-up code | webpack 5 with swc, Terser with 5 compress passes, async-only `splitChunks`, workers excluded, `RetryChunkLoadPlugin`, SRI. Search and RAW WASM run lazily inside workers or SharedWorkers. | `packages/pack/webpack/optimization.js`, `plugins.js` | Lazy-load heavy WASM and libraries (§2 items 8–9). |
| No numbers to watch | **BundleMon** per app; sampled web vitals (5%); Drive page-load and data-load histograms (first item, first page, full list); a docs load histogram by update count; per-step performance marks. | `.bundlemonrc.json`, `packages/metrics/webvitals.ts`, `drive/modules/metrics/internal/drivePerformanceMetrics.ts` | Add a bundle-size check in CI and load-time marks (privacy-preserving, local-only or aggregate). |

**Where Proton is not ahead.** Compression, caching headers, CDN use and duplication across subdomains look much like Kutup's. Their advantages are in the data path:
- no converter on open;
- the editor loads in parallel with the data;
- a crypto worker pool;
- events instead of refetches;
- encrypted local caches for boot models, commits and thumbnails;
- block-wise direct-from-storage downloads;
- a one-round-trip session resume.

**The one place Proton is ahead on delivery** is that every asset is content-hashed and cached; Kutup's WASM and editor files are not.

## 6. Progress (branch `perf/web-performance`)

Measured with the same harness on the same local stack (in-memory browser
contexts unless "disk profile"; 40 Mbps / 40 ms unless noted).

| Page | Before | After Tier 1 | After Tier 2 |
|---|---:|---:|---:|
| .docx first open | 19.5 s, 89 MB | 4.7 s, 16.2 MB | 3.5 s, 15.4 MB (disk profile) |
| .docx second open | 13.4 s | 1.7 s | 1.8 s (disk profile; 1.5 s after a browser restart, 0.01 MB) |
| .docx at 5 Mbps | fails | 24.6 s | – |
| .docx on slow 4G | fails | 74 s | 80 s |
| Office home, first visit | 1.33 s, 3.54 MB | 0.84 s, 1.05 MB | 0.49 s, 0.70 MB |
| Office home, slow 4G | 19.2 s | 6.7 s | 4.3 s |
| Drive root, slow 4G | 21.5 s | – | 4.9 s |

Done:
- **Tier 1:**
  - **Compression:** gzip and brotli stored at build time and served as they are; the frontend image uses Alpine's nginx with the brotli module.
  - **Caching:** versioned OnlyOffice directories and content-hashed WASM, all immutable.
  - **Edge proxy:** HTTP/1.1 to the frontend, gzip for API JSON, TLS session cache.
  - **Remount timer:** the editor waits for quiet loading instead of a wall-clock 7 s.
  - **Source maps:** kept out of the image.
- **Tier 2:**
  - **Editor overlap:** `api.js` loads while the document converts; x2t is not loaded for PDFs; a hidden warm-up frame fetches x2t and the SDK while Drive downloads the document.
  - **Chat WASM:** not loaded when there is nobody to exchange profiles with, and otherwise only once the page is idle.
  - **Lazy loading:** libsodium, bip39, maplibre in Photos, livekit in Chat, and account's admin and recovery pages.
  - **Smaller WASM:** a `wasm-release` profile (LTO, one codegen unit) and stripped name sections: crypto 1.37 → 1.04 MB, chat 11.0 → 7.7 MB, Argon2 about 5% faster.
  - **Session restore:** in parallel (the WASM and the profile alongside the token, the server settings alongside the restore), and `/auth/settings` is fetched once per page.
  - **Office home:** the document list is memoised and previews load when visible.

Start-up JS per app, before → after: office 1,873 → 687 KB, drive 2,268 → 1,085 KB, chat 3,024 → 1,298 KB, photos 3,116 → 919 KB, maps 3,080 → 1,865 KB.

Tried and set aside (measured):
- **An encrypted local catalog of opened file records** (Phase 4 of
  document 16 without a change feed): 300 files in one folder loaded no
  faster with it, at normal speed or with the CPU slowed 4× (Drive about
  1.4 s of main-thread time either way). Opening a file record is not the
  cost at that size; rendering the rows is. It would also have kept
  decrypted file keys on disk. Not shipped; worth revisiting only with a
  change feed, for folders of thousands of files, after the render costs
  below.
- **Virtualized lists (done, as Proton Drive does).** Drive's list and grid
  and the Office home draw only the rows near the screen
  (`@kutup/ui/lib/shownRange`, TanStack Virtual against the window), the
  rest stood in for by empty space. Like Proton (`DriveExplorer`'s
  `useListVirtualizer` / `useGridVirtualizer`, `defaultConfig.overscan: 5`):
  always, whatever the count, with 5 rows drawn beyond the screen. Row height
  and the grid's columns are measured from what is drawn; End, Home and the
  arrow keys scroll to a row before focusing it; Ctrl+A still selects every
  item. With 300 files and the CPU slowed 4×: Drive 1.35 → 0.76 s of
  main-thread time (an empty Drive is 0.69 s), Office home ~1.0 → 0.66 s.
  Find in page only sees the rows drawn, as in Proton; Drive's own search
  covers the folder.
- **Render costs found instead:** every Drive row made four `Intl`
  formatters (about 1,200 per render of 300 rows, ~25 ms of formatting at
  normal speed, ~100 ms on a slow phone); they are now made once per locale
  and options.

- **The editor on the Office site (item 18, done).** Every document opens
  at `office.<domain>/file/…`, one address per file: notes and code, office
  documents, PDFs and whiteboards, whichever app they are opened from. Drive
  keeps photos, videos, audio and other files, and sends documents to Office;
  an old `drive.<domain>/file/…` link to a document is replaced by the Office
  one. The file page became a package (`@kutup/editors`) that both apps
  mount, loaded only when a file is opened. Opening from the Office home is
  now a navigation inside Office (its session, keys and query cache stay),
  not a cold start of Drive with its own restore. Start-up JS, gzip: Office
  228 → 219 KB, Drive 330 → 249 KB (the file page left Drive's start).
- **A minified OnlyOffice build (item 4), measured by swapping in a
  minified `sdk-all.js` and `sdk-all-min.js` on the local stack (medians of
  three rounds, disk profile):** first open 1.61 → 1.51 s unthrottled,
  4.96 → 4.76 s at 40 Mbps, 7.03 → 6.65 s at 40 Mbps with the CPU slowed 4×;
  second opens about 0.1 s faster. Main-thread time did not change (parsing
  is not the cost) and 1.14 MB less is downloaded compressed: about 3–6%.
  Left for the fork's release process rather than done here.

Still open:
- **OnlyOffice release build** in the fork (minified `sdk-all.js`, built web-apps): low value, see above.
- **Cross-folder listing and change feed**, the encrypted local catalog, a crypto worker, and a shared static origin or CDN (Tier 3).
- **HTTP/3:** needs UDP 443 open in the host firewall.
