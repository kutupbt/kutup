# OnlyOffice in kutup

**Status:** current. Office editing is included in the normal Compose frontend
build through a public digest-pinned asset image; ONLYOFFICE is credited in
the editor's "About this editor" notice (its logo is hidden, as 9.4's licence
allows).

kutup uses a **CryptPad-pinned bundle** of OnlyOffice — not the upstream `@onlyoffice/document-server`. This doc explains the why, the layout, and the cost of the choice.

---

> **Where it runs.** The editor's code runs in a frame on its own hostname,
> `editor.<domain>` (`KUTUP_EDITOR_URL`), which holds no session and no keys
> and which only Drive may embed. `office.<domain>` is a different thing: the
> Office home, a signed-in app that lists documents and opens them in Drive.

## Why pin to CryptPad's bundle

OnlyOffice upstream assumes a **server that reads document plaintext**:

- **DocServer converts OOXML ↔ internal binary on the server.** Every open and save round-trips through a Node-based converter. That converter must read the file content.
- **CommandService URL on a backend handles co-authoring, locks, and save callbacks.** Each editor session phones home to a service that brokers operations between peers, persisted via the same plaintext-readable database.
- **Spell-check, fonts, plugins, format-convert menus** all roundtrip plaintext to the server.

That model is **incompatible with kutup's E2EE invariant** — our backend is a pure ciphertext relay. Adopting upstream OO would force one of:

1. Decrypt files on the server (breaks E2EE).
2. Re-implement the entire OO server side as a JS-based, browser-resident shim (a year of work).

CryptPad already did option 2. They maintain a fork of OnlyOffice's `web-apps` repo (`cryptpad/onlyoffice-builds`) with these patches:

1. **Client-side x2t conversion** — the OOXML ↔ binary converter compiled to WebAssembly, loaded inside an isolated iframe. Replaces server-side conversion entirely.
2. **postMessage bridge replaces CommandService** — CryptPad's `inner.html` and `inner.js` (~3400 LOC) sit between the OO editor and the host page, brokering operations over `window.postMessage`. The host page (kutup, in our case) wires this bridge to its own transport — for us, our envelope-framed WebSocket relay.
3. **Stripped server-required features** — spell-check, format-convert, callback URLs, telemetry.
4. **Kutup presentation layer** — CSS removes selected stock chrome and unavailable controls without patching the editor source. It also hides the ONLYOFFICE logo (`#header-logo`): 9.4's licence no longer asks for it, and the attribution it does ask for is Kutup's "About this editor" notice.
5. **Hooks for `getDoc` / `setDoc` / `saveChanges`** — entry points the host page uses to feed initial bytes in, get current bytes out, and react to changes.

The total surface is **tens of thousands of lines of patches** to OnlyOffice's compiled JS. Building it from scratch on top of upstream OO would mean redoing that work, then re-doing it on every OO release.

By pinning to CryptPad's bundle, kutup inherits all the E2EE plumbing for free. We pay nothing per OO upgrade — we just sync to whichever bundle CryptPad ships next.

---

## What we ship

```
frontend/public/onlyoffice/
├── dist/
│   ├── v9/                     ← current bundle, CryptPad's 9th revision
│   │   ├── web-apps/apps/
│   │   │   ├── documenteditor/         (.docx)
│   │   │   ├── presentationeditor/     (.pptx)
│   │   │   ├── spreadsheeteditor/      (.xlsx)
│   │   │   └── pdfeditor/              (.pdf)
│   │   ├── sdkjs/
│   │   │   ├── word/   slide/   cell/   ← word's also runs the PDF editor
│   │   │   └── pdf/    visio/   ← PDF engine (drawingfile WASM), Visio runtime
│   │   ├── fonts/
│   │   └── dictionaries/
│   └── x2t/                    ← OOXML ↔ internal-binary converter (WASM)
├── inner.html                  ← postMessage bridge (kutup's host-side hooks)
├── templates/                  ← empty doc seeds for the New menu
├── LICENSES/                   ← exact third-party license texts
├── SOURCE.json                 ← immutable source coordinates and hashes
├── SBOM.spdx.json              ← SPDX 2.3 package inventory
└── FILES.sha512                ← whole-tree integrity manifest
```

**Versioning:** CryptPad numbers their bundles `v1`…`v9` independently of OnlyOffice's upstream version. Kutup builds them itself from its forks of CryptPad's build repositories, [`kutupbt/onlyoffice-editor`](https://github.com/kutupbt/onlyoffice-editor) and [`kutupbt/onlyoffice-x2t-wasm`](https://github.com/kutupbt/onlyoffice-x2t-wasm) (branch `kutup`), and releases them as `kutup-<version>.<n>`: currently `kutup-v9.4.0.131.3` (editor, with the PDF editor) and `kutup-v9.4.0.131.1` (x2t), **ONLYOFFICE 9.4.0**, pulled from ONLYOFFICE (`git subtree pull`) with CryptPad's changes carried over and Kutup's own (each fork's `MODIFICATIONS.md`; docs/plans/onlyoffice-default-bundling.md). Kutup follows ONLYOFFICE: CryptPad's `v9.3.2+` editor builds are based on Euro-Office, a separate fork of OnlyOffice, and are not merged.

**Licence terms (from 9.4):** ONLYOFFICE's `LICENSE` files add terms under AGPLv3 Section 7: keep notices and attribution, mark modified versions (with dates, as based on ONLYOFFICE by Ascensio System SIA), show Appropriate Legal Notices in the interface, no trademark rights, CC BY-SA 4.0 for non-code content. Kutup meets them with the forks' `MODIFICATIONS.md` (shipped in the asset package under `LICENSES/`) and the **About this editor** button in the office editor's header (`EditorNotice.tsx`), which names ONLYOFFICE and Ascensio System SIA as the original developer, says the version is modified, and links the licence, the additional terms and both forks' source. The editor's own ONLYOFFICE logo is hidden (not required from 9.4; decided 2026-09-28). Keep both notices in place when changing the editor (`frontend/apps/editor/public/onlyoffice/ONLYOFFICE-ADDITIONAL-TERMS.md`).

**inner.html** is the kutup-specific glue: it loads the chosen editor app, talks to the OO instance via `postMessage`, and exposes hooks (`window.APP`, `getLock`, `saveChanges`, `oo-self`) that `OfficeEditor.tsx` wires through our envelope WebSocket.

- **Theme:** the editor opens in ONLYOFFICE's classic light or its dark theme,
  following Drive's (`init` carries it); toggling Drive's theme switches it live
  (`oo-theme`, through ONLYOFFICE's own `Common.UI.Themes.setTheme`, a private
  API to re-check on each update). The document page stays white.
- **Failures:** a document the editor cannot open (a file with no PDF header in
  its first 1024 bytes, an unknown type, a startup error) is reported to Drive
  (`failed`), which shows why instead of the loading screen.
- **Content blockers:** uBlock Origin and browsers that build it in block any
  file named `Analytics.js`. ONLYOFFICE's editors wait for their (inert) module
  of that name, so the fork ships it as `common/UiEvents.js`. Keep file names
  that blockers match out of the bundle when updating it.

## PDFs

A PDF you may change (write access, on this server) opens straight in
ONLYOFFICE's PDF editor: annotate, fill in forms, change text and pages. One
you may only read, or on another server, opens in Drive's viewer. The PDF editor opens the raw PDF (no x2t on
the way in: its `drawingfile` WASM engine reads it) and routes straight to
`pdfeditor` (`document.isForm: false`; left undefined, `api.js` would ask
DocumentServer whether it is a form). Saving asks the editor for its
"compiled changes" (`DocumentRenderer.Save()`, a binary relative to the PDF
it opened) and x2t applies them to those bytes (`m_bFromChanges`, the
changes as `changes/changes0.bin` beside the original; `x2t.html`), writing
the edited PDF as a new version. PDF locks are object-shaped, like
spreadsheets'. CryptPad never shipped the PDF editor: its client-only
patches (no server-version or licence checks, no support links) are applied
to it in the editor fork.

## Collaboration sessions

ONLYOFFICE's edits name objects created during an editing session, so a tab
can only apply a peer's edits if it holds the same objects: the version the
session started from, plus every edit since. Kutup follows ONLYOFFICE's own
model (DocumentServer never hands a newcomer a newer save mid-session):

- The first tab to open a document (nobody editing it) claims the version it
  loaded as the session's **base** on the collaboration relay
  (`{"type":"base","versionId","seq"}`) and the log is trimmed up to it.
- A tab joining a live session is told the base; if it loaded a newer save
  it reopens from the base (`GET /api/files/:id/original` when the session
  began before the first save) and replays the log after it. Edits that
  arrive before its editor has authenticated are handed over as the
  document's initial changes (`getInitialChanges`), as DocumentServer does.
- Saving during a session creates a version (history, downloads,
  thumbnails) recording its log position, but trims nothing and does not
  move the base: nobody's editor reloads on save.
- Restoring an old version replaces the document for everyone: the
  restoring tab resets the base (`reset: true`) and the other open tabs
  reopen from it.
- The base lives with the relay's room and ends when the last tab leaves.

Before this, a tab replayed the whole log onto the latest save, and a tab
joining after a save could not apply edits made in an older session (checked
in a browser for .docx and PDF: save, keep editing, a second tab joins; and
restore while another tab is open). One unexplained failure was seen once in
about sixteen runs of the PDF two-tab test (the editing tab kept its edit
locally without sending it) and not reproduced since; watch for it.

## How the bundle is delivered

`docker compose up -d --build` requires no preparation step. The frontend
Dockerfile uses the public, static
[`kutupbt/kutup-office-assets`](https://github.com/kutupbt/kutup-office-assets)
image as a build-only stage, pinned by OCI digest. It overlays the verified
assets into `public/onlyoffice/` before Vite runs, and the final Nginx image
serves the complete editor same-origin. The asset image is not a service and
does not run in production.

In the image the client and x2t move to directories named for their versions
(`dist/kutup-v9.4.0.131.3/`, `dist/x2t-kutup-v9.4.0.131.1/`, from their
`.version` files) and the bridge pages are rewritten to match, so everything
under `/onlyoffice/dist/` is cached as immutable and a new asset image is a
new URL; the bridge pages themselves are `no-cache`. Every text file and WASM
is stored compressed (gzip and brotli) at build time and served as it is
(`frontend/docker/precompress.sh`, `brotli_static`/`gzip_static`): a cold
document open downloads about 16 MB instead of 89 MB
(docs/research/17-web-performance.md). In development (`./install-onlyoffice.sh`
and Vite) the directories keep their plain names (`dist/v9/`, `dist/x2t/`).

Opening a document overlaps its steps: while Drive downloads and decrypts the
file, a hidden `inner.html?warm=1&type=…` frame fetches x2t and the editor's SDK
into the browser cache (only what is not cached already); the bridge loads
`api.js` while x2t converts; and a PDF, which opens as itself, loads x2t only
when it is first needed (saving, thumbnails).

The bridge mounts the editor again if ONLYOFFICE's frame never reports ready
(a handshake race seen on warm reloads), but only after loading has gone quiet
for 7 s: on a slow link the SDK alone takes minutes, and an earlier version
that counted 7 s from the mount aborted those downloads and never opened the
document below about 10 Mbps.

The packaging repository pins immutable upstream commits and artifact hashes,
rejects unsafe archives, verifies required files and the complete output tree,
and publishes source metadata, licenses, modification notices, and an SPDX
SBOM. For local frontend work outside
Docker, run `./install-onlyoffice.sh`; this is a development fallback, not a
Compose prerequisite.

---

## Our forks, and CryptPad upstream

Kutup holds the OnlyOffice source it ships: the forks carry OnlyOffice's
`sdkjs`, `web-apps` and `core` (as git subtrees) with CryptPad's changes, and
Kutup's own changes go on their `kutup` branches. So Kutup can:

- fix or change the editor or converter itself, without waiting for CryptPad;
- take CryptPad's new bundles by merging their tags into `kutup`; and
- take OnlyOffice upstream directly (`git subtree pull`, as each fork's
  README says), for example the PDF editor, which CryptPad's `v9` does not
  include, or a security fix.

What it costs: every change is ours to build, test and carry across
updates. Each fork's `KUTUP.md` says how to build and release.

---

## Updating the editor or converter

1. Change the fork's `kutup` branch (a CryptPad tag merged in, an OnlyOffice
   subtree pull, or a Kutup change), build it (`make build`; x2t with
   `docker build`, see `KUTUP.md`) and release it as `kutup-<version>.<n>`
   with the source commit in the notes.
2. Update `assets.lock.json` in `kutupbt/kutup-office-assets` with the
   release's commit, artifact size and hashes, license inputs, and the new
   package version; update `install-onlyoffice.sh` to match.
3. Build and run the independent verifier locally; check that the licence,
   `MODIFICATIONS.md` and the editor's About notice still meet the licence's
   terms.
4. Update `inner.html` if the bridge contract shifted and update its editor path
   if the packaged directory changes.
5. Smoke-test `.docx`, `.xlsx`, and `.pptx` open/edit/save, two-tab collaboration,
   refresh, the logo staying hidden, and the About notice and its links.
6. Publish an AMD64/ARM64 OCI index, then update Kutup's Dockerfile to its exact
   digest and repeat the clean-clone Compose test.

---

## Related

- [`docs/architecture.md`](architecture.md) — overall system & E2EE model.
- [`docs/research/05-cryptpad-onlyoffice-integration.md`](research/05-cryptpad-onlyoffice-integration.md) — deep code-level analysis of CryptPad's integration (May 2026 snapshot).
- [`docs/research/04-office-collab-engines.md`](research/04-office-collab-engines.md) — original engine-selection rationale.
- [`frontend/apps/drive/src/features/editor/office/OfficeEditor.tsx`](../frontend/apps/drive/src/features/editor/office/OfficeEditor.tsx) — host-side React wrapper.
- [`frontend/apps/editor/public/onlyoffice/inner.html`](../frontend/apps/editor/public/onlyoffice/inner.html) — postMessage bridge.
