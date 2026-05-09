# OnlyOffice in kutup

kutup uses a **CryptPad-pinned bundle** of OnlyOffice — not the upstream `@onlyoffice/document-server`. This doc explains the why, the layout, and the cost of the choice.

---

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
3. **Stripped server-required features** — spell-check, format-convert, callback URLs, telemetry. CSS hides upstream branding without source patches.
4. **Hooks for `getDoc` / `setDoc` / `saveChanges`** — entry points the host page uses to feed initial bytes in, get current bytes out, and react to changes.

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
│   │   │   └── spreadsheeteditor/      (.xlsx)
│   │   ├── sdkjs/
│   │   │   ├── word/   slide/   cell/
│   │   │   └── pdf/    visio/   ← runtime SDKs only; no editor UI app
│   │   ├── fonts/
│   │   └── dictionaries/
│   └── x2t/                    ← OOXML ↔ internal-binary converter (WASM)
├── inner.html                  ← postMessage bridge (kutup's host-side hooks)
└── templates/                  ← empty doc seeds for the New menu
```

**Versioning:** CryptPad numbers their bundles `v1`…`v9` independently of OnlyOffice's upstream version. `v9` corresponds to a specific OO upstream commit pinned in CryptPad's `install-onlyoffice.sh`.

**inner.html** is the kutup-specific glue: it loads the chosen editor app, talks to the OO instance via `postMessage`, and exposes hooks (`window.APP`, `getLock`, `saveChanges`, `oo-self`) that `OfficeEditor.tsx` wires through our envelope WebSocket.

---

## The cost: we ride CryptPad's cadence

We do not get OnlyOffice upgrades automatically. Specifically:

- **No PDF editor** — OnlyOffice 8.x ships a dedicated `pdfeditor` web-app. CryptPad's `v9` does not include it (the `sdkjs/pdf/` runtime is bundled but the UI app is not). Until CryptPad pulls pdfeditor into a future bundle, kutup PDFs stay in the read-only `PdfViewer.tsx` (pdf.js).
- **New OO features lag.** A feature shipped upstream in OO 8.3 lands in kutup whenever CryptPad next bumps. Their cadence is "every few months" historically.
- **Security patches** in OO that don't touch the patches CryptPad maintains can be hand-cherry-picked, but in practice we wait for the next CryptPad bundle.

This tradeoff is intentional. The alternative — maintaining a parallel patch set against upstream OO — would mean a permanent staffed maintenance cost. For a project of kutup's scale, riding CryptPad's cadence is right.

---

## When CryptPad ships a new bundle

The procedure (rough; not yet automated):

1. CryptPad publishes `vN+1` in `cryptpad/onlyoffice-builds`.
2. Pull their `dist/vN+1/` tree into `frontend/public/onlyoffice/dist/vN+1/`.
3. Update `inner.html` if their bridge contract shifted (rare but happens; check their `www/common/onlyoffice/inner.js` diff).
4. Update the editor-loader path in `inner.html` to point at `dist/vN+1/`.
5. Manual smoke test: open a `.docx`, `.xlsx`, `.pptx`, edit + save, two-tab collab, refresh. The Playwright office specs (`08–17`) gate this.
6. Bump the bundle path constant; commit.

We do **not** maintain forks of CryptPad's patches. If kutup ever needs a behavior CryptPad doesn't expose (e.g. PDF editing, custom export filters), the right move is to upstream a feature request to CryptPad rather than fork.

---

## Related

- [`docs/architecture.md`](architecture.md) — overall system & E2EE model.
- [`docs/research/05-cryptpad-onlyoffice-integration.md`](research/05-cryptpad-onlyoffice-integration.md) — deep code-level analysis of CryptPad's integration (May 2026 snapshot).
- [`docs/research/04-office-collab-engines.md`](research/04-office-collab-engines.md) — original engine-selection rationale.
- [`frontend/src/components/editors/office/OfficeEditor.tsx`](../frontend/src/components/editors/office/OfficeEditor.tsx) — host-side React wrapper.
- [`frontend/public/onlyoffice/inner.html`](../frontend/public/onlyoffice/inner.html) — postMessage bridge.
