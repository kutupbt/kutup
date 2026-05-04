# Research: Self-hosted Collaborative Office-Doc Editing Engines

**Captured:** 2026-05-04
**Scope:** Comparison of production-ready engines for browser-based real-time collaborative editing of `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, `.odp`. Evaluated specifically for kutup's E2EE constraint.

**Conclusion (preview):** Only one path preserves E2EE — the **CryptPad pattern**: take only the OnlyOffice client-side JS + the `x2t` WASM converter, drop the OnlyOffice Document Server entirely, layer kutup's libsodium scheme on top. This is a multi-month integration project, not an off-the-shelf install. The user has chosen this path for kutup; details are in research file `05-cryptpad-onlyoffice-integration.md`.

---

## 1. OnlyOffice Document Server (Community Edition)

- **License.** AGPLv3 with mandatory branding-retention add-on terms (logo cannot be removed without a commercial license). The FSF ruled in April 2026 that the branding-retention terms violate AGPLv3 freedoms.
- **Native format.** OOXML is the core format. `.docx`, `.xlsx`, `.pptx` processed directly; ODF (`.odt`, `.ods`, `.odp`) converted to OOXML on open and back on save — ODF round-trip is lossy.
- **Self-host.** Official Docker image `onlyoffice/documentserver`. **Heavy:** ≥ 8 GB RAM (12 GB recommended); real-world idle 1–2 GB, climbing to 7–10 GB under load. Multi-GB container.
- **CE limits.** Hard-coded **20 simultaneous-connection cap** (one user × N tabs counts as N connections). Branding fixed.
- **Real-time collab.** Client-side rendering — full editor JS runs in browser, server coordinates via OT. Not tile-rendered.
- **E2EE posture.** OnlyOffice "Private Rooms" exist only in the Desktop Editors + Workspace combination, not via embedded Document Server. Inside the standard WOPI flow the **server reads document content in plaintext**.
- **Integration.** WOPI-like callback API (custom, not strict WOPI). Used by Nextcloud, ownCloud, Seafile, Moodle.

## 2. Collabora Online (CODE / COOL)

- **License.** MPL-2.0. No user/feature gating in source. Trademarks reserved.
- **Native format.** LibreOffice core ⇒ **ODF first-class native** (`.odt`, `.ods`, `.odp`). OOXML support is excellent. In-memory model is LibreOffice's, so OOXML is the converted side.
- **Self-host.** `collabora/code` Docker image. **Lighter than OnlyOffice:** docs say 1 GB + 100 MB/user; in practice ~500 MiB idle, ~10 MiB per active user. CODE image ~300 MB.
- **Real-time collab.** **Server-rendered tile architecture.** LibreOffice runs server-side (one `Kit` process per document, forked from a `ForKit`). Browser receives PNG/JPEG **tile images over WebSocket**, sends back keystrokes/mouse events. Server-authoritative; not OT or CRDT in the client sense — the server *is* the document.
- **E2EE posture.** **Fundamentally incompatible with E2EE.** Server must run LibreOffice over the plaintext file to render tiles. There is no client-only mode.
- **Active maintenance (2026).** Very active. Current release line is COOL 25.04.x.
- **Integration.** Strict **WOPI** protocol. Powers Nextcloud Office (richdocuments) and ownCloud.

## 3. LibreOffice Online (LOOL)

**Status May 2026.** Frozen 2020, sat in TDF's "attic" for 4+ years. **Revived in February 2026** ("a fresh start" announcement). **Not a product yet** — TDF says "may not be for months, even years." Source on GitHub but no usable build. Not a viable target today.

## 4. WebODF / Native Browser ODF Editors

- **WebODF.** AGPL JS library that renders ODF in the browser. Last meaningful commit ~6 years ago. **Effectively unmaintained.**
- A new NLnet-funded "browser ODF editor" project has a milestone in June 2026 but nothing shipped. **Not production-ready.**

## 5. Etherpad / EtherCalc

- **Etherpad** (`ether/etherpad-lite`). Collaborative HTML/text only — no docx/xlsx/pptx. v2.6.0 latest. Uses OT. Not office-grade.
- **EtherCalc.** Spreadsheet-only, currently being rewritten in TypeScript on Cloudflare Workers/Durable Objects. Limited to its own format.

Neither covers `.docx/.xlsx/.pptx/.odt/.ods/.odp`. Wrong category for this comparison.

## 6. CryptPad (the actual E2EE answer)

CryptPad is AGPLv3, takes only the **client-side** OnlyOffice JS (forked as `cryptpad/onlyoffice-builds`, `onlyoffice-editor`, `onlyoffice-x2t-wasm`), runs format conversion in browser via WASM, **does not run OnlyOffice Document Server**, and layers its own E2EE on top. Winter 2026.2.0 release brought OnlyOffice 9 client. **This is the architecture for kutup.**

---

## Comparison table

|  | OnlyOffice DS CE | Collabora Online | LOOL | WebODF | Etherpad/EtherCalc | CryptPad |
|---|---|---|---|---|---|---|
| License | AGPLv3 + branding (disputed) | MPL-2.0 | MPL-2.0 | AGPL | Apache-2.0 / CPAL | AGPLv3 |
| Native format | OOXML | ODF (LibreOffice core) | ODF | ODF | own | OOXML (client only) |
| Self-host RAM | 8–12 GB | 1 GB + 100 MB/user | n/a | n/a | tiny | ~OnlyOffice client only |
| Container | multi-GB | ~300 MB | n/a | n/a | small | small |
| Collab arch | Client editor + OT | Server tile render + WS | (LOOL legacy) | Client DOM | OT | CRDT/OT client-side, E2EE |
| ODF fidelity | Lossy | Excellent | (Excellent) | Limited | n/a | OnlyOffice-equivalent |
| OOXML fidelity | Excellent | Excellent | (Good) | None | n/a | Excellent |
| CE limits | 20 connections | None | n/a | n/a | None | None |
| **E2EE-compatible** | No (server reads content) | **No** (server runs LO) | No | Yes (client only) | No | **Yes** |
| Maintenance 2026 | Active, controversial | Very active (25.04) | Just revived, not usable | Dead | Active but wrong scope | Very active (2026.2.0) |
| Integration | Custom WOPI-ish | Strict WOPI | (would be WOPI) | embed | embed | full app |

---

## Decision for kutup

**Path B: CryptPad-style E2EE office editor** — fork the OnlyOffice client-side JS + `x2t-wasm`, drop the Document Server, layer libsodium on top. The user explicitly selected this on 2026-05-04 over the easier "Path A" (Collabora via WOPI, with office docs leaving the zero-knowledge boundary). E2EE is non-negotiable for kutup's value proposition.

Implementation specifics (file paths in CryptPad's repo, how `x2t-wasm` is wired, how OnlyOffice's OT messages are wrapped, performance limits) are documented in research file `05-cryptpad-onlyoffice-integration.md`.

---

## Sources

- [ONLYOFFICE/DocumentServer GitHub](https://github.com/ONLYOFFICE/DocumentServer)
- [DeepWiki: ONLYOFFICE Editions and Licensing](https://deepwiki.com/ONLYOFFICE/DocumentServer/3-editions-and-licensing)
- [ONLYOFFICE Community: 20-connection limit explained](https://community.onlyoffice.com/t/what-exactly-is-document-server-20-connection-limit/4481)
- [ONLYOFFICE Docs CE for Docker — system requirements](https://helpcenter.onlyoffice.com/docs/installation/docs-community-sys-reqs-docker.aspx)
- [ONLYOFFICE License FAQ](https://www.onlyoffice.com/license-faq)
- [FSF on OnlyOffice AGPL add-ons (Apr 2026)](https://news.slashdot.org/story/26/04/18/0417208/fsf-to-onlyoffice-you-cant-use-the-gnu-agpl-to-take-software-freedom-away)
- [ONLYOFFICE Private Rooms (E2EE Desktop)](https://www.onlyoffice.com/private-rooms)
- [Seald cryptography review of OnlyOffice E2EE plugin](https://www.seald.io/blog/cryptography-review-onlyoffice)
- [CollaboraOnline/online GitHub](https://github.com/CollaboraOnline/online)
- [Collabora Online MPLv2 terms](https://www.collaboraonline.com/terms/collabora-online-mplv2/)
- [Collabora Online Wikipedia](https://en.wikipedia.org/wiki/Collabora_Online)
- [DeepWiki: LibreOffice/online collaboration features](https://deepwiki.com/LibreOffice/online/3.4-collaborative-editing-features)
- [collabora/code Docker Hub](https://hub.docker.com/r/collabora/code)
- [Nextcloud forum: System requirements for Collabora Online](https://help.nextcloud.com/t/system-requirements-for-collabora-online/30694)
- [DeepWiki: Nextcloud richdocuments WOPI integration](https://deepwiki.com/nextcloud/richdocuments/2-wopi-integration)
- [The Register: LibreOffice Online dragged out of the attic (Mar 2026)](https://www.theregister.com/2026/03/02/libreoffice_online_deatticized/)
- [TDF blog: LibreOffice Online — a fresh start (Feb 2026)](https://blog.documentfoundation.org/blog/2026/02/24/libreoffice-online-a-fresh-start/)
- [WebODF GitHub](https://github.com/webodf/WebODF)
- [Etherpad releases (v2.6.0)](https://github.com/ether/etherpad-lite/releases)
- [audreyt/ethercalc GitHub](https://github.com/audreyt/ethercalc)
- [CryptPad GitHub](https://github.com/cryptpad/cryptpad)
- [CryptPad: OnlyOffice client-side fork (cryptpad/onlyoffice-builds)](https://github.com/cryptpad/onlyoffice-builds)
- [CryptPad issue #586 — OnlyOffice concerns / server-blind approach](https://github.com/cryptpad/cryptpad/issues/586)
- [Privacy Guides: CryptPad review (Feb 2025)](https://www.privacyguides.org/articles/2025/02/07/cryptpad-review/)
