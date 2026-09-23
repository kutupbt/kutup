# Licensing note for `frontend/public/onlyoffice/`

Kutup is licensed under **AGPL-3.0-only** (see top-level
[LICENSE](../../../LICENSE)). This subdirectory plus
`frontend/src/components/editors/office/` form the integration with the
[OnlyOffice client editor](https://github.com/cryptpad/onlyoffice-editor).
Kutup-authored integration files carry `AGPL-3.0-or-later` SPDX headers where
they link to the editor.

The normal Docker build copies these assets from the verified, digest-pinned
office-assets image. For non-Docker development, `./install-onlyoffice.sh`
downloads the same pinned inputs:

- `dist/v9/web-apps/...` — the CryptPad wrapper plus OnlyOffice-derived client
  code ([cryptpad/onlyoffice-editor](https://github.com/cryptpad/onlyoffice-editor));
- `dist/x2t/...` — the OnlyOffice-derived x2t WASM converter
  ([cryptpad/onlyoffice-x2t-wasm](https://github.com/cryptpad/onlyoffice-x2t-wasm));
- `templates/oo*_base.js` — empty document templates (AGPL-3.0-or-later, from [cryptpad/cryptpad](https://github.com/cryptpad/cryptpad))

Pinned OnlyOffice-derived source headers carry AGPLv3 Section 7 terms requiring
Appropriate Legal Notices and the original Product logo to remain present,
denying trademark rights, and identifying GUI/content material as CC BY-SA
4.0. See [ONLYOFFICE-ADDITIONAL-TERMS.md](ONLYOFFICE-ADDITIONAL-TERMS.md).
Kutup preserves the visible OnlyOffice logo and attribution.

Generated third-party assets remain outside Kutup Git. Exact license copies
are installed under `LICENSES/`, and exact versions, commits, and hashes are
maintained by
[`kutupbt/kutup-office-assets`](https://github.com/kutupbt/kutup-office-assets).
