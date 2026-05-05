# Licensing note for `frontend/public/onlyoffice/`

Kutup is licensed under **AGPL-3.0-only** (see top-level [LICENSE](../../../LICENSE)). This subdirectory plus
`frontend/src/components/editors/office/` form the optional integration with the [OnlyOffice client editor](https://github.com/cryptpad/onlyoffice-editor) and carry the upstream's `AGPL-3.0-or-later` SPDX header so they can link the OnlyOffice client.

When you run `./install-onlyoffice.sh`, the script downloads:

- `dist/v9/web-apps/...` — OnlyOffice client (AGPL-3.0-or-later, [cryptpad/onlyoffice-editor](https://github.com/cryptpad/onlyoffice-editor))
- `dist/x2t/...` — x2t WASM converter (AGPL-3.0-or-later, [cryptpad/onlyoffice-x2t-wasm](https://github.com/cryptpad/onlyoffice-x2t-wasm))
- `templates/oo*_base.js` — empty document templates (AGPL-3.0-or-later, from [cryptpad/cryptpad](https://github.com/cryptpad/cryptpad))

These third-party assets are gitignored and never enter the kutup repository — operators opt in by running the install script. The kutup-authored bridge files (`inner.html`, `OfficeEditor.tsx`, etc.) ship in the repo with their `AGPL-3.0-or-later` SPDX header.
