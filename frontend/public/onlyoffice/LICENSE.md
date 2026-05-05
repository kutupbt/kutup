# Dual-license note for `frontend/public/onlyoffice/`

The kutup project is MIT-licensed (see top-level [LICENSE](../../../LICENSE)). This subdirectory is the exception: every file under

- `frontend/public/onlyoffice/`
- `frontend/src/components/editors/office/`

is licensed under **AGPL-3.0-or-later**, because together they form the optional integration with the AGPL [OnlyOffice client editor](https://github.com/cryptpad/onlyoffice-editor) and would not function without it.

When you run `./install-onlyoffice.sh`, the script also downloads:

- `dist/v9/web-apps/...` — OnlyOffice client (AGPL, [cryptpad/onlyoffice-editor](https://github.com/cryptpad/onlyoffice-editor))
- `dist/x2t/...` — x2t WASM converter (AGPL, [cryptpad/onlyoffice-x2t-wasm](https://github.com/cryptpad/onlyoffice-x2t-wasm))
- `templates/oo*_base.js` — empty document templates (AGPL, from [cryptpad/cryptpad](https://github.com/cryptpad/cryptpad))

These third-party assets are gitignored and never enter the kutup repository — operators opt in by running the install script. The kutup-authored bridge files (`inner.html`, `OfficeEditor.tsx`, etc.) ship in the repo with the AGPL license header.

If you fork kutup and disable / remove the office integration entirely (delete this directory and the `editors/office/` directory, drop the `chooseOfficeEditor` dispatch), the remainder of kutup remains MIT.
