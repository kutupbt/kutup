# OnlyOffice integration assets

This directory holds the optional OnlyOffice client JS and x2t WASM
converter that power the `.docx` / `.xlsx` / `.pptx` collaborative
editor. The actual JS/WASM blobs are AGPL-3.0-or-later (sourced from
[cryptpad/onlyoffice-editor][] and [cryptpad/onlyoffice-x2t-wasm][]); they
are **not** committed to this repository.

To enable OnlyOffice editing, run from the kutup repo root:

```sh
./install-onlyoffice.sh
```

That populates `dist/v9/` (the editor) and `dist/x2t/` (the converter)
in this directory. Then rebuild the frontend:

```sh
docker compose up -d --build frontend
```

The kutup app code (TypeScript / React) lives in
`frontend/src/components/editors/office/`; only the third-party static
assets land here.

[cryptpad/onlyoffice-editor]: https://github.com/cryptpad/onlyoffice-editor
[cryptpad/onlyoffice-x2t-wasm]: https://github.com/cryptpad/onlyoffice-x2t-wasm
