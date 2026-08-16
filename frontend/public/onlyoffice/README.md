# OnlyOffice integration assets

This directory holds the OnlyOffice client JS and x2t WASM
converter that power the `.docx` / `.xlsx` / `.pptx` collaborative
editor. The actual JS/WASM blobs use their applicable AGPL and file-level
Section 7 terms (sourced from
[cryptpad/onlyoffice-editor][] and [cryptpad/onlyoffice-x2t-wasm][]); they
are **not** committed to this repository.

For local frontend development without the normal Docker asset image, run from
the Kutup repository root:

```sh
./install-onlyoffice.sh
```

Set `KUTUP_ONLYOFFICE_ROOT` to install into a separate staging directory (for
example when preparing an air-gapped image) instead of modifying the frontend
public tree.

That populates `dist/v9/` (the editor) and `dist/x2t/` (the converter)
in this directory. Then rebuild the frontend:

```sh
docker compose up -d --build frontend
```

Normal Docker builds consume the immutable package produced by the
[Kutup office-assets repository][kutup-office-assets]. The Kutup app code
(TypeScript / React) lives in
`frontend/src/components/editors/office/`; only the third-party static
assets land here.

[cryptpad/onlyoffice-editor]: https://github.com/cryptpad/onlyoffice-editor
[cryptpad/onlyoffice-x2t-wasm]: https://github.com/cryptpad/onlyoffice-x2t-wasm
[kutup-office-assets]: https://github.com/kutupbt/kutup-office-assets
