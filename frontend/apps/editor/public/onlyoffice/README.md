# OnlyOffice integration assets

This directory holds the OnlyOffice client JS and x2t WASM
converter that power the `.docx` / `.xlsx` / `.pptx` collaborative
editor. The actual JS/WASM blobs use their applicable AGPL and file-level
Section 7 terms (built from Kutup's forks
[kutupbt/onlyoffice-editor][] and [kutupbt/onlyoffice-x2t-wasm][] of
CryptPad's builds); they
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
pnpm -C frontend dev:office
```

Normal Docker builds consume the immutable package produced by the
[Kutup office-assets repository][kutup-office-assets]. The Kutup app code
(TypeScript / React) lives in
`frontend/packages/editors/src/office/`; only the third-party
static assets land here. They are served from the office sandbox origin
(`editor.<domain>`, `pnpm -C frontend dev:editor` in development), which
holds no session or keys; Drive embeds `inner.html` from there.

[kutupbt/onlyoffice-editor]: https://github.com/kutupbt/onlyoffice-editor
[kutupbt/onlyoffice-x2t-wasm]: https://github.com/kutupbt/onlyoffice-x2t-wasm
[kutup-office-assets]: https://github.com/kutupbt/kutup-office-assets
