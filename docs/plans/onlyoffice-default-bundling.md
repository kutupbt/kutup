# Default client-side OnlyOffice bundling

**Status:** implemented, merged, and clean-clone verified

**Written:** 2026-08-16

**Completed:** 2026-08-16; default bundling merged as `5601add`, and the
fresh-clone S3 credential correction found during acceptance merged as
`6db48b8`

**Scope:** make Kutup's existing CryptPad-shaped, client-only OnlyOffice editor
available in a clean source checkout through the normal Docker Compose build,
without vendoring its large generated assets in the Kutup Git repository or
introducing OnlyOffice DocumentServer

## Outcome

After the normal Kutup secret and TLS bootstrap, a clean checkout must support
`.docx`, `.xlsx`, and `.pptx` editing with:

```sh
docker compose up -d --wait
```

The frontend image must contain the pinned editor, x2t WASM converter, empty
document templates, applicable license texts, attribution, and exact source
coordinates. No download may occur when the container starts. The visible
OnlyOffice logo and attribution remain preserved.

This work does not add OnlyOffice DocumentServer. Document conversion and
editing stay in the browser so the Kutup server continues to handle only
ciphertext.

## Pinned-input audit

The current installer was audited against the immutable upstream objects below.
An upgrade changes the compliance and security input set and requires a fresh
audit; the license on a future upstream branch is not assumed to be the license
of these pinned artifacts.

### Editor

- release: `cryptpad/onlyoffice-editor` `v9.2.0.119+5`;
- source commit: `4fcd833d00b3ba9852165874533925c7db2c4c56`;
- archive size: `583548212` bytes;
- GitHub SHA-256:
  `3f4987af072ba18ad2543c82ada6e41e33a6f38b1ec5930f79b66d1afb7e0715`;
- installer SHA-512:
  `1f1184fb04cf72a7eb2a49a9740074b5419486c79e1fd713e1f8c09b8594a826050ae941fed6ac6a96807ba73cc751d7c807bd7e6b73de9e4f8e74cd5ed04cfa`;
- source license files: `LICENSES/AGPL-3.0-or-later.txt`,
  `sdkjs/LICENSE.txt`, and `web-apps/LICENSE.txt`;
- file-level headers in the pinned `sdkjs` source add AGPLv3 Section 7 terms:
  modified interfaces must retain Appropriate Legal Notices and the original
  Product logo, no trademark rights are granted, and identified GUI/content
  material is CC BY-SA 4.0; and
- packaging fact: the release Dockerfile zips only generated `web-apps`,
  `sdkjs`, fonts, dictionaries, and the CryptPad editor API. It does not put
  these license files in `onlyoffice-editor.zip`.

### x2t

- release: `cryptpad/onlyoffice-x2t-wasm` `v7.3+1`;
- source commit: `a9b92bc026dea7c2160fb31839ef74d58d9c3652`;
- archive size: `12072169` bytes;
- installer SHA-512:
  `ab0c05b0e4c81071acea83f0c6a8e75f5870c360ec4abc4af09105dd9b52264af9711ec0b7020e87095193ac9b6e20305e446f2321a541f743626a598e5318c1`;
- source license: `core/LICENSE.txt` (AGPLv3);
- file-level headers in the pinned x2t core carry the same original-logo,
  legal-notice, trademark, warranty, and CC BY-SA Section 7 terms; and
- packaging fact: `x2t.zip` contains only `x2t.js` and `x2t.wasm`, not the
  license text.

### Templates

- source: `cryptpad/cryptpad` tag `2025.6.0` resolved to immutable commit
  `ae5da10f8dad9d07a90751b8069f7ea101409a7c`;
- `oocell_base.js` SHA-512:
  `93be3572fa10c09be609f0bd78e7b77f20cb20a19761863db22935305489e33028b94e576eabe75d1f148463501c095dec86eb6cc68fed37ec95aece964f07ad`;
- `oodoc_base.js` SHA-512:
  `7e6f64972e6fff2a04454ea8534cee11dc00aba02a0b9e311a0e58742bd04320451bc3df192425fb81e2400ab9c0dff5428e5ae13020396cc869fdc3dae7b185`;
  and
- `ooslide_base.js` SHA-512:
  `8457790509b752e000de8996c3c1ea58f1784061fa3d010267212f668e8e04a9416eb2b4b8082d6c7776b3d09a0a20709db841aa97aaa7e532c685ecf3168c45`.

The locally installed template bytes matched that immutable commit exactly.
The previous installer downloaded from the movable tag name and did not check
the three template hashes; this implementation replaces that behavior with
immutable commit URLs and SHA-512 checks.

## License and attribution boundary

Kutup is `AGPL-3.0-only`; the pinned CryptPad editor wrapper identifies its
wrapper code as `AGPL-3.0-or-later`, while its bundled OnlyOffice-derived code
and the pinned x2t core carry AGPLv3 plus file-level Section 7 terms. Those
headers require the original Product logo and Appropriate Legal Notices to
remain present, deny trademark rights, and identify GUI/content material as CC
BY-SA 4.0. The exact pinned license texts and file-level notices are the
distribution inputs. Current or future license text on an unrelated upstream
branch must not silently replace them.

The packaging repository and image must:

1. include verbatim copies of every applicable license plus a durable record of
   the file-level ONLYOFFICE Section 7 notices;
2. publish the exact corresponding-source commits and a downloadable source
   archive or durable equivalent for the delivered artifacts;
3. expose the notices and source coordinates under the same `/onlyoffice/`
   static tree and from Kutup's third-party notices UI;
4. retain upstream copyright and SPDX notices;
5. preserve the visible OnlyOffice logo and attribution; and
6. be reviewed again before every input-version change.

This is an engineering compliance record, not a substitute for legal advice.

## Distribution architecture

### Separate source and packaging repository

Create the public repository `kutupbt/kutup-office-assets`. Do not name the
repository simply `onlyoffice`, do not present it as an official OnlyOffice
project, and do not commit generated editor binaries to Git.

The repository owns:

- a machine-readable lock manifest containing the versions, full commits,
  URLs, sizes, and hashes above;
- reproducible download, verification, layout, and validation scripts;
- Kutup-authored additions such as the no-op service-worker file;
- exact license texts, notices, source coordinates, and source-offer metadata;
- an SBOM and build provenance; and
- a release workflow that publishes a public static-asset OCI image to
  `ghcr.io/kutupbt/kutup-office-assets`.

The image is a data image, not a service. Its stable output contract is:

```text
/opt/kutup/onlyoffice/
  dist/v9/...
  dist/x2t/...
  templates/...
  LICENSE.md
  LICENSES/...
  LICENSES/ONLYOFFICE-ADDITIONAL-TERMS.md
  SOURCE.json
  SBOM.spdx.json
```

The audited package was published as
`ghcr.io/kutupbt/kutup-office-assets:2026.08.16-cryptpad-v9` and Kutup pins
the OCI index digest
`sha256:c3142b6f74a22f6c5db14256be59e9c160e25b77234b069c0cd889405f2bd8b3`.
Its platform manifests are
`sha256:4f4fc26ae75676192744358523af2a53b547d8f0b2fa23c0a36f9af2367575bb`
for AMD64 and
`sha256:84fb52a4536dd3ce6f9aa98f0aa2279509b0e9c43a8ed4089ee1783b529f2536`
for ARM64; both reference the same static asset layer.

Publish version tags for humans and pin every Kutup consumer by OCI digest.
Because the contents are static and architecture-independent, publish an OCI
index that is available to both AMD64 and ARM64 builders.

### Kutup frontend consumption

Use the asset image as a build-only stage in `frontend/Dockerfile` and copy
`/opt/kutup/onlyoffice/` into `frontend/public/onlyoffice/` before the Vite
build. The final frontend image remains self-contained and continues to serve
the editor same-origin from `/onlyoffice/`.

The default asset reference must be digest-pinned. A build argument may allow
maintainers to test a candidate digest, but production Compose and release
builds may not use `latest` or a tag without a digest.

Keep `install-onlyoffice.sh` as a development and air-gap preparation tool.
Refactor it to mirror the same immutable lock data, use immutable commit URLs,
verify all files, install license/source metadata, and support a caller-provided
destination. It must not be the normal Compose prerequisite.

Do not add a runtime installer container, a Git submodule, Git LFS assets, a
bind mount from the source checkout, or an OnlyOffice DocumentServer service.

## Implementation phases

### 1. Packaging repository

1. Create `kutupbt/kutup-office-assets` as a public repository with a clear
   unofficial-integration description.
2. Add the audited lock manifest and fail-closed verifier.
3. Assemble the stable output layout in a scratch/static OCI image.
4. Include licenses, notices, source metadata, SBOM, provenance, and OCI source
   labels.
5. Publish an immutable candidate image and record its digest.

### 2. Kutup build integration

1. Add the digest-pinned asset stage to `frontend/Dockerfile`.
2. Copy assets before `pnpm run build:web` without copying local gitignored
   assets into the build context.
3. Refactor the local installer to the same immutable coordinates and checks.
4. Update `.dockerignore`, `.gitignore`, README, self-hosting, contributing,
   OnlyOffice, and third-party-license documentation.
5. Change Office-file fallback messaging: a release image missing the required
   assets is a build/release defect, not a normal optional configuration.

### 3. Verification

Add a fast asset verifier that checks:

- pinned version markers and archive/file hashes;
- expected editor API, word, sheet, presentation, x2t, and template files;
- absence of archive residue and unexpected symlinks;
- license, notice, source, and SBOM files;
- the preserved visible OnlyOffice logo/attribution contract; and
- no network installation path in the final running container.

The release gate must build from a clean Git worktree that has no ignored
`frontend/public/onlyoffice/dist` or `templates` directory, start Compose, and
verify byte-serving for:

- `/onlyoffice/inner.html`;
- the editor API;
- x2t JavaScript and WASM;
- all three templates; and
- license and source metadata.

Then run the existing zero-retry browser coverage for document, spreadsheet,
and presentation creation/open/save/reload plus the two-browser collaboration
scenario. Reproduce these commands locally before spending hosted CI credits.

### 4. Upgrade and rollback

- Candidate upgrades are pull requests that update the source audit, lock
  manifest, asset-image digest, SBOM, notices, and browser evidence together.
- A version bump may not reuse an old license conclusion.
- Keep the previous immutable image digest available for rollback.
- Never replace an existing version tag or OCI digest.

## Acceptance criteria

- A clean checkout needs no manual `install-onlyoffice.sh` invocation for the
  normal Compose deployment.
- The frontend image is reproducible from immutable, hash-verified inputs.
- Generated assets do not enter Kutup Git history or a Git submodule.
- The running frontend makes no startup-time asset download.
- Applicable license texts, notices, attribution, and exact source coordinates
  ship with the editor and are accessible to users.
- The visible OnlyOffice logo and attribution remain preserved.
- Kutup's server never receives plaintext Office document content.
- DOCX, XLSX, and PPTX create/open/save/reload pass from a clean build.
- Two-browser encrypted collaboration passes without retry masking.
- AMD64 and ARM64 builds resolve the same logical asset version.

## Verification record

Completed locally on 2026-08-16 without a hosted CI run:

- the packaging verifier passed against the assembled asset tree;
- the published OCI index resolved anonymously after removing GHCR credentials;
- AMD64 and ARM64 manifests reference the same static asset layer;
- the frontend built from a context excluding local generated office assets;
- the final Nginx image returned HTTP 200 for the bridge, editor API, preserved
  logo SVG, x2t JavaScript/WASM, three templates, licenses, source manifest,
  SBOM, and whole-tree integrity manifest; and
- the frontend Vitest suite passed all 55 files and 350 tests;
- all 21 dedicated office Playwright tests passed locally with one worker and
  zero retries, covering DOCX/XLSX/PPTX creation and typing, reload, peer
  cursors, two-way edits, formatting, saves, version history, and restore;
- the simultaneous XLSX edit regression passed five consecutive zero-retry
  repetitions after durable per-file sequence allocation was serialized in
  PostgreSQL; and
- Playwright now uses full Chromium headless mode. The legacy standalone
  headless shell produced confirmed SIGTRAP crashes under the repeated nested
  canvas/worker load; the full 21-test matrix produced no new browser crash;
- a public `master` clone at merge commit `5601add` built the frontend without
  running `install-onlyoffice.sh`, resolved the pinned public GHCR digest, and
  passed the Dockerfile's required-file and version checks; and
- the clean-clone run exposed and fixed a pre-existing first-start credential
  mismatch: Compose now injects the configured S3 credentials into SeaweedFS,
  its initializer, and every backend. Default, named-volume, and dual-bucket
  federation initialization passed with the static credential file removed,
  the default stack reached full health, and a real XLSX edit/save browser
  smoke test passed with zero retries.

## Primary upstream references

- <https://github.com/cryptpad/onlyoffice-editor/tree/v9.2.0.119%2B5>
- <https://github.com/cryptpad/onlyoffice-x2t-wasm/tree/v7.3%2B1>
- <https://github.com/cryptpad/cryptpad/tree/2025.6.0/www/common/onlyoffice>
- <https://github.com/cryptpad/cryptpad/blob/main/install-onlyoffice.sh>
- <https://github.com/ONLYOFFICE/sdkjs>
- <https://github.com/ONLYOFFICE/web-apps>
