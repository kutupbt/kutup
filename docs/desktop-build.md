# Building the kutup desktop app

The desktop app is a Tauri 2 native shell wrapping the same React frontend
that powers the web. Build it locally with:

```bash
pnpm -C frontend install
pnpm tauri:build
```

Artifacts land in `src-tauri/target/release/bundle/`:

| Host OS  | Bundle types produced |
| -------- | ----------------------------- |
| Linux    | `.deb`, `.AppImage`, `.rpm`   |
| macOS    | `.dmg`, `.app.tar.gz`         |
| Windows  | `.msi`, `.exe` (NSIS)         |

The build cross-compiles only to the host OS — to ship all platforms, run
the build on each, or push a `desktop-v*` tag to run the `Release Desktop`
GitHub Actions workflow (`.github/workflows/release-desktop.yml`), which
builds Linux / macOS / Windows in a matrix and drafts a GitHub Release with
all the installers.

For the **iOS / Android** apps, see [`mobile-build.md`](mobile-build.md).

The bundled executable is named **`kutup-client`** (`mainBinaryName` in
`tauri.conf.json`), not `kutup` — the plain `kutup` name belongs to the CLI
(`crates/kutup-cli`), and a `.deb` shipping `/usr/bin/kutup` would clash with it.
The Cargo crate is still `kutup`; only the produced binary is renamed. The
bundle identifier is **`dev.kutup.client`** — applies to desktop + iOS +
Android (one ID for the whole product); it's also the OS-keychain service
name (`src-tauri/src/lib.rs`) and the suffix of the desktop app-data dir
(`$APPDATA/dev.kutup.client/`).

## Cutting a release

Releases are tag-triggered; the **tag is the source of truth for the
version** (the desktop workflow writes it into `tauri.conf.json` before the
build).

| What | CLI (`v*` → GoReleaser) | Desktop (`desktop-v*` → tauri-action) |
| --- | --- | --- |
| Stable | `git tag v0.1.0 && git push origin v0.1.0` | `git tag desktop-v0.1.0 && git push origin desktop-v0.1.0` |
| Prerelease | `git tag v0.1.0-alpha.1 …` | `git tag desktop-v0.1.0-alpha.1 …` |

A `-alpha.N` / `-beta.N` / `-rc.N` segment makes GitHub flag the release
**"Pre-release"** (so it's excluded from "Latest release") and, for the
desktop app, gets baked into the installer version
(`Kutup_0.1.0-alpha.1_amd64.deb`, …). Both workflows create a **draft**
release — review it on GitHub, then publish. (This is just the GitHub
prerelease *flag*; a real alpha auto-update *channel* would need
`tauri-plugin-updater` configured first — not done yet.)

## OnlyOffice is excluded from the desktop bundle

`tauri.conf.json`'s `beforeBuildCommand` runs `pnpm -C frontend
build:tauri`, which builds `dist/` and then deletes `dist/onlyoffice/`.
That directory is the ~2.6 GB OnlyOffice document-editor SDK (copied from
`frontend/public/onlyoffice/dist/`). `tauri::generate_context!()` embeds
**all** of `frontendDist` into the binary as a static byte array — embedding
2.6 GB OOMs `rustc` on any machine, so it has to go.

Consequence: **the desktop app cannot open `.docx` / `.xlsx` / `.pptx`
files in v1.** Everything else (Excalidraw, CodeMirror text/code editors,
file browse / upload / download, sharing, admin) works. The follow-up is
to point the OnlyOffice iframe at `${serverUrl}/onlyoffice/...` instead of
the relative `/onlyoffice/...` so the desktop app streams the SDK from the
user's kutup server — at which point it can be re-enabled without bloating
the binary. (`OfficeEditor.tsx` + the hardcoded paths in
`frontend/public/onlyoffice/inner.html` / `x2t.html` are the touch points.)

## Memory note for the build itself

The `kutup` shell crate is built at `opt-level = 1`
(`[profile.release.package.kutup]` in `src-tauri/Cargo.toml`) — `rustc`'s
peak memory const-evaluating the embedded bundle + the
`Builder::default()…run()` monomorphizations exceeds ~4 GB at the default
`opt-level = 3`. opt-level=1 roughly halves that; the shell crate is thin
glue so the perf cost is irrelevant. Deps stay at opt-level=3. The `[lib]
crate-type` is `["staticlib", "cdylib", "rlib"]` — `rlib` for the desktop
binary, `staticlib`/`cdylib` for Tauri Mobile's iOS/Android FFI tooling
(cargo only emits the ones a given build requests, so a desktop build still
produces just `rlib`).

## Linux prerequisites

```bash
sudo apt install -y \
  libwebkit2gtk-4.1-dev libssl-dev libgtk-3-0 libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev
```

The runtime `.deb` and `.AppImage` only depend on the user-space libs
declared in `src-tauri/Cargo.toml` (`libwebkit2gtk-4.1-0`, `libgtk-3-0`).

## Server URL prompt

On first launch the app shows a server-picker screen (Nextcloud / Mastodon
style). The user enters a kutup backend URL, the app probes
`GET ${url}/api/health`, and on success persists the choice via the
Tauri Store plugin at `$APPDATA/dev.kutup.client/kutup.dat`.

URL normalization:

- bare hosts get `https://` prepended
- `http://` is refused except for `localhost`, `127.0.0.1`, `::1`, `*.local`
- trailing slash is stripped
- malformed URLs are rejected before the probe fires

## Self-signed certificate caveat

Kutup's local development stack runs at `https://localhost:38443` with a
self-signed cert. The Tauri webview rejects this by default — there is no
"continue anyway" UX baked in.

Three workable paths during development:

1. **Real cert via tunnel.** Run [cloudflared](https://github.com/cloudflare/cloudflared)
   or [ngrok](https://ngrok.com) and point the desktop app at the tunnel
   URL (which has a trusted cert).
2. **OS trust store.** Generate the dev cert with `mkcert` (auto-trusts
   on macOS / Windows / Linux when the root CA is installed) and run the
   backend behind that.
3. **Plain http on localhost.** `http://localhost:38443` is allowed by
   the server-picker, and the webview accepts it. Skip TLS for local
   dev — tunnel-or-cert remains the production requirement.

For production deploys the server should serve TLS via a real certificate
(Let's Encrypt, Cloudflare, etc.) and the desktop app then "just works".

## OS keychain (restart persistence)

After a successful login the app stashes the access token + master key +
private key in the OS keychain so the next launch restores the session
silently. Profile data + server URL live in the Tauri Store-plugin file.

Per-platform backends:

| OS       | Backend                                |
| -------- | -------------------------------------- |
| Linux    | libsecret (gnome-keyring / KWallet)    |
| macOS    | macOS Keychain                         |
| Windows  | Windows Credential Manager             |

The Linux backend requires a Secret Service daemon at runtime. Headless
sessions without `gnome-keyring` or similar surface a one-time toast
*"Stay-signed-in is unavailable on this machine…"* and fall back to
re-login on every launch — the app keeps working, the convenience just
drops out.

Install on Debian / Ubuntu:

```bash
sudo apt install -y gnome-keyring libsecret-1-0
```

## CORS

Cross-origin Tauri requests need explicit origins, since `withCredentials:
true` (used for the refresh-cookie path) is incompatible with the wildcard
`AllowOrigins: "*"`. The backend reads an env-driven allowlist:

```bash
# default — covers the dev stack + Tauri's custom protocol origins
ALLOWED_ORIGINS="https://localhost:38443,tauri://localhost,http://tauri.localhost"
```

Add your production frontend domain (e.g.
`https://kutup.example.com`) to the comma-separated list when deploying.

## Smoke test

After a fresh `.AppImage`:

1. Launch → expect the server-picker screen.
2. Enter your backend URL → expect a redirect to `/login`.
3. Sign in → expect `/drive`.
4. Quit + relaunch → expect to land directly on `/drive` (vault restored).
5. Click "Sign out" → quit + relaunch → expect `/login` (vault wiped).
6. Click "Switch server" → expect the picker again with the input cleared.
