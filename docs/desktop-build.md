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
the build on each (or wire CI matrices later).

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
Tauri Store plugin at `$APPDATA/io.kutup.app/kutup.dat`.

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
