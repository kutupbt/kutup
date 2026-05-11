# Kutup — Tauri 2 native shell

This directory hosts the cross-platform native shell that wraps the Vite
React app in `../frontend/`. One Rust+web codebase ships to five targets:
Windows, macOS, Linux, iOS, Android.

Strategy decision and reasoning lives in
`~/.claude/plans/read-all-docs-it-splendid-widget.md` (the plan doc).

## Quick prerequisites

| Target | What you need |
|---|---|
| Linux desktop | `rustup`, `webkit2gtk-4.1`, `gtk-3`, `libsoup-3` headers, `pkg-config` |
| Windows desktop | `rustup`, Visual Studio C++ Build Tools, WebView2 (auto-installed at runtime) |
| macOS desktop | `rustup`, Xcode Command Line Tools |
| Android | Android SDK + NDK + `cmdline-tools` + a `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android` |
| iOS | macOS host, Xcode, `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios` |

### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
rustc --version  # 1.77+
```

### Install node deps (from repo root)

```bash
pnpm install
```

That picks up `@tauri-apps/cli` from `package.json` so `pnpm tauri ...`
works without a global install.

## Desktop dev loop

```bash
pnpm tauri:dev
```

Spins up:
1. `pnpm -C frontend dev` → Vite on http://localhost:5173
2. Native Tauri window over that URL

Hot reload: anything you edit in `frontend/src/` reflects immediately.
Anything you edit in `src-tauri/src/*.rs` triggers a Rust rebuild +
window restart (~3–15 s depending on the change).

## Desktop release build

```bash
pnpm tauri:build
```

Outputs platform installers in `target/release/bundle/`:

- `.dmg` / `.app` on macOS
- `.msi` / `.exe` on Windows
- `.AppImage` / `.deb` / `.rpm` on Linux

Code-signing identities + the updater pubkey will go in `tauri.conf.json`
once we're ready to ship.

## Mobile initialization

First time only, per target:

```bash
pnpm tauri:android:init   # creates gen/android/
pnpm tauri:ios:init       # creates gen/apple/   (requires macOS)
```

Then iterate with:

```bash
pnpm tauri:android:dev    # builds + deploys to a connected device / emulator
pnpm tauri:ios:dev        # ditto for iOS sim
```

Release builds:

```bash
pnpm tauri:android:build  # .apk / .aab
pnpm tauri:ios:build      # .ipa (requires Apple Developer cert)
```

`gen/` is in `.gitignore` because it embeds absolute paths and signing
metadata — each contributor regenerates locally.

## Layout

```
src-tauri/
├── Cargo.toml            # Rust deps + crate metadata
├── tauri.conf.json       # Tauri 2 config (windows, bundle, plugins)
├── build.rs              # tauri-build hook
├── capabilities/
│   └── default.json      # permission grants per window
├── icons/                # generate via `pnpm tauri:icon <source.png>`
└── src/
    ├── main.rs           # desktop entry → calls lib::run()
    └── lib.rs            # shared entry incl. mobile_entry_point
```

## What's NOT here yet

- Real icons (placeholder is `icons/README.md`). Generate from a logo PNG via `pnpm tauri:icon`.
- Custom `#[tauri::command]` handlers. The shell is intentionally thin for v1; we'll add streaming-upload + folder-walk commands as they land.
- Updater public key (auto-update config goes in `tauri.conf.json` `plugins.updater` once we have a signing key).
- Code-signing config (Apple Developer + Windows EV cert + Linux GPG).
- App-store metadata.

## Reference repos

- [`spacedrive/apps/tauri`](https://github.com/spacedriveapp/spacedrive) — file-management precedent, lots of Tauri 2 idioms.
- [`padloc/packages/tauri`](https://github.com/padloc/padloc) — E2EE precedent (Tauri v1, useful for the thin-shell pattern).
