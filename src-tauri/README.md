# Kutup Tauri 2 shell

**Status:** desktop shell implemented; retained Tauri-mobile targets are
experimental. The dedicated native iOS and Android apps are separate work in
progress and are not release-ready.

This directory wraps the React frontend in a Tauri 2 shell. Its supported
documentation entry point is [`../docs/desktop-build.md`](../docs/desktop-build.md).
For the mobile ownership boundary and binding workflow, see
[`../docs/mobile-build.md`](../docs/mobile-build.md) and
[`../docs/chat-native-bindings.md`](../docs/chat-native-bindings.md).

## Desktop development

Install the root package dependencies, then start the shell:

```sh
pnpm install
pnpm tauri:dev
```

The command starts Vite on `http://localhost:5173` and opens a native Tauri
window. Frontend edits hot-reload; Rust shell changes rebuild and restart the
window.

Build a host-platform installer with:

```sh
pnpm tauri:build
```

Artifacts are written under `src-tauri/target/release/bundle/`. Builds are
currently unsigned. The embedded build deliberately strips the multi-gigabyte
OnlyOffice SDK, so Office documents do not open in the desktop bundle; the web
deployment remains the complete Office surface.

## Layout

```text
src-tauri/
├── Cargo.toml            # standalone Rust crate and platform dependencies
├── tauri.conf.json       # bundle identity, window, build, and target settings
├── build.rs              # tauri-build hook
├── capabilities/         # scoped plugin permissions
├── icons/                # generated desktop/mobile icon inputs
└── src/
    ├── main.rs           # desktop entry point
    └── lib.rs            # plugin setup, vault commands, mobile entry point
```

The identifier and keychain service are `dev.kutup.client`; the installed
desktop executable is `kutup-client` so it does not collide with the `kutup`
CLI.

## Retained experimental mobile commands

The root package still exposes `tauri:ios:*` and `tauri:android:*` scripts.
They generate gitignored projects under `src-tauri/gen/` and are useful for
shell experiments, but they do not build the dedicated native apps and must not
be used as a mobile release-readiness claim. Current status and limitations are
kept in [`../docs/mobile-build.md`](../docs/mobile-build.md).

## Remaining desktop release work

- Apple and Windows code-signing/notarization configuration.
- Updater public key and signed update channel.
- Loading OnlyOffice assets securely from the selected homeserver instead of
  embedding them.
- Tauri session-persistence and installer acceptance coverage.
