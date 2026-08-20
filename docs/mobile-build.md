# Kutup mobile development (iOS / Android)

**Status:** work in progress; the native mobile apps are not release-ready.

Kutup's intended iOS and Android product apps are developed in the sibling
`kutup-ios` and `kutup-android` repositories. They use native Swift/Kotlin
presentation and platform security while consuming shared Rust Chat logic from
this repository through UniFFI. This repository does not build, test, sign, or
publish complete native mobile applications by itself.

The Tauri shell under `src-tauri/` still has compilable mobile entry points and
convenience scripts. Treat those targets as an experimental shared-web-shell
path, not evidence that the dedicated native apps have reached feature parity
or release readiness.

## What is ready in this repository

- `crates/kutup-chat-core` owns the shared libsignal/OpenMLS engine used by web
  WASM and native integrations.
- `crates/kutup-client-ffi` exposes the current Swift/Kotlin UniFFI boundary.
- `scripts/generate-native-bindings.sh` generates Swift and Kotlin bindings
  from the compiled library metadata.
- The responsive web application includes mobile layouts, but browser mobile
  UI and dedicated native apps are different delivery surfaces.
- `src-tauri/` can still initialize experimental iOS/Android wrapper projects.

The current FFI API is the phase-2b Direct Chat engine boundary documented in
[`chat-native-bindings.md`](chat-native-bindings.md). Native integration,
packaging, platform lifecycle, MLS/media/backup parity, store signing, and
device-level acceptance remain work in progress in the mobile repositories.

## Generate the native Chat bindings

Generation requires Rust 1.91.1 or newer and `protoc`. On Linux or macOS:

```sh
scripts/generate-native-bindings.sh /tmp/kutup-native-bindings
```

The output contains Swift source/header/modulemap files and Kotlin source. It
is a build artifact and is not committed here. Packaging those artifacts as an
XCFramework/Swift package or Android AAR is owned by the corresponding mobile
repository; see [`chat-native-bindings.md`](chat-native-bindings.md) for the
threading, SQLCipher, Keychain/Keystore, and backup-exclusion requirements.

## Experimental Tauri-mobile path

These commands exercise the retained Tauri wrapper, not the dedicated native
product apps:

```sh
pnpm install
pnpm tauri:ios:init       # macOS + Xcode required
pnpm tauri:ios:dev

pnpm tauri:android:init   # Android SDK + NDK required
pnpm tauri:android:dev
```

`src-tauri/gen/` is gitignored because the generated Xcode/Gradle projects
contain host paths and signing configuration. The scripts regenerate icons
from `src-tauri/icons/source.png` after initialization.

Known Tauri-mobile limitations include no Android keyring backend, no supported
mobile plaintext-export/share-sheet flow, no Office editor assets in the
embedded bundle, and no mobile release CI. These limitations do not define the
architecture of the dedicated native apps, but they mean the wrapper is not a
release candidate either.

## Server requirement

Every mobile client connects to a Kutup homeserver over HTTPS. A physical
device must trust the server certificate; the local self-signed Compose
certificate is not suitable unless its CA is deliberately installed on the
device. Use a publicly trusted certificate for normal development and all
release testing.

The product-wide application identifier is `dev.kutup.client`. Platform
signing, entitlements, backup exclusions, Keychain/Keystore access,
notification permissions, and store metadata must be finalized and verified
in the native repositories before either app is described as ready.
