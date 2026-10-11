# Kutup mobile development (iOS / Android)

**Status:** not started. No native app code exists yet; the shared Rust
layer below is the only part built. Native work is deferred until the web
apps are done.

## Decision: one native app per product (2026-10-11)

There is no single "Kutup" mobile app. Each product ships as its own app,
as on the web (`drive.`, `chat.`, `mail.` …), the way Proton ships Proton
Mail, Proton Drive and Proton Pass separately:

- **Kutup Drive** (files; documents open in it as Office does on the web),
  **Kutup Chat** (messages, calls, meetings) and **Kutup Mail** (with
  Contacts and Calendar inside it, as Proton Mail has them) come first.
- **Kutup Photos** follows later (docs/plans/photos.md), and more may come,
  for example a password vault.
- **One repository per app**, covering both iOS and Android (for example
  `kutup-drive-mobile`; each is named when it is created). The
  `kutup-ios` and `kutup-android` repositories, created on 2026-09-23 and
  still empty, are retired, and with them the earlier plan of one
  repository per platform holding several app targets
  (docs/plans/multi-app-web-rewrite.md).
- Every app uses native Swift/Kotlin presentation and platform security and
  consumes the shared Rust logic from this repository through UniFFI
  (`kutup-client-ffi`, `kutup-chat-core`, `kutup-crypto`), so formats,
  crypto and protocol behaviour stay identical across apps and the web.
- Signing in once for all of them (an iOS keychain access group, an Android
  signature-protected provider) is planned, as Nextcloud does for Files and
  Talk.

This repository does not build, test, sign, or publish native applications
by itself.

## What is ready in this repository

- `crates/kutup-chat-core` owns the shared libsignal/OpenMLS engine used by web
  WASM and native integrations.
- `crates/kutup-client-ffi` exposes the current Swift/Kotlin UniFFI boundary.
- `scripts/generate-native-bindings.sh` generates Swift and Kotlin bindings
  from the compiled library metadata.
- The responsive web application includes mobile layouts, but browser mobile
  UI and dedicated native apps are different delivery surfaces.

The current FFI API is the phase-2b Direct Chat engine boundary documented in
[`chat-native-bindings.md`](chat-native-bindings.md). Native integration,
packaging, platform lifecycle, MLS/media/backup parity, store signing, and
device-level acceptance belong to each app's repository once it exists.

## Generate the native Chat bindings

Generation requires Rust 1.91.1 or newer and `protoc`. On Linux or macOS:

```sh
scripts/generate-native-bindings.sh /tmp/kutup-native-bindings
```

The output contains Swift source/header/modulemap files and Kotlin source. It
is a build artifact and is not committed here. Packaging those artifacts as an
XCFramework/Swift package or Android AAR is owned by each app's
repository; see [`chat-native-bindings.md`](chat-native-bindings.md) for the
threading, SQLCipher, Keychain/Keystore, and backup-exclusion requirements.

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
