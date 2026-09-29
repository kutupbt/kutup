# Kutup mobile development (iOS / Android)

**Status:** work in progress; the native mobile apps are not release-ready.

Kutup's intended iOS and Android product apps are developed in the sibling
`kutup-ios` and `kutup-android` repositories. They use native Swift/Kotlin
presentation and platform security while consuming shared Rust Chat logic from
this repository through UniFFI. This repository does not build, test, sign, or
publish complete native mobile applications by itself.

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
