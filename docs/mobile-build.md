# Building the Kutup mobile apps (iOS / Android)

The mobile apps are the same [Tauri 2](https://tauri.app) shell + React frontend as the [desktop app](desktop-build.md), built for iOS and Android. The Rust side is already mobile-ready (`src-tauri/src/lib.rs` has the `tauri::mobile_entry_point`; `[lib] crate-type` includes `staticlib`/`cdylib`; `src-tauri/icons/{ios,android}/` are generated). What's left is `init`-ing the platform projects and building.

`src-tauri/gen/` (the generated Xcode / Android Studio projects) is **gitignored** — it contains absolute paths + signing config. You regenerate it locally with `tauri ios init` / `tauri android init`; don't commit it.

## Prerequisites

**iOS — needs a Mac.**
- Xcode + Command Line Tools (`xcode-select --install`), and an iOS Simulator runtime (Xcode → Settings → Components).
- For a real device or App Store build: an Apple Developer account — the signing team goes into the generated `gen/apple/` project (or you're prompted at `tauri ios init`). Simulator builds don't need it.

**Android — works on Linux, macOS, or Windows.**
- Android Studio (gives you the SDK + an emulator) *or* the command-line SDK tools, plus the **NDK**.
- Env vars: `ANDROID_HOME` (the SDK root) and `NDK_HOME` (the NDK root, e.g. `$ANDROID_HOME/ndk/<version>`). On macOS Android Studio puts the SDK at `~/Library/Android/sdk`; on Linux `~/Android/Sdk`.
- An emulator (AVD) or a device with USB debugging enabled.

Both also need the repo's normal toolchain: `pnpm install` (root, for the `tauri` CLI) and a Rust toolchain.

## iOS

```sh
pnpm tauri:ios:init     # one-time: creates src-tauri/gen/apple/ (the Xcode project)
pnpm tauri:ios:dev      # builds + runs in the iOS Simulator, hot-reloads the frontend
pnpm tauri:ios:build    # release build → .ipa under src-tauri/gen/apple/build/
```

`tauri ios dev --open` opens the project in Xcode if you want to run on a device / tweak signing there.

## Android

```sh
pnpm tauri:android:init   # one-time: creates src-tauri/gen/android/ (the Gradle project)
pnpm tauri:android:dev    # builds + runs in an emulator / connected device
pnpm tauri:android:build  # release build → .apk / .aab under src-tauri/gen/android/app/build/outputs/
```

## v1 limitations

- **No session persistence on mobile.** The OS-keychain vault (`vault_set/get/delete` in `src-tauri/src/lib.rs`) is desktop-only — the `keyring` crate has no Android backend, and the iOS path isn't wired yet — so the commands are stubs on mobile and you re-pick your server + re-login on every launch. (Follow-up: iOS Keychain via `keyring`'s `apple-native`; Android Keystore via a small native plugin.)
- **Downloads aren't wired for mobile.** The desktop download path uses a native "save as" dialog + filesystem write, which doesn't map to mobile's sandboxed FS / share-sheet model — file downloads will fail (gracefully, with an error toast) on iOS/Android for now. Everything else works: server-picker → login → browse, upload, the notes/code editor, Excalidraw whiteboards, sharing. (Follow-up: route through the iOS share sheet / Android Storage Access Framework.)
- **No mobile release CI yet.** Mobile builds are local for now; a `release-mobile.yml` (macOS runner + signing/provisioning for iOS, a keystore for Android) is a follow-up like `release-desktop.yml`.

The bundle identifier is `dev.kutup.client` (shared with desktop — it becomes the iOS bundle ID / Android package name); `productName` is `Kutup`.

## Server requirement (same as desktop)

The app talks to a Kutup server over HTTPS — the server must serve a certificate the device already trusts (a self-signed cert won't work). Plain `http://` is only accepted for `localhost`-class hosts, which isn't useful from a phone — use a real cert or a tunnel.
