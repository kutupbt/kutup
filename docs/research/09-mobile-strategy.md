# Research: Mobile strategy — Tauri-mobile shell + native secure-storage plugins (forward-looking)

**Captured:** 2026-05-13
**Status:** Reasoning + plugin survey. iOS half shipped (`feat/ios-keychain`: `keyring`'s `apple-native` widened to cover iOS). Android half is the open follow-up — this note is the reasoning pinned down before whoever picks it up.
**Scope:** Two intertwined decisions about the mobile app — (a) which native shell layer we use (Tauri-mobile vs React Native vs Capacitor); (b) the Android secure-storage path now that iOS Keychain works.

---

## 1. What we're deciding

Two questions came up during the mobile bring-up and got deep-researched:

1. **"Should we make the mobile apps in React Native?"** — the question every "we've got a Tauri desktop, what about phones?" project asks. Prior art keeps surfacing: Spacedrive went RN+Expo, OneKeePass went a separate RN-ish repo.
2. **"Can we use our keychain approach for Android?"** — the desktop `vault_set/get/delete` commands wrap the `keyring` crate. iOS turned out to be a one-line cfg flip; Android has no `keyring` backend at all.

The two are entangled. RN-without-a-secure-storage-story is meaningless; choosing the shell layer changes which secure-storage primitives you can reach. Resolving them together also names what kutup's mobile app *is*: the same web app, wrapped in a thin native shell, with a small punch-list of native plugins for things the browser can't do.

---

## 2. Part 1: Native-shell layer — stay on Tauri-mobile

The blocker for any non-Tauri path is **kutup's editor stack is DOM-bound** by deep design choices:

- **Excalidraw** is a React **DOM** component. There is no React-Native build of it. (Excalidraw on mobile *is* "Excalidraw in a webview.")
- **CodeMirror 6** is DOM-based — its `EditorView` constructs DOM nodes and listens for DOM events.
- **Yjs** itself is portable, but its **editor bindings** (`y-codemirror.next`, `y-prosemirror`) bind to DOM editors.
- **OnlyOffice** ships a **browser** JS SDK and an HTML page (`/web-apps/apps/…`); CryptPad's pattern (which we follow per `docs/onlyoffice.md`) embeds the editor as an `iframe`, then trades OT operations through `postMessage`. No SDK exists for an RN context.
- **libsodium** is compiled to **WASM** for the frontend (`libsodium-wrappers`) — no RN-native build is currently in our pipeline.

Any "React Native kutup" still embeds a `react-native-webview` for every editor surface. At which point you've got two UI stacks, two crypto bindings, the Tauri shell↔webview bridge plus the RN bridge, and the webview is still there. *Worst of both worlds.*

### What an RN rewrite would actually cost

- Rewrite the entire UI in RN primitives — drive browser, share/federation flows, settings, sign-in/recovery, every dialog. None of `frontend/src/` carries over directly.
- Rebuild libsodium bindings for RN (or marshal everything across an FFI boundary).
- Maintain **`frontend/`** (web + desktop) **and** an RN app forever.
- The `frontend/src/crypto/` ↔ `cmd/kutup/internal/crypto/` mirror that CLAUDE.md already flags as a maintenance hazard balloons ×10 across a much bigger surface.

### Prior art — why Spacedrive and OneKeePass don't generalize to us

| Product | Mobile stack | Why their choice doesn't translate |
|---|---|---|
| **Spacedrive** (Tauri desktop) | **React Native + Expo**, separate codebase; the Rust core (a virtual filesystem) is shared via FFI. `expo-secure-store` for secrets. | Their core is **headless Rust** — there are no DOM-bound editors forcing a webview. They built a mobile UI from scratch because they had to; we don't. The dual-codebase burden is real and they've talked about it publicly. |
| **OneKeePass** (Tauri desktop) | **Separate mobile repo**; RN-ish UI + the same Rust KDBX engine via FFI. Native Swift (iOS Keychain) and Kotlin (Android Keystore) do the secure storage. | Same shape: headless engine + bespoke mobile UI. A password manager has no browser-only dependencies. |
| **Padloc** | Web Components + **Capacitor** (not Tauri-mobile, not RN). | Different framework, same *pattern* as Tauri-mobile (native shell + webview around a web app). Predates Tauri-mobile's maturity. |

The common theme: products that went RN have a headless native core and built a mobile UI from scratch by necessity. kutup has neither — the "core" is the web UI itself, and our crypto runs in the browser via WASM.

### Why Capacitor doesn't help us either

Capacitor wraps a web app in a native webview shell — same architectural pattern Tauri-mobile uses. Trading Tauri-mobile for Capacitor would replace a Rust shell with a Node-ier one for no architectural gain, while throwing away `src-tauri/` and the desktop pipeline that already builds on it. Capacitor is only the right answer if you've not yet committed to a desktop shell; we have.

### Decision

**Stay on Tauri-mobile.** Treat the mobile gaps as a finite punch-list of native plugins:

- Secure storage (Section 3 of this note).
- Downloads via the iOS share-sheet / Android Storage Access Framework (the desktop save-dialog + fs-write sink doesn't apply on mobile).
- Safe-area insets, system back gesture, larger touch targets in the drive view.

Each is bounded and ships independently. None of it justifies abandoning the shared frontend.

### When to reconsider

Only if "feels truly native on iOS/Android" becomes a hard product requirement (App Store positioning, native gestures everywhere). Even then the cheaper move is **Capacitor**, not RN, because Capacitor keeps the web UI. RN would be the choice only if we wanted to throw the web UI away, which we don't.

---

## 3. Part 2: Mobile secure-storage — iOS done, Android still needs a native plugin

### 3.1. iOS — already wired (`feat/ios-keychain`)

The `keyring` crate's `apple-native` backend is built on the `security-framework` crate, which targets **both macOS and iOS** — the same Security framework APIs (`kSecClassGenericPassword` via `SecItemAdd` / `SecItemCopyMatching` / `SecItemDelete`) exist on iOS. The previous "iOS stub" in `src-tauri/src/lib.rs` was a deliberate skip from when mobile was unplanned, not a technical limit.

What shipped on `feat/ios-keychain`:

- `src-tauri/Cargo.toml` — split the dep block. `tauri-plugin-updater` stays desktop-only (App Store / TestFlight / Play handle mobile updates, and the plugin doesn't compile for iOS/Android targets anyway). `keyring` widens to `cfg(not(target_os = "android"))`, so macOS + Windows + Linux + **iOS** all build the apple-native / windows-native / sync-secret-service backends.
- `src-tauri/src/lib.rs` — `vault_set`/`vault_get`/`vault_delete` cfg gates flip from `not(any(android, ios))` → `not(android)`. Android keeps its existing stubs (`vault_get` → `Ok(None)`, `vault_set` → `Err("vault unavailable…")`, `vault_delete` → `Ok(())`).

Verified on iPhone 17 Pro Simulator (iOS 26.5): the "Stay signed in unavailable" toast no longer fires; quit + relaunch lands directly on `/drive` (vault round-trip works).

**Real-device caveat:** the Simulator's keychain is permissive without an explicit `keychain-access-groups` entitlement. For TestFlight / App Store builds the entitlement should be present. Tauri can inject one via `tauri.conf.json`'s iOS bundle config — wire it up when we ship the first signed real-device build.

### 3.2. Android — no Rust crate covers it

The `keyring` crate has **no Android backend** and there's no equivalent Rust crate that covers Android Keystore. Anything that wants hardware-backed key storage on Android has to cross the JNI boundary.

#### Plugin survey

| Plugin / approach | What it is | Verdict for kutup |
|---|---|---|
| **`impierce/tauri-plugin-keystore`** | Kotlin (~56%) wrapping Android Keystore + Swift (~20%) wrapping iOS Keychain + a thin Rust bridge + JS API (`store()` / `retrieve()` / `remove()`). Android 9+ (API 28+), Tauri 2, Rust ≥ 1.77.2. | **Recommended.** Closest to standard prior art and exposes the same shape as our `vault_*` commands. **Caveat:** every `retrieve()` triggers Face ID / fingerprint / device-PIN (`setUserAuthenticationRequired`), so this is "unlock with biometrics," not silent stay-signed-in. For an E2EE app, arguably the *right* model — the master key sits behind biometrics. The plugin does no preflight, so pair with `tauri-plugin-biometric` for "is biometric enrolled?". |
| `lindongchen/tauri-plugin-keychain` | iOS Keychain Services + Android `AccountManager`. | **Avoid.** `AccountManager` is **not** hardware-backed secure storage — substantially weaker than Keystore-backed `EncryptedSharedPreferences`. |
| `ThatzOkay/tauri-plugin-secure-storage` | Newer multiplatform Tauri-2 keychain plugin. | Less battle-tested. Reasonable fallback if `impierce/tauri-plugin-keystore` regresses or its biometric-gating turns out to be a UX blocker. |
| **`tauri-plugin-stronghold`** (Tauri official) | Pure-Rust IOTA Stronghold encrypted vault; works on Android/iOS without any native-language code. | **Wrong primitive.** Stronghold is password-unlocked → chicken-and-egg for *silent* persistence. Useful only if we accept a "type a PIN to unlock kutup" UX, or derive the Stronghold password from another device-bound secret (which lands us back at this same problem). |
| **`tauri-plugin-biometric`** (Tauri official) | The Face ID / fingerprint / device-PIN prompt itself. Not storage. | Pair with `tauri-plugin-keystore` (or whatever Android backing). |
| Hand-rolled Kotlin Tauri plugin in `src-tauri/` | Wrap `androidx.security:security-crypto`'s `EncryptedSharedPreferences` (Android Keystore-backed master key) directly, expose Tauri commands matching `vault_*`. | Fallback if the impierce plugin doesn't fit, or if we want `setUserAuthenticationRequired(false)` for silent persistence at the cost of biometric protection. Most control, most code. |

#### Recommendation

When this is picked up, the path I'd take is **`tauri-plugin-keystore` + `tauri-plugin-biometric`**, with the existing JS contract (`vault_set` / `vault_get` / `vault_delete` in `src-tauri/src/lib.rs`) kept identical across desktop / iOS / Android. The frontend already handles missing-vault gracefully — `frontend/src/lib/sessionVault.ts` defines a `VaultUnavailableError` that turns into a "Stay signed in unavailable" toast — so the same code path covers "Android device with no biometric enrolled" without further work.

Trade-off accepted: an Android user with biometrics enrolled gets a Face ID / fingerprint prompt on app launch (to unlock the persisted session keys). For an E2EE drive that's the right UX — the master key never sits in plaintext storage. An Android user without biometrics falls back to re-login per launch (the same behaviour Linux gets when no Secret Service provider is running).

If silent stay-signed-in becomes a hard requirement, fall back to the hand-rolled Kotlin plugin with `setUserAuthenticationRequired(false)` — weaker but UX-consistent with desktop.

### 3.3. Why there's no first-party answer

Tauri's own Discussion [tauri-apps/tauri#7846] ("Is there any built-in safe storage API for securely storing secrets?") has been open since 2023 with no first-party answer. The official `store` plugin is convenience storage, not secure storage; `stronghold` is the closest official cross-platform secret store but is password-unlocked. Community plugins are how this gets solved today.

---

## 4. Cross-references

- **`docs/mobile-build.md`** — current-state how-to-build doc; lists "session persistence on Android" as a follow-up. After Android lands, that section gets rewritten.
- **`src-tauri/src/lib.rs`** — `vault_set` / `vault_get` / `vault_delete` commands and the cfg gates this note recommends modifying.
- **`src-tauri/Cargo.toml`** — the `keyring` dep block (now `cfg(not(target_os = "android"))`); the `tauri-plugin-updater` block (still desktop-only).
- **`frontend/src/lib/sessionVault.ts`** — `VaultUnavailableError` (line 57) and the `isTauri`-gated load/save flow that already handles "no vault" as graceful degradation.
- **`docs/onlyoffice.md`** — why the editor stack is DOM-bound (Section 2 above).

---

## 5. Sources

- [tauri-apps/tauri Discussion #7846 — "any built-in safe storage API?"](https://github.com/tauri-apps/tauri/discussions/7846) (open, no first-party answer)
- [impierce/tauri-plugin-keystore](https://github.com/impierce/tauri-plugin-keystore) — Android Keystore + iOS Keychain (Kotlin + Swift + Rust bridge)
- [lindongchen/tauri-plugin-keychain](https://github.com/lindongchen/tauri-plugin-keychain) — iOS Keychain + Android AccountManager (not recommended)
- [ThatzOkay/tauri-plugin-secure-storage](https://github.com/thatzokay/tauri-plugin-secure-storage) — multiplatform Tauri-2 keychain
- [Tauri Stronghold plugin](https://v2.tauri.app/plugin/stronghold/) — pure-Rust encrypted vault, password-unlocked
- [Tauri Biometric plugin](https://v2.tauri.app/plugin/biometric/) — Face ID / fingerprint / device-PIN prompt
- [Tauri Store plugin](https://v2.tauri.app/plugin/store/) — convenience storage (not secure)
- [OneKeePass desktop (Tauri)](https://github.com/OneKeePass/desktop) · [OneKeePass mobile (separate codebase)](https://github.com/OneKeePass/mobile)
- [spacedriveapp/spacedrive](https://github.com/spacedriveapp/spacedrive) — RN+Expo mobile, Tauri desktop
- [awesome-tauri](https://github.com/tauri-apps/awesome-tauri) — plugin and app inventory
- [`keyring` crate (crates.io)](https://crates.io/crates/keyring) — `apple-native` covers macOS + iOS; no Android backend
