// Kutup native shell entry point.
//
// Desktop builds run this from src/main.rs; mobile builds (iOS / Android) enter
// here directly via the `tauri::mobile_entry_point` attribute, which generates
// the platform-specific FFI symbols (`__cdecl _start_app` on iOS,
// `Java_app_tauri_..._start` on Android).
//
// Custom commands exposed to the frontend live below the `run()` function and
// are registered via `tauri::generate_handler![...]`.

// OS-keychain backend. Desktop-only — see Cargo.toml for the target gate.
// We re-export the keyring `Error` type so the command bodies below can use
// the `NoEntry` variant for "soft-miss" semantics (a missing key is not a
// failure for vault_get / vault_delete).
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use keyring::{Entry, Error as KeyringError};

// Service namespace under which all kutup secrets live in the OS keychain.
// Matches the bundle identifier so secrets don't collide with other apps
// and are visible under that name in Keychain Access / seahorse / etc.
const KEYRING_SERVICE: &str = "io.kutup.app";

// vault_set / vault_get / vault_delete — invoked from the frontend via
// `@tauri-apps/api/core::invoke()` to persist session secrets (access
// token, master key, private key) across app restarts.
//
// On mobile builds the keyring crate isn't available, so the commands
// return an error string; the JS side treats that as "vault unavailable"
// and falls back to the existing sessionStorage-only flow.

#[tauri::command]
async fn vault_set(key: String, value: String) -> Result<(), String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let entry = Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;
        entry.set_password(&value).map_err(|e| e.to_string())
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = (key, value);
        Err("vault unavailable on this platform".to_string())
    }
}

#[tauri::command]
async fn vault_get(key: String) -> Result<Option<String>, String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let entry = Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = key;
        Ok(None)
    }
}

#[tauri::command]
async fn vault_delete(key: String) -> Result<(), String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let entry = Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(KeyringError::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = key;
        Ok(())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // NOTE: tauri-plugin-updater is intentionally NOT registered here yet.
    // It requires `plugins.updater` config in tauri.conf.json (endpoint +
    // minisign pubkey), which we'll add once we have a signing key and
    // a release-artifact host. For now app launches without it.
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_process::init())
        .invoke_handler(tauri::generate_handler![
            vault_set,
            vault_get,
            vault_delete,
        ])
        .run(tauri::generate_context!())
        .expect("error while running kutup");
}
