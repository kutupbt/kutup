// Kutup native shell entry point.
//
// Desktop builds run this from src/main.rs; mobile builds (iOS / Android) enter
// here directly via the `tauri::mobile_entry_point` attribute, which generates
// the platform-specific FFI symbols (`__cdecl _start_app` on iOS,
// `Java_app_tauri_..._start` on Android).
//
// We keep this file thin: register plugins + run the builder. Custom Rust
// commands (streaming uploads, etc.) will live in dedicated modules and be
// pulled into `invoke_handler` below as they are added.

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
        .invoke_handler(tauri::generate_handler![])
        .run(tauri::generate_context!())
        .expect("error while running kutup");
}
