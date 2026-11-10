// The window only. Everything about the network lives in the Go service (mistgate-clientd); this process never touches it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("the window could not start");
}
