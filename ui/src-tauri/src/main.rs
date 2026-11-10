// The window only. Everything about the network lives in the Go service (mistgate-clientd); this process never touches it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bridge;

use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(bridge::spawn(app.handle().clone()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![bridge::rpc])
        .run(tauri::generate_context!())
        .expect("the window could not start");
}
