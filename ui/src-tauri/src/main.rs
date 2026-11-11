// The window only. Everything about the network lives in the Go service (mistgate-clientd); this process never touches it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bridge;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, LogicalSize, Manager, PhysicalPosition, PhysicalSize, State, WindowEvent};

const TRAY_WIDTH: f64 = 372.0; // the design's quick panel (356) and a little air for its edge

struct Shell {
    close_to_tray: AtomicBool,
    // where the quick panel hangs: the tray icon's centre and top, in physical pixels
    anchor: Mutex<(f64, f64)>,
    // a click on the tray icon first takes the focus from the panel (which hides it): that click must not reopen it
    hidden_at: Mutex<Instant>,
}

fn show_main_window(app: &AppHandle, screen: Option<String>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        if let Some(screen) = screen {
            let _ = window.emit("mg://nav", screen);
        }
    }
}

fn place_tray(app: &AppHandle, shell: &Shell) {
    let Some(window) = app.get_webview_window("tray") else { return };
    let (centre, top) = *shell.anchor.lock().unwrap();
    let size = window.outer_size().unwrap_or(PhysicalSize::new(372, 560));
    let (mut x, y) = (centre - size.width as f64 / 2.0, top - size.height as f64 - 8.0);
    if let Ok(Some(monitor)) = window.current_monitor() {
        let (left, right) = (
            monitor.position().x as f64,
            monitor.position().x as f64 + monitor.size().width as f64,
        );
        x = x.min(right - size.width as f64 - 8.0).max(left + 8.0);
    }
    let _ = window.set_position(PhysicalPosition::new(x, y.max(0.0)));
}

/// The tray icon for the current state, drawn by the window from the design's glyphs, and its tooltip.
#[tauri::command]
fn tray_state(app: AppHandle, rgba: Vec<u8>, size: u32, tooltip: String) {
    let Some(tray) = app.tray_by_id("main") else { return };
    if rgba.len() == (size as usize) * (size as usize) * 4 && size > 0 {
        let _ = tray.set_icon(Some(Image::new_owned(rgba, size, size)));
    }
    let _ = tray.set_tooltip(Some(tooltip));
}

/// The quick panel reports its height (CSS pixels) after every change: the window is exactly the panel.
#[tauri::command]
fn tray_fit(app: AppHandle, shell: State<'_, Shell>, height: f64) {
    let Some(window) = app.get_webview_window("tray") else { return };
    let _ = window.set_size(LogicalSize::new(TRAY_WIDTH, height.clamp(120.0, 900.0)));
    place_tray(&app, &shell);
}

#[tauri::command]
fn shell_prefs(shell: State<'_, Shell>, close_to_tray: bool) {
    shell.close_to_tray.store(close_to_tray, Ordering::Relaxed);
}

/// Quitting the window. The VPN is the service's and stays as it is, unless the user chose "disconnect on exit":
/// the main window's page knows that choice, so it is asked to finish (it calls quit_now). If it does not answer,
/// quit anyway.
fn quit_app(app: &AppHandle) {
    if app.emit_to("main", "mg://quit", ()).is_err() {
        return app.exit(0);
    }
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(4));
        app.exit(0);
    });
}

#[tauri::command]
fn quit_now(app: AppHandle) {
    app.exit(0);
}

// The clipboard's text, read by the window itself when the user presses "use the link from the clipboard": the
// webview's own clipboard call shows a browser permission prompt. Capped: a subscription is never this long.
#[tauri::command]
fn clipboard_text() -> String {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
        use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
        const CF_UNICODETEXT: u32 = 13;
        const MAX_UNITS: usize = 1 << 20;
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return String::new();
        }
        let mut text = String::new();
        let handle = GetClipboardData(CF_UNICODETEXT);
        if !handle.is_null() {
            let data = GlobalLock(handle) as *const u16;
            if !data.is_null() {
                let mut len = 0;
                while len < MAX_UNITS && *data.add(len) != 0 {
                    len += 1;
                }
                text = String::from_utf16_lossy(std::slice::from_raw_parts(data, len));
                GlobalUnlock(handle);
            }
        }
        CloseClipboard();
        text
    }
    #[cfg(not(windows))]
    String::new()
}

#[tauri::command]
fn show_main(app: AppHandle, screen: Option<String>) {
    if let Some(tray) = app.get_webview_window("tray") {
        let _ = tray.hide();
    }
    show_main_window(&app, screen);
}

/// Start the window with Windows: the user's Run key. ponytail: reg.exe instead of a registry crate; the installer
/// may take this over.
#[tauri::command]
fn autostart(enabled: bool, minimized: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut command = std::process::Command::new("reg.exe");
        if enabled {
            let value = format!("\"{}\"{}", exe.display(), if minimized { " --minimized" } else { "" });
            command.args(["add", KEY, "/v", "Mistgate", "/t", "REG_SZ", "/d", &value, "/f"]);
        } else {
            command.args(["delete", KEY, "/v", "Mistgate", "/f"]);
        }
        let status = command.creation_flags(0x0800_0000).status().map_err(|e| e.to_string())?; // no console window
        // deleting a value that is not there is fine
        if !status.success() && enabled {
            return Err("the Run key could not be written".into());
        }
    }
    let _ = (enabled, minimized);
    Ok(())
}

/// One Mistgate per user session. A second start brings the first one's window up and leaves.
#[cfg(windows)]
fn already_running() -> bool {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow, ShowWindow, SW_SHOW};
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    // kept for the life of the process: the mutex is the mark
    unsafe { CreateMutexW(std::ptr::null(), 0, wide("Local\\net.mistgate.client").as_ptr()) };
    if unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
        return false;
    }
    // ponytail: found by its title; a named message would survive a renamed window
    let window = unsafe { FindWindowW(std::ptr::null(), wide("Mistgate").as_ptr()) };
    if !window.is_null() {
        unsafe {
            ShowWindow(window, SW_SHOW);
            SetForegroundWindow(window);
        }
    }
    true
}

fn main() {
    #[cfg(windows)]
    if already_running() {
        return;
    }
    tauri::Builder::default()
        .manage(Shell {
            close_to_tray: AtomicBool::new(true),
            anchor: Mutex::new((0.0, 0.0)),
            hidden_at: Mutex::new(Instant::now()),
        })
        .setup(|app| {
            app.manage(bridge::spawn(app.handle().clone()));

            // ponytail: English labels and the system's menu; the design's own menu is a panel like the quick one
            let open = MenuItem::with_id(app, "open", "Open Mistgate", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            let mut tray = TrayIconBuilder::with_id("main")
                .tooltip("Mistgate")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "open" => show_main_window(app, None),
                    "quit" => quit_app(app),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, rect, .. } = event else { return };
                    let app = tray.app_handle();
                    let shell = app.state::<Shell>();
                    let Some(window) = app.get_webview_window("tray") else { return };
                    if window.is_visible().unwrap_or(false) {
                        let _ = window.hide();
                        return;
                    }
                    if shell.hidden_at.lock().unwrap().elapsed() < Duration::from_millis(300) {
                        return;
                    }
                    let scale = window.scale_factor().unwrap_or(1.0);
                    let position: PhysicalPosition<f64> = rect.position.to_physical(scale);
                    let size: PhysicalSize<f64> = rect.size.to_physical(scale);
                    *shell.anchor.lock().unwrap() = (position.x + size.width / 2.0, position.y);
                    place_tray(app, &shell);
                    let _ = window.show();
                    let _ = window.set_focus();
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;

            // started by Windows with "start minimized": stay in the tray
            if !std::env::args().any(|a| a == "--minimized") {
                show_main_window(app.handle(), None);
            }
            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } if window.label() == "main" => {
                if window.state::<Shell>().close_to_tray.load(Ordering::Relaxed) {
                    api.prevent_close();
                    let _ = window.hide();
                } else {
                    api.prevent_close();
                    let _ = window.hide();
                    quit_app(window.app_handle());
                }
            }
            WindowEvent::Focused(false) if window.label() == "tray" => {
                let _ = window.hide();
                *window.state::<Shell>().hidden_at.lock().unwrap() = Instant::now();
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![bridge::rpc, tray_state, tray_fit, shell_prefs, show_main, autostart, quit_now, clipboard_text])
        .run(tauri::generate_context!())
        .expect("the window could not start");
}
