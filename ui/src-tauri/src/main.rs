// The window only. Everything about the network lives in the Go service (mistgate-clientd); this process never touches it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#![cfg_attr(feature = "setup", allow(dead_code, unused_imports))]

mod bridge;
#[cfg(all(feature = "setup", windows))]
mod setup;

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
    // a subscription link handed over by a mistgate:// link, until the window takes it
    link: Mutex<Option<String>>,
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

// The subscription page, in the user's browser, and a Telegram proxy link. Only an https address: the window passes
// what the service keeps.
#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    if !url.starts_with("https://") || url.len() > 4096 || url.chars().any(|c| c.is_control() || c == '"') {
        return Err("not an https address".into());
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let verb = wide("open");
        let open = |address: &str| ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), wide(address).as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL) as usize > 32;
        // A Telegram proxy link goes to Telegram itself, which then offers to connect; as a web address it is only a
        // page with a button. No Telegram on this PC: the page, as before.
        if let Some(proxy) = url.strip_prefix("https://t.me/proxy?") {
            if open(&format!("tg://proxy?{proxy}")) {
                return Ok(());
            }
        }
        open(&url);
    }
    Ok(())
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

// "Add .exe" on the Routes screen: Windows' own file dialog, programs only. Async, so the dialog's loop does not hold
// the window's. Empty when the user cancels.
// A Windows notification from the window's own watcher (Settings > Notifications). Plain text, capped. A press on it
// opens the main window. The toast is Windows' own, under the installed app's identity (its Start menu shortcut); a
// build run from the target folder has none and borrows PowerShell's, as the Tauri plugin does.
// ponytail: the press is heard only while this process lives and the toast is still its own; one pressed later in the
// notification centre starts nothing. Upgrade = a COM activator registered by the installer.
#[tauri::command]
fn notify(app: AppHandle, title: String, body: String) -> Result<(), String> {
    use tauri_winrt_notification::Toast;
    let short = |text: String, max: usize| text.chars().filter(|c| !c.is_control()).take(max).collect::<String>();
    let dev = std::env::current_exe().ok().and_then(|exe| exe.parent().map(|dir| dir.ends_with("target/debug") || dir.ends_with("target/release"))).unwrap_or(false);
    let id = if dev { Toast::POWERSHELL_APP_ID.to_string() } else { app.config().identifier.clone() };
    Toast::new(&id)
        .title(&short(title, 80))
        .text1(&short(body, 240))
        .on_activated(move |_| {
            show_main_window(&app, None);
            Ok(())
        })
        .show()
        .map_err(|_| "the notification could not be shown".to_string())
}

// A program's own icon for its tile on the Routes screen: the picture Windows shows for the exe, as raw pixels the
// window draws itself: width and height (two bytes each, little end first), then RGBA rows. Empty: no icon.
// ponytail: Windows' "large" size (32 px at 100%); sharper = SHGetImageList's 48 px list.
#[tauri::command]
async fn app_icon(path: String) -> tauri::ipc::Response {
    tauri::ipc::Response::new(icon_pixels(&path).unwrap_or_default())
}

#[cfg(not(windows))]
fn icon_pixels(_: &str) -> Option<Vec<u8>> {
    None
}

#[cfg(windows)]
fn icon_pixels(path: &str) -> Option<Vec<u8>> {
    use windows_sys::Win32::Graphics::Gdi::{DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS};
    use windows_sys::Win32::UI::Shell::ExtractIconExW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};
    if !path.to_ascii_lowercase().ends_with(".exe") || path.len() > 512 || path.chars().any(|c| c.is_control()) {
        return None;
    }
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    unsafe {
        // the exe's own first icon, read from the file: the shell's way (SHGetFileInfo) needs COM on the calling thread
        let mut icon = std::ptr::null_mut();
        if ExtractIconExW(wide.as_ptr(), 0, &mut icon, std::ptr::null_mut(), 1) == 0 || icon.is_null() {
            return None;
        }
        let mut info: ICONINFO = std::mem::zeroed();
        let mut out = None;
        if GetIconInfo(icon, &mut info) != 0 {
            let mut shape: BITMAP = std::mem::zeroed();
            if !info.hbmColor.is_null() && GetObjectW(info.hbmColor as _, std::mem::size_of::<BITMAP>() as i32, &mut shape as *mut _ as _) != 0 {
                let (w, h) = (shape.bmWidth, shape.bmHeight);
                if w > 0 && h > 0 && w <= 256 && h <= 256 {
                    let mut header: BITMAPINFO = std::mem::zeroed();
                    header.bmiHeader = BITMAPINFOHEADER { biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32, biWidth: w, biHeight: -h, biPlanes: 1, biBitCount: 32, ..std::mem::zeroed() };
                    let mut pixels = vec![0u8; (w * h * 4) as usize];
                    let screen = GetDC(std::ptr::null_mut());
                    let rows = GetDIBits(screen, info.hbmColor, 0, h as u32, pixels.as_mut_ptr() as _, &mut header, DIB_RGB_COLORS);
                    ReleaseDC(std::ptr::null_mut(), screen);
                    if rows == h {
                        let opaque = pixels.chunks_exact(4).all(|p| p[3] == 0); // an old icon without an alpha channel
                        for p in pixels.chunks_exact_mut(4) {
                            p.swap(0, 2); // BGRA to RGBA
                            if opaque {
                                p[3] = 255;
                            }
                        }
                        let mut data = Vec::with_capacity(4 + pixels.len());
                        data.extend_from_slice(&(w as u16).to_le_bytes());
                        data.extend_from_slice(&(h as u16).to_le_bytes());
                        data.extend_from_slice(&pixels);
                        out = Some(data);
                    }
                }
            }
            if !info.hbmColor.is_null() {
                DeleteObject(info.hbmColor as _);
            }
            if !info.hbmMask.is_null() {
                DeleteObject(info.hbmMask as _);
            }
        }
        DestroyIcon(icon);
        out
    }
}

#[tauri::command]
async fn pick_exe(app: AppHandle) -> String {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::UI::Controls::Dialogs::{
            GetOpenFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_HIDEREADONLY, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
        };
        let filter: Vec<u16> = "*.exe *.exe  ".encode_utf16().collect();
        let mut file = [0u16; 1024];
        let mut dialog: OPENFILENAMEW = std::mem::zeroed();
        dialog.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
        // owned by the main window: the dialog stays over it, and the window takes no clicks meanwhile
        dialog.hwndOwner = app.get_webview_window("main").and_then(|w| w.hwnd().ok()).map_or(std::ptr::null_mut(), |h| h.0 as _);
        dialog.lpstrFilter = filter.as_ptr();
        dialog.lpstrFile = file.as_mut_ptr();
        dialog.nMaxFile = file.len() as u32;
        dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
        if GetOpenFileNameW(&mut dialog) == 0 {
            return String::new();
        }
        let len = file.iter().position(|&c| c == 0).unwrap_or(0);
        String::from_utf16_lossy(&file[..len])
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

/// A "mistgate://add?url=<subscription link>" link, as a subscription page's "add to the app" button gives it: the
/// https link inside, or nothing. The link carries the person's token: it is never logged, and the window only shows
/// what it would add and asks, as for a pasted link.
fn link_of(args: &[String]) -> Option<String> {
    let link = args.iter().find(|a| a.to_ascii_lowercase().starts_with("mistgate://add"))?;
    let url = tauri::Url::parse(link).ok()?.query_pairs().find(|(key, _)| key == "url")?.1.into_owned();
    (url.starts_with("https://") && url.len() <= 4096 && !url.chars().any(|c| c.is_control())).then_some(url)
}

/// Keeps the link for the window to take, and brings the window up on its first screen.
fn offer_link(app: &AppHandle, args: &[String]) -> bool {
    let Some(url) = link_of(args) else { return false };
    *app.state::<Shell>().link.lock().unwrap() = Some(url);
    show_main_window(app, Some("Main".into()));
    let _ = app.emit("mg://add", ());
    true
}

// the window takes the link once: on its start, and when told one has come
#[tauri::command]
fn take_link(shell: State<Shell>) -> String {
    shell.link.lock().unwrap().take().unwrap_or_default()
}

#[cfg(feature = "setup")]
fn main() {
    #[cfg(windows)]
    setup::run();
}

#[cfg(not(feature = "setup"))]
fn main() {
    tauri::Builder::default()
        // One Mistgate per user session: a second start hands its arguments to the first and leaves. The first
        // brings its window up, and takes a mistgate:// link if that is what the start was for.
        .plugin(tauri_plugin_single_instance::init(|app, args, _| {
            if !offer_link(app, &args) {
                show_main_window(app, None);
            }
        }))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(Shell {
            close_to_tray: AtomicBool::new(true),
            anchor: Mutex::new((0.0, 0.0)),
            hidden_at: Mutex::new(Instant::now()),
            link: Mutex::new(None),
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
            let args: Vec<String> = std::env::args().collect();
            if !offer_link(app.handle(), &args) && !args.iter().any(|a| a == "--minimized") {
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
        .invoke_handler(tauri::generate_handler![bridge::rpc, tray_state, tray_fit, shell_prefs, show_main, autostart, quit_now, clipboard_text, open_url, pick_exe, app_icon, notify, take_link])
        .run(tauri::generate_context!())
        .expect("the window could not start");
}
