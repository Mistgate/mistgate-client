// The setup program: the design's installer window (the Setup screen) in front of the ordinary installer, which it
// carries inside and runs silently. Built from this same crate with the "setup" feature (tools/setup-build.mjs).
// ponytail: the installer inside carries the window's program a second time (about 10 MB more to download); one
// payload for both is the upgrade, at the price of doing the installer's own work (files, registry, uninstaller) here.
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

static PAYLOAD: &[u8] = include_bytes!(env!("MG_SETUP_PAYLOAD"));
static BUSY: AtomicBool = AtomicBool::new(false);
const NO_WINDOW: u32 = 0x0800_0000;
const UNINSTALL_KEY: &str = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Mistgate";

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// A folder the installer may be pointed at: on a drive letter, nothing a command line would read as its own.
fn valid(path: &str) -> bool {
    let b = path.as_bytes();
    b.len() > 3 && b.len() < 200 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
        && !path.chars().any(|c| c.is_control() || "\"<>|?*/".contains(c)) && !path[2..].contains(':') && !path.ends_with('\\')
}

/// Whether a program without the administrator's rights could swap the folder for its own. The service in it runs
/// as the system, so such a folder would hand the system to any program of the user. Asked of Windows directly:
/// may this (unelevated) program delete or rename what lies in any folder above? The folder's own contents are
/// closed by the installer (installer.nsh).
/// ponytail: a setup started as administrator cannot ask this way and lets every folder through; the installer's
/// own closing of the folder still holds there.
fn open_to_user(path: &str) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, OPEN_EXISTING};
    use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
    if unsafe { IsUserAnAdmin() } != 0 {
        return false;
    }
    Path::new(path).ancestors().skip(1).filter(|above| above.exists()).any(|above| unsafe {
        let handle = CreateFileW(wide(above.as_os_str()).as_ptr(), 0x40 /* FILE_DELETE_CHILD */, 7, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, std::ptr::null_mut());
        if handle == INVALID_HANDLE_VALUE {
            return false;
        }
        CloseHandle(handle);
        true
    })
}

/// Where Mistgate is installed now (an update goes to the same place), or the usual folder.
fn default_path() -> String {
    let out = std::process::Command::new("reg.exe").args(["query", UNINSTALL_KEY, "/ve"]).creation_flags(NO_WINDOW).output();
    if let Ok(out) = out {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some((_, value)) = text.split_once("REG_SZ") {
            let value = value.trim().trim_matches('"');
            if valid(value) {
                return value.to_string();
            }
        }
    }
    format!("{}\\Mistgate", std::env::var("ProgramW6432").or_else(|_| std::env::var("ProgramFiles")).unwrap_or_else(|_| r"C:\Program Files".into()))
}

#[derive(Serialize)]
struct Info {
    path: String,
    need_mb: u64,
    free_mb: u64,
    open: bool, // any program of the user could replace the folder: not a place for the service
    version: &'static str,
}

/// What the Folder step shows: the folder, what the install needs and what its drive has free.
#[tauri::command]
fn setup_info(path: Option<String>) -> Info {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let path = path.filter(|p| valid(p)).unwrap_or_else(default_path);
    // the folder may not exist yet: its nearest parent that does is on the same drive
    let mut at = Path::new(&path);
    while !at.exists() {
        match at.parent() {
            Some(parent) => at = parent,
            None => break,
        }
    }
    let mut free = 0u64;
    unsafe { GetDiskFreeSpaceExW(wide(at.as_os_str()).as_ptr(), &mut free, std::ptr::null_mut(), std::ptr::null_mut()) };
    let open = open_to_user(&path);
    Info { path, open, need_mb: env!("MG_SETUP_MB").parse().unwrap_or(0), free_mb: free >> 20, version: env!("CARGO_PKG_VERSION") }
}

/// "Change…": Windows' own folder dialog. The answer is the folder Mistgate would go to (the chosen one, with its
/// own folder inside), or empty when cancelled.
#[tauri::command]
async fn setup_pick(app: AppHandle) -> String {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{SHBrowseForFolderW, SHGetPathFromIDListW, BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS, BROWSEINFOW};
    unsafe {
        let mut dialog: BROWSEINFOW = std::mem::zeroed();
        dialog.hwndOwner = app.get_webview_window("setup").and_then(|w| w.hwnd().ok()).map_or(std::ptr::null_mut(), |h| h.0 as _);
        dialog.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        let item = SHBrowseForFolderW(&dialog);
        if item.is_null() {
            return String::new();
        }
        let mut buffer = [0u16; 260];
        let ok = SHGetPathFromIDListW(item, buffer.as_mut_ptr());
        CoTaskMemFree(item as _);
        if ok == 0 {
            return String::new();
        }
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(0);
        let folder = String::from_utf16_lossy(&buffer[..len]);
        let folder = folder.trim_end_matches('\\');
        let path = if folder.to_ascii_lowercase().ends_with("\\mistgate") { folder.to_string() } else { format!("{folder}\\Mistgate") };
        if valid(&path) { path } else { String::new() }
    }
}

#[derive(Serialize)]
struct Outcome {
    state: &'static str, // ok, denied (Windows' permission prompt was refused) or failed
    code: u32,
}

/// Runs the installer inside, silently, with Windows' permission prompt. Waits for it to finish.
#[tauri::command]
async fn setup_install(path: String, desktop: bool) -> Outcome {
    if !valid(&path) || open_to_user(&path) || BUSY.swap(true, Ordering::SeqCst) {
        return Outcome { state: "failed", code: 0 };
    }
    let outcome = tauri::async_runtime::spawn_blocking(move || install(&path, desktop)).await.unwrap_or(Outcome { state: "failed", code: 0 });
    BUSY.store(false, Ordering::SeqCst);
    outcome
}

fn install(path: &str, desktop: bool) -> Outcome {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    let failed = |code: u32| Outcome { state: "failed", code };
    let dir = std::env::temp_dir().join(format!("mistgate-setup-{}", std::process::id()));
    let file = dir.join("Mistgate Setup.exe");
    let _ = std::fs::remove_dir_all(&dir);
    if std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&file, PAYLOAD)).is_err() {
        return failed(0);
    }
    // The file is about to run with the administrator's rights from a folder any of the user's programs can write
    // to. It is held open so that nothing can replace it (others may only read), and read back through that hold:
    // what runs is what this program carries.
    let held = std::fs::OpenOptions::new().read(true).share_mode(1 /* FILE_SHARE_READ */).open(&file);
    let same = held.as_ref().ok().and_then(|mut f| {
        let mut bytes = Vec::with_capacity(PAYLOAD.len());
        std::io::Read::read_to_end(&mut f, &mut bytes).ok().map(|_| bytes == PAYLOAD)
    });
    let outcome = if same != Some(true) {
        failed(0)
    } else {
        // /D= goes last and unquoted: the installer reads everything after it as the folder
        let args = format!("/S {}/D={}", if desktop { "" } else { "/NODESK " }, path);
        let (verb, exe, args) = (wide("runas".as_ref()), wide(file.as_os_str()), wide(args.as_ref()));
        unsafe {
            let mut run: SHELLEXECUTEINFOW = std::mem::zeroed();
            run.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            run.fMask = SEE_MASK_NOCLOSEPROCESS;
            run.lpVerb = verb.as_ptr();
            run.lpFile = exe.as_ptr();
            run.lpParameters = args.as_ptr();
            if ShellExecuteExW(&mut run) == 0 || run.hProcess.is_null() {
                let error = GetLastError();
                if error == ERROR_CANCELLED { Outcome { state: "denied", code: error } } else { failed(error) }
            } else {
                WaitForSingleObject(run.hProcess, INFINITE);
                let mut code = 1u32;
                GetExitCodeProcess(run.hProcess, &mut code);
                CloseHandle(run.hProcess);
                if code == 0 { Outcome { state: "ok", code } } else { failed(code) }
            }
        }
    };
    drop(held);
    let _ = std::fs::remove_dir_all(&dir);
    outcome
}

/// After a good install: "start with Windows" as the switch says, for this user.
#[tauri::command]
fn setup_autostart(path: String, enabled: bool) {
    const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    let mut command = std::process::Command::new("reg.exe");
    if enabled && valid(&path) {
        command.args(["add", KEY, "/v", "Mistgate", "/t", "REG_SZ", "/d", &format!("\"{path}\\mistgate.exe\" --minimized"), "/f"]);
    } else {
        command.args(["delete", KEY, "/v", "Mistgate", "/f"]);
    }
    let _ = command.creation_flags(NO_WINDOW).status();
}

/// "Add subscription" on the last step: Mistgate itself starts, the setup window leaves.
#[tauri::command]
fn setup_launch(app: AppHandle, path: String) {
    let exe = PathBuf::from(&path).join("mistgate.exe");
    if valid(&path) && exe.is_file() {
        let _ = std::process::Command::new(exe).spawn();
    }
    app.exit(0);
}

/// Without the WebView2 runtime this window cannot be drawn (Windows 10 before its updates): the installer inside
/// is shown as it is, and it brings the runtime.
fn plain_installer() {
    let file = std::env::temp_dir().join("Mistgate Setup.exe");
    if std::fs::write(&file, PAYLOAD).is_ok() {
        let _ = std::process::Command::new(&file).status();
        let _ = std::fs::remove_file(&file);
    }
}

pub fn run() {
    if tauri::webview_version().is_err() {
        return plain_installer();
    }
    let mut context = tauri::generate_context!();
    context.config_mut().app.windows.clear(); // the app's own windows are not this program's
    tauri::Builder::default()
        .setup(|app| {
            WebviewWindowBuilder::new(app, "setup", WebviewUrl::App("index.html?screen=Setup".into()))
                .title("Mistgate Setup")
                .inner_size(760.0, 500.0)
                .resizable(false)
                .maximizable(false)
                .decorations(false)
                .transparent(true)
                .shadow(false)
                .center()
                .build()?;
            Ok(())
        })
        .on_window_event(|_, event| {
            // the installer cannot be stopped half-way from here: the window stays until it ends
            if let WindowEvent::CloseRequested { api, .. } = event {
                if BUSY.load(Ordering::SeqCst) {
                    api.prevent_close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![setup_info, setup_pick, setup_install, setup_autostart, setup_launch])
        .run(context)
        .expect("the setup window could not start");
}
