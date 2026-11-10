use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::{mpsc, oneshot};

const PIPE_NAME: &str = r"\\.\pipe\mistgate-client";
const MAX_LINE_BYTES: usize = 1 << 20;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

#[derive(Clone)]
pub struct BridgeState {
    requests: mpsc::Sender<Command>,
    shared: Arc<Shared>,
    next_id: Arc<AtomicU64>,
}

struct Shared {
    up: AtomicBool,
    generation: AtomicU64,
}

enum Command {
    Request {
        generation: u64,
        id: u64,
        line: Vec<u8>,
        reply: oneshot::Sender<Result<Value, RpcError>>,
    },
}

enum Pending {
    Request(oneshot::Sender<Result<Value, RpcError>>),
    Hello,
    Subscribe,
}

impl BridgeState {
    async fn rpc(&self, method: String, params: Value) -> Result<Value, RpcError> {
        if !self.shared.up.load(Ordering::Acquire) {
            return Err(service_down());
        }
        let generation = self.shared.generation.load(Ordering::Acquire);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (reply, response) = oneshot::channel();
        let params = if params.is_null() { json!({}) } else { params };
        let line = encode_request_line(id, &method, params)?;
        let command = Command::Request {
            generation,
            id,
            line,
            reply,
        };

        match tokio::time::timeout(REQUEST_TIMEOUT, async {
            self.requests
                .send(command)
                .await
                .map_err(|_| service_down())?;
            response.await.map_err(|_| service_down())?
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(RpcError {
                code: "timeout".into(),
                message: "The service did not answer in time.".into(),
            }),
        }
    }
}

pub fn spawn(app: AppHandle) -> BridgeState {
    let (requests, receiver) = mpsc::channel(128);
    let shared = Arc::new(Shared {
        up: AtomicBool::new(false),
        generation: AtomicU64::new(0),
    });
    let next_id = Arc::new(AtomicU64::new(1));

    #[cfg(windows)]
    tauri::async_runtime::spawn(run_bridge(app, receiver, shared.clone(), next_id.clone()));

    #[cfg(not(windows))]
    drop((app, receiver));

    BridgeState {
        requests,
        shared,
        next_id,
    }
}

#[tauri::command]
pub async fn rpc(
    state: State<'_, BridgeState>,
    method: String,
    params: Value,
) -> Result<Value, RpcError> {
    state.rpc(method, params).await
}

#[derive(Default)]
struct LineDecoder {
    current: Vec<u8>,
    limit: usize,
}

impl LineDecoder {
    fn new(limit: usize) -> Self {
        Self {
            current: Vec::with_capacity(4096),
            limit,
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, RpcError> {
        let mut lines = Vec::new();
        for byte in bytes {
            if *byte == b'\n' {
                lines.push(std::mem::take(&mut self.current));
                continue;
            }
            if self.current.len() == self.limit {
                return Err(RpcError {
                    code: "protocol_error".into(),
                    message: "The service sent an oversized line.".into(),
                });
            }
            self.current.push(*byte);
        }
        Ok(lines)
    }
}

fn matching_response_id(pending: &HashMap<u64, Pending>, response: &Value) -> Option<u64> {
    let id = response.get("id").and_then(Value::as_u64)?;
    pending.contains_key(&id).then_some(id)
}

fn next_backoff(current: Duration) -> Duration {
    if current.is_zero() {
        return MIN_BACKOFF;
    }
    current.saturating_mul(2).min(MAX_BACKOFF)
}

fn service_down() -> RpcError {
    RpcError {
        code: "service_down".into(),
        message: "The Mistgate service is not available.".into(),
    }
}

fn encode_request_line(id: u64, method: &str, params: Value) -> Result<Vec<u8>, RpcError> {
    let mut line = serde_json::to_vec(&json!({"id": id, "method": method, "params": params}))
        .map_err(|_| RpcError {
            code: "bad_params".into(),
            message: "The request could not be encoded.".into(),
        })?;
    if line.len() > MAX_LINE_BYTES {
        return Err(RpcError {
            code: "bad_params".into(),
            message: "The request is too large.".into(),
        });
    }
    line.push(b'\n');
    Ok(line)
}

#[cfg(windows)]
async fn run_bridge(
    app: AppHandle,
    mut requests: mpsc::Receiver<Command>,
    shared: Arc<Shared>,
    next_id: Arc<AtomicU64>,
) {
    let mut backoff = MIN_BACKOFF;
    loop {
        match open_verified_pipe() {
            Ok(pipe) => {
                set_service_state(&app, &shared, true);
                backoff = MIN_BACKOFF;
                let mut pending = HashMap::new();
                let outcome =
                    run_connected(&app, &mut requests, &shared, &next_id, pipe, &mut pending).await;
                set_service_state(&app, &shared, false);
                fail_pending(&mut pending, service_down());
                if requests.is_closed() {
                    return;
                }
                if let Err(reason) = outcome {
                    log_bridge(&app, &format!("IPC disconnected: {reason}"));
                }
            }
            Err(reason) => {
                log_bridge(&app, &format!("IPC connection rejected: {reason}"));
            }
        }

        let keep_running = wait_while_down(&mut requests, backoff).await;
        if !keep_running {
            return;
        }
        backoff = next_backoff(backoff);
    }
}

#[cfg(windows)]
async fn wait_while_down(requests: &mut mpsc::Receiver<Command>, delay: Duration) -> bool {
    let timer = tokio::time::sleep(delay);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            _ = &mut timer => return true,
            command = requests.recv() => match command {
                Some(command) => fail_command(command, service_down()),
                None => return false,
            }
        }
    }
}

#[cfg(windows)]
async fn run_connected(
    app: &AppHandle,
    requests: &mut mpsc::Receiver<Command>,
    shared: &Shared,
    next_id: &AtomicU64,
    pipe: tokio::net::windows::named_pipe::NamedPipeClient,
    pending: &mut HashMap<u64, Pending>,
) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut reader, mut writer) = tokio::io::split(pipe);
    let hello_id = next_id.fetch_add(1, Ordering::Relaxed);
    let subscribe_id = next_id.fetch_add(1, Ordering::Relaxed);
    pending.insert(hello_id, Pending::Hello);
    pending.insert(subscribe_id, Pending::Subscribe);
    let hello_line = encode_request_line(hello_id, "hello", json!({"client": "0.0.1"}))
        .map_err(|error| error.message)?;
    writer
        .write_all(&hello_line)
        .await
        .map_err(|error| format!("could not send hello: {error}"))?;
    let subscribe_line = encode_request_line(
        subscribe_id,
        "subscribe",
        json!({"events": ["status", "traffic", "log", "subs", "settings", "diag"]}),
    )
    .map_err(|error| error.message)?;
    writer
        .write_all(&subscribe_line)
        .await
        .map_err(|error| format!("could not subscribe to service events: {error}"))?;

    let mut handshakes_left = 2;
    let handshake_deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    let handshake_timer = tokio::time::sleep_until(handshake_deadline);
    tokio::pin!(handshake_timer);
    let mut decoder = LineDecoder::new(MAX_LINE_BYTES);
    let mut buffer = [0u8; 8192];

    loop {
        prune_closed_requests(pending);
        tokio::select! {
            result = reader.read(&mut buffer) => {
                let count = result.map_err(|error| format!("pipe read failed: {error}"))?;
                if count == 0 {
                    return Err("service closed the pipe".into());
                }
                let lines = decoder.feed(&buffer[..count]).map_err(|error| error.message)?;
                for line in lines {
                    let message: Value = serde_json::from_slice(&line)
                        .map_err(|_| "service sent invalid JSON".to_string())?;
                    if let Some(event_name) = message.get("event").and_then(Value::as_str) {
                        emit_service_event(app, event_name, message.get("data").cloned().unwrap_or(Value::Null));
                        continue;
                    }
                    let Some(id) = matching_response_id(pending, &message) else {
                        continue;
                    };
                    let Some(entry) = pending.remove(&id) else {
                        continue;
                    };
                    match entry {
                        Pending::Request(reply) => {
                            let response = decode_rpc_response(&message);
                            let _ = reply.send(response);
                        }
                        Pending::Hello => {
                            let result = message.get("result").ok_or_else(|| "service hello failed".to_string())?;
                            if result.get("trusted").and_then(Value::as_bool) != Some(true)
                                || result.get("api").and_then(Value::as_u64) != Some(0)
                            {
                                return Err("service hello rejected this client or API version".into());
                            }
                            handshakes_left -= 1;
                        }
                        Pending::Subscribe => {
                            if message.get("error").is_some() {
                                return Err("service rejected event subscriptions".into());
                            }
                            handshakes_left -= 1;
                        }
                    }
                }
            }
            command = requests.recv() => {
                match command {
                    Some(Command::Request { generation, id, line, reply }) => {
                        if !shared.up.load(Ordering::Acquire)
                            || generation != shared.generation.load(Ordering::Acquire)
                        {
                            let _ = reply.send(Err(service_down()));
                            continue;
                        }
                        pending.insert(id, Pending::Request(reply));
                        if let Err(error) = writer.write_all(&line).await {
                            return Err(format!("pipe write failed: {error}"));
                        }
                    }
                    None => return Err("bridge request channel closed".into()),
                }
            }
            _ = &mut handshake_timer, if handshakes_left > 0 => {
                return Err("service handshake timed out".into());
            }
        }
    }
}

#[cfg(windows)]
fn decode_rpc_response(message: &Value) -> Result<Value, RpcError> {
    if let Some(error) = message.get("error") {
        Err(serde_json::from_value(error.clone()).unwrap_or(RpcError {
            code: "protocol_error".into(),
            message: "The service returned an invalid error.".into(),
        }))
    } else if let Some(result) = message.get("result") {
        Ok(result.clone())
    } else {
        Err(RpcError {
            code: "protocol_error".into(),
            message: "The service returned an invalid response.".into(),
        })
    }
}

#[cfg(windows)]
fn prune_closed_requests(pending: &mut HashMap<u64, Pending>) {
    pending.retain(|_, entry| match entry {
        Pending::Request(reply) => !reply.is_closed(),
        Pending::Hello | Pending::Subscribe => true,
    });
}

#[cfg(windows)]
fn fail_pending(pending: &mut HashMap<u64, Pending>, error: RpcError) {
    for (_, entry) in pending.drain() {
        if let Pending::Request(reply) = entry {
            let _ = reply.send(Err(error.clone()));
        }
    }
}

#[cfg(windows)]
fn fail_command(command: Command, error: RpcError) {
    let Command::Request { reply, .. } = command;
    let _ = reply.send(Err(error));
}

#[cfg(windows)]
fn emit_service_event(app: &AppHandle, event: &str, data: Value) {
    let target = match event {
        "status" => "mg://status",
        "traffic" => "mg://traffic",
        "log" => "mg://log",
        "subs" => "mg://subs",
        "settings" => "mg://settings",
        "diag" => "mg://diag",
        _ => return,
    };
    let _ = app.emit(target, data);
}

#[cfg(windows)]
fn set_service_state(app: &AppHandle, shared: &Shared, up: bool) {
    if shared.up.swap(up, Ordering::AcqRel) != up {
        shared.generation.fetch_add(1, Ordering::AcqRel);
        let _ = app.emit("mg://service", json!({"up": up}));
    }
}

#[cfg(windows)]
// ponytail: bridge diagnostics reach the debugger and window event stream, but are not persisted locally.
fn log_bridge(app: &AppHandle, message: &str) {
    use std::time::{SystemTime, UNIX_EPOCH};
    use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;

    let mut wide: Vec<u16> = format!("Mistgate bridge: {message}")
        .encode_utf16()
        .collect();
    wide.push(0);
    unsafe { OutputDebugStringW(wide.as_ptr()) };
    let t_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let _ = app.emit(
        "mg://log",
        json!({"t_unix_ms": t_unix_ms, "level": "warn", "msg": message}),
    );
}

#[cfg(windows)]
fn open_verified_pipe() -> Result<tokio::net::windows::named_pipe::NamedPipeClient, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let pipe = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(PIPE_NAME)
        .map_err(|error| format!("pipe open failed: {error}"))?;
    let pipe_handle = pipe.as_raw_handle() as HANDLE;
    let mut server_pid = 0u32;
    if unsafe { GetNamedPipeServerProcessId(pipe_handle, &mut server_pid) } == 0 {
        return Err("could not read the pipe server process id".into());
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid) };
    if process.is_null() {
        return Err("could not open the pipe server process".into());
    }
    let mut image = vec![0u16; 32768];
    let mut length = image.len() as u32;
    let query_result =
        unsafe { QueryFullProcessImageNameW(process, 0, image.as_mut_ptr(), &mut length) };
    unsafe {
        CloseHandle(process);
    }
    if query_result == 0 {
        return Err("could not read the pipe server image path".into());
    }
    let image_path = String::from_utf16_lossy(&image[..length as usize]);
    let window_path = std::env::current_exe()
        .map_err(|_| "could not read the window image path".to_string())?
        .to_string_lossy()
        .into_owned();

    #[cfg(debug_assertions)]
    let development_service = std::env::var("MISTGATE_DEV_SERVICE").ok();
    #[cfg(not(debug_assertions))]
    let development_service: Option<String> = None;

    if !server_path_allowed(&window_path, &image_path, development_service.as_deref()) {
        return Err("pipe server image is outside the trusted service path".into());
    }
    Ok(pipe)
}

fn server_path_allowed(
    window_exe: &str,
    server_exe: &str,
    development_service: Option<&str>,
) -> bool {
    if let Some(development_service) = development_service {
        if normalize_windows_path(development_service) == normalize_windows_path(server_exe) {
            return true;
        }
    }
    let window_dir = windows_parent(window_exe);
    let server_dir = windows_parent(server_exe);
    windows_basename(server_exe).eq_ignore_ascii_case("mistgate-clientd.exe")
        && normalize_windows_path(&window_dir) == normalize_windows_path(&server_dir)
}

fn normalize_windows_path(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn windows_basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn windows_parent(path: &str) -> String {
    path.rfind(['\\', '/'])
        .map(|index| path[..index].to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        encode_request_line, matching_response_id, next_backoff, server_path_allowed, LineDecoder,
        Pending, MAX_LINE_BYTES,
    };
    use serde_json::json;
    use std::collections::HashMap;
    use std::time::Duration;

    #[test]
    fn response_matching_uses_the_request_id() {
        let (reply, _response) = tokio::sync::oneshot::channel();
        let pending = HashMap::from([(17, Pending::Request(reply))]);
        assert_eq!(
            matching_response_id(&pending, &json!({"id": 17, "result": {}})),
            Some(17)
        );
        assert_eq!(
            matching_response_id(&pending, &json!({"id": 18, "result": {}})),
            None
        );
        assert_eq!(
            matching_response_id(&pending, &json!({"event": "status", "data": {}})),
            None
        );
    }

    #[test]
    fn line_decoder_splits_partial_and_multiple_lines() {
        let mut decoder = LineDecoder::new(64);
        assert!(decoder.feed(b"{\"id\":").unwrap().is_empty());
        let lines = decoder.feed(b"1}\n{\"id\":2}\n").unwrap();
        assert_eq!(lines, vec![b"{\"id\":1}".to_vec(), b"{\"id\":2}".to_vec()]);
    }

    #[test]
    fn line_decoder_enforces_the_contract_limit() {
        let mut decoder = LineDecoder::new(MAX_LINE_BYTES);
        assert!(decoder.feed(&vec![b'x'; MAX_LINE_BYTES]).is_ok());
        assert!(decoder.feed(b"x").is_err());
    }

    #[test]
    fn request_lines_are_framed_and_capped() {
        let line = encode_request_line(2, "status", json!({})).unwrap();
        assert_eq!(line.last(), Some(&b'\n'));
        let oversized = json!({"payload": "x".repeat(MAX_LINE_BYTES)});
        assert_eq!(
            encode_request_line(3, "connect", oversized)
                .unwrap_err()
                .code,
            "bad_params"
        );
    }

    #[test]
    fn reconnect_backoff_grows_to_five_seconds() {
        let mut backoff = Duration::ZERO;
        let expected = [200, 400, 800, 1600, 3200, 5000, 5000];
        for millis in expected {
            backoff = next_backoff(backoff);
            assert_eq!(backoff, Duration::from_millis(millis));
        }
    }

    #[test]
    fn server_process_path_is_checked() {
        assert!(server_path_allowed(
            r"C:\Mistgate\Mistgate.exe",
            r"c:/mistgate/MISTGATE-CLIENTD.EXE",
            None,
        ));
        assert!(!server_path_allowed(
            r"C:\Mistgate\Mistgate.exe",
            r"C:\Other\mistgate-clientd.exe",
            None,
        ));
        assert!(server_path_allowed(
            r"C:\Mistgate\Mistgate.exe",
            r"D:\dev\mistgate-service.exe",
            Some(r"d:/DEV/MISTGATE-SERVICE.EXE"),
        ));
    }
}
