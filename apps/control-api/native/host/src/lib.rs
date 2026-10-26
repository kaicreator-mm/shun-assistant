//! shun-consent-host — trusted host-side napi addon for the Shun private IPC
//! consent broker (v0.2 T08 C02). Windows-only; the TypeScript loader fails
//! closed when the artifact is unavailable and NEVER falls back to a
//! hand-written JS pipe layer.
//!
//! Trusted surface implemented here (all through windows-rs, no koffi):
//!   * random unguessable pipe name (BCryptGenRandom) handed to the spawned
//!     broker process;
//!   * broker spawn with piped stderr (redacted broker log capture);
//!   * client connect that VERIFIES the pipe SERVER's image path through
//!     GetNamedPipeServerProcessId -> OpenProcess -> QueryFullProcessImageNameW
//!     before the first frame — a squatter with a different image can never be
//!     mistaken for the broker;
//!   * frame-JSON conversation: consent request / verify+consume / nonce
//!     probe / clean shutdown / kill, plus broker exit codes;
//!   * the dialog automation instrument (test-only): finds the broker's REAL
//!     #32770 MessageBox by pid and clicks its Yes/No BUTTON control — an
//!     automation of a real OS dialog, never a substitute for it;
//!   * OS-token inspection for principal evidence rows.

#![allow(clippy::missing_safety_doc)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use napi::bindgen_prelude::*;
use napi_derive::napi;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, HWND, LPARAM, LocalFree,
    SetHandleInformation, WAIT_OBJECT_0, WPARAM,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::{CreatePipe, GetNamedPipeServerProcessId, WaitNamedPipeW};
use windows::Win32::System::StationsAndDesktops::CreateDesktopW;
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, DETACHED_PROCESS,
    PROCESS_INFORMATION,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, STARTUPINFOW,
    STARTUPINFOW_FLAGS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GetClassNameW, GetDlgCtrlID, GetWindowTextW,
    GetWindowThreadProcessId, PostMessageW,
};

const STARTF_USESTDHANDLES: STARTUPINFOW_FLAGS = STARTUPINFOW_FLAGS(0x0000_0100);

const MAX_FRAME_BYTES: u32 = 64 * 1024;
const BM_CLICK: u32 = 0x00F5;
const IDYES: i32 = 6;
const IDNO: i32 = 7;

fn to_wide(s: &str) -> Vec<u16> {
    let mut units: Vec<u16> = s.encode_utf16().collect();
    units.push(0);
    units
}

fn from_wide_len(buf: &[u16], len: i32) -> String {
    let clamped = (len.max(0) as usize).min(buf.len());
    String::from_utf16_lossy(&buf[..clamped])
}

/// Random pipe name `\\.\pipe\shun-consent-<32 hex>` from the system CSP RNG.
#[napi]
pub fn generate_pipe_name() -> Result<String> {
    let mut raw = [0u8; 16];
    let status = unsafe { BCryptGenRandom(None, &mut raw, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if !status.is_ok() {
        return Err(Error::new(Status::GenericFailure, "BCryptGenRandom failed"));
    }
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("\\\\.\\pipe\\shun-consent-{hex}"))
}

// ---------------------------------------------------------------------------
// Frame codec (client side; mirrors the broker's protocol byte-for-byte)
// ---------------------------------------------------------------------------

fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> Option<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let mut got = 0u32;
        let ok = unsafe { ReadFile(pipe, Some(&mut buf[done..]), Some(&mut got), None) };
        if ok.is_err() || got == 0 {
            return None;
        }
        done += got as usize;
    }
    Some(())
}

fn write_all(pipe: HANDLE, buf: &[u8]) -> bool {
    let mut done = 0usize;
    while done < buf.len() {
        let mut wrote = 0u32;
        let ok = unsafe { WriteFile(pipe, Some(&buf[done..]), Some(&mut wrote), None) };
        if ok.is_err() {
            return false;
        }
        done += wrote as usize;
    }
    true
}

fn write_frame(pipe: HANDLE, body: &[u8]) -> Option<()> {
    if body.len() as u64 > u64::from(MAX_FRAME_BYTES) {
        return None;
    }
    if write_all(pipe, &(body.len() as u32).to_le_bytes()) && write_all(pipe, body) {
        Some(())
    } else {
        None
    }
}

fn read_frame(pipe: HANDLE) -> Option<serde_json::Value> {
    let mut len_buf = [0u8; 4];
    read_exact(pipe, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len == 0 || len > MAX_FRAME_BYTES {
        return None;
    }
    let mut body = vec![0u8; len as usize];
    read_exact(pipe, &mut body)?;
    serde_json::from_slice(&body).ok()
}

fn roundtrip(pipe: HANDLE, message: &serde_json::Value) -> Option<serde_json::Value> {
    write_frame(pipe, &serde_json::to_vec(message).ok()?)?;
    read_frame(pipe)
}

/// HANDLE is a raw pointer wrapper, so it is not Send by default; the spawn
/// registry lives in a global Mutex and is read from other threads.
struct SendHandle(usize);

unsafe impl Send for SendHandle {}

impl SendHandle {
    fn get(&self) -> HANDLE {
        HANDLE(self.0 as *mut _)
    }
}

// ---------------------------------------------------------------------------
// Broker spawn + registry
// ---------------------------------------------------------------------------

#[napi(object)]
pub struct BrokerSpawn {
    pub pid: u32,
    pub pipe_name: String,
    pub image_path: String,
}

struct SpawnedBroker {
    process: SendHandle,
    log: Arc<Mutex<Vec<u8>>>,
}

static REGISTRY: Mutex<Option<HashMap<u32, SpawnedBroker>>> = Mutex::new(None);

fn with_registry<R>(f: impl FnOnce(&mut HashMap<u32, SpawnedBroker>) -> R) -> R {
    let mut guard = REGISTRY.lock().expect("broker registry poisoned");
    guard.get_or_insert_with(HashMap::new);
    f(guard.as_mut().expect("registry initialized"))
}

/// Spawn the broker exe with `--pipe <name>` and piped stderr. `desktop`
/// overrides STARTUPINFO.lpDesktop — the ONLY reason it exists is the
/// non-interactive refusal proof (a broker on a private window station must
/// refuse), never a production path.
#[napi]
pub fn spawn_broker(
    exe_path: String,
    pipe_name: String,
    desktop: Option<String>,
) -> Result<BrokerSpawn> {
    if let Some(desktop_name) = desktop.as_deref() {
        ensure_desktop_exists(desktop_name);
    }
    let cmdline_string = format!("\"{exe_path}\" --pipe {pipe_name}");
    let mut cmdline = to_wide(&cmdline_string);
    let mut app_units = to_wide(&exe_path);
    app_units.pop();
    let mut desktop_units: Vec<u16> = desktop.map(|d| to_wide(&d)).unwrap_or_default();
    // A desktop override only exists for the non-interactive refusal proof.
    // CREATE_NO_WINDOW allocates a hidden console tied to the CURRENT desktop
    // and kills such a child during console-subsystem init; DETACHED_PROCESS
    // allocates no console and lets the child reach main.
    let creation_flags = if desktop_units.is_empty() {
        CREATE_NO_WINDOW
    } else {
        DETACHED_PROCESS
    };

    unsafe {
        let (read_end, write_end) = {
            let mut read_end = HANDLE::default();
            let mut write_end = HANDLE::default();
            CreatePipe(&mut read_end, &mut write_end, None, 0)
                .map_err(|e| Error::new(Status::GenericFailure, format!("CreatePipe: {}", e.code().0)))?;
            if SetHandleInformation(write_end, 1, HANDLE_FLAG_INHERIT).is_err() {
                let _ = CloseHandle(read_end);
                let _ = CloseHandle(write_end);
                return Err(Error::new(Status::GenericFailure, "SetHandleInformation failed"));
            }
            (read_end, write_end)
        };

        let mut startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: HANDLE(-1isize as *mut _),
            hStdOutput: write_end,
            hStdError: write_end,
            ..Default::default()
        };
        if !desktop_units.is_empty() {
            startup.lpDesktop = PWSTR(desktop_units.as_mut_ptr());
        }

        let mut info = PROCESS_INFORMATION::default();
        let created = CreateProcessW(
            PCWSTR(app_units.as_ptr()),
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            true,
            creation_flags,
            None,
            PCWSTR::null(),
            &startup,
            &mut info,
        );
        // The parent keeps only the read end of the stderr pipe.
        let _ = CloseHandle(write_end);
        if let Err(err) = created {
            let _ = CloseHandle(read_end);
            return Err(Error::new(
                Status::GenericFailure,
                format!("CreateProcessW: {}", err.code().0),
            ));
        }
        let _ = CloseHandle(info.hThread);

        let log: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let reader_log = Arc::clone(&log);
        let reader_pipe = SendHandle(read_end.0 as usize);
        std::thread::spawn(move || {
            let read_end = reader_pipe.get();
            let mut chunk = [0u8; 4096];
            loop {
                let mut got = 0u32;
                let ok = ReadFile(read_end, Some(&mut chunk), Some(&mut got), None);
                if ok.is_err() || got == 0 {
                    let _ = CloseHandle(read_end);
                    break;
                }
                if let Ok(mut l) = reader_log.lock() {
                    l.extend_from_slice(&chunk[..got as usize]);
                }
            }
        });

        let pid = info.dwProcessId;
        with_registry(|map| {
            map.insert(
                pid,
                SpawnedBroker {
                    process: SendHandle(info.hProcess.0 as usize),
                    log,
                },
            );
        });
        Ok(BrokerSpawn {
            pid,
            pipe_name,
            image_path: exe_path,
        })
    }
}

/// Desktops referenced by spawned children must EXIST before the child's
/// user32 initialization runs, or the child dies pre-main with
/// STATUS_DLL_NOT_INITIALIZED. Created handles are deliberately leaked for
/// the process lifetime so the object cannot vanish under an attached child.
static LEAKED_DESKTOPS: Mutex<Option<Vec<usize>>> = Mutex::new(None);

fn ensure_desktop_exists(desktop_spec: &str) {
    // Accept "winsta0\\Name" or a bare "Name"; creation is always in the
    // CURRENT (interactive) window station.
    let name = desktop_spec.rsplit('\\').next().unwrap_or(desktop_spec);
    if name.is_empty() {
        return;
    }
    let mut name_units = to_wide(name);
    let created = unsafe {
        CreateDesktopW(
            PCWSTR(name_units.as_ptr()),
            PCWSTR::null(),
            None,
            windows::Win32::System::StationsAndDesktops::DESKTOP_CONTROL_FLAGS(0),
            0x000F_01FF, // DESKTOP_ALL
            None,
        )
    };
    if let Ok(desk) = created {
        let raw = desk.0 as usize;
        let mut guard = LEAKED_DESKTOPS.lock().expect("desktop registry poisoned");
        guard.get_or_insert_with(Vec::new).push(raw);
    }
    // An error here usually means the desktop already exists — the spawn
    // itself will tell us if the name is unusable.
}

/// Captured (redacted) stderr of a spawned broker that never completed
/// connect/handshake — the startup-failure evidence stream.
#[napi]
pub fn spawned_broker_log(pid: u32) -> String {
    let log = with_registry(|map| match map.get(&pid) {
        Some(spawned) => Some(Arc::clone(&spawned.log)),
        None => None,
    });
    let bytes = log.and_then(|l| l.lock().map(|l| l.clone()).ok()).unwrap_or_default();
    String::from_utf8_lossy(&bytes).to_string()
}

/// Hard-kill a spawned broker by pid (leak guard when connect/handshake
/// fails after a successful spawn; the process handle stays in the registry).
#[napi]
pub fn kill_spawned_broker(pid: u32) -> bool {
    let spawned = with_registry(|map| map.remove(&pid));
    let Some(spawned) = spawned else {
        return false;
    };
    let process = spawned.process.get();
    unsafe {
        let _ = TerminateProcess(process, 1);
        WaitForSingleObject(process, 3_000);
        let _ = CloseHandle(process);
    }
    true
}

// ---------------------------------------------------------------------------
// Connect + session
// ---------------------------------------------------------------------------

#[napi(object)]
pub struct BrokerFacts {
    pub pid: u32,
    pub pipe_name: String,
    pub broker_id: String,
    pub broker_revision: String,
    pub os_session_id: f64,
    pub principal_user_sid: String,
    pub logon_sid: String,
    pub server_image: String,
    pub protocol: f64,
}

#[napi(object)]
pub struct ConsentOutcomeJs {
    pub outcome: String,
    pub detail: String,
    pub approval_json: Option<String>,
}

#[napi(object)]
pub struct VerifyOutcomeJs {
    pub valid: bool,
    pub reason: String,
}

#[napi(object)]
pub struct ExitOutcomeJs {
    pub exit_code: Option<f64>,
    pub timed_out: bool,
}

#[napi]
pub struct BrokerSession {
    pipe: SendHandle,
    pid: u32,
    facts: BrokerFacts,
    log: Arc<Mutex<Vec<u8>>>,
    process: SendHandle,
}

fn open_pipe_client(pipe_name: &str, timeout_ms: u32) -> Result<HANDLE> {
    let name_units = to_wide(pipe_name);
    let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
    loop {
        let handle = unsafe {
            CreateFileW(
                PCWSTR(name_units.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        match handle {
            Ok(pipe) => return Ok(pipe),
            Err(err) => {
                if err.code() == windows::Win32::Foundation::ERROR_PIPE_BUSY.to_hresult() {
                    let wait_units = to_wide(pipe_name);
                    let _ = unsafe { WaitNamedPipeW(PCWSTR(wait_units.as_ptr()), 1000) };
                }
                if Instant::now() >= deadline {
                    return Err(Error::new(
                        Status::GenericFailure,
                        format!("connect timeout: {}", err.code().0),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn image_path_of(process: HANDLE) -> Option<String> {
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
    };
    if ok.is_err() {
        return None;
    }
    Some(from_wide_len(&buf, len as i32))
}

fn eq_path(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.trim_start_matches("\\\\?\\")
            .replace('/', "\\")
            .to_ascii_lowercase()
    };
    norm(a) == norm(b)
}

/// Connect to the broker pipe, verify the SERVER's image path against the
/// expected broker exe, and complete the protocol handshake.
#[napi]
pub fn connect_broker(
    pipe_name: String,
    expect_exe_path: String,
    timeout_ms: u32,
) -> Result<BrokerSession> {
    let pipe = open_pipe_client(&pipe_name, timeout_ms)?;
    let mut server_pid = 0u32;
    if let Err(err) = unsafe { GetNamedPipeServerProcessId(pipe, &mut server_pid) } {
        let _ = unsafe { CloseHandle(pipe) };
        return Err(Error::new(
            Status::GenericFailure,
            format!("GetNamedPipeServerProcessId: {}", err.code().0),
        ));
    }
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            server_pid,
        )
    }
    .map_err(|e| {
        let _ = unsafe { CloseHandle(pipe) };
        Error::new(Status::GenericFailure, format!("OpenProcess(server): {}", e.code().0))
    })?;
    let server_image = image_path_of(process).unwrap_or_default();
    if !eq_path(&server_image, &expect_exe_path) {
        let _ = unsafe { CloseHandle(process) };
        let _ = unsafe { CloseHandle(pipe) };
        return Err(Error::new(
            Status::GenericFailure,
            "REFUSED_SERVER_IDENTITY".to_string(),
        ));
    }

    let hello = serde_json::json!({"t":"hello","protocol":1,"host":"shun-control-api"});
    let Some(welcome) = roundtrip(pipe, &hello) else {
        let _ = unsafe { CloseHandle(process) };
        let _ = unsafe { CloseHandle(pipe) };
        return Err(Error::new(
            Status::GenericFailure,
            "REFUSED_HANDSHAKE".to_string(),
        ));
    };
    if welcome.get("t") != Some(&serde_json::json!("welcome")) {
        let _ = unsafe { CloseHandle(process) };
        let _ = unsafe { CloseHandle(pipe) };
        return Err(Error::new(
            Status::GenericFailure,
            "REFUSED_HANDSHAKE".to_string(),
        ));
    }

    // Adopt the spawn registry entry (process handle + captured stderr).
    let spawned = with_registry(|map| map.remove(&server_pid));
    let log = spawned
        .as_ref()
        .map(|s| Arc::clone(&s.log))
        .unwrap_or_else(|| Arc::new(Mutex::new(Vec::new())));
    let adopted_process = spawned.map(|s| s.process);
    let process = match adopted_process {
        Some(send) => send,
        None => SendHandle(process.0 as usize),
    };
    let facts = BrokerFacts {
        pid: server_pid,
        pipe_name,
        broker_id: welcome
            .get("brokerId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string(),
        broker_revision: welcome
            .get("brokerRevision")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string(),
        os_session_id: welcome
            .get("osSessionId")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as f64,
        principal_user_sid: welcome
            .get("principalUserSid")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string(),
        logon_sid: welcome
            .get("logonSid")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string(),
        server_image,
        protocol: welcome
            .get("protocol")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as f64,
    };
    Ok(BrokerSession {
        pipe: SendHandle(pipe.0 as usize),
        pid: server_pid,
        facts,
        log,
        process,
    })
}

#[napi]
impl BrokerSession {
    #[napi(getter)]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    #[napi(getter)]
    pub fn facts(&self) -> BrokerFacts {
        BrokerFacts {
            pid: self.facts.pid,
            pipe_name: self.facts.pipe_name.clone(),
            broker_id: self.facts.broker_id.clone(),
            broker_revision: self.facts.broker_revision.clone(),
            os_session_id: self.facts.os_session_id,
            principal_user_sid: self.facts.principal_user_sid.clone(),
            logon_sid: self.facts.logon_sid.clone(),
            server_image: self.facts.server_image.clone(),
            protocol: self.facts.protocol,
        }
    }

    /// Blocking consent round trip. The dialog belongs to the broker process;
    /// while this call is parked the test drives the REAL dialog via
    /// arm_dialog_automation.
    #[napi]
    pub fn request_consent(&self, request_json: String) -> Result<ConsentOutcomeJs> {
        let parsed: serde_json::Value = serde_json::from_str(&request_json)
            .map_err(|_| Error::new(Status::GenericFailure, "REFUSED_REQUEST_MALFORMED"))?;
        let dialog_timeout = parsed
            .get("dialogTimeoutMs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(120_000);
        let message = serde_json::json!({
            "t": "consent",
            "request": parsed,
            "dialogTimeoutMs": dialog_timeout,
        });
        let Some(reply) = roundtrip(self.pipe.get(), &message) else {
            return Ok(ConsentOutcomeJs {
                outcome: "REFUSED_TRANSPORT".to_string(),
                detail: String::new(),
                approval_json: None,
            });
        };
        let outcome = reply
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("REFUSED_TRANSPORT");
        Ok(ConsentOutcomeJs {
            outcome: outcome.to_string(),
            detail: reply
                .get("detail")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
            approval_json: reply
                .get("approval")
                .map(|a| a.to_string()),
        })
    }

    /// Verify + atomically consume the broker assertion of an approval.
    #[napi]
    pub fn verify_approval(&self, approval_json: String) -> Result<VerifyOutcomeJs> {
        let approval: serde_json::Value = serde_json::from_str(&approval_json)
            .map_err(|_| Error::new(Status::GenericFailure, "REFUSED_REQUEST_MALFORMED"))?;
        let message = serde_json::json!({ "t": "verify", "approval": approval });
        let Some(reply) = roundtrip(self.pipe.get(), &message) else {
            return Ok(VerifyOutcomeJs {
                valid: false,
                reason: "REFUSED_TRANSPORT".to_string(),
            });
        };
        Ok(VerifyOutcomeJs {
            valid: reply
                .get("valid")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            reason: reply
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }

    /// Non-consuming nonce freshness probe (CloudConsentCurrentness backing).
    #[napi]
    pub fn check_nonce(&self, confirmation_nonce: String) -> Result<bool> {
        let message = serde_json::json!({ "t": "nonce", "confirmationNonce": confirmation_nonce });
        let Some(reply) = roundtrip(self.pipe.get(), &message) else {
            return Ok(false);
        };
        Ok(reply
            .get("unused")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false))
    }

    /// Redacted broker stderr log captured so far (evidence stream).
    #[napi]
    pub fn broker_log(&self) -> String {
        let bytes = self.log.lock().map(|l| l.clone()).unwrap_or_default();
        String::from_utf8_lossy(&bytes).to_string()
    }

    /// Ask the broker to exit cleanly and report its OS exit code.
    #[napi]
    pub fn shutdown(&self, timeout_ms: u32) -> Result<ExitOutcomeJs> {
        let message = serde_json::json!({ "t": "shutdown" });
        let _ = roundtrip(self.pipe.get(), &message);
        let _ = unsafe { CloseHandle(self.pipe.get()) };
        let waited = unsafe { WaitForSingleObject(self.process.get(), timeout_ms) };
        if waited != WAIT_OBJECT_0 {
            return Ok(ExitOutcomeJs {
                exit_code: None,
                timed_out: true,
            });
        }
        let mut code = 0u32;
        if let Err(err) = unsafe { GetExitCodeProcess(self.process.get(), &mut code) } {
            return Err(Error::new(
                Status::GenericFailure,
                format!("GetExitCodeProcess: {}", err.code().0),
            ));
        }
        Ok(ExitOutcomeJs {
            exit_code: Some(f64::from(code)),
            timed_out: false,
        })
    }

    /// Hard-kill the broker (restart-invalidation evidence path).
    #[napi]
    pub fn kill(&self) -> Result<ExitOutcomeJs> {
        let _ = unsafe { TerminateProcess(self.process.get(), 1) };
        unsafe {
            WaitForSingleObject(self.process.get(), 5_000);
        }
        let mut code = 0u32;
        if let Err(err) = unsafe { GetExitCodeProcess(self.process.get(), &mut code) } {
            return Err(Error::new(
                Status::GenericFailure,
                format!("GetExitCodeProcess: {}", err.code().0),
            ));
        }
        Ok(ExitOutcomeJs {
            exit_code: Some(f64::from(code)),
            timed_out: false,
        })
    }
}

// ---------------------------------------------------------------------------
// Dialog automation (test instrument: clicks the REAL broker MessageBox)
// ---------------------------------------------------------------------------

struct AutomationShared {
    found: bool,
    clicked: bool,
    done: bool,
}

static AUTOMATIONS: Mutex<Option<HashMap<u32, Arc<Mutex<AutomationShared>>>>> = Mutex::new(None);
static AUTOMATION_SEQ: AtomicU32 = AtomicU32::new(1);

fn with_automations<R>(f: impl FnOnce(&mut HashMap<u32, Arc<Mutex<AutomationShared>>>) -> R) -> R {
    let mut guard = AUTOMATIONS.lock().expect("automation registry poisoned");
    guard.get_or_insert_with(HashMap::new);
    f(guard.as_mut().expect("automation registry initialized"))
}

struct FindCtx {
    pid: u32,
    found: Option<HWND>,
}

unsafe extern "system" fn find_dialog_cb(hwnd: HWND, lparam: LPARAM) -> windows::core::BOOL {
    let ctx = unsafe { &mut *(lparam.0 as *mut FindCtx) };
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    if pid != ctx.pid {
        return windows::core::BOOL(1);
    }
    let mut class = [0u16; 64];
    let class_len = unsafe { GetClassNameW(hwnd, &mut class) };
    if from_wide_len(&class, class_len) != "#32770" {
        return windows::core::BOOL(1);
    }
    let mut title = [0u16; 128];
    let title_len = unsafe { GetWindowTextW(hwnd, &mut title) };
    let title_s = from_wide_len(&title, title_len);
    if !title_s.starts_with("Shun") {
        return windows::core::BOOL(1);
    }
    ctx.found = Some(hwnd);
    windows::core::BOOL(0)
}

struct ClickCtx {
    target_id: i32,
    clicked: bool,
}

unsafe extern "system" fn click_button_cb(hwnd: HWND, lparam: LPARAM) -> windows::core::BOOL {
    let ctx = unsafe { &mut *(lparam.0 as *mut ClickCtx) };
    let mut class = [0u16; 32];
    let class_len = unsafe { GetClassNameW(hwnd, &mut class) };
    if from_wide_len(&class, class_len) != "Button" {
        return windows::core::BOOL(1);
    }
    let ctrl = unsafe { GetDlgCtrlID(hwnd) };
    if ctrl == ctx.target_id {
        let _ = unsafe { PostMessageW(Some(hwnd), BM_CLICK, WPARAM(0), LPARAM(0)) };
        ctx.clicked = true;
        return windows::core::BOOL(0);
    }
    windows::core::BOOL(1)
}

/// Arm a background automation against the broker's REAL confirmation dialog:
/// "allow" clicks the Yes button, "deny" clicks No, "none" only records
/// whether a dialog appeared (negative-path evidence). This automates input
/// to a genuine OS-owned MessageBox; it cannot mint anything by itself.
#[napi]
pub fn arm_dialog_automation(pid: u32, action: String, find_timeout_ms: u32) -> u32 {
    let id = AUTOMATION_SEQ.fetch_add(1, Ordering::SeqCst);
    let shared = Arc::new(Mutex::new(AutomationShared {
        found: false,
        clicked: false,
        done: false,
    }));
    with_automations(|map| {
        map.insert(id, Arc::clone(&shared));
    });
    let target_id = if action == "allow" { IDYES } else { IDNO };
    let only_observe = action == "none";
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(u64::from(find_timeout_ms));
        while Instant::now() < deadline {
            let mut ctx = FindCtx { pid, found: None };
            let _ = unsafe { EnumWindows(Some(find_dialog_cb), LPARAM(&mut ctx as *mut FindCtx as isize)) };
            if let Some(dialog) = ctx.found {
                if let Ok(mut state) = shared.lock() {
                    state.found = true;
                }
                if only_observe {
                    break;
                }
                let mut click = ClickCtx {
                    target_id,
                    clicked: false,
                };
                let _ = unsafe {
                    EnumChildWindows(
                        Some(dialog),
                        Some(click_button_cb),
                        LPARAM(&mut click as *mut ClickCtx as isize),
                    )
                };
                if click.clicked {
                    if let Ok(mut state) = shared.lock() {
                        state.clicked = true;
                    }
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if let Ok(mut state) = shared.lock() {
            state.done = true;
        }
    });
    id
}

#[napi(object)]
pub struct AutomationReport {
    pub found: bool,
    pub clicked: bool,
    pub done: bool,
}

/// Collect the final state of an armed automation (waits for its completion).
#[napi]
pub fn collect_dialog_automation(id: u32) -> AutomationReport {
    let deadline = Instant::now() + Duration::from_secs(70);
    loop {
        let shared = with_automations(|map| map.get(&id).map(Arc::clone));
        let Some(shared) = shared else {
            return AutomationReport {
                found: false,
                clicked: false,
                done: true,
            };
        };
        if let Ok(state) = shared.lock() {
            if state.done || Instant::now() > deadline {
                return AutomationReport {
                    found: state.found,
                    clicked: state.clicked,
                    done: state.done,
                };
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

// ---------------------------------------------------------------------------
// OS-token principal evidence
// ---------------------------------------------------------------------------

#[napi(object)]
pub struct TokenEvidence {
    pub openable: bool,
    pub user_sid: Option<String>,
    pub logon_sid: Option<String>,
    pub session_id: Option<f64>,
    pub image: Option<String>,
    pub detail: String,
}

struct SidString(PWSTR);

impl SidString {
    fn as_string(&self) -> String {
        if self.0.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        unsafe {
            while *self.0.as_ptr().add(len) != 0 {
                len += 1;
            }
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(self.0.as_ptr(), len) })
    }
}

impl Drop for SidString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.as_ptr().cast())));
            }
        }
    }
}

/// Real OS-token facts of any pid (principal evidence rows). A foreign or
/// protected principal yields openable=false — itself a refusal-grade fact.
#[napi]
pub fn inspect_process_token(pid: f64) -> Result<TokenEvidence> {
    let pid = pid as u32;
    unsafe {
        let process = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => handle,
            Err(err) => {
                return Ok(TokenEvidence {
                    openable: false,
                    user_sid: None,
                    logon_sid: None,
                    session_id: None,
                    image: None,
                    detail: format!("OpenProcess refused: {}", err.code().0),
                });
            }
        };
        let image = image_path_of(process);
        let mut token_out = windows::Win32::Foundation::HANDLE::default();
        let token = match OpenProcessToken(process, TOKEN_QUERY, &mut token_out).map(|_| token_out) {
            Ok(handle) => handle,
            Err(err) => {
                let _ = CloseHandle(process);
                return Ok(TokenEvidence {
                    openable: false,
                    user_sid: None,
                    logon_sid: None,
                    session_id: None,
                    image,
                    detail: format!("OpenProcessToken refused: {}", err.code().0),
                });
            }
        };

        let user_sid = query_token_user_sid(token);
        let (logon_sid, session_id) = query_token_groups(token);
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
        let open = user_sid.is_some() && logon_sid.is_some();
        Ok(TokenEvidence {
            openable: open,
            user_sid,
            logon_sid,
            session_id: session_id.map(f64::from),
            image,
            detail: if open {
                "token read".to_string()
            } else {
                "token facts incomplete".to_string()
            },
        })
    }
}

unsafe fn query_token_user_sid(token: HANDLE) -> Option<String> {
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};
    let mut needed = 0u32;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u8; needed as usize];
    unsafe {
        GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), needed, &mut needed)
            .ok()?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut pw = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut pw).ok()?;
        Some(SidString(pw).as_string())
    }
}

unsafe fn query_token_groups(token: HANDLE) -> (Option<String>, Option<u32>) {
    use windows::Win32::Security::{
        GetTokenInformation, TokenGroups, TokenSessionId, TOKEN_GROUPS,
    };
    let mut needed = 0u32;
    let _ = unsafe { GetTokenInformation(token, TokenGroups, None, 0, &mut needed) };
    let mut logon_sid = None;
    if needed > 0 {
        let mut buf = vec![0u8; needed as usize];
        if unsafe {
            GetTokenInformation(token, TokenGroups, Some(buf.as_mut_ptr().cast()), needed, &mut needed)
        }
        .is_ok()
        {
            let groups = unsafe { &*(buf.as_ptr() as *const TOKEN_GROUPS) };
            const SE_GROUP_LOGON_ID: u32 = 0xC0_00_00_00;
            let entries = unsafe {
                std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
            };
            for entry in entries {
                if entry.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID {
                    let mut pw = PWSTR::null();
                    if unsafe { ConvertSidToStringSidW(entry.Sid, &mut pw) }.is_ok() {
                        logon_sid = Some(SidString(pw).as_string());
                    }
                    break;
                }
            }
        }
    }
    let mut session_id = 0u32;
    let mut have_session = false;
    if unsafe {
        GetTokenInformation(
            token,
            TokenSessionId,
            Some((&mut session_id as *mut u32).cast()),
            std::mem::size_of::<u32>() as u32,
            &mut 0,
        )
    }
    .is_ok()
    {
        have_session = true;
    }
    (logon_sid, if have_session { Some(session_id) } else { None })
}
