//! shun-consent-broker — the Shun-owned private IPC trusted consent broker
//! (v0.2 T08 C02). One process owns BOTH the desktop confirmation dialog and
//! the protected named pipe; the public Control API can only REQUEST a prompt
//! over that pipe and can never mint or forge an approval.
//!
//! Hard security properties (all enforced in this process, never in JS):
//!   * pipe DACL: only the broker's own logon SID / user SID may connect,
//!     remote clients rejected (PIPE_REJECT_REMOTE_CLIENTS);
//!   * per-connection OS-token admission: the CONNECTING client's user SID,
//!     logon SID and session id must equal the broker's own (never a PID or
//!     client-claimed JSON);
//!   * the EXACT T01 disclosure projection is digest-pinned before any dialog;
//!   * approvals are minted only on a real interactive-desktop confirmation,
//!     carry a single-use nonce and an HMAC proof under a per-process random
//!     key (restart invalidates every outstanding approval);
//!   * zero egress by construction: this binary performs no network I/O.
//!
//! Exit codes: 0 clean shutdown · 2 init/usage failure · 3 fatal protocol
//! error. Every refusal is logged redacted on stderr (never the goal text).

mod consent;
mod crypto;
mod dialog;
mod proto;
mod timeutil;
mod token;

use consent::{ConsentCore, PROTOCOL};
use serde_json::{json, Value};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    AddAccessAllowedAceEx, InitializeAcl, InitializeSecurityDescriptor,
    SetSecurityDescriptorDacl, ACE_FLAGS, ACL, ACE_REVISION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_GENERIC_WRITE, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

const PIPE_PREFIX: &str = "\\\\.\\pipe\\shun-consent-";
const DIALOG_CAPTION: &str = "Shun 私有授权确认 / Shun private consent";
const DEFAULT_DIALOG_TIMEOUT_MS: u32 = 120_000;

fn log_line(kind: &str, detail: &str) {
    eprintln!("BRD {} {} {}", timeutil::format_iso_utc(timeutil::now_ms()), kind, detail);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pipe_name = match parse_pipe_arg(&args) {
        Some(name) => name,
        None => {
            eprintln!("BRD usage: shun-consent-broker --pipe \\\\.\\pipe\\shun-consent-<32hex>");
            std::process::exit(2);
        }
    };

    let self_facts = match token::self_facts() {
        Some(facts) => facts,
        None => {
            log_line("INIT_FAILED", "self token unreadable");
            std::process::exit(2);
        }
    };

    let pipe = create_protected_pipe(&pipe_name, &self_facts);
    if pipe.is_invalid() {
        log_line("INIT_FAILED", "CreateNamedPipeW failed (invalid handle)");
        std::process::exit(2);
    }

    log_line(
        "READY",
        &format!(
            "broker={} session={} userSidPrefix={}",
            consent::BROKER_ID,
            self_facts.session_id,
            sid_prefix(&self_facts.user_sid),
        ),
    );

    let mut core = ConsentCore::new();
    let io = proto::FrameIo::new(pipe);

    loop {
        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(err) = connected {
            // A client that connected between pipe creation and
            // ConnectNamedPipe surfaces ERROR_PIPE_CONNECTED — serve it.
            if err.code() != windows::Win32::Foundation::ERROR_PIPE_CONNECTED.to_hresult() {
                log_line("ACCEPT_FAILED", &format!("{}", err.code().0));
                continue;
            }
        }

        // OS-token admission of the CONNECTING client, before any bytes flow.
        let admission = token::client_facts(pipe).and_then(|facts| {
            if facts.user_sid == self_facts.user_sid
                && facts.logon_sid == self_facts.logon_sid
                && facts.session_id == self_facts.session_id
            {
                Some(facts)
            } else {
                None
            }
        });
        let Some(client_facts) = admission else {
            log_line("CLIENT_REFUSED", "token principal mismatch or unreadable");
            unsafe { let _ = DisconnectNamedPipe(pipe); }
            continue;
        };
        log_line("CLIENT", &format!("session={} luid={:x}", client_facts.session_id, client_facts.logon_luid));

        let outcome = serve_connection(&io, &mut core, &self_facts);
        unsafe { let _ = DisconnectNamedPipe(pipe); }
        if outcome == ServeOutcome::Shutdown {
            let _ = unsafe { CloseHandle(pipe) };
            log_line("EXIT", "clean shutdown");
            std::process::exit(0);
        }
        if outcome == ServeOutcome::Fatal {
            let _ = unsafe { CloseHandle(pipe) };
            std::process::exit(3);
        }
    }
}

#[derive(PartialEq)]
enum ServeOutcome {
    Continue,
    Shutdown,
    Fatal,
}

fn parse_pipe_arg(args: &[String]) -> Option<String> {
    if args.len() != 3 || args[1] != "--pipe" {
        return None;
    }
    let name = &args[2];
    let suffix = name.strip_prefix(PIPE_PREFIX)?;
    if suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Some(name.clone())
    } else {
        None
    }
}

fn sid_prefix(sid: &str) -> String {
    // Redacted evidence form: the machine/account tail never reaches the log.
    sid.split('-').take(6).collect::<Vec<_>>().join("-")
}

/// Create the pipe with an explicit DACL: allow FILE read/write ONLY to the
/// broker's own user SID and logon SID. No other ACE exists, so any other
/// principal (including remote) is denied by the object manager before a
/// single byte is exchanged. PIPE_REJECT_REMOTE_CLIENTS additionally refuses
/// any network-originated connection.
fn create_protected_pipe(name: &str, facts: &token::TokenFacts) -> HANDLE {
    let sids: Vec<Vec<u8>> = [facts.user_sid.as_str(), facts.logon_sid.as_str()]
        .iter()
        .map(|sid| sid_string_to_bytes(sid))
        .collect();

    let mut sd = SECURITY_DESCRIPTOR::default();
    let sd_ptr = PSECURITY_DESCRIPTOR(&mut sd as *mut SECURITY_DESCRIPTOR as *mut _);
    if (unsafe { InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION) }).is_err() {
        return HANDLE::default();
    }

    let mut acl = vec![0u8; 512];
    if (unsafe { InitializeAcl(acl.as_mut_ptr() as *mut ACL, 512, ACE_REVISION(4)) }).is_err() {
        return HANDLE::default();
    }
    let access = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0;
    for sid in &sids {
        if sid.is_empty() {
            return HANDLE::default();
        }
        let added = unsafe {
            AddAccessAllowedAceEx(
                acl.as_mut_ptr() as *mut ACL,
                ACE_REVISION(4),
                ACE_FLAGS(0),
                access,
                windows::Win32::Security::PSID(sid.as_ptr() as *mut _),
            )
        };
        if added.is_err() {
            return HANDLE::default();
        }
    }
    if (unsafe {
        SetSecurityDescriptorDacl(sd_ptr, true, Some(acl.as_ptr() as *const ACL), false)
    })
    .is_err()
    {
        return HANDLE::default();
    }

    let mut name_units: Vec<u16> = name.encode_utf16().collect();
    name_units.push(0);
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: &mut sd as *mut SECURITY_DESCRIPTOR as *mut _,
        bInheritHandle: false.into(),
    };
    const FILE_FLAG_FIRST_INSTANCE: FILE_FLAGS_AND_ATTRIBUTES =
        FILE_FLAGS_AND_ATTRIBUTES(0x0008_0000);
    unsafe {
        CreateNamedPipeW(
            PCWSTR(name_units.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            Some(&sa as *const SECURITY_ATTRIBUTES),
        )
    }
}

fn sid_string_to_bytes(sid: &str) -> Vec<u8> {
    // S-R-I-S-S... — rebuild the binary SID so it can be referenced by the
    // DACL without holding the token open.
    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() < 3 || parts[0] != "S" {
        return Vec::new();
    }
    let revision: u8 = parts[1].parse().unwrap_or(1);
    let authority: u64 = if let Some(hex) = parts[2].strip_prefix("0x") {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        parts[2].parse().unwrap_or(0)
    };
    let subauthorities: Vec<u64> = parts[3..].iter().filter_map(|p| p.parse().ok()).collect();
    let count: u8 = subauthorities.len().min(15) as u8;
    let mut bytes = Vec::with_capacity(8 + count as usize * 4);
    bytes.push(revision);
    bytes.push(count);
    bytes.extend_from_slice(&authority.to_be_bytes()[2..]);
    for sub in subauthorities.iter().take(count as usize) {
        bytes.extend_from_slice(&(*sub as u32).to_le_bytes());
    }
    bytes
}

fn serve_connection(io: &proto::FrameIo, core: &mut ConsentCore, self_facts: &token::TokenFacts) -> ServeOutcome {
    // Handshake: hello -> welcome (protocol + broker identity + OS facts).
    let Some(hello_bytes) = io.read_frame() else {
        return ServeOutcome::Continue;
    };
    let hello: Value = match serde_json::from_slice(&hello_bytes) {
        Ok(value) => value,
        Err(_) => {
            log_line("PROTOCOL", "malformed hello");
            return ServeOutcome::Continue;
        }
    };
    if hello.get("t") != Some(&Value::String("hello".into()))
        || hello.get("protocol") != Some(&json!(PROTOCOL))
    {
        log_line("PROTOCOL", "hello rejected");
        return ServeOutcome::Continue;
    }
    let welcome = json!({
        "t": "welcome",
        "protocol": PROTOCOL,
        "brokerId": consent::BROKER_ID,
        "brokerRevision": consent::BROKER_REVISION,
        "osSessionId": self_facts.session_id,
        "principalUserSid": self_facts.user_sid,
        "logonSid": self_facts.logon_sid,
    });
    if !io.write_frame(serde_json::to_vec(&welcome).unwrap_or_default().as_slice()) {
        return ServeOutcome::Continue;
    }

    loop {
        let Some(frame) = io.read_frame() else {
            return ServeOutcome::Continue;
        };
        let message: Value = match serde_json::from_slice(&frame) {
            Ok(value) => value,
            Err(_) => {
                log_line("PROTOCOL", "malformed frame");
                return ServeOutcome::Fatal;
            }
        };
        let kind = message.get("t").and_then(Value::as_str).unwrap_or("");
        match kind {
            "consent" => {
                let reply = handle_consent(core, &message);
                if !io.write_frame(serde_json::to_vec(&reply).unwrap_or_default().as_slice()) {
                    return ServeOutcome::Continue;
                }
            }
            "verify" => {
                let approval = message.get("approval").cloned().unwrap_or(Value::Null);
                let (valid, reason) = core.verify_consume(&approval, timeutil::now_ms());
                log_line(
                    if valid { "CONSUMED" } else { "VERIFY_REFUSED" },
                    reason,
                );
                let reply = json!({ "t": "verifyResult", "valid": valid, "reason": reason });
                if !io.write_frame(serde_json::to_vec(&reply).unwrap_or_default().as_slice()) {
                    return ServeOutcome::Continue;
                }
            }
            "nonce" => {
                let nonce = message
                    .get("confirmationNonce")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let unused = if nonce.is_empty() {
                    false
                } else {
                    core.nonce_unused(nonce, timeutil::now_ms())
                };
                let reply = json!({ "t": "nonceState", "unused": unused });
                if !io.write_frame(serde_json::to_vec(&reply).unwrap_or_default().as_slice()) {
                    return ServeOutcome::Continue;
                }
            }
            "shutdown" => {
                let reply = json!({ "t": "ackShutdown" });
                let _ = io.write_frame(serde_json::to_vec(&reply).unwrap_or_default().as_slice());
                let _ = io.flush();
                return ServeOutcome::Shutdown;
            }
            _ => {
                log_line("PROTOCOL", "unknown message kind");
                return ServeOutcome::Fatal;
            }
        }
    }
}

fn handle_consent(core: &mut ConsentCore, message: &Value) -> Value {
    let request = match message.get("request") {
        Some(Value::Object(map)) if !map.is_empty() => Value::Object(map.clone()),
        _ => {
            return json!({ "t": "consentResult", "outcome": "REFUSED_SCOPE_INVALID", "detail": "missing request" });
        }
    };
    let validated = match consent::validate_request(&request) {
        Ok(validated) => validated,
        Err(err) => {
            log_line("REFUSED", err.code());
            return json!({ "t": "consentResult", "outcome": err.code(), "detail": "" });
        }
    };

    let digest_short: String = validated.approved_projection_sha256.chars().take(16).collect();
    log_line(
        "REQUEST",
        &format!("task={} digest={}", validated.task_id, digest_short),
    );

    let dialog_timeout = message
        .get("dialogTimeoutMs")
        .and_then(Value::as_u64)
        .map(|v| v.clamp(1_000, 600_000) as u32)
        .unwrap_or(DEFAULT_DIALOG_TIMEOUT_MS);

    let scope_get = |key: &str| {
        validated
            .scope_json
            .get(key)
            .map(|v| v.to_string())
            .unwrap_or_default()
    };
    let text = format_dialog_text(&validated, &scope_get);
    log_line("PROMPT", &format!("task={} dialogMs={}", validated.task_id, dialog_timeout));
    let outcome = dialog::confirm(&text, DIALOG_CAPTION, dialog_timeout);

    match outcome {
        dialog::DialogOutcome::Approved => {
            let minted = core.mint(&validated, timeutil::now_ms());
            core.register(&minted.approval);
            log_line("GRANTED", &format!("task={} digest={}", validated.task_id, digest_short));
            json!({ "t": "consentResult", "outcome": "APPROVED", "approval": minted.approval })
        }
        dialog::DialogOutcome::Denied => {
            log_line("DENIED", &format!("task={}", validated.task_id));
            json!({ "t": "consentResult", "outcome": "DENIED", "detail": "" })
        }
        dialog::DialogOutcome::DeniedTimeout => {
            log_line("DENIED_TIMEOUT", &format!("task={}", validated.task_id));
            json!({ "t": "consentResult", "outcome": "DENIED_TIMEOUT", "detail": "" })
        }
        dialog::DialogOutcome::NonInteractive => {
            log_line("REFUSED", "REFUSED_NONINTERACTIVE");
            json!({ "t": "consentResult", "outcome": "REFUSED_NONINTERACTIVE", "detail": "" })
        }
    }
}

fn format_dialog_text(validated: &consent::ValidatedRequest, scope_get: &dyn Fn(&str) -> String) -> String {
    let mut goal = validated.goal_preview.replace('\r', " ").replace('\n', " ");
    if validated.goal_preview.chars().count() > 96 {
        goal.push('…');
    }
    format!(
        "允许 Shun 将下面披露的 GOAL_TEXT 发送一次到 DeepSeek 云端吗?\n\
         Allow Shun to send the disclosed GOAL_TEXT to the DeepSeek cloud ONCE?\n\n\
         任务 Task: {}\n\
         目标预览 Goal preview: {}\n\n\
         披露投影 SHA-256 / disclosed projection digest:\n{}\n\n\
         目的地 Destination: {}\n\
         模型 Model: deepseek / deepseek-flash\n\
         限额 Limits: maxCalls={} maxInputTokens={} maxOutputTokens={} maxCostMicros={}\n\
         修订 Revisions: scope={} registry={} policy={} pricing={} revocationEpoch={}\n\
         有效期 Window: issued {} -> expires {}\n\n\
         「是」= 仅授权这一次发送 / Yes = authorize this ONE send only\n\
         「否」(默认)= 拒绝,零外发 / No (default) = deny, zero egress",
        validated.task_id,
        goal,
        validated.approved_projection_sha256,
        consent::DEEPSEEK_DESTINATION,
        num_of(&validated.scope_json, "maxCalls"),
        num_of(&validated.scope_json, "maxInputTokens"),
        num_of(&validated.scope_json, "maxOutputTokens"),
        num_of(&validated.scope_json, "maxCostMicros"),
        scope_get("scopeRevision"),
        scope_get("registryRevision"),
        scope_get("policyRevision"),
        scope_get("pricingRevision"),
        scope_get("revocationEpoch"),
        scope_get("issuedAt"),
        scope_get("expiresAt"),
    )
}

fn num_of(scope: &serde_json::Map<String, Value>, key: &str) -> String {
    scope.get(key).and_then(Value::as_number).and_then(|n| n.as_u64()).unwrap_or(0).to_string()
}
