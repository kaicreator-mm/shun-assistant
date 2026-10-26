//! OS-token principal facts. The broker NEVER trusts a client-claimed pid or
//! JSON identity: every fact below is read from the process token through
//! GetTokenInformation, and connection admission is decided by comparing the
//! CONNECTING client's token against the broker's own token (same user SID,
//! same logon SID, same session id).

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, TokenGroups, TokenSessionId, TokenStatistics, TokenUser, PSID,
    TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[derive(Clone, Debug, PartialEq)]
pub struct TokenFacts {
    pub user_sid: String,
    pub logon_sid: String,
    pub session_id: u32,
    pub logon_luid: u64,
}

struct OwnedPwstr(PWSTR);

impl OwnedPwstr {
    fn to_string_lossy(&self) -> String {
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

impl Drop for OwnedPwstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.as_ptr().cast())));
            }
        }
    }
}

fn sid_to_string(sid: PSID) -> Option<String> {
    let mut pw = PWSTR::null();
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut pw) };
    if ok.is_err() || pw.is_null() {
        return None;
    }
    Some(OwnedPwstr(pw).to_string_lossy())
}

fn query_token_varlen(handle: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u8>> {
    let mut needed = 0u32;
    unsafe {
        let first = GetTokenInformation(handle, class, None, 0, &mut needed);
        if first.is_err() && needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        GetTokenInformation(
            handle,
            class,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
        .ok()?;
        Some(buf)
    }
}

/// Extract the security facts the broker binds connections to.
pub fn token_facts(handle: HANDLE) -> Option<TokenFacts> {
    let user_buf = query_token_varlen(handle, TokenUser)?;
    let user = unsafe { &*(user_buf.as_ptr() as *const TOKEN_USER) };
    let user_sid = sid_to_string(user.User.Sid)?;

    let groups_buf = query_token_varlen(handle, TokenGroups)?;
    let groups = unsafe { &*(groups_buf.as_ptr() as *const TOKEN_GROUPS) };
    const SE_GROUP_LOGON_ID: u32 = 0xC0_00_00_00;
    let mut logon_sid = None;
    let entries =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    for entry in entries {
        if entry.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID {
            logon_sid = sid_to_string(entry.Sid);
            break;
        }
    }

    let mut session_id = 0u32;
    unsafe {
        GetTokenInformation(
            handle,
            TokenSessionId,
            Some((&mut session_id as *mut u32).cast()),
            std::mem::size_of::<u32>() as u32,
            &mut 0,
        )
        .ok()?;
    }

    let stats_buf = query_token_varlen(handle, TokenStatistics)?;
    let stats = unsafe { &*(stats_buf.as_ptr() as *const TOKEN_STATISTICS) };
    let luid = stats.AuthenticationId;
    let logon_luid = ((luid.HighPart as u64) << 32) | u64::from(luid.LowPart);

    Some(TokenFacts {
        user_sid,
        logon_sid: logon_sid?,
        session_id,
        logon_luid,
    })
}

/// The broker's own principal facts (user SID, logon SID, session id, LUID).
pub fn self_facts() -> Option<TokenFacts> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let facts = token_facts(token);
        let _ = CloseHandle(token);
        facts
    }
}

/// Principal facts of the CONNECTING named-pipe client (OS token, never a
/// client-claimed identity). `None` when the token cannot be opened — the
/// caller refuses the connection in that case too.
pub fn client_facts(pipe: HANDLE) -> Option<TokenFacts> {
    let mut pid = 0u32;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }.ok()?;
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.ok()?;
    let facts = token_facts(token);
    unsafe {
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
    }
    facts
}
