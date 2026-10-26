//! The ONE trusted UI gesture: a real Win32 MessageBox confirmation owned by
//! the broker process on the interactive desktop. Fail-closed posture:
//!
//! - the broker prompts only when its CURRENT thread desktop IS the session's
//!   input desktop (compared by desktop object name). A broker running on a
//!   hidden/non-input desktop or a non-interactive window station refuses —
//!   it must never approve through a dialog nobody can actually see;
//! - default button is NO; closing the box (X, Esc, WM_CLOSE) denies;
//! - if nobody answers within the per-request timeout, the broker retries a
//!   WM_CLOSE against the dialog for a bounded grace window and then reports
//!   a timeout DENIAL. The dialog thread is only joined after a confirmed
//!   answer, so an orphaned box can never wedge the pipe loop.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use windows::core::{BOOL, PCWSTR};
use windows::Win32::Foundation::{HANDLE, HWND, LPARAM, WPARAM};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetUserObjectInformationW, GetThreadDesktop, OpenInputDesktop,
    DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, HDESK, UOI_NAME,
};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    EnumThreadWindows, MessageBoxW, PostMessageW, MB_DEFBUTTON2, MB_ICONWARNING, MB_TOPMOST,
    MB_YESNO, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE,
};

const WM_CLOSE: u32 = 0x0010;
const IDYES: i32 = 6;
/// Bounded grace for closing an unattended box before giving up on the
/// dialog thread (which is then deliberately left to itself).
const CLOSE_GRACE: Duration = Duration::from_millis(2_000);
const CLOSE_RETRY: Duration = Duration::from_millis(100);

pub enum DialogOutcome {
    Approved,
    Denied,
    DeniedTimeout,
    NonInteractive,
}

fn desktop_object_name(desk: HDESK) -> Option<String> {
    let mut buf = [0u16; 256];
    let mut needed = 0u32;
    let ok = unsafe {
        GetUserObjectInformationW(
            HANDLE(desk.0),
            UOI_NAME,
            Some(buf.as_mut_ptr().cast()),
            (buf.len() * 2) as u32,
            Some(&mut needed),
        )
    };
    if ok.is_err() || needed == 0 {
        return None;
    }
    let units = (needed as usize / 2).min(buf.len());
    let end = buf[..units].iter().position(|&c| c == 0).unwrap_or(units);
    Some(String::from_utf16_lossy(&buf[..end]))
}

/// True only when this process's current thread desktop IS the session input
/// desktop: the confirmation would be physically displayed to the user. A
/// broker on a service window station (OpenInputDesktop fails) or on a
/// hidden desktop inside the interactive station (name mismatch) must refuse
/// instead of approving invisibly.
fn on_interactive_input_desktop() -> bool {
    let input = unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) };
    let Ok(input_desk) = input else {
        return false;
    };
    let input_name = desktop_object_name(input_desk).unwrap_or_default();
    let current_desk = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
    let Ok(current_desk) = current_desk else {
        let _ = unsafe { CloseDesktop(input_desk) };
        return false;
    };
    let current_name = desktop_object_name(current_desk).unwrap_or_default();
    let _ = unsafe { CloseDesktop(input_desk) };
    !input_name.is_empty() && input_name == current_name
}

/// Show the bilingual confirmation and block until the user answers or the
/// timeout closes the box.
pub fn confirm(text: &str, caption: &str, timeout_ms: u32) -> DialogOutcome {
    if !on_interactive_input_desktop() {
        return DialogOutcome::NonInteractive;
    }

    let (tx_thread, rx_thread) = mpsc::channel::<u32>();
    let (tx_result, rx_result) = mpsc::channel::<MESSAGEBOX_RESULT>();
    let text_owned = text.to_string();
    let caption_owned = caption.to_string();

    let handle = thread::spawn(move || {
        unsafe {
            let _ = tx_thread.send(GetCurrentThreadId());
        }
        let mut text_units: Vec<u16> = text_owned.encode_utf16().collect();
        text_units.push(0);
        let mut caption_units: Vec<u16> = caption_owned.encode_utf16().collect();
        caption_units.push(0);
        // Deliberately no MB_SETFOREGROUND: the foreground-lock stall would
        // delay the prompt; MB_TOPMOST keeps it visibly on top instead.
        let style: MESSAGEBOX_STYLE = MB_YESNO | MB_DEFBUTTON2 | MB_TOPMOST | MB_ICONWARNING;
        let result = unsafe {
            MessageBoxW(
                None,
                PCWSTR(text_units.as_ptr()),
                PCWSTR(caption_units.as_ptr()),
                style,
            )
        };
        let _ = tx_result.send(result);
    });

    let Some(dialog_thread_id) = rx_thread.recv().ok() else {
        let _ = handle.join();
        return DialogOutcome::Denied;
    };
    match rx_result.recv_timeout(Duration::from_millis(u64::from(timeout_ms))) {
        Ok(answer) => {
            let _ = handle.join();
            if answer.0 as i32 == IDYES {
                DialogOutcome::Approved
            } else {
                // IDNO, and IDCANCEL from X/Esc/WM_CLOSE: all deny.
                DialogOutcome::Denied
            }
        }
        Err(_timeout) => {
            // Retry the close for a bounded grace: a WM_CLOSE posted before
            // the box finished creating is lost. Join ONLY after a confirmed
            // answer — an orphaned box must never wedge the pipe loop.
            let mut answered: Option<i32> = None;
            let deadline = Instant::now() + CLOSE_GRACE;
            while Instant::now() < deadline {
                close_thread_dialogs(dialog_thread_id);
                if let Ok(answer) = rx_result.try_recv() {
                    answered = Some(answer.0 as i32);
                    break;
                }
                thread::sleep(CLOSE_RETRY);
            }
            if let Some(answer) = answered {
                let _ = handle.join();
                if answer == IDYES {
                    DialogOutcome::Approved
                } else {
                    DialogOutcome::DeniedTimeout
                }
            } else {
                // Orphaned box: its late answer goes nowhere (the receiver is
                // dropped after return); the denial already stands.
                DialogOutcome::DeniedTimeout
            }
        }
    }
}

/// WM_CLOSE every top-level window of the dialog thread: the MessageBox
/// returns IDCANCEL, i.e. a denial, never an approval.
fn close_thread_dialogs(thread_id: u32) {
    unsafe extern "system" fn enum_cb(hwnd: HWND, _lparam: LPARAM) -> BOOL {
        let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
        BOOL(1)
    }
    unsafe {
        let _ = EnumThreadWindows(thread_id, Some(enum_cb), LPARAM(0));
    }
}
