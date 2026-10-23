//! T04 physical-canary instrument (test-only): the minimal kernel32 surface
//! the canary tests need to prove OS primitives independently of the code
//! under test. Compiled as a SEPARATE addon from `shun-win32-impl` and built
//! on disjoint declarations: the implementation walks via ntdll
//! (NtOpenFile/NtQueryDirectoryFile) while these probes go through kernel32
//! CreateFileW flag semantics, so no canary result can be produced by the
//! implementation's own code path.
//!
//! Never imported by production code; only scoped-file-search.test.ts loads
//! this addon.
#![allow(clippy::missing_safety_doc)]

use napi::bindgen_prelude::BigInt;
use napi_derive::napi;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
    BY_HANDLE_FILE_INFORMATION, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_SHARE_MODE, GETFINALPATHNAMEBYHANDLE_FLAGS,
};

const FILE_READ_ATTRIBUTES: u32 = 0x00000080;
const FILE_SHARE_READ_WRITE: u32 = 0x00000003;
const OPEN_EXISTING: u32 = 3;
// FILE_FLAG_BACKUP_SEMANTICS (0x02000000) alone follows junctions/symlinks;
// adding FILE_FLAG_OPEN_REPARSE_POINT (0x00200000) opens the link object.
const FOLLOW_FLAGS: u32 = 0x02000000;
const NO_FOLLOW_FLAGS: u32 = 0x02200000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;
const FINAL_PATH_CHARS: usize = 600;

fn handle_from_raw(handle: BigInt) -> Option<HANDLE> {
    let (_sign_bit, value, lossless) = handle.get_u64();
    if lossless {
        Some(HANDLE(value as usize as *mut core::ffi::c_void))
    } else {
        None
    }
}

fn create_file(path: &str, share: u32, flags: u32) -> Option<u64> {
    let mut wide: Vec<u16> = path.encode_utf16().collect();
    wide.push(0);
    let opened = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_MODE(share),
            None,
            FILE_CREATION_DISPOSITION(OPEN_EXISTING),
            FILE_FLAGS_AND_ATTRIBUTES(flags),
            None,
        )
    };
    opened.ok().map(|handle| handle.0 as usize as u64)
}

#[napi]
pub fn open_no_follow(path: String) -> Option<BigInt> {
    create_file(&path, FILE_SHARE_READ_WRITE, NO_FOLLOW_FLAGS).map(|h| BigInt::from(h))
}

#[napi]
pub fn open_follow(path: String) -> Option<BigInt> {
    create_file(&path, FILE_SHARE_READ_WRITE, FOLLOW_FLAGS).map(|h| BigInt::from(h))
}

/// Open with share mode 0 to hold the target exclusively pinned.
#[napi]
pub fn pin_exclusive(path: String) -> Option<BigInt> {
    create_file(&path, 0, FOLLOW_FLAGS).map(|h| BigInt::from(h))
}

#[napi]
pub fn is_reparse(handle: BigInt) -> bool {
    let Some(handle) = handle_from_raw(handle) else {
        return false;
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    ok.is_ok() && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

#[napi]
pub fn final_path(handle: BigInt) -> Option<String> {
    let handle = handle_from_raw(handle)?;
    let mut buffer = [0u16; FINAL_PATH_CHARS];
    let len = unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, GETFINALPATHNAMEBYHANDLE_FLAGS(0)) };
    if len == 0 || len as usize > FINAL_PATH_CHARS {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..len as usize]))
}

#[napi]
pub fn close(handle: BigInt) {
    if let Some(handle) = handle_from_raw(handle) {
        let _ = unsafe { CloseHandle(handle) };
    }
}
