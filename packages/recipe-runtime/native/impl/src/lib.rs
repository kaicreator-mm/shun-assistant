//! T04 trusted OS capability adapter (implementation side): the raw NT
//! syscalls the scoped file search needs, exposed to Node through napi-rs
//! over windows-rs. This is a Windows-only addon; the JS loader fails closed
//! when the compiled artifact is unavailable and never falls back to a
//! path-based walk.
//!
//! Deliberately minimal surface: no parsing, no bounds policy, no refusal
//! logic lives here. Every status, attribute mask and byte count is returned
//! verbatim to the reviewed TypeScript layer, which owns all validation.
#![allow(clippy::missing_safety_doc)]

use napi::bindgen_prelude::{BigInt, Buffer};
use napi_derive::napi;
use windows::core::PWSTR;
use windows::Wdk::Foundation::{NtClose, OBJECT_ATTRIBUTES};
use windows::Wdk::Storage::FileSystem::{
    FileIdBothDirectoryInformation, NtOpenFile, NtQueryDirectoryFile,
};
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING, OBJECT_ATTRIBUTE_FLAGS};
use windows::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
    GETFINALPATHNAMEBYHANDLE_FLAGS,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;

const FILE_LIST_DIRECTORY: u32 = 0x00000001;
const FILE_READ_ATTRIBUTES: u32 = 0x00000080;
const SYNCHRONIZE: u32 = 0x00100000;
const FILE_SHARE_ALL: u32 = 0x00000007;
const FILE_DIRECTORY_FILE: u32 = 0x00000001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const FILE_OPEN_REPARSE_POINT: u32 = 0x00200000;
const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
const FINAL_PATH_CHARS: usize = 600;
// Upper sanity bound for caller-supplied enumeration buffer sizes; the JS
// layer passes its own reviewed constant (262144) and re-validates every
// returned byte count against it.
const MAX_ENUM_BUFFER_BYTES: i64 = 1 << 26;

fn handle_from_raw(handle: BigInt) -> Option<HANDLE> {
    let (_sign_bit, value, lossless) = handle.get_u64();
    if lossless {
        Some(HANDLE(value as usize as *mut core::ffi::c_void))
    } else {
        None
    }
}

fn handle_to_raw(handle: HANDLE) -> BigInt {
    BigInt::from(handle.0 as usize as u64)
}

/// Open one directory. `parent` anchors name resolution inside an
/// already-verified directory object (null = absolute NT pathname in `name`,
/// which must already carry the `\??\` prefix built by the JS layer). The
/// FILE_OPEN_REPARSE_POINT option makes a junction/symlink entry open the
/// reparse point itself instead of its target. Any failure is null; the
/// distinction between statuses never changes the JS refusal outcome.
#[napi]
pub fn open_dir(parent: Option<BigInt>, name: String) -> Option<BigInt> {
    let mut name_bytes: Vec<u16> = name.encode_utf16().collect();
    name_bytes.push(0);
    let unicode = UNICODE_STRING {
        Length: ((name_bytes.len() - 1) * 2) as u16,
        MaximumLength: (name_bytes.len() * 2) as u16,
        Buffer: PWSTR(name_bytes.as_mut_ptr()),
    };
    let parent_handle = match parent {
        Some(parent) => match handle_from_raw(parent) {
            Some(handle) => handle,
            None => return None,
        },
        None => HANDLE::default(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent_handle,
        ObjectName: &unicode,
        Attributes: OBJECT_ATTRIBUTE_FLAGS(OBJ_CASE_INSENSITIVE),
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = HANDLE::default();
    let mut iosb = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtOpenFile(
            &mut handle,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes,
            &mut iosb,
            FILE_SHARE_ALL,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        )
    };
    if status.is_ok() {
        Some(handle_to_raw(handle))
    } else {
        None
    }
}

/// Raw file attributes of an open handle (GetFileInformationByHandle). The
/// JS layer applies the DIRECTORY/REPARSE_POINT bit tests itself.
#[napi]
pub fn entry_info(handle: BigInt) -> Option<u32> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let handle = handle_from_raw(handle)?;
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok.is_ok() {
        Some(info.dwFileAttributes)
    } else {
        None
    }
}

/// GetFinalPathNameByHandleW verbatim (with the `\\?\` namespace prefix where
/// the OS puts one); the JS layer strips and compares it.
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

#[napi(object)]
pub struct Enumerated {
    pub status: u32,
    pub returned: i64,
    pub data: Buffer,
}

/// One NtQueryDirectoryFile(FileIdBothDirectoryInformation) round trip into a
/// fresh buffer. `status` and `returned` are the raw NTSTATUS and
/// IO_STATUS_BLOCK.Information; the JS layer owns the chain parsing and every
/// bound check. The buffer is per-call, so no state is shared across calls.
#[napi]
pub fn enumerate(handle: BigInt, restart: bool, buffer_bytes: i64) -> Option<Enumerated> {
    if buffer_bytes <= 0 || buffer_bytes > MAX_ENUM_BUFFER_BYTES {
        return None;
    }
    let handle = handle_from_raw(handle)?;
    let mut data = vec![0u8; buffer_bytes as usize];
    let mut iosb = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtQueryDirectoryFile(
            handle,
            None,
            None,
            None,
            &mut iosb,
            data.as_mut_ptr().cast(),
            buffer_bytes as u32,
            FileIdBothDirectoryInformation,
            false,
            None,
            restart,
        )
    };
    Some(Enumerated {
        status: status.0 as u32,
        returned: iosb.Information as i64,
        data: Buffer::from(data),
    })
}

#[napi]
pub fn close(handle: BigInt) {
    if let Some(handle) = handle_from_raw(handle) {
        let status: NTSTATUS = unsafe { NtClose(handle) };
        debug_assert!(status.is_ok());
    }
}
