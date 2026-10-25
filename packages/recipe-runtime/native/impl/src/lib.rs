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
use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::Foundation::{NtClose, OBJECT_ATTRIBUTES};
use windows::Wdk::Storage::FileSystem::{
    FileIdBothDirectoryInformation, NtOpenFile, NtQueryDirectoryFile, NtReadFile,
};
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING, OBJECT_ATTRIBUTE_FLAGS};
use windows::Win32::Storage::FileSystem::{
    GetDriveTypeW, GetFileInformationByHandle, GetFinalPathNameByHandleW, QueryDosDeviceW,
    BY_HANDLE_FILE_INFORMATION, FILE_READ_DATA, GETFINALPATHNAMEBYHANDLE_FLAGS,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;

const FILE_LIST_DIRECTORY: u32 = 0x00000001;
const FILE_READ_ATTRIBUTES: u32 = 0x00000080;
const SYNCHRONIZE: u32 = 0x00100000;
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
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

// --- Raw attestation and anchored file reads (independent post-state oracle)
// --- The same surface rules as above apply: raw values only, every check in
// --- the TypeScript layer.

/// QueryDosDeviceW verbatim (first NUL-terminated mapping of the multi-sz
/// result). This is a purely local object-manager namespace lookup: it never
/// opens or queries the volume the letter points at, so the JS admission
/// layer can attest a drive letter's device provenance before performing any
/// IO on that drive (mapped SMB roots are refused without any network op).
#[napi]
pub fn dos_device(letter: String) -> Option<String> {
    let mut letter_bytes: Vec<u16> = letter.encode_utf16().collect();
    letter_bytes.push(0);
    let mut target = [0u16; 1024];
    let len = unsafe { QueryDosDeviceW(PCWSTR(letter_bytes.as_ptr()), Some(&mut target)) };
    if len == 0 || len as usize > target.len() {
        return None;
    }
    let window = &target[..len as usize];
    let end = window.iter().position(|&c| c == 0).unwrap_or(window.len());
    Some(String::from_utf16_lossy(&window[..end]))
}

/// GetDriveTypeW verbatim (0..=6). A local kernel question about the drive
/// letter's device class; it performs no filesystem IO on the volume itself.
#[napi]
pub fn drive_type(root: String) -> Option<u32> {
    let mut root_bytes: Vec<u16> = root.encode_utf16().collect();
    root_bytes.push(0);
    Some(unsafe { GetDriveTypeW(PCWSTR(root_bytes.as_ptr())) })
}

/// Open one regular FILE anchored at an already-verified parent directory
/// handle: single name component, FILE_OPEN_REPARSE_POINT so a reparse entry
/// yields the reparse point itself (attributes refused in JS; the target is
/// never touched) and FILE_NON_DIRECTORY_FILE so only files open.
#[napi]
pub fn open_file(parent: BigInt, name: String) -> Option<BigInt> {
    let mut name_bytes: Vec<u16> = name.encode_utf16().collect();
    name_bytes.push(0);
    let unicode = UNICODE_STRING {
        Length: ((name_bytes.len() - 1) * 2) as u16,
        MaximumLength: (name_bytes.len() * 2) as u16,
        Buffer: PWSTR(name_bytes.as_mut_ptr()),
    };
    let parent_handle = match handle_from_raw(parent) {
        Some(handle) => handle,
        None => return None,
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
            FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes,
            &mut iosb,
            FILE_SHARE_ALL,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        )
    };
    if status.is_ok() {
        Some(handle_to_raw(handle))
    } else {
        None
    }
}

#[napi(object)]
pub struct FileRead {
    pub status: u32,
    pub returned: i64,
    pub data: Buffer,
}

#[napi(object)]
pub struct EntryIdentity {
    pub attrs: u32,
    /// The 64-bit file reference as an exact BigInt: file IDs exceed the
    /// double-precision safe-integer range, so a JS Number would silently
    /// round and break the identity cross-check.
    pub index: BigInt,
}

/// GetFileInformationByHandle attributes + file index (the 64-bit file
/// reference) for an open handle. The JS identity layer cross-checks every
/// opened object against the FileId enumerated from its already-verified
/// parent handle, so a same-name swap between enumeration and open is
/// refused before any content is read.
#[napi]
pub fn entry_id(handle: BigInt) -> Option<EntryIdentity> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let handle = handle_from_raw(handle)?;
    unsafe { GetFileInformationByHandle(handle, &mut info) }.ok()?;
    let reference = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);
    Some(EntryIdentity {
        attrs: info.dwFileAttributes,
        index: BigInt::from(reference),
    })
}

// Upper sanity bound for caller-supplied read sizes; the JS layer passes its
// own reviewed per-file cap (<= this) and re-validates the returned count.
const MAX_READ_BYTES: i64 = 8 << 20;

/// One NtReadFile round trip from the current file position into a fresh
/// buffer (synchronous non-alert handle, so no explicit byte offset). Raw
/// NTSTATUS and IO_STATUS_BLOCK.Information; the JS layer owns every check.
#[napi]
pub fn read_file(handle: BigInt, length: i64) -> Option<FileRead> {
    if length <= 0 || length > MAX_READ_BYTES {
        return None;
    }
    let handle = handle_from_raw(handle)?;
    let mut data = vec![0u8; length as usize];
    let mut iosb = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtReadFile(
            handle,
            None,
            None,
            None,
            &mut iosb,
            data.as_mut_ptr().cast(),
            length as u32,
            None,
            None,
        )
    };
    Some(FileRead {
        status: status.0 as u32,
        returned: iosb.Information as i64,
        data: Buffer::from(data),
    })
}
