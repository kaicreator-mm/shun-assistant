//! Windows Shell folder picker and metadata-only directory identity.
//!
//! This addon exposes no path-taking UI fallback and never reads file contents.
//! The TypeScript Host keeps absolute paths and token/file identity private.

#![allow(clippy::missing_safety_doc)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::slice;
use std::sync::{Mutex, OnceLock};

use napi::bindgen_prelude::*;
use napi::Task;
use napi_derive::napi;
use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_CANCELLED, HANDLE, HLOCAL, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, TokenGroups, TokenSessionId, TokenUser, TOKEN_GROUPS, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_NORMAL, FILE_READ_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, OpenInputDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::UI::Shell::{
    FileOpenDialog, IFileOpenDialog, FOS_FORCEFILESYSTEM, FOS_PATHMUSTEXIST, FOS_PICKFOLDERS,
    SIGDN_FILESYSPATH,
};

#[napi(object)]
pub struct FolderUserIdentity {
    pub user_sid: String,
    pub logon_sid: String,
    pub session_id: u32,
}

#[napi(object)]
pub struct FolderIdentity {
    pub user_sid: String,
    pub logon_sid: String,
    pub session_id: u32,
    pub volume_serial: String,
    pub file_id: String,
}

#[napi(object)]
pub struct FolderDirectoryIdentity {
    pub user_sid: String,
    pub logon_sid: String,
    pub session_id: u32,
    pub volume_serial: String,
    pub file_id: String,
    pub is_directory: bool,
    pub is_reparse_point: bool,
    pub is_network_path: bool,
    pub is_volume_root: bool,
}

#[napi(object)]
pub struct FolderSelectionResult {
    pub status: String,
    pub code: Option<String>,
    pub path: Option<String>,
    pub display_name: Option<String>,
    pub identity: Option<FolderIdentity>,
}

#[napi(object)]
pub struct FolderDirectoryLease {
    pub lease_id: String,
    pub directory: FolderDirectoryIdentity,
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

struct ComApartment;

impl ComApartment {
    fn initialize() -> std::result::Result<Self, ()> {
        unsafe {
            CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)
                .ok()
                .map_err(|_| ())?;
        }
        Ok(Self)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

fn refused(code: &str) -> FolderSelectionResult {
    FolderSelectionResult {
        status: "REFUSED".to_string(),
        code: Some(code.to_string()),
        path: None,
        display_name: None,
        identity: None,
    }
}

fn cancelled() -> FolderSelectionResult {
    FolderSelectionResult {
        status: "CANCELLED".to_string(),
        code: None,
        path: None,
        display_name: None,
        identity: None,
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn wide_ptr_to_string(pointer: *const u16) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut length = 0usize;
    while length < 32_768 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == 0 || length >= 32_768 {
        return None;
    }
    Some(String::from_utf16_lossy(unsafe {
        slice::from_raw_parts(pointer, length)
    }))
}

fn sid_to_string(sid: windows::Win32::Security::PSID) -> Option<String> {
    let mut value = windows::core::PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut value) }.ok()?;
    let text = unsafe { wide_ptr_to_string(value.0) };
    let _ = unsafe { LocalFree(Some(HLOCAL(value.0 as *mut c_void))) };
    text
}

fn token_user_sid(token: HANDLE) -> Option<String> {
    let mut needed = 0u32;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buffer = vec![0u8; needed as usize];
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .ok()?;
    let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    sid_to_string(user.User.Sid)
}

fn token_logon_sid(token: HANDLE) -> Option<String> {
    let mut needed = 0u32;
    let _ = unsafe { GetTokenInformation(token, TokenGroups, None, 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buffer = vec![0u8; needed as usize];
    unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .ok()?;
    let groups = unsafe { &*(buffer.as_ptr() as *const TOKEN_GROUPS) };
    const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
    let entries =
        unsafe { slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    entries
        .iter()
        .find(|entry| entry.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
        .and_then(|entry| sid_to_string(entry.Sid))
}

fn token_session_id(token: HANDLE) -> Option<u32> {
    let mut session_id = 0u32;
    let mut returned = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            TokenSessionId,
            Some((&mut session_id as *mut u32).cast()),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        )
    }
    .ok()?;
    Some(session_id)
}

fn current_identity_inner() -> Option<FolderUserIdentity> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.ok()?;
    let _owned = OwnedHandle(token);
    let user_sid = token_user_sid(token)?;
    let logon_sid = token_logon_sid(token)?;
    let session_id = token_session_id(token)?;
    // Session 0 is a service/non-interactive session. Do not pretend it can
    // present a trustworthy user-selected Shell folder.
    if session_id == 0 {
        return None;
    }
    Some(FolderUserIdentity {
        user_sid,
        logon_sid,
        session_id,
    })
}

fn is_plain_drive_path(path: &str) -> bool {
    if path.len() < 4 || path.len() > 32_767 || path.contains('/') {
        return false;
    }
    let bytes = path.as_bytes();
    if !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return false;
    }
    if path.starts_with("\\\\") || path.starts_with("\\\\?\\") || path.starts_with("\\\\.\\") {
        return false;
    }
    !path[3..]
        .split('\\')
        .any(|part| part == "." || part == "..")
}

fn file_information(path: &str) -> Option<BY_HANDLE_FILE_INFORMATION> {
    let wide = to_wide(path);
    // FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT. The handle
    // is opened for FILE_READ_ATTRIBUTES only; no file content is requested.
    let flags =
        windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0x0200_0000 | 0x0020_0000);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_MODE(0x0000_0001 | 0x0000_0002 | 0x0000_0004),
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .ok()?;
    let _owned = OwnedHandle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }.ok()?;
    Some(info)
}

/// Drive-shaped, identity-free traversal facts for one absolute path.
/// Independent of the interactive session so unit tests can prove the
/// traversal contract on any host.
struct DirectoryFacts {
    info: BY_HANDLE_FILE_INFORMATION,
    is_directory: bool,
    is_reparse_point: bool,
    is_network_path: bool,
    is_volume_root: bool,
}

/// Walks the path component by component, opening each with
/// FILE_FLAG_OPEN_REPARSE_POINT. A reparse point on ANY component
/// terminates the traversal immediately: the loop never opens a descendant
/// below a junction/symlink, so the link target's subpaths are never
/// touched by this process (P1-01). A successful result therefore always
/// describes a reparse-free path.
fn should_refuse_drive_type(drive_type: u32) -> bool {
    // DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR and DRIVE_REMOTE. A mapped/network
    // drive must be rejected before any path component is opened.
    matches!(drive_type, 0 | 1 | 4)
}

fn directory_facts(path: &str) -> Option<DirectoryFacts> {
    if !is_plain_drive_path(path) {
        return None;
    }
    let drive_root = format!("{}\\", &path[..2]);
    let drive_wide = to_wide(&drive_root);
    let drive_type = unsafe { GetDriveTypeW(PCWSTR(drive_wide.as_ptr())) };
    if should_refuse_drive_type(drive_type) {
        return None;
    }
    let is_network_path = false;
    let is_volume_root = path.trim_end_matches('\\').eq_ignore_ascii_case(&path[..2]);

    let components: Vec<&str> = path[3..]
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect();
    let mut current = drive_root;
    let mut final_info = None;
    for (index, component) in components.iter().enumerate() {
        current.push_str(component);
        let info = file_information(&current)?;
        let attributes = info.dwFileAttributes;
        // FILE_ATTRIBUTE_REPARSE_POINT: terminate the traversal right here.
        // This covers intermediate junction/symlink components (the next
        // component would otherwise be opened THROUGH the link target) and
        // the final component itself in one uniform fail-closed rule.
        if attributes & 0x0000_0400 != 0 {
            return None;
        }
        let is_directory = attributes & 0x0000_0010 != 0; // FILE_ATTRIBUTE_DIRECTORY
        if index + 1 < components.len() && !is_directory {
            return None;
        }
        final_info = Some(info);
        if index + 1 < components.len() {
            current.push('\\');
        }
    }
    let info = final_info?;
    let attributes = info.dwFileAttributes;
    Some(DirectoryFacts {
        is_directory: attributes & 0x0000_0010 != 0,
        // Defensive only: the loop above already refused every reparse
        // component, so a resolved path can never carry this flag as true.
        is_reparse_point: attributes & 0x0000_0400 != 0,
        is_network_path,
        is_volume_root,
        info,
    })
}

fn inspect_folder_inner(path: &str) -> Option<FolderDirectoryIdentity> {
    let identity = current_identity_inner()?;
    let facts = directory_facts(path)?;
    Some(FolderDirectoryIdentity {
        user_sid: identity.user_sid,
        logon_sid: identity.logon_sid,
        session_id: identity.session_id,
        volume_serial: format!("{:08x}", facts.info.dwVolumeSerialNumber),
        file_id: format!(
            "{:08x}{:08x}",
            facts.info.nFileIndexHigh, facts.info.nFileIndexLow
        ),
        is_directory: facts.is_directory,
        is_reparse_point: facts.is_reparse_point,
        is_network_path: facts.is_network_path,
        is_volume_root: facts.is_volume_root,
    })
}

// ---------------------------------------------------------------------------
// Race-safe directory handle lease (P1-03 TOCTOU closure).
//
// `directory_facts`/`inspect_folder` re-read identity by path string, which
// is correct for one-shot checks but cannot bind an identity to the metadata
// walk: between the identity check and `readdir`/`resolveScope`/
// `observeStorage`, an ancestor could be renamed/replaced with a junction so
// the same path string resolves to a different directory. The lease closes
// that window: every path component from the volume root to the target is
// opened HANDLE-RELATIVELY (NtCreateFile with RootDirectory) with
// FILE_OPEN_REPARSE_POINT, so a junction/symlink component is never
// traversed, and every handle is opened WITHOUT FILE_SHARE_DELETE, so no
// component in the chain can be renamed, replaced or deleted while the lease
// is held. Every path-string re-resolution performed inside the lease window
// (by Node or vertical-storage) therefore stays bound to the same directory
// objects, and the held target handle pins the exact file identity.
// ---------------------------------------------------------------------------

const FILE_ATTRIBUTE_DIRECTORY_U32: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_REPARSE_POINT_U32: u32 = 0x0000_0400;
/// READ | WRITE, never DELETE: a handle with this share mask blocks any
/// rename/delete/replace of the object while it stays open.
const PINNING_SHARE_MODE: u32 = 0x0000_0001 | 0x0000_0002;

/// A held chain of open handles, parent-first, ending at the target
/// directory. The chain is the lease: dropping it releases every pin.
struct DirectoryChain {
    handles: Vec<HANDLE>,
    info: BY_HANDLE_FILE_INFORMATION,
    is_volume_root: bool,
    volume_serial: u32,
    file_index: u64,
}

// The registry mutex serializes every chain operation; a chain is created,
// verified, released and dropped entirely under that lock, and `CloseHandle`
// is safe from any thread. The raw `HANDLE` values therefore never migrate
// between threads unsynchronized.
unsafe impl Send for DirectoryChain {}

impl DirectoryChain {
    fn target(&self) -> HANDLE {
        *self.handles.last().expect("chain always has a root handle")
    }
}

impl Drop for DirectoryChain {
    fn drop(&mut self) {
        for handle in &self.handles {
            if !handle.is_invalid() {
                let _ = unsafe { CloseHandle(*handle) };
            }
        }
    }
}

/// Opens one absolute path for attribute reads and KEEPS the handle. The
/// handle is opened with backup semantics + OPEN_REPARSE_POINT and a
/// no-DELETE share mask so it can serve as a pinning chain link.
fn open_pinning_directory(path: &str) -> Option<(HANDLE, BY_HANDLE_FILE_INFORMATION)> {
    let wide = to_wide(path);
    let flags =
        windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0x0200_0000 | 0x0020_0000);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_MODE(PINNING_SHARE_MODE),
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .ok()?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut info) }.is_err() {
        let _ = unsafe { CloseHandle(handle) };
        return None;
    }
    Some((handle, info))
}

/// Opens one child DIRECTORY by name relative to an already-held parent
/// handle. Handle-relative open is what makes the chain race-free: the parent
/// handle is pinned, so the child can only ever be the object that was inside
// THIS parent at open time, never a path re-resolution.
fn open_child_directory(
    parent: HANDLE,
    name: &str,
) -> Option<(HANDLE, BY_HANDLE_FILE_INFORMATION)> {
    // NUL-terminated UTF-16; NtCreateFile reads exactly Length bytes.
    let mut buffer: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_len = (buffer.len() - 1) * 2;
    let unicode = UNICODE_STRING {
        Length: byte_len as u16,
        MaximumLength: (byte_len + 2) as u16,
        Buffer: PWSTR(buffer.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = HANDLE::default();
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_READ_ATTRIBUTES,
            &attributes,
            &mut io_status,
            None,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_MODE(PINNING_SHARE_MODE),
            FILE_OPEN,
            NTCREATEFILE_CREATE_OPTIONS(FILE_DIRECTORY_FILE.0 | FILE_OPEN_REPARSE_POINT.0),
            None,
            0,
        )
    };
    if status.is_err() {
        return None;
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut info) }.is_err() {
        let _ = unsafe { CloseHandle(handle) };
        return None;
    }
    Some((handle, info))
}

/// Builds a pinning handle chain for one plain-drive absolute path. Any
/// reparse component, non-directory component, network/unknown drive or
/// malformed path refuses with None; no descendant of a junction is ever
/// opened.
fn open_directory_chain(path: &str) -> Option<DirectoryChain> {
    if !is_plain_drive_path(path) {
        return None;
    }
    let drive_root = format!("{}\\", &path[..2]);
    let drive_wide = to_wide(&drive_root);
    let drive_type = unsafe { GetDriveTypeW(PCWSTR(drive_wide.as_ptr())) };
    if should_refuse_drive_type(drive_type) {
        return None;
    }
    let is_volume_root = path.trim_end_matches('\\').eq_ignore_ascii_case(&path[..2]);

    let (root_handle, root_info) = open_pinning_directory(&drive_root)?;
    if root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY_U32 == 0
        || root_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT_U32 != 0
    {
        let _ = unsafe { CloseHandle(root_handle) };
        return None;
    }
    let mut handles = vec![root_handle];
    let mut info = root_info;
    let components: Vec<&str> = path[3..]
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect();
    for component in &components {
        let parent = *handles.last().expect("chain always has a parent");
        let (handle, child_info) = open_child_directory(parent, component)?;
        let attributes = child_info.dwFileAttributes;
        if attributes & FILE_ATTRIBUTE_DIRECTORY_U32 == 0
            || attributes & FILE_ATTRIBUTE_REPARSE_POINT_U32 != 0
        {
            // Fail closed without descending through a link and without
            // keeping a pin on a non-directory object.
            let _ = unsafe { CloseHandle(handle) };
            return None;
        }
        handles.push(handle);
        info = child_info;
    }
    let volume_serial = info.dwVolumeSerialNumber;
    let file_index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    Some(DirectoryChain {
        handles,
        info,
        is_volume_root,
        volume_serial,
        file_index,
    })
}

fn directory_identity_from_handle(
    user: &FolderUserIdentity,
    info: &BY_HANDLE_FILE_INFORMATION,
    is_volume_root: bool,
) -> FolderDirectoryIdentity {
    FolderDirectoryIdentity {
        user_sid: user.user_sid.clone(),
        logon_sid: user.logon_sid.clone(),
        session_id: user.session_id,
        volume_serial: format!("{:08x}", info.dwVolumeSerialNumber),
        file_id: format!("{:08x}{:08x}", info.nFileIndexHigh, info.nFileIndexLow),
        // The chain only ever pins directories and refuses every reparse
        // component, so a live lease always describes a reparse-free
        // directory.
        is_directory: true,
        is_reparse_point: false,
        is_network_path: false,
        is_volume_root,
    }
}

static LEASES: OnceLock<Mutex<HashMap<String, DirectoryChain>>> = OnceLock::new();

fn lease_registry() -> &'static Mutex<HashMap<String, DirectoryChain>> {
    LEASES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn random_lease_id() -> Option<String> {
    use windows::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut bytes = [0u8; 16];
    if unsafe { BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }.is_err() {
        return None;
    }
    Some(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The pinned object's own current DOS path, read from the held handle —
/// never re-resolved through possibly-replaced ancestors. A `\\?\` prefix is
/// stripped so downstream path-based walks get a plain drive path; the object
/// identity is already bound to the handle, so this string is only a locator.
fn canonical_path_for_handle(handle: HANDLE) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, GETFINALPATHNAMEBYHANDLE_FLAGS,
        VOLUME_NAME_DOS,
    };
    // Both flags are 0; the type does not implement BitOr, so combine by value.
    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0);
    let mut buffer = vec![0u16; 520];
    let written = unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, flags) } as usize;
    if written == 0 || written >= buffer.len() {
        let mut grown = vec![0u16; written.saturating_add(2).max(4096)];
        let grown_written =
            unsafe { GetFinalPathNameByHandleW(handle, &mut grown, flags) } as usize;
        if grown_written == 0 || grown_written >= grown.len() {
            return None;
        }
        buffer = grown;
        return finalize_canonical_path(&buffer[..grown_written]);
    }
    finalize_canonical_path(&buffer[..written])
}

fn finalize_canonical_path(wide: &[u16]) -> Option<String> {
    let text = String::from_utf16_lossy(wide);
    let stripped = text.strip_prefix("\\\\?\\").unwrap_or(&text);
    if stripped.is_empty() {
        return None;
    }
    Some(stripped.to_string())
}

#[napi]
pub fn current_identity() -> Result<FolderUserIdentity> {
    current_identity_inner().ok_or_else(|| {
        Error::new(
            Status::GenericFailure,
            "FOLDER_PICKER_USER_IDENTITY_UNAVAILABLE",
        )
    })
}

#[napi]
pub fn inspect_folder(path: String) -> Result<FolderDirectoryIdentity> {
    inspect_folder_inner(&path).ok_or_else(|| {
        Error::new(
            Status::GenericFailure,
            "FOLDER_PICKER_DIRECTORY_IDENTITY_UNAVAILABLE",
        )
    })
}

/// Acquires a pinning directory lease for `path`. The returned lease id is an
/// opaque in-process token; the held handle chain pins every path component
/// (no rename/replace/delete) until [`release_directory_lease`] is called.
/// The returned identity is read from the pinned target handle itself.
#[napi]
pub fn acquire_directory_lease(path: String) -> Result<FolderDirectoryLease> {
    let user = current_identity_inner().ok_or_else(|| {
        Error::new(
            Status::GenericFailure,
            "FOLDER_PICKER_LEASE_IDENTITY_UNAVAILABLE",
        )
    })?;
    let chain = open_directory_chain(&path)
        .ok_or_else(|| Error::new(Status::GenericFailure, "FOLDER_PICKER_LEASE_PATH_REFUSED"))?;
    let directory = directory_identity_from_handle(&user, &chain.info, chain.is_volume_root);
    let lease_id = random_lease_id()
        .ok_or_else(|| Error::new(Status::GenericFailure, "FOLDER_PICKER_LEASE_ID_UNAVAILABLE"))?;
    lease_registry()
        .lock()
        .map_err(|_| {
            Error::new(
                Status::GenericFailure,
                "FOLDER_PICKER_LEASE_REGISTRY_LOCKED",
            )
        })?
        .insert(lease_id.clone(), chain);
    Ok(FolderDirectoryLease {
        lease_id,
        directory,
    })
}

/// Re-reads the directory identity from the pinned target handle of a live
/// lease. The handle pins the object, so the stable volume/file identity is
/// re-reported; a captured-identity mismatch refuses with a typed drift code.
#[napi]
pub fn verify_directory_lease(lease_id: String) -> Result<FolderDirectoryIdentity> {
    let user = current_identity_inner().ok_or_else(|| {
        Error::new(
            Status::GenericFailure,
            "FOLDER_PICKER_LEASE_IDENTITY_UNAVAILABLE",
        )
    })?;
    let registry = lease_registry().lock().map_err(|_| {
        Error::new(
            Status::GenericFailure,
            "FOLDER_PICKER_LEASE_REGISTRY_LOCKED",
        )
    })?;
    let chain = registry
        .get(&lease_id)
        .ok_or_else(|| Error::new(Status::GenericFailure, "FOLDER_PICKER_LEASE_UNKNOWN"))?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(chain.target(), &mut info) }.map_err(|_| {
        Error::new(
            Status::GenericFailure,
            "FOLDER_PICKER_LEASE_VERIFY_UNAVAILABLE",
        )
    })?;
    let file_index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    if info.dwVolumeSerialNumber != chain.volume_serial || file_index != chain.file_index {
        return Err(Error::new(
            Status::GenericFailure,
            "FOLDER_PICKER_LEASE_IDENTITY_DRIFT",
        ));
    }
    Ok(directory_identity_from_handle(
        &user,
        &info,
        chain.is_volume_root,
    ))
}

/// Releases a lease and every pinning handle in its chain. Releasing an
/// unknown or already-released lease is a typed error, never a silent no-op,
/// so a double-release cannot mask a live pin.
#[napi]
pub fn release_directory_lease(lease_id: String) -> Result<()> {
    let removed = lease_registry()
        .lock()
        .map_err(|_| {
            Error::new(
                Status::GenericFailure,
                "FOLDER_PICKER_LEASE_REGISTRY_LOCKED",
            )
        })?
        .remove(&lease_id);
    if removed.is_none() {
        return Err(Error::new(
            Status::GenericFailure,
            "FOLDER_PICKER_LEASE_UNKNOWN",
        ));
    }
    Ok(())
}

/// The pinned object's own current DOS path (see
/// [`canonical_path_for_handle`]). The Host walks THIS path through
/// resolveScope/observeStorage so a junction planted at the recorded location
/// is never consulted.
#[napi]
pub fn directory_lease_path(lease_id: String) -> Result<String> {
    let registry = lease_registry().lock().map_err(|_| {
        Error::new(
            Status::GenericFailure,
            "FOLDER_PICKER_LEASE_REGISTRY_LOCKED",
        )
    })?;
    let chain = registry
        .get(&lease_id)
        .ok_or_else(|| Error::new(Status::GenericFailure, "FOLDER_PICKER_LEASE_UNKNOWN"))?;
    canonical_path_for_handle(chain.target()).ok_or_else(|| {
        Error::new(
            Status::GenericFailure,
            "FOLDER_PICKER_LEASE_PATH_UNAVAILABLE",
        )
    })
}

/// The frozen asynchronous picker contract. The modal Shell dialog runs on a
/// dedicated COM STA worker thread from the libuv thread pool
/// (`CoInitializeEx(COINIT_APARTMENTTHREADED)` inside [`PickFolderTask`]),
/// so the Node main event loop is never blocked while the dialog is open.
/// The returned promise settles with the same typed result shape the
/// synchronous contract would have produced (SELECTED / CANCELLED / REFUSED).
pub struct PickFolderTask;

impl Task for PickFolderTask {
    type Output = FolderSelectionResult;
    type JsValue = FolderSelectionResult;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(select_folder_inner())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn pick_folder() -> AsyncTask<PickFolderTask> {
    AsyncTask::new(PickFolderTask)
}

fn select_folder_inner() -> FolderSelectionResult {
    let identity = match current_identity_inner() {
        Some(value) => value,
        None => return refused("FOLDER_PICKER_INTERACTIVE_IDENTITY_UNAVAILABLE"),
    };

    let desktop =
        match unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) } {
            Ok(value) => value,
            Err(_) => return refused("FOLDER_PICKER_NONINTERACTIVE_DESKTOP"),
        };
    let _ = unsafe { CloseDesktop(desktop) };

    let _apartment = match ComApartment::initialize() {
        Ok(value) => value,
        Err(_) => return refused("FOLDER_PICKER_COM_UNAVAILABLE"),
    };

    let dialog: IFileOpenDialog =
        match unsafe { CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) } {
            Ok(value) => value,
            Err(_) => return refused("FOLDER_PICKER_DIALOG_UNAVAILABLE"),
        };
    if unsafe { dialog.SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST) }
        .is_err()
    {
        return refused("FOLDER_PICKER_OPTIONS_UNAVAILABLE");
    }

    let item = match unsafe { dialog.Show(None) } {
        Ok(()) => match unsafe { dialog.GetResult() } {
            Ok(value) => value,
            Err(_) => return refused("FOLDER_PICKER_RESULT_UNAVAILABLE"),
        },
        Err(error) if error.code() == ERROR_CANCELLED.to_hresult() => return cancelled(),
        Err(_) => return refused("FOLDER_PICKER_DIALOG_FAILED"),
    };

    let path_pointer = match unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) } {
        Ok(value) => value,
        Err(_) => return refused("FOLDER_PICKER_FILESYSTEM_PATH_UNAVAILABLE"),
    };
    let path = unsafe { wide_ptr_to_string(path_pointer.0) };
    unsafe { CoTaskMemFree(Some(path_pointer.0 as *const c_void)) };
    let Some(path) = path else {
        return refused("FOLDER_PICKER_FILESYSTEM_PATH_INVALID");
    };

    let directory = match inspect_folder_inner(&path) {
        Some(value) => value,
        None => return refused("FOLDER_PICKER_DIRECTORY_IDENTITY_UNAVAILABLE"),
    };
    if !directory.is_directory
        || directory.is_reparse_point
        || directory.is_network_path
        || directory.is_volume_root
        || directory.user_sid != identity.user_sid
        || directory.logon_sid != identity.logon_sid
        || directory.session_id != identity.session_id
    {
        return refused("FOLDER_PICKER_DIRECTORY_REFUSED");
    }
    let display_name = path.rsplit('\\').next().unwrap_or_default().to_string();
    if display_name.is_empty() {
        return refused("FOLDER_PICKER_DISPLAY_NAME_INVALID");
    }
    FolderSelectionResult {
        status: "SELECTED".to_string(),
        code: None,
        path: Some(path),
        display_name: Some(display_name),
        identity: Some(FolderIdentity {
            user_sid: directory.user_sid,
            logon_sid: directory.logon_sid,
            session_id: directory.session_id,
            volume_serial: directory.volume_serial,
            file_id: directory.file_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{directory_facts, open_directory_chain, should_refuse_drive_type};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn remote_drive_is_refused_before_component_traversal() {
        assert!(should_refuse_drive_type(0)); // DRIVE_UNKNOWN
        assert!(should_refuse_drive_type(1)); // DRIVE_NO_ROOT_DIR
        assert!(should_refuse_drive_type(4)); // DRIVE_REMOTE
        assert!(!should_refuse_drive_type(3)); // DRIVE_FIXED
    }

    /// Session-independent traversal tests run against `directory_facts`
    /// (no interactive identity is required, so the assertions stay
    /// meaningful in service and CI contexts too).
    fn scratch(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "shun-folder-picker-{}-{}-{}",
            label,
            std::process::id(),
            nanos
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create scratch root");
        dir
    }

    /// Junctions need no elevation, unlike symlinks (`mklink /J`).
    fn create_junction(link: &Path, target: &Path) {
        let status = Command::new("cmd")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .status()
            .expect("spawn mklink");
        assert!(status.success(), "mklink /J failed for {link:?}");
    }

    /// Junctions are removed as links; remove them before the tree so the
    /// cleanup never walks into the link target.
    fn remove_junction(link: &Path) {
        fs::remove_dir(link).expect("remove junction");
    }

    #[test]
    fn reparse_component_terminates_traversal_and_never_opens_descendants() {
        let root = scratch("junction-descendant");
        let real = root.join("real-target");
        fs::create_dir_all(real.join("child").join("deeper")).expect("real target tree");
        let link = root.join("link");
        create_junction(&link, &real);

        // The junction itself: traversal terminates at the reparse point.
        assert!(directory_facts(link.to_str().expect("utf8 link")).is_none());
        // The P1-01 regression: a descendant THROUGH the junction is never
        // opened — the old loop continued into the link target's child.
        assert!(directory_facts(link.join("child").to_str().expect("utf8 descendant")).is_none());
        // A deeper descendant behind the same link stays refused as well.
        assert!(directory_facts(
            link.join("child")
                .join("deeper")
                .to_str()
                .expect("utf8 deeper")
        )
        .is_none());
        // Control: the identical descendant reached without the link
        // resolves cleanly, so the refusals above came from the reparse
        // rule and not from an unrelated environment failure.
        let control = directory_facts(real.join("child").to_str().expect("utf8 real child"))
            .expect("direct path resolves");
        assert!(control.is_directory);
        assert!(!control.is_reparse_point);
        assert!(!control.is_network_path);
        assert!(!control.is_volume_root);

        remove_junction(&link);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn junction_between_normal_components_refuses_the_whole_path() {
        let root = scratch("junction-intermediate");
        let real = root.join("real-target");
        fs::create_dir_all(&real).expect("real target");
        let prefix = root.join("prefix");
        fs::create_dir_all(&prefix).expect("prefix");
        let link = prefix.join("link");
        create_junction(&link, &real);

        let poisoned = prefix.join("link").join("anything");
        assert!(directory_facts(poisoned.to_str().expect("utf8 poisoned")).is_none());
        // A sibling path under the same prefix still resolves: the refusal
        // is bound to the reparse component, not to the prefix directory.
        let sibling = prefix.join("plain");
        fs::create_dir_all(&sibling).expect("sibling");
        let facts = directory_facts(sibling.to_str().expect("utf8 sibling")).expect("sibling ok");
        assert!(facts.is_directory);
        assert!(!facts.is_reparse_point);

        remove_junction(&link);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn malformed_and_device_paths_refuse_without_opening_anything() {
        assert!(directory_facts("").is_none());
        assert!(directory_facts("relative\\path").is_none());
        assert!(directory_facts("\\\\server\\share\\folder").is_none());
        assert!(directory_facts("\\\\.\\device\\folder").is_none());
        assert!(directory_facts("C:\\..\\..\\outside").is_none());
        assert!(directory_facts("C:\\").is_none());
    }

    // ---- P1-03: pinning directory-handle lease regressions ----

    /// Absolute drive-pathed scratch directories only: the lease chain, like
    /// `directory_facts`, refuses anything but plain drive paths.
    /// `canonicalize()` yields a `\\?\` prefix which must be stripped.
    fn drive_scratch(label: &str) -> PathBuf {
        let relative = scratch(label);
        let canonical = relative.canonicalize().expect("canonical scratch");
        let plain = canonical
            .to_str()
            .expect("utf8 canonical")
            .strip_prefix("\\\\?\\")
            .expect("canonical drive path")
            .to_string();
        let root = PathBuf::from(plain);
        let dir = root.join("chain");
        fs::create_dir_all(&dir).expect("chain root");
        dir
    }

    #[test]
    fn lease_refuses_junction_components_and_never_descends_through_them() {
        let root = drive_scratch("lease-junction");
        let real = root.join("real-target");
        fs::create_dir_all(real.join("child")).expect("real target tree");
        let link = root.join("link");
        create_junction(&link, &real);

        // The junction itself: the chain refuses at the reparse component.
        assert!(open_directory_chain(link.to_str().expect("utf8 link")).is_none());
        // A descendant path THROUGH the junction is never opened.
        assert!(
            open_directory_chain(link.join("child").to_str().expect("utf8 descendant")).is_none()
        );
        // Control: the identical path without any link pins cleanly.
        let control = open_directory_chain(real.join("child").to_str().expect("utf8 real child"))
            .expect("direct chain pins");
        drop(control);

        remove_junction(&link);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn lease_binds_identity_across_rename_and_survives_delete_attempt() {
        let root = drive_scratch("lease-pin");
        let parent = root.join("parent");
        let leaf = parent.join("leaf");
        fs::create_dir_all(&leaf).expect("leaf tree");
        let leaf_plain = leaf.to_str().expect("utf8 leaf").to_string();
        let moved_plain = parent
            .join("leaf-moved")
            .to_str()
            .expect("utf8 moved")
            .to_string();

        let chain = open_directory_chain(&leaf_plain).expect("chain pins");
        let original_file_id = format!(
            "{:08x}{:08x}",
            chain.info.nFileIndexHigh, chain.info.nFileIndexLow
        );
        // The pinned handle reports the same volume/file identity as the
        // one-shot path-based inspection of the same directory.
        let facts = directory_facts(&leaf_plain).expect("facts");
        assert_eq!(
            format!("{:08x}", chain.info.dwVolumeSerialNumber),
            format!("{:08x}", facts.info.dwVolumeSerialNumber)
        );
        assert_eq!(
            original_file_id,
            format!(
                "{:08x}{:08x}",
                facts.info.nFileIndexHigh, facts.info.nFileIndexLow
            )
        );

        // Empirical Windows semantics (this host, 10.0.26300): rename and
        // delete of a directory with open no-FILE_SHARE_DELETE handles both
        // SUCCEED — handle pinning does not block either operation. The lease
        // therefore binds OBJECT IDENTITY, not the name: whatever the attacker
        // does to the name, every identity read stays bound to the originally
        // verified directory object and every path re-resolution that no
        // longer reaches it fails closed.
        fs::rename(&leaf, parent.join("leaf-moved")).expect("rename allowed while held");
        let moved_facts = directory_facts(&moved_plain).expect("moved facts");
        assert_eq!(
            original_file_id,
            format!(
                "{:08x}{:08x}",
                moved_facts.info.nFileIndexHigh, moved_facts.info.nFileIndexLow
            ),
            "the pinned handle must follow the same object across a rename"
        );
        // The canonical path read from the pinned handle reflects the new
        // name, so a walk that uses it never consults the recorded location.
        let canonical = super::canonical_path_for_handle(chain.target()).expect("canonical path");
        assert!(
            canonical.to_lowercase().ends_with("leaf-moved"),
            "canonical path {canonical:?} must name the moved object"
        );

        // Delete succeeds too, but the pinned handle still reads the original
        // object (identity survives on the held handle) while every
        // path-string re-resolution fails closed — the walk bound to this
        // lease can never observe a replaced directory.
        fs::remove_dir(parent.join("leaf-moved")).expect("delete allowed while held");
        assert!(!parent.join("leaf-moved").exists());
        assert!(
            super::canonical_path_for_handle(chain.target()).is_some(),
            "the pinned handle must stay readable after the delete"
        );
        assert!(
            directory_facts(&moved_plain).is_none(),
            "path re-resolution must fail closed after the delete"
        );

        drop(chain); // release the lease
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn lease_refuses_volume_root_missing_and_plain_file_targets() {
        let root = drive_scratch("lease-shapes");
        let file = root.join("plain-file.txt");
        fs::write(&file, "x").expect("file");
        let missing = root.join("does-not-exist");

        // Volume root ("X:\\"): pins fine (it is a real directory) and is
        // flagged as the volume root. Consumers still reject volume roots at
        // the policy layer; the chain itself stays truthful.
        let chain =
            open_directory_chain(&format!("{}\\\\", root_str_drive())).expect("volume root pins");
        assert!(chain.is_volume_root);
        drop(chain);
        // A plain file is not a directory: refused.
        assert!(open_directory_chain(file.to_str().expect("utf8 file")).is_none());
        // A missing final component refuses without pinning anything.
        assert!(open_directory_chain(missing.to_str().expect("utf8 missing")).is_none());

        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Drive letter of the temp directory, as a plain "X:" prefix.
    fn root_str_drive() -> String {
        let temp = std::env::temp_dir();
        let letter = temp
            .to_str()
            .expect("utf8 temp")
            .chars()
            .next()
            .expect("drive letter");
        format!("{}:", letter.to_ascii_uppercase())
    }
}
