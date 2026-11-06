//! Windows Shell folder picker and metadata-only directory identity.
//!
//! This addon exposes no path-taking UI fallback and never reads file contents.
//! The TypeScript Host keeps absolute paths and token/file identity private.

#![allow(clippy::missing_safety_doc)]

use std::ffi::c_void;
use std::slice;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_CANCELLED, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, TokenGroups, TokenSessionId, TokenUser, TOKEN_GROUPS, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    FILE_READ_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, OpenInputDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
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

fn inspect_directory_inner(path: &str) -> Option<FolderDirectoryIdentity> {
    if !is_plain_drive_path(path) {
        return None;
    }
    let identity = current_identity_inner()?;
    let drive_root = format!("{}\\", &path[..2]);
    let drive_wide = to_wide(&drive_root);
    let drive_type = unsafe { GetDriveTypeW(PCWSTR(drive_wide.as_ptr())) };
    let is_network_path = drive_type == 4; // DRIVE_REMOTE
    if drive_type == 0 || drive_type == 1 {
        return None;
    }
    let is_volume_root = path.trim_end_matches('\\').eq_ignore_ascii_case(&path[..2]);

    let components: Vec<&str> = path[3..]
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect();
    let mut current = drive_root;
    let mut final_info = None;
    let mut any_reparse_point = false;
    for (index, component) in components.iter().enumerate() {
        current.push_str(component);
        let info = file_information(&current)?;
        let attributes = info.dwFileAttributes;
        let is_reparse = attributes & 0x0000_0400 != 0; // FILE_ATTRIBUTE_REPARSE_POINT
        let is_directory = attributes & 0x0000_0010 != 0; // FILE_ATTRIBUTE_DIRECTORY
        any_reparse_point |= is_reparse;
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
    let is_directory = attributes & 0x0000_0010 != 0;
    let is_reparse_point = any_reparse_point || attributes & 0x0000_0400 != 0;
    Some(FolderDirectoryIdentity {
        user_sid: identity.user_sid,
        logon_sid: identity.logon_sid,
        session_id: identity.session_id,
        volume_serial: format!("{:08x}", info.dwVolumeSerialNumber),
        file_id: format!("{:08x}{:08x}", info.nFileIndexHigh, info.nFileIndexLow),
        is_directory,
        is_reparse_point,
        is_network_path,
        is_volume_root,
    })
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
pub fn inspect_directory(path: String) -> Result<FolderDirectoryIdentity> {
    inspect_directory_inner(&path).ok_or_else(|| {
        Error::new(
            Status::GenericFailure,
            "FOLDER_PICKER_DIRECTORY_IDENTITY_UNAVAILABLE",
        )
    })
}

#[napi]
pub fn select_folder() -> FolderSelectionResult {
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

    let directory = match inspect_directory_inner(&path) {
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
