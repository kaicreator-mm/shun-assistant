//! Windows Shell folder picker and metadata-only directory identity.
//!
//! This addon exposes no path-taking UI fallback and never reads file contents.
//! The TypeScript Host keeps absolute paths and token/file identity private.

#![allow(clippy::missing_safety_doc)]

use std::ffi::c_void;
use std::slice;

use napi::bindgen_prelude::*;
use napi::Task;
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
fn directory_facts(path: &str) -> Option<DirectoryFacts> {
    if !is_plain_drive_path(path) {
        return None;
    }
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
    use super::directory_facts;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

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
}
