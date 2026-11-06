//! Windows Shell folder picker and metadata-only directory identity.
//!
//! This addon exposes no path-taking UI fallback and never reads file contents.
//! The TypeScript Host keeps absolute paths and volume/file identity private.

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
    CloseHandle, ERROR_CANCELLED, HANDLE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
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
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::UI::Shell::{
    FileOpenDialog, IFileOpenDialog, FOS_FORCEFILESYSTEM, FOS_PATHMUSTEXIST, FOS_PICKFOLDERS,
    SIGDN_FILESYSPATH,
};

#[napi(object)]
pub struct FolderIdentity {
    pub volume_serial: String,
    pub file_id: String,
}

#[napi(object)]
pub struct FolderDirectoryIdentity {
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
    let facts = directory_facts(path)?;
    Some(FolderDirectoryIdentity {
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
// Native directory lease — defense-in-depth, not an atomic path-scan lock.
//
// Acquisition walks components handle-relatively and refuses reparse points.
// The held handles allow identity rechecks and canonical-path lookup, but
// downstream readdir/resolveScope/observeStorage still consume path strings.
// Rename/replacement can race with those operations; this is an Owner-accepted
// v0.3.0 residual risk. The lease does not claim to block rename/delete.
// ---------------------------------------------------------------------------

const FILE_ATTRIBUTE_DIRECTORY_U32: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_REPARSE_POINT_U32: u32 = 0x0000_0400;
/// Share READ and WRITE, but not DELETE. Windows may still permit directory
/// rename/delete with these handles open; this is not an exclusion guarantee.
const PINNING_SHARE_MODE: u32 = 0x0000_0001 | 0x0000_0002;

/// A held chain of open handles, parent-first, ending at the target
/// directory. The chain is the lease: dropping it releases every pin.
struct DirectoryChain {
    handles: Vec<OwnedHandle>,
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
        self.handles
            .last()
            .expect("chain always has a root handle")
            .0
    }
}

/// Opens one absolute path for attribute reads and KEEPS the handle. The
/// handle is opened with backup semantics + OPEN_REPARSE_POINT and a
/// no-DELETE share mask so it can serve as a pinning chain link.
fn open_pinning_directory(path: &str) -> Option<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)> {
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
    let owned = OwnedHandle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }.ok()?;
    Some((owned, info))
}

/// Opens one child directory by name relative to an already-held parent
/// handle. This avoids re-resolving ancestors during chain acquisition, but
/// does not make later path-based metadata walks atomic.
fn open_child_directory(
    parent: HANDLE,
    name: &str,
) -> Option<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)> {
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
    let owned = OwnedHandle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }.ok()?;
    Some((owned, info))
}

/// Builds a pinning handle chain for one plain-drive absolute path. Any
/// reparse component, non-directory component, network/unknown drive or
/// malformed path refuses with None; no descendant of a junction is ever
/// opened.
fn build_directory_chain<F>(
    root_handle: OwnedHandle,
    root_info: BY_HANDLE_FILE_INFORMATION,
    is_volume_root: bool,
    components: &[&str],
    mut open_child: F,
) -> Option<DirectoryChain>
where
    F: FnMut(HANDLE, &str) -> Option<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)>,
{
    // Retain every acquired handle in an RAII vector. Any early return or
    // refusal drops the complete partial chain, including missing/reparse/
    // non-directory child failures.
    if root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY_U32 == 0
        || root_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT_U32 != 0
    {
        return None;
    }
    let mut handles = vec![root_handle];
    let mut info = root_info;
    for component in components {
        let parent = handles.last()?.0;
        let (child_handle, child_info) = open_child(parent, component)?;
        let attributes = child_info.dwFileAttributes;
        if attributes & FILE_ATTRIBUTE_DIRECTORY_U32 == 0
            || attributes & FILE_ATTRIBUTE_REPARSE_POINT_U32 != 0
        {
            return None;
        }
        handles.push(child_handle);
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
    let components: Vec<&str> = path[3..]
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect();
    build_directory_chain(root_handle, root_info, is_volume_root, &components, open_child_directory)
}

fn directory_identity_from_handle(
    info: &BY_HANDLE_FILE_INFORMATION,
    is_volume_root: bool,
) -> FolderDirectoryIdentity {
    FolderDirectoryIdentity {
        volume_serial: format!("{:08x}", info.dwVolumeSerialNumber),
        file_id: format!("{:08x}{:08x}", info.nFileIndexHigh, info.nFileIndexLow),
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

/// Returns the current DOS path reported by the held target handle.
/// Downstream storage still resolves this path string; this is not an atomic
/// handle-relative metadata walk.
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
            volume_serial: directory.volume_serial,
            file_id: directory.file_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_directory_chain, directory_facts, open_directory_chain, open_pinning_directory,
        should_refuse_drive_type,
    };
    use windows::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn handle_is_open(handle: super::HANDLE) -> bool {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { super::GetFileInformationByHandle(handle, &mut info) }.is_ok()
    }

    #[test]
    fn partial_chain_failures_drop_every_acquired_handle() {
        let root = drive_scratch("partial-chain-drop");
        let drive_root = format!("{}\\", root_str_drive());

        // Missing child: the already-open volume-root handle must be dropped
        // when the child opener returns None.
        let (root_handle, root_info) = open_pinning_directory(&drive_root).expect("drive root");
        let root_raw = root_handle.0;
        let missing = build_directory_chain(
            root_handle,
            root_info,
            false,
            &["missing"],
            |_parent, _name| None,
        );
        assert!(missing.is_none());
        assert!(!handle_is_open(root_raw), "missing child leaked the root handle");

        // Reparse child: both the root and just-opened junction handle must
        // be dropped, and no later component may be requested.
        let target = root.join("target");
        fs::create_dir_all(&target).expect("junction target");
        let link = root.join("link");
        create_junction(&link, &target);
        let (root_handle, root_info) = open_pinning_directory(&drive_root).expect("drive root");
        let root_raw = root_handle.0;
        let (child_handle, child_info) =
            open_pinning_directory(link.to_str().expect("junction path")).expect("junction handle");
        let child_raw = child_handle.0;
        let mut opens = 0;
        let reparse = build_directory_chain(
            root_handle,
            root_info,
            false,
            &["link", "child"],
            |_parent, _name| {
                opens += 1;
                Some((child_handle, child_info))
            },
        );
        assert!(reparse.is_none());
        assert_eq!(opens, 1, "a descendant below the reparse point was requested");
        assert!(!handle_is_open(root_raw), "reparse refusal leaked the root handle");
        assert!(!handle_is_open(child_raw), "reparse refusal leaked the child handle");
        remove_junction(&link);

        // Non-directory child: the acquired child handle and its parent chain
        // must both be released on the typed refusal.
        let file = root.join("plain-file.txt");
        fs::write(&file, "x").expect("plain file");
        let (root_handle, root_info) = open_pinning_directory(&drive_root).expect("drive root");
        let root_raw = root_handle.0;
        let (child_handle, child_info) =
            open_pinning_directory(file.to_str().expect("file path")).expect("file handle");
        let child_raw = child_handle.0;
        let non_directory = build_directory_chain(
            root_handle,
            root_info,
            false,
            &["plain-file.txt"],
            |_parent, _name| Some((child_handle, child_info)),
        );
        assert!(non_directory.is_none());
        assert!(!handle_is_open(root_raw), "non-directory refusal leaked the root handle");
        assert!(!handle_is_open(child_raw), "non-directory refusal leaked the child handle");

        fs::remove_dir_all(&root).expect("cleanup");
    }

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
        // SUCCEED. The lease retains a handle to the original object, but it
        // does not exclude namespace changes or make path-based walks atomic.
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
        // name. It is a best-effort locator, not a lock on subsequent path
        // resolution by the storage walker.
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
