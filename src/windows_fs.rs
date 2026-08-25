//! Windows handle-relative filesystem primitives.
//!
//! Win32 path APIs do not accept an already-open directory as the authority
//! for an open. This module therefore uses the documented native
//! `NtCreateFile` root-directory contract one component at a time. Every open
//! requests `OBJ_DONT_REPARSE` and `FILE_OPEN_REPARSE_POINT`, then rejects a
//! returned reparse-point handle. The only path-based open is the drive
//! anchor, which contains no attacker-controlled child component.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Component, Path, PathBuf, Prefix};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, NtFlushBuffersFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    LocalFree, RtlNtStatusToDosError, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE,
    OBJ_DONT_REPARSE,
};
use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetEffectiveRightsFromAclW, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SDDL_REVISION_1,
    SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetLengthSid, GetTokenInformation, TokenOwner, TokenUser,
    WinAuthenticatedUserSid, WinBuiltinUsersSid, WinWorldSid, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_INFORMATION_CLASS, TOKEN_OWNER,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, FileIdInfo,
    FileRenameInfo, FileStandardInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetFileType, LockFileEx, SetFileInformationByHandle, UnlockFileEx, BY_HANDLE_FILE_INFORMATION,
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
    FILE_INFO_BY_HANDLE_CLASS, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
    FILE_READ_EA, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_STANDARD_INFO, FILE_TRAVERSE, FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FILE_WRITE_EA, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, OPEN_EXISTING, READ_CONTROL,
    SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};

const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const DIRECTORY_ACCESS: u32 =
    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
const DIRECTORY_WRITE_ACCESS: u32 = DIRECTORY_ACCESS
    | FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES;
const FILE_READ_ACCESS: u32 =
    FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
const FILE_WRITE_ACCESS: u32 = FILE_READ_ACCESS
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | DELETE;
const SECURITY_MAX_SID_SIZE: usize = 68;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    pub volume: u64,
    pub id: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileVersion {
    pub identity: FileIdentity,
    pub length: u64,
    pub links: u32,
    pub attributes: u32,
    pub creation_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
}

impl FileVersion {
    pub const fn is_directory(self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    pub const fn is_reparse_point(self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
}

#[derive(Clone, Copy)]
pub enum ObjectKind {
    Directory,
    Regular,
}

#[derive(Clone, Copy)]
pub enum OpenAccess {
    Read,
    Write,
    ExclusiveWrite,
}

#[derive(Clone, Copy)]
pub enum OpenDisposition {
    Open,
    Create,
    OpenOrCreate,
}

pub struct OpenedFile {
    pub file: File,
}

pub struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl OwnedSecurityDescriptor {
    pub const fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }
}

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: both security conversion and GetSecurityInfo allocate
            // their returned descriptor with LocalAlloc.
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this guard uniquely owns a token handle.
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

pub fn path_is_within(path: &Path, root: &Path) -> bool {
    let path_components = path.components().collect::<Vec<_>>();
    let root_components = root.components().collect::<Vec<_>>();
    path_components.len() >= root_components.len()
        && path_components
            .iter()
            .zip(root_components.iter())
            .all(|(left, right)| os_eq_ignore_case(left.as_os_str(), right.as_os_str()))
}

pub fn relative_to_root(path: &Path, root: &Path) -> io::Result<PathBuf> {
    let path_components = path.components().collect::<Vec<_>>();
    let root_components = root.components().collect::<Vec<_>>();
    if path_components.len() < root_components.len()
        || !path_components
            .iter()
            .zip(root_components.iter())
            .all(|(left, right)| os_eq_ignore_case(left.as_os_str(), right.as_os_str()))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path is outside its Windows capability root",
        ));
    }
    let mut relative = PathBuf::new();
    for component in path_components.into_iter().skip(root_components.len()) {
        relative.push(component.as_os_str());
    }
    if relative.as_os_str().is_empty() {
        relative.push(".");
    }
    Ok(relative)
}

fn os_eq_ignore_case(left: &OsStr, right: &OsStr) -> bool {
    let left = left.encode_wide().collect::<Vec<_>>();
    let right = right.encode_wide().collect::<Vec<_>>();
    let Ok(left_len) = i32::try_from(left.len()) else {
        return false;
    };
    let Ok(right_len) = i32::try_from(right.len()) else {
        return false;
    };
    // SAFETY: both buffers remain live and their explicit lengths are valid.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

/// Open an absolute directory by pinning its drive anchor and walking
/// every remaining component without processing reparse points.
pub fn open_absolute_directory(path: &Path) -> io::Result<File> {
    open_absolute_directory_with_access(path, OpenAccess::Read)
}

pub fn open_absolute_directory_for_write(path: &Path) -> io::Result<File> {
    open_absolute_directory_with_access(path, OpenAccess::Write)
}

fn open_absolute_directory_with_access(path: &Path, access: OpenAccess) -> io::Result<File> {
    let (anchor, components) = split_absolute(path)?;
    let anchor_wide = nul_terminated(&anchor)?;
    // SAFETY: the path is NUL-terminated. The anchor contains only a drive or
    // UNC share root, never an untrusted descendant component.
    let handle = unsafe {
        CreateFileW(
            anchor_wide.as_ptr(),
            if components.is_empty() {
                directory_access(access)
            } else {
                DIRECTORY_ACCESS
            },
            SHARE_ALL,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a fresh owned file handle.
    let mut current = unsafe { File::from_raw_handle(handle.cast()) };
    validate_kind(&current, ObjectKind::Directory)?;
    let component_count = components.len();
    for (index, component) in components.into_iter().enumerate() {
        current = open_one(
            &current,
            &component,
            ObjectKind::Directory,
            if index + 1 == component_count {
                access
            } else {
                OpenAccess::Read
            },
            OpenDisposition::Open,
            None,
        )?
        .file;
    }
    Ok(current)
}

const fn directory_access(access: OpenAccess) -> u32 {
    match access {
        OpenAccess::Read => DIRECTORY_ACCESS,
        OpenAccess::Write | OpenAccess::ExclusiveWrite => DIRECTORY_WRITE_ACCESS,
    }
}

pub fn open_relative(
    root: &File,
    relative: &Path,
    kind: ObjectKind,
    access: OpenAccess,
    disposition: OpenDisposition,
    security: Option<&OwnedSecurityDescriptor>,
) -> io::Result<OpenedFile> {
    let components = relative_components(relative)?;
    if components.is_empty() {
        if !matches!(kind, ObjectKind::Directory) || !matches!(disposition, OpenDisposition::Open) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "capability root can only be opened as an existing directory",
            ));
        }
        return Ok(OpenedFile {
            file: root.try_clone()?,
        });
    }
    let mut current = root.try_clone()?;
    for component in &components[..components.len() - 1] {
        current = open_one(
            &current,
            component,
            ObjectKind::Directory,
            access,
            OpenDisposition::Open,
            None,
        )?
        .file;
    }
    open_one(
        &current,
        &components[components.len() - 1],
        kind,
        access,
        disposition,
        security,
    )
}

pub fn create_directories(root: &File, relative: &Path) -> io::Result<()> {
    let components = relative_components(relative)?;
    let mut current = root.try_clone()?;
    for component in components {
        current = match open_one(
            &current,
            &component,
            ObjectKind::Directory,
            OpenAccess::Write,
            OpenDisposition::Create,
            None,
        ) {
            Ok(opened) => opened.file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                open_one(
                    &current,
                    &component,
                    ObjectKind::Directory,
                    OpenAccess::Write,
                    OpenDisposition::Open,
                    None,
                )?
                .file
            }
            Err(error) => return Err(error),
        };
    }
    Ok(())
}

/// Create one owner-private absolute directory below an existing parent, or
/// validate the existing directory if another process won the creation race.
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    match create_new_private_directory(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let parent = path.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private Windows directory has no parent",
                )
            })?;
            let name = path.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private Windows directory has no final component",
                )
            })?;
            let parent = open_absolute_directory_for_write(parent)?;
            let directory = open_relative(
                &parent,
                Path::new(name),
                ObjectKind::Directory,
                OpenAccess::Read,
                OpenDisposition::Open,
                None,
            )?
            .file;
            validate_owned_acl(&directory, true)
        }
        Err(error) => Err(error),
    }
}

pub fn create_new_private_directory(path: &Path) -> io::Result<File> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private Windows directory has no parent",
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private Windows directory has no final component",
        )
    })?;
    let parent = open_absolute_directory_for_write(parent)?;
    let security = private_security_descriptor()?;
    let directory = open_relative(
        &parent,
        Path::new(name),
        ObjectKind::Directory,
        OpenAccess::Write,
        OpenDisposition::Create,
        Some(&security),
    )?
    .file;
    validate_owned_acl(&directory, true)?;
    Ok(directory)
}

fn open_one(
    parent: &File,
    name: &OsStr,
    kind: ObjectKind,
    access: OpenAccess,
    disposition: OpenDisposition,
    security: Option<&OwnedSecurityDescriptor>,
) -> io::Result<OpenedFile> {
    validate_component(name)?;
    let mut name_wide = name.encode_wide().collect::<Vec<_>>();
    let byte_len = name_wide
        .len()
        .checked_mul(2)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Windows component is too long")
        })?;
    let unicode = windows_sys::Win32::Foundation::UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: name_wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>())
            .expect("OBJECT_ATTRIBUTES size fits u32"),
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: &raw const unicode,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: security.map_or(std::ptr::null(), |value| {
            value
                .as_ptr()
                .cast::<windows_sys::Win32::Security::SECURITY_DESCRIPTOR>()
                .cast_const()
        }),
        SecurityQualityOfService: std::ptr::null(),
    };
    let desired_access = match (kind, access) {
        (ObjectKind::Directory, OpenAccess::Read) => DIRECTORY_ACCESS,
        (ObjectKind::Directory, OpenAccess::Write | OpenAccess::ExclusiveWrite) => {
            DIRECTORY_WRITE_ACCESS
        }
        (ObjectKind::Regular, OpenAccess::Read) => FILE_READ_ACCESS,
        (ObjectKind::Regular, OpenAccess::Write | OpenAccess::ExclusiveWrite) => FILE_WRITE_ACCESS,
    };
    let create_disposition = match disposition {
        OpenDisposition::Open => FILE_OPEN,
        OpenDisposition::Create => FILE_CREATE,
        OpenDisposition::OpenOrCreate => FILE_OPEN_IF,
    };
    let kind_option = match kind {
        ObjectKind::Directory => FILE_DIRECTORY_FILE,
        ObjectKind::Regular => FILE_NON_DIRECTORY_FILE,
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut io_status = IO_STATUS_BLOCK::default();
    // SAFETY: all structures and buffers remain live for the synchronous call;
    // a successful handle is transferred immediately into `File`.
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            desired_access,
            &raw const attributes,
            &raw mut io_status,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            if matches!(access, OpenAccess::ExclusiveWrite) {
                FILE_SHARE_READ
            } else {
                SHARE_ALL
            },
            create_disposition,
            kind_option | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    nt_result(status)?;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(
            "NtCreateFile succeeded without returning a usable handle",
        ));
    }
    // SAFETY: NtCreateFile returned a fresh owned file handle.
    let file = unsafe { File::from_raw_handle(handle) };
    validate_kind(&file, kind)?;
    Ok(OpenedFile { file })
}

fn validate_kind(file: &File, kind: ObjectKind) -> io::Result<()> {
    let version = file_version(file)?;
    if version.is_reparse_point() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows reparse points are not filesystem capabilities",
        ));
    }
    // SAFETY: the handle is live and owned by `file`.
    if unsafe { GetFileType(file.as_raw_handle() as HANDLE) } != FILE_TYPE_DISK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "handle is not a disk filesystem object",
        ));
    }
    match (kind, version.is_directory()) {
        (ObjectKind::Directory, true) | (ObjectKind::Regular, false) => Ok(()),
        (ObjectKind::Directory, false) => Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "handle does not name a directory",
        )),
        (ObjectKind::Regular, true) => Err(io::Error::new(
            io::ErrorKind::IsADirectory,
            "handle does not name a regular file",
        )),
    }
}

pub fn file_version(file: &File) -> io::Result<FileVersion> {
    let handle = file.as_raw_handle() as HANDLE;
    let identity = file_identity(file)?;
    let mut standard = FILE_STANDARD_INFO::default();
    query_handle(handle, FileStandardInfo, &raw mut standard)?;
    let mut basic = windows_sys::Win32::Storage::FileSystem::FILE_BASIC_INFO::default();
    query_handle(
        handle,
        windows_sys::Win32::Storage::FileSystem::FileBasicInfo,
        &raw mut basic,
    )?;
    Ok(FileVersion {
        identity,
        length: u64::try_from(standard.EndOfFile).unwrap_or(0),
        links: standard.NumberOfLinks,
        attributes: basic.FileAttributes,
        creation_time: basic.CreationTime,
        last_write_time: basic.LastWriteTime,
        change_time: basic.ChangeTime,
    })
}

pub fn file_identity(file: &File) -> io::Result<FileIdentity> {
    let mut info = FILE_ID_INFO::default();
    if query_handle(file.as_raw_handle() as HANDLE, FileIdInfo, &raw mut info).is_ok()
        && info.FileId.Identifier != [0; 16]
    {
        return Ok(FileIdentity {
            volume: info.VolumeSerialNumber,
            id: info.FileId.Identifier,
        });
    }

    let mut legacy = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: both handle and output pointer are valid. This fallback keeps
    // the capability usable on filesystems that do not expose 128-bit IDs.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &raw mut legacy) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(legacy.nFileIndexHigh) << 32) | u64::from(legacy.nFileIndexLow);
    let mut id = [0_u8; 16];
    id[..8].copy_from_slice(&index.to_le_bytes());
    Ok(FileIdentity {
        volume: u64::from(legacy.dwVolumeSerialNumber),
        id,
    })
}

fn query_handle<T>(
    handle: HANDLE,
    class: FILE_INFO_BY_HANDLE_CLASS,
    output: *mut T,
) -> io::Result<()> {
    // SAFETY: `output` points to writable storage of the exact class type.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            class,
            output.cast(),
            u32::try_from(std::mem::size_of::<T>()).expect("Windows info type fits u32"),
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn security_descriptor(file: &File) -> io::Result<OwnedSecurityDescriptor> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: output points to a LocalAlloc-owned descriptor on success.
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if error == 0 && !descriptor.is_null() {
        Ok(OwnedSecurityDescriptor(descriptor))
    } else if error == 0 {
        Err(io::Error::other(
            "GetSecurityInfo succeeded without a security descriptor",
        ))
    } else {
        Err(io::Error::from_raw_os_error(error.cast_signed()))
    }
}

pub fn private_security_descriptor() -> io::Result<OwnedSecurityDescriptor> {
    let sid = current_user_sid()?;
    let mut sid_string = std::ptr::null_mut();
    // SAFETY: the SID buffer is valid; the returned string is LocalAlloc-owned.
    if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &raw mut sid_string) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if sid_string.is_null() {
        return Err(io::Error::other(
            "ConvertSidToStringSidW succeeded without a SID string",
        ));
    }
    let sid_units = unsafe {
        let mut length = 0_usize;
        while *sid_string.add(length) != 0 {
            length += 1;
        }
        std::slice::from_raw_parts(sid_string, length).to_vec()
    };
    // SAFETY: ConvertSidToStringSidW allocated this string with LocalAlloc.
    unsafe {
        LocalFree(sid_string.cast());
    }
    let sid_text = String::from_utf16(&sid_units).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "current user SID is not UTF-16")
    })?;
    let sddl = format!("O:{sid_text}D:P(A;;FA;;;{sid_text})(A;;FA;;;SY)(A;;FA;;;BA)");
    let wide = nul_terminated(OsStr::new(&sddl))?;
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: SDDL is NUL-terminated and output receives LocalAlloc storage.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else if descriptor.is_null() {
        Err(io::Error::other(
            "security descriptor conversion returned a null descriptor",
        ))
    } else {
        Ok(OwnedSecurityDescriptor(descriptor))
    }
}

pub fn validate_owned_acl(file: &File, private_content: bool) -> io::Result<()> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: all output pointers remain valid for the call and descriptor is
    // released below after the borrowed owner/DACL pointers are consumed.
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error.cast_signed()));
    }
    if descriptor.is_null() {
        return Err(io::Error::other(
            "GetSecurityInfo succeeded without a security descriptor",
        ));
    }
    let descriptor_guard = OwnedSecurityDescriptor(descriptor);
    if !owner_matches_current_process_token(owner)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "filesystem object is not owned by the current Windows token",
        ));
    }
    if dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "filesystem object has an unrestricted null DACL",
        ));
    }
    let broad_mask = if private_content {
        FILE_READ_DATA
            | FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | DELETE
            | WRITE_DAC
            | WRITE_OWNER
    } else {
        FILE_ADD_FILE
            | FILE_ADD_SUBDIRECTORY
            | FILE_DELETE_CHILD
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | DELETE
            | WRITE_DAC
            | WRITE_OWNER
    };
    for sid_type in [WinWorldSid, WinAuthenticatedUserSid, WinBuiltinUsersSid] {
        let sid = well_known_sid(sid_type)?;
        let mut trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: sid.as_ptr().cast_mut().cast(),
        };
        let mut rights = 0_u32;
        // SAFETY: DACL and SID live until the call returns.
        let rights_error =
            unsafe { GetEffectiveRightsFromAclW(dacl, &raw mut trustee, &raw mut rights) };
        if rights_error != 0 {
            return Err(io::Error::from_raw_os_error(rights_error.cast_signed()));
        }
        if rights & broad_mask != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "filesystem ACL grants broad access beyond the current Windows user",
            ));
        }
    }
    drop(descriptor_guard);
    Ok(())
}

fn current_user_sid() -> io::Result<Vec<usize>> {
    current_process_token_sid(ProcessTokenSid::User)
}

fn owner_matches_current_process_token(owner: PSID) -> io::Result<bool> {
    if owner.is_null() {
        return Ok(false);
    }
    // A Windows access token can designate an enabled group (commonly the
    // Administrators SID for an elevated process) as the default owner of new
    // objects. Accept the token user and that exact default-owner SID; the
    // independent DACL checks below still reject broadly writable objects.
    for kind in [ProcessTokenSid::User, ProcessTokenSid::DefaultOwner] {
        let candidate = current_process_token_sid(kind)?;
        // SAFETY: GetSecurityInfo returned `owner` as a valid SID and the
        // candidate buffer owns a complete, suitably aligned SID.
        if unsafe { EqualSid(owner, candidate.as_ptr().cast_mut().cast()) } != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone, Copy)]
enum ProcessTokenSid {
    User,
    DefaultOwner,
}

impl ProcessTokenSid {
    const fn information_class(self) -> TOKEN_INFORMATION_CLASS {
        match self {
            Self::User => TokenUser,
            Self::DefaultOwner => TokenOwner,
        }
    }

    const fn header_size(self) -> usize {
        match self {
            Self::User => std::mem::size_of::<TOKEN_USER>(),
            Self::DefaultOwner => std::mem::size_of::<TOKEN_OWNER>(),
        }
    }
}

fn current_process_token_sid(kind: ProcessTokenSid) -> io::Result<Vec<usize>> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: output receives one owned token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if token.is_null() || token == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(
            "OpenProcessToken succeeded without a usable token handle",
        ));
    }
    let token = OwnedHandle(token);
    let mut required = 0_u32;
    // SAFETY: the first call intentionally supplies no buffer to obtain size.
    unsafe {
        GetTokenInformation(
            token.0,
            kind.information_class(),
            std::ptr::null_mut(),
            0,
            &raw mut required,
        );
    }
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let required_bytes = usize::try_from(required).unwrap_or(0);
    if required_bytes < kind.header_size() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows token returned a truncated SID record",
        ));
    }
    let words = required_bytes.div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    // SAFETY: the word allocation is suitably aligned for TOKEN_USER and has
    // at least the requested byte length.
    if unsafe {
        GetTokenInformation(
            token.0,
            kind.information_class(),
            buffer.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetTokenInformation initialized the selected, properly aligned
    // token record at the start of the word buffer.
    let source_sid = unsafe {
        match kind {
            ProcessTokenSid::User => (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid,
            ProcessTokenSid::DefaultOwner => (*buffer.as_ptr().cast::<TOKEN_OWNER>()).Owner,
        }
    };
    if source_sid.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows token returned a null SID",
        ));
    }
    // SAFETY: the selected token record contains a valid SID pointer.
    let length = unsafe { GetLengthSid(source_sid) };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let length = usize::try_from(length).unwrap_or(0);
    let mut sid = vec![0_usize; length.div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: both ranges are valid for `length` bytes, do not overlap, and
    // the word allocation preserves the alignment required when this owned
    // SID is later passed back to Windows.
    unsafe {
        std::ptr::copy_nonoverlapping(
            source_sid.cast::<u8>(),
            sid.as_mut_ptr().cast::<u8>(),
            length,
        );
    }
    Ok(sid)
}

fn well_known_sid(sid_type: i32) -> io::Result<Vec<usize>> {
    let mut buffer = vec![0_usize; SECURITY_MAX_SID_SIZE.div_ceil(std::mem::size_of::<usize>())];
    let mut length =
        u32::try_from(buffer.len() * std::mem::size_of::<usize>()).expect("SID buffer fits u32");
    // SAFETY: output buffer and length are valid.
    if unsafe {
        CreateWellKnownSid(
            sid_type,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

pub fn rename_relative(
    file: &File,
    parent: &File,
    new_name: &OsStr,
    replace: bool,
) -> io::Result<()> {
    validate_component(new_name)?;
    let name = new_name.encode_wide().collect::<Vec<_>>();
    let name_bytes = name
        .len()
        .checked_mul(2)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename target is too long"))?;
    let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let length = offset
        .checked_add(usize::try_from(name_bytes).unwrap_or(usize::MAX))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename buffer is too long"))?;
    let words = length.div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: storage is aligned and large enough for the fixed header and
    // exact UTF-16 payload.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = parent.as_raw_handle() as HANDLE;
        (*info).FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
    }
    // SAFETY: the handle and complete FILE_RENAME_INFO buffer remain live.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileRenameInfo,
            info.cast(),
            u32::try_from(length).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "rename buffer exceeds u32")
            })?,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn delete_handle(file: &File) -> io::Result<()> {
    let disposition = windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO_EX {
        Flags: windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_FLAG_DELETE
            | windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: the handle and disposition structure remain live.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            windows_sys::Win32::Storage::FileSystem::FileDispositionInfoEx,
            (&raw const disposition).cast(),
            u32::try_from(std::mem::size_of_val(&disposition)).expect("disposition size fits u32"),
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn flush(file: &File) -> io::Result<()> {
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: the file handle and output block are valid for the synchronous
    // native flush. Unlike FlushFileBuffers, this contract also accepts the
    // directory handles returned by NtCreateFile.
    let result = unsafe { NtFlushBuffersFile(file.as_raw_handle() as HANDLE, &raw mut status) };
    nt_result(result)
}

pub fn lock_exclusive(file: &File) -> io::Result<()> {
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: handle and OVERLAPPED storage remain live for the synchronous,
    // fail-immediately byte-range lock request.
    if unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &raw mut overlapped,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn unlock(file: &File) {
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: the handle is live; close would also release the range lock.
    unsafe {
        UnlockFileEx(
            file.as_raw_handle() as HANDLE,
            0,
            u32::MAX,
            u32::MAX,
            &raw mut overlapped,
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryEntryKind {
    Directory,
    Regular,
    Other,
}

pub struct DirectoryEntry {
    pub name: OsString,
    pub kind: DirectoryEntryKind,
}

pub fn enumerate_directory(
    file: &File,
    mut visit: impl FnMut(DirectoryEntry) -> bool,
) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DEVICE, FILE_ID_BOTH_DIR_INFO};

    let mut restart = true;
    loop {
        let mut buffer = vec![0_u64; (64 * 1_024) / std::mem::size_of::<u64>()];
        let class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        // SAFETY: buffer is aligned and writable for the variable-length
        // FILE_ID_BOTH_DIR_INFO records returned by the directory query.
        let success = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                class,
                buffer.as_mut_ptr().cast(),
                u32::try_from(buffer.len() * std::mem::size_of::<u64>())
                    .expect("enumeration buffer fits u32"),
            )
        };
        if success == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES.cast_signed())
            {
                break;
            }
            return Err(error);
        }
        restart = false;
        let bytes = buffer.len() * std::mem::size_of::<u64>();
        let mut offset = 0_usize;
        loop {
            if !offset.is_multiple_of(std::mem::align_of::<FILE_ID_BOTH_DIR_INFO>())
                || bytes.saturating_sub(offset) < std::mem::size_of::<FILE_ID_BOTH_DIR_INFO>()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows directory enumeration returned a truncated or misaligned record",
                ));
            }
            // SAFETY: offset was range-checked and records are naturally aligned.
            let word_offset = offset / std::mem::size_of::<u64>();
            let record = unsafe {
                &*buffer
                    .as_ptr()
                    .add(word_offset)
                    .cast::<FILE_ID_BOTH_DIR_INFO>()
            };
            let name_units = usize::try_from(record.FileNameLength)
                .ok()
                .filter(|length| length % 2 == 0)
                .map(|length| length / 2)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Windows file-name length",
                    )
                })?;
            let name_offset = offset + std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
            if name_offset
                .checked_add(name_units.saturating_mul(2))
                .is_none_or(|end| end > bytes)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows directory entry name exceeds its query buffer",
                ));
            }
            // SAFETY: the UTF-16 range is within the validated record buffer.
            let name = OsString::from_wide(unsafe {
                std::slice::from_raw_parts(record.FileName.as_ptr(), name_units)
            });
            if name != OsStr::new(".") && name != OsStr::new("..") {
                let kind = if record.FileAttributes
                    & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)
                    != 0
                {
                    DirectoryEntryKind::Other
                } else if record.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    DirectoryEntryKind::Directory
                } else {
                    DirectoryEntryKind::Regular
                };
                if !visit(DirectoryEntry { name, kind }) {
                    return Ok(());
                }
            }
            if record.NextEntryOffset == 0 {
                break;
            }
            let next = usize::try_from(record.NextEntryOffset).unwrap_or(usize::MAX);
            if next == 0 || offset.checked_add(next).is_none_or(|value| value >= bytes) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows directory enumeration returned an invalid next offset",
                ));
            }
            offset += next;
        }
    }
    Ok(())
}

fn split_absolute(path: &Path) -> io::Result<(OsString, Vec<OsString>)> {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows capability root must be absolute",
        ));
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows capability root must include a rooted drive or share",
        ));
    }
    let anchor = match prefix.kind() {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
            OsString::from(format!(r"\\?\{}:\", char::from(letter)))
        }
        // A share handle cannot be used as FileRenameInfo.RootDirectory over
        // every network redirector. Reject it during capability construction
        // instead of allowing ordinary writes to fail later.
        Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UNC capability roots are unsupported by the handle-relative atomic backend",
            ));
        }
        Prefix::Verbatim(_) | Prefix::DeviceNS(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "device-namespace capability roots are unsupported",
            ));
        }
    };
    let mut names = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) => {
                validate_component(name)?;
                names.push(name.to_os_string());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows capability root contains traversal",
                ));
            }
        }
    }
    Ok((anchor, names))
}

fn relative_components(path: &Path) -> io::Result<Vec<OsString>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                validate_component(name)?;
                components.push(name.to_os_string());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows relative capability path contains traversal or a root",
                ));
            }
        }
    }
    Ok(components)
}

pub fn validate_component(name: &OsStr) -> io::Result<()> {
    let units = name.encode_wide().collect::<Vec<_>>();
    if units.is_empty()
        || units.contains(&0)
        || units.iter().any(|unit| {
            *unit < 0x20 || matches!(*unit, 0x22 | 0x2a | 0x3a | 0x3c | 0x3e | 0x3f | 0x7c)
        })
        || units
            .last()
            .is_some_and(|unit| matches!(*unit, 0x20 | 0x2e))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Windows filesystem component",
        ));
    }
    let upper = name.to_string_lossy().to_ascii_uppercase();
    let stem = upper.split('.').next().unwrap_or_default();
    let reserved = matches!(stem, "CON" | "PRN" | "AUX" | "NUL")
        || stem.strip_prefix("COM").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || stem.strip_prefix("LPT").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        });
    if reserved {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reserved Windows device name is not a filesystem capability",
        ));
    }
    Ok(())
}

fn nul_terminated(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn nt_result(status: i32) -> io::Result<()> {
    if status >= 0 {
        Ok(())
    } else {
        // SAFETY: translating an NTSTATUS has no pointer preconditions.
        let code = unsafe { RtlNtStatusToDosError(status) };
        Err(io::Error::from_raw_os_error(code.cast_signed()))
    }
}
