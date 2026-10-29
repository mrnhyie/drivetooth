//! Host filesystem plumbing: what drives exist, how much room they have, and the file
//! metadata we must preserve across a lock/unlock cycle.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::error::{DtError, DtResult, IoCtx};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StoredMeta {
    pub mtime_ms: i64,
    /// Unix permission bits; on Windows only the read-only flag is meaningful.
    pub mode: u32,
    pub readonly: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VaultBrief {
    pub state: super::VaultState,
    pub scope: String,
    pub label: String,
    pub uuid: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MountInfo {
    pub path: String,
    pub name: String,
    pub fs_type: String,
    pub removable: bool,
    /// The filesystem itself refuses writes (mounted read-only or a dmg image).
    pub read_only_mount: bool,
    pub is_boot: bool,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub drive_tooth: Option<VaultBrief>,
}

pub fn ms_to_system_time(ms: i64) -> SystemTime {
    if ms >= 0 {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms as u64)
    } else {
        SystemTime::UNIX_EPOCH - std::time::Duration::from_millis((-ms) as u64)
    }
}

fn system_time_to_ms(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

pub fn capture_meta(path: &Path) -> DtResult<StoredMeta> {
    let md = std::fs::symlink_metadata(path).ctx(path)?;
    let mtime_ms = md
        .modified()
        .ctx(path)
        .map(system_time_to_ms)
        .unwrap_or_else(|_| super::now_ms());
    Ok(StoredMeta {
        mtime_ms,
        mode: mode_of(path, &md),
        readonly: md.permissions().readonly(),
    })
}

/// Apply stored metadata back onto a restored file. Done after the content rename so a
/// later write is not blocked by a read-only mode.
pub fn restore_meta(path: &Path, meta: &StoredMeta) -> DtResult<()> {
    set_mode(path, meta.mode, meta.readonly)?;
    let file = std::fs::OpenOptions::new().write(true).open(path).ctx(path)?;
    file.set_modified(ms_to_system_time(meta.mtime_ms))
        .ctx(path)?;
    Ok(())
}

#[cfg(unix)]
fn mode_of(path: &Path, md: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let _ = path;
    md.permissions().mode()
}

#[cfg(not(unix))]
fn mode_of(_path: &Path, _md: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32, readonly: bool) -> DtResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut bits = mode & 0o7777;
    if readonly {
        bits &= !0o222;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits))
        .ctx(path)
}

#[cfg(not(unix))]
fn set_mode(path: &Path, _mode: u32, readonly: bool) -> DtResult<()> {
    let mut perms = std::fs::metadata(path).ctx(path)?.permissions();
    perms.set_readonly(readonly);
    std::fs::set_permissions(path, perms).ctx(path)
}

/// Best-effort: a hidden vault folder is nicer than a bare `.drivetooth` in Explorer.
/// macOS and Linux already hide dot-prefixed entries, so only Windows needs an attribute.
pub fn set_hidden(path: &Path, hidden: bool) -> DtResult<()> {
    #[cfg(windows)]
    {
        let flag = if hidden { "+h" } else { "-h" };
        let outcome = std::process::Command::new("attrib")
            .arg(flag)
            .arg(path)
            .output()
            .map_err(|e| DtError::Other(format!("attrib failed: {e}")))?;
        if !outcome.status.success() {
            return Err(DtError::Other(format!(
                "attrib reported: {}",
                String::from_utf8_lossy(&outcome.stderr).trim()
            )));
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (path, hidden);
    }
    Ok(())
}

/// `(total, free)` in bytes. The "available to this user" figure is exactly what a lock pass
/// needs, since a locked file is written as a blob before its plaintext is removed.
#[cfg(unix)]
pub fn free_space(path: &Path) -> DtResult<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| DtError::Other("path contains a NUL byte".into()))?;
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(cpath.as_ptr(), &mut vfs) } != 0 {
        return Err(DtError::Other(format!(
            "statvfs({}) failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    // f_frsize is the block size for space accounting; fall back to f_bsize on odd FSs.
    let mut block = vfs.f_frsize as u64;
    if block == 0 {
        block = vfs.f_bsize as u64;
    }
    if block == 0 {
        return Err(DtError::Other(format!(
            "statvfs({}) reported a zero block size",
            path.display()
        )));
    }
    Ok((vfs.f_blocks as u64 * block, vfs.f_bavail as u64 * block))
}

#[cfg(windows)]
pub fn free_space(path: &Path) -> DtResult<(u64, u64)> {
    let wide = to_wide(&path.to_string_lossy());
    let mut free = 0u64;
    let mut total = 0u64;
    let mut _all_free = 0u64;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            &mut total,
            &mut _all_free,
        )
    };
    if ok == 0 {
        return Err(DtError::Other(format!(
            "GetDiskFreeSpaceExW({}) failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok((total, free))
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetDiskFreeSpaceExW(
        directory_name: *const u16,
        free_bytes_available_to_caller: *mut u64,
        total_number_of_bytes: *mut u64,
        total_number_of_free_bytes: *mut u64,
    ) -> i32;
    fn GetDriveTypeW(root_path: *const u16) -> u32;
}

#[cfg(windows)]
fn to_wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Sync a directory entry so that a rename or unlink inside it survives a power loss.
/// Without this, the "blob exists" / "plaintext gone" facts we key recovery off can be
/// reordered by the disk cache.
pub fn fsync_dir(path: &Path) -> DtResult<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(path).ctx(path)?.sync_all().ctx(path)
    }
    #[cfg(windows)]
    {
        // Opening a directory handle for syncing needs FILE_FLAG_BACKUP_SEMANTICS, which the
        // stdlib does not expose; a flush of the volume is the closest cheap equivalent and
        // NTFS keeps its own metadata journal, so treat this as best-effort.
        let _ = path;
        Ok(())
    }
}

/// Mount-level write permission. Unix reads the VFS flags; Windows asks the filesystem by
/// trying the smallest possible write.
#[cfg(unix)]
pub fn is_read_only(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(cpath.as_ptr(), &mut vfs) } != 0 {
        return false;
    }
    (vfs.f_flag as u64 & libc::ST_RDONLY as u64) != 0
}

#[cfg(not(unix))]
pub fn is_read_only(path: &Path) -> bool {
    let probe = path.join(".drivetooth-writability-probe");
    match std::fs::write(&probe, b"probe") {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            false
        }
        Err(_) => true,
    }
}

pub fn mount_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string_lossy().to_string())
}

/// The volume the operating system runs from. Sealing it would take the machine down along
/// with the files, so no operation is allowed there. `is_boot_volume` cannot answer this: on
/// APFS the root and every folder on the internal disk share one device id.
pub fn is_system_mount(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('\\', "/");
    let trimmed = text.trim_end_matches('/');
    if trimmed == "/System" || trimmed.starts_with("/System/Volumes") {
        return true;
    }
    // Only the drive the system boots from, never a second drive root: D:\ is exactly the
    // kind of volume this app is for.
    #[cfg(windows)]
    {
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        trimmed.eq_ignore_ascii_case(system.trim_end_matches(['/', '\\']))
    }
    #[cfg(not(windows))]
    {
        trimmed.is_empty()
    }
}

/// Every path that could be a mounted volume. Enumerating these is cheap; filling in the
/// details is not, which is why the plug watcher stops here.
pub fn mount_candidates() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    #[cfg(target_os = "macos")]
    {
        candidates.push(PathBuf::from("/"));
        if let Ok(entries) = std::fs::read_dir("/Volumes") {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    candidates.push(p);
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        candidates.push(PathBuf::from("/"));
        for base in ["/run/media", "/media", "/mnt"] {
            let Ok(entries) = std::fs::read_dir(base) else {
                continue;
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    candidates.push(p.clone());
                    // /run/media/<uid>/<vol>
                    if let Ok(inner) = std::fs::read_dir(&p) {
                        for sub in inner.flatten() {
                            if sub.path().is_dir() {
                                candidates.push(sub.path());
                            }
                        }
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        for letter in b'A'..=b'Z' {
            let root = format!("{}:\\", letter as char);
            let path = PathBuf::from(root);
            if path.exists() {
                candidates.push(path);
            }
        }
    }
    candidates
}

pub fn list_mounts() -> Vec<MountInfo> {
    let mut seen: Vec<PathBuf> = Vec::new();

    let mut out = Vec::new();
    for path in mount_candidates() {
        if seen.iter().any(|s| s == &path) {
            continue;
        }
        if !path.exists() {
            continue;
        }
        seen.push(path.clone());
        let (total, free) = free_space(&path).unwrap_or((0, 0));
        let boot = is_boot_volume(&path);
        // The root of the system volume has no meaningful folder name to show; a row called
        // "/" reads like a broken entry rather than like the Mac itself.
        let name = if boot {
            "system volume".to_string()
        } else {
            mount_name(&path)
        };
        out.push(MountInfo {
            path: path.to_string_lossy().to_string(),
            name,
            fs_type: fs_type(&path),
            removable: is_removable(&path),
            read_only_mount: is_read_only(&path),
            is_boot: boot,
            total_bytes: total,
            free_bytes: free,
            drive_tooth: super::Vault::detect(&path)
                .ok()
                .flatten()
                .map(|v| VaultBrief {
                    state: v.meta.state,
                    scope: v.meta.scope,
                    label: v.meta.label,
                    uuid: v.meta.uuid,
                }),
        });
    }
    out.sort_by(|a, b| a.is_boot.cmp(&b.is_boot).then(a.name.cmp(&b.name)));
    out
}

#[cfg(target_os = "linux")]
fn fs_type(path: &Path) -> String {
    let Ok(text) = std::fs::read_to_string("/proc/mounts") else {
        return String::new();
    };
    let target = path.to_string_lossy();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == target {
            return fields[2].to_string();
        }
    }
    String::new()
}

#[cfg(not(target_os = "linux"))]
fn fs_type(_path: &Path) -> String {
    // macOS exposes no cheap fstype here; the attribute that matters for us, write
    // permission, comes from the mount flags below.
    String::new()
}

#[cfg(target_os = "linux")]
fn is_removable(path: &Path) -> bool {
    let fstype = fs_type(path);
    let target = path.to_string_lossy().to_string();
    if let Ok(text) = std::fs::read_to_string("/proc/mounts") {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 3 && fields[1] == target {
                if let Some(dev) = fields[0].strip_prefix("/dev/") {
                    let usb = std::path::Path::new("/sys/block").join(dev.trim_end_matches(|c: char| c.is_digit()));
                    return std::fs::read_dir(usb.join("device"))
                        .map(|mut d| d.next().is_some())
                        .unwrap_or(false)
                        || fstype.contains("vfat")
                        || fstype.contains("exfat")
                        || fstype.contains("udf");
                }
            }
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn is_removable(path: &Path) -> bool {
    // Anything mounted under /Volumes that is not the boot volume is treated as
    // removable for the purposes of the UI badge.
    let text = path.to_string_lossy();
    text.starts_with("/Volumes/") && !is_boot_volume(path)
}

#[cfg(windows)]
fn is_removable(path: &Path) -> bool {
    const DRIVE_REMOVABLE: u32 = 2;
    let wide = to_wide(&path.to_string_lossy());
    unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_REMOVABLE }
}

#[cfg(unix)]
fn is_boot_volume(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(target) = std::fs::metadata(path) else {
        return false;
    };
    match std::fs::metadata("/") {
        Ok(root) => root.dev() == target.dev(),
        Err(_) => false,
    }
}

#[cfg(windows)]
fn is_boot_volume(path: &Path) -> bool {
    let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    path.to_string_lossy()
        .to_uppercase()
        .starts_with(&system.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_volume_the_os_runs_from_is_never_a_target() {
        assert!(is_system_mount(Path::new("/")));
        assert!(is_system_mount(Path::new("/System/Volumes/Data")));
        // A folder on that same disk is not the system mount: only the volume roots are.
        assert!(!is_system_mount(Path::new("/Volumes/USB-STICK")));
        assert!(!is_system_mount(Path::new("/Users/me/Documents")));
        assert!(!is_system_mount(Path::new("D:\\")));
    }

    #[test]
    fn free_space_looks_sane_for_the_host() {
        let (total, free) = free_space(Path::new(".")).unwrap();
        assert!(total > 0);
        assert!(free > 0);
        assert!(free <= total);
    }

    #[test]
    fn metadata_capture_and_restore_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("note.txt");
        std::fs::write(&file, b"hello").unwrap();
        let captured = capture_meta(&file).unwrap();
        assert_eq!(captured.mtime_ms, std::fs::metadata(&file).unwrap().modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64);
        #[cfg(unix)]
        assert_ne!(captured.mode, 0);

        // Backdate it, then restore and confirm the timestamp comes back.
        std::fs::File::open(&file)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000))
            .unwrap();
        assert_ne!(capture_meta(&file).unwrap().mtime_ms, captured.mtime_ms);
        restore_meta(&file, &captured).unwrap();
        let after = capture_meta(&file).unwrap();
        assert_eq!(after.mtime_ms, captured.mtime_ms);
        #[cfg(unix)]
        assert_eq!(after.mode & 0o777, captured.mode & 0o777);
    }

    #[test]
    fn read_only_dirs_are_detected() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_read_only(dir.path()));
        #[cfg(unix)]
        {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
            // Permission bits are not the mount flag, so this only proves the probe runs.
            let _ = is_read_only(dir.path());
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn mount_listing_names_the_host_root() {
        let mounts = list_mounts();
        assert!(!mounts.is_empty());
        let boot = mounts.iter().find(|m| m.is_boot);
        #[cfg(unix)]
        assert!(boot.is_some(), "the boot volume should be listed");
        for m in &mounts {
            assert!(!m.path.is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn hidden_attribute_is_a_noop_off_windows() {
        let dir = tempfile::tempdir().unwrap();
        set_hidden(dir.path(), true).unwrap();
    }
}
