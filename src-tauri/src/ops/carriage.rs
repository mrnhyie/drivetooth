//! The copy of DriveTooth that rides on the drive.
//!
//! A sealed stick is only useful if it can be opened where you happen to be, and the laptop at
//! the hotel desk has no DriveTooth on it. So the program can put a copy of itself in a plain
//! folder at the root of the drive — plain because it has to run before anything on the volume
//! can be decrypted, and it holds no key: the copy is the same program, nothing more. That
//! folder is never scanned, encrypted, browsed or deleted by an operation.
//!
//! The copy can only open a drive on the platform it was made from, because that is the only
//! build a running program has with it. The other two come from the release page.

use std::path::{Path, PathBuf};

use serde::Serialize;
use walkdir::WalkDir;

use crate::error::{DtError, DtResult, IoCtx};
use crate::ops::{SPACE_MARGIN, require_space};
use crate::volume::fs;
use crate::volume::now_ms;

/// The folder at the root of the drive. Not dotted and not the vault: this one is meant to be
/// found by whoever ends up holding the stick.
pub const CARRIAGE_DIR: &str = "DriveTooth";
pub const README_NAME: &str = "START HERE.txt";

/// Case-insensitive because exFAT and NTFS look names up that way, so a stray `drivetooth`
/// folder is the same folder to the operating system.
pub fn is_carriage_name(name: &str) -> bool {
    name.eq_ignore_ascii_case(CARRIAGE_DIR)
}

pub fn carriage_path(root: &Path) -> PathBuf {
    root.join(CARRIAGE_DIR)
}

/// A program in the shape a foreign machine can launch: one file, or one folder tree.
#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    pub path: PathBuf,
    pub name: String,
    /// True for a folder tree (a macOS bundle), false for a single file.
    pub bundle: bool,
    pub bytes: u64,
    pub files: u64,
}

/// Where the running program lives, as something that can be copied.
///
/// On macOS `current_exe` is the binary two levels inside `DriveTooth.app`, and the bundle is
/// the portable unit, so the walk up is the whole trick. On Linux an AppImage mounts itself
/// under a FUSE path, so `current_exe` points inside a temporary filesystem — `$APPIMAGE` is
/// the single file the user actually ran. Windows needs no adjustment: the exe is the program.
pub fn running_artifact() -> DtResult<Artifact> {
    let exe = std::env::current_exe().ctx(Path::new("this program"))?;
    let mut path = exe.clone();

    #[cfg(target_os = "macos")]
    {
        path = bundle_of(&exe).unwrap_or_else(|| exe.clone());
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(image) = std::env::var_os("APPIMAGE") {
            path = PathBuf::from(image);
        }
    }

    if !path.exists() {
        return Err(DtError::Other(format!(
            "cannot find the program to copy: {}",
            path.display()
        )));
    }
    let (bytes, files) = measure(&path)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| CARRIAGE_DIR.to_string());
    Ok(Artifact {
        bundle: path.is_dir(),
        path,
        name,
        bytes,
        files,
    })
}

#[cfg(target_os = "macos")]
fn bundle_of(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .find(|p| p.extension().map(|e| e == "app").unwrap_or(false))
        .map(|p| p.to_path_buf())
}

fn measure(path: &Path) -> DtResult<(u64, u64)> {
    let mut bytes = 0u64;
    let mut files = 0u64;
    if path.is_file() {
        return Ok((path.metadata().map(|m| m.len()).unwrap_or(0), 1));
    }
    for entry in WalkDir::new(path).follow_links(false).into_iter() {
        let Ok(entry) = entry else { continue };
        if entry.file_type().is_file() {
            bytes += std::fs::metadata(entry.path()).map(|m| m.len()).unwrap_or(0);
            files += 1;
        }
    }
    Ok((bytes, files))
}

/// What the drive already carries.
#[derive(Debug, Clone, Serialize)]
pub struct Carried {
    pub name: String,
    pub bytes: u64,
    pub files: u64,
    pub written_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    /// Where the copy would go.
    pub path: String,
    pub present: Option<Carried>,
    /// The running build, so the UI can say what copying costs.
    pub available: Option<Artifact>,
    pub free_bytes: u64,
    pub writable: bool,
    /// False on the volume the operating system runs from.
    pub allowed: bool,
}

pub fn status(root: &Path) -> Status {
    Status {
        path: carriage_path(root).to_string_lossy().to_string(),
        present: carried(root),
        available: running_artifact().ok(),
        free_bytes: fs::free_space(root).map(|(_, free)| free).unwrap_or(0),
        writable: !fs::is_read_only(root),
        allowed: !fs::is_system_mount(root),
    }
}

pub fn carried(root: &Path) -> Option<Carried> {
    let dir = carriage_path(root);
    if !dir.is_dir() {
        return None;
    }
    let (bytes, files) = measure(&dir).ok()?;
    let written_ms = std::fs::metadata(&dir)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let name = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .find(|n| !is_readme(n))
        .unwrap_or_else(|| CARRIAGE_DIR.to_string());
    Some(Carried {
        name,
        bytes,
        files,
        written_ms,
    })
}

fn is_readme(name: &str) -> bool {
    name.eq_ignore_ascii_case(README_NAME)
}

/// Copy the running program onto the drive. Split from [`running_artifact`] so the tree
/// walking can be tested without repackaging the application.
pub fn install(root: &Path, source: &Path, replace: bool) -> DtResult<Carried> {
    if fs::is_system_mount(root) {
        return Err(DtError::State(
            "that is the volume the system runs from".into(),
        ));
    }
    if fs::is_read_only(root) {
        return Err(DtError::State("the drive is mounted read-only".into()));
    }
    if !source.exists() {
        return Err(DtError::Other(format!(
            "nothing to copy at {}",
            source.display()
        )));
    }

    let dest = carriage_path(root);
    if dest.exists() && !replace {
        return Err(DtError::State(format!(
            "{CARRIAGE_DIR}/ is already on this drive"
        )));
    }
    // Copying a bundle into the folder that holds it would fill the drive until it fails.
    if source.starts_with(&dest) || dest.starts_with(source) {
        return Err(DtError::State(
            "this program is already running from that folder".into(),
        ));
    }

    let (bytes, files) = measure(source)?;
    require_space(root, bytes + SPACE_MARGIN)?;

    if dest.exists() {
        std::fs::remove_dir_all(&dest).ctx(&dest)?;
    }
    std::fs::create_dir_all(&dest).ctx(&dest)?;
    if files == 0 {
        return Err(DtError::Other("there is nothing inside the program to copy".into()));
    }

    let target = if source.is_dir() {
        let name = source
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "program".to_string());
        let target = dest.join(&name);
        copy_tree(source, &target)?;
        target
    } else {
        let target = dest.join(
            source
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "drivetooth".to_string()),
        );
        std::fs::copy(source, &target).ctx(source)?;
        target
    };
    write_readme(&dest, &target)?;
    fs::fsync_dir(&dest)?;

    Ok(carried(root).ok_or_else(|| DtError::Other("the copy did not appear".into()))?)
}

/// Everything under `src` into `dst`, which must not exist yet. Symlinks are skipped rather
/// than followed: exFAT and FAT32 have no such thing, so a link that survives the copy would
/// be a broken file on the machine that needs it.
fn copy_tree(src: &Path, dst: &Path) -> DtResult<()> {
    std::fs::create_dir_all(dst).ctx(dst)?;
    for entry in std::fs::read_dir(src).ctx(src)?
        .flatten()
        .filter(|e| e.file_type().map(|t| !t.is_symlink()).unwrap_or(true))
    {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to).ctx(&from)?;
        }
    }
    Ok(())
}

fn write_readme(dest: &Path, target: &Path) -> DtResult<()> {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let text = format!(
        "This drive is locked by DriveTooth.\n\
         \n\
         Nothing on it can be read without the password, and there is no way to recover one:\n\
         no support address, no backup code. The files belong to whoever holds this stick.\n\
         \n\
         To open it, run the copy of the program sitting in this folder:\n\
         \n\
           \x20 {name}\n\
         \n\
         It is the ordinary application, not a special build. It holds no key, installs nothing\n\
         on the computer, and remembers nothing after you lock the drive and unplug.\n\
         \n\
         This copy only runs on {platform}. For another system, download the same program from\n\
         the project page and run that instead:\n\
         \n\
           https://github.com/mrnhyie/drivetooth\n\
         \n\
         Written {when}.\n",
        platform = std::env::consts::OS,
        when = chrono_free_date(),
    );
    std::fs::write(dest.join(README_NAME), text).ctx(dest)
}

/// `YYYY-MM-DD` in UTC without pulling in a date crate.
fn chrono_free_date() -> String {
    let days = now_ms().div_euclid(86_400_000);
    let mut y = 1970i64;
    let mut d = days;
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let len = if leap { 366 } else { 365 };
        if d < len {
            let mut m = 1;
            let sizes = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            let mut rem = d;
            for size in sizes {
                if rem < size {
                    return format!("{y:04}-{:02}-{:02}", m, rem + 1);
                }
                rem -= size;
                m += 1;
            }
            return format!("{y}-?");
        }
        d -= len;
        y += 1;
    }
}

pub fn remove(root: &Path) -> DtResult<()> {
    let dest = carriage_path(root);
    if dest.exists() {
        if fs::is_read_only(root) {
            return Err(DtError::State("the drive is mounted read-only".into()));
        }
        std::fs::remove_dir_all(&dest).ctx(&dest)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_bundle(parent: &Path) -> PathBuf {
        let app = parent.join("DriveTooth.app");
        std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        std::fs::create_dir_all(app.join("Contents/Resources")).unwrap();
        std::fs::write(app.join("Contents/Info.plist"), b"plist").unwrap();
        std::fs::write(app.join("Contents/MacOS/drivetooth"), b"binary").unwrap();
        std::fs::write(app.join("Contents/Resources/logo.png"), b"png").unwrap();
        app
    }

    #[test]
    fn a_bundle_lands_whole_next_to_a_note() {
        let src_root = tempfile::tempdir().unwrap();
        let drive = tempfile::tempdir().unwrap();
        let app = fake_bundle(src_root.path());

        let report = install(drive.path(), &app, false).unwrap();
        assert_eq!(report.files, 3);
        assert!(drive.path().join("DriveTooth/START HERE.txt").is_file());
        assert_eq!(
            std::fs::read(drive.path().join("DriveTooth/DriveTooth.app/Contents/MacOS/drivetooth"))
                .unwrap(),
            b"binary"
        );
    }

    #[test]
    fn a_single_file_carriage_keeps_its_name() {
        let src_root = tempfile::tempdir().unwrap();
        let drive = tempfile::tempdir().unwrap();
        let exe = src_root.path().join("drivetooth");
        std::fs::write(&exe, b"elf").unwrap();

        install(drive.path(), &exe, false).unwrap();
        assert!(drive.path().join("DriveTooth/drivetooth").is_file());
        assert_eq!(carried(drive.path()).unwrap().name, "drivetooth");
    }

    #[test]
    fn an_existing_copy_survives_until_asked_otherwise() {
        let src_root = tempfile::tempdir().unwrap();
        let drive = tempfile::tempdir().unwrap();
        let app = fake_bundle(src_root.path());
        install(drive.path(), &app, false).unwrap();

        let err = install(drive.path(), &app, false).unwrap_err();
        assert!(matches!(err, DtError::State(_)), "{err:?}");
        assert!(install(drive.path(), &app, true).is_ok());
        assert_eq!(carried(drive.path()).unwrap().files, 3);
    }

    #[test]
    fn a_program_running_from_the_carriage_cannot_copy_itself() {
        let drive = tempfile::tempdir().unwrap();
        let app = fake_bundle(drive.path());
        install(drive.path(), &app, false).unwrap();
        std::fs::remove_dir_all(carriage_path(drive.path())).unwrap();
        std::fs::create_dir_all(carriage_path(drive.path())).unwrap();

        let inside = carriage_path(drive.path()).join("DriveTooth.app");
        std::fs::create_dir_all(inside.join("Contents")).unwrap();
        let err = install(drive.path(), &inside, true).unwrap_err();
        assert!(matches!(err, DtError::State(_)), "{err:?}");
    }

    #[test]
    fn the_carriage_folder_is_the_same_name_in_any_case() {
        assert!(is_carriage_name("DriveTooth"));
        assert!(is_carriage_name("drivetooth"));
        assert!(!is_carriage_name("DRIVETOOH"));
        assert!(!is_carriage_name(".drivetooth"));
    }

    #[test]
    fn removing_the_copy_leaves_the_drive_plain() {
        let src_root = tempfile::tempdir().unwrap();
        let drive = tempfile::tempdir().unwrap();
        let app = fake_bundle(src_root.path());
        std::fs::create_dir_all(drive.path().join("docs")).unwrap();
        std::fs::write(drive.path().join("docs/note.txt"), b"hi").unwrap();
        install(drive.path(), &app, false).unwrap();
        assert!(carried(drive.path()).is_some());

        remove(drive.path()).unwrap();
        assert!(carried(drive.path()).is_none());
        assert!(drive.path().join("docs/note.txt").is_file());
    }

    #[test]
    fn the_note_dates_itself_without_a_date_crate() {
        assert_eq!(chrono_free_date().len(), 10);
        assert!(chrono_free_date().matches('-').count() == 2);
    }
}
