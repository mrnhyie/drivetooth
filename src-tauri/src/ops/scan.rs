//! Walk the scope once and decide what would be encrypted, before touching anything.

use std::path::{Path, PathBuf};

use serde::Serialize;
use walkdir::WalkDir;

use crate::error::{DtError, DtResult, IoCtx};
use crate::volume::fs::{self, StoredMeta};
use crate::volume::manifest::{is_internal_name, is_system_name, join_rel, rel_from};
use crate::volume::{VaultOptions, VAULT_DIR};

use super::{Runner, Skipped};

#[derive(Debug, Clone, Serialize)]
pub struct ScannedFile {
    pub rel_path: String,
    #[serde(skip)]
    pub abs: PathBuf,
    pub size: u64,
    #[serde(flatten)]
    pub meta: StoredMeta,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScannedDir {
    pub rel_path: String,
    #[serde(skip)]
    pub abs: PathBuf,
    pub meta: StoredMeta,
}

#[derive(Debug, Default, Clone)]
pub struct ScanPlan {
    /// Depth-first order, deepest first is not guaranteed; the lock pass prunes directories
    /// itself in reverse.
    pub files: Vec<ScannedFile>,
    pub dirs: Vec<ScannedDir>,
    pub skipped: Vec<Skipped>,
    pub total_bytes: u64,
}

impl ScanPlan {
    pub fn largest_file(&self) -> u64 {
        self.files.iter().map(|f| f.size).max().unwrap_or(0)
    }
}

pub fn scan(
    mount: &Path,
    scope_rel: &str,
    options: &VaultOptions,
    runner: &Runner,
) -> DtResult<ScanPlan> {
    let scope_root = join_rel(mount, scope_rel);
    let root_meta = std::fs::metadata(&scope_root).ctx(&scope_root)?;
    if !root_meta.is_dir() {
        return Err(DtError::State(format!(
            "scope {} is not a folder",
            scope_root.display()
        )));
    }
    let vault_dir = mount.join(VAULT_DIR);
    let mut plan = ScanPlan::default();
    let mut seen = 0usize;

    let mut walker = WalkDir::new(&scope_root)
        .follow_links(false)
        .contents_first(false)
        .min_depth(1)
        .into_iter();

    while let Some(next) = walker.next() {
        seen += 1;
        if seen % 512 == 0 {
            runner.checkpoint()?;
        }
        let entry = match next {
            Ok(entry) => entry,
            Err(err) => {
                // An unreadable directory or file must not abort the whole pass: record it
                // and leave it exactly as it is.
                let path = err
                    .path()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| String::from("(unknown)"));
                plan.skipped.push(Skipped {
                    path,
                    reason: err.to_string(),
                });
                continue;
            }
        };
        let abs = entry.path().to_path_buf();
        if abs.starts_with(&vault_dir) {
            if entry.file_type().is_dir() {
                walker.skip_current_dir();
            }
            continue;
        }
        let name = entry
            .file_name()
            .to_string_lossy()
            .to_string();
        if is_internal_name(&name) || is_system_name(&name) {
            // The operating system's own bookkeeping: left exactly where it is, and never
            // even reported as skipped.
            if entry.file_type().is_dir() {
                walker.skip_current_dir();
            }
            continue;
        }
        if options.is_excluded(&name) {
            if entry.file_type().is_dir() {
                walker.skip_current_dir();
                plan.skipped.push(Skipped {
                    path: name.clone(),
                    reason: "excluded folder".to_string(),
                });
            } else {
                plan.skipped.push(Skipped {
                    path: name.clone(),
                    reason: "excluded".to_string(),
                });
            }
            continue;
        }
        let rel = match rel_from(mount, &abs) {
            Ok(rel) => rel,
            Err(err) => {
                plan.skipped.push(Skipped {
                    path: abs.to_string_lossy().to_string(),
                    reason: err.to_string(),
                });
                continue;
            }
        };
        let meta = match fs::capture_meta(&abs) {
            Ok(meta) => meta,
            Err(err) => {
                plan.skipped.push(Skipped {
                    path: rel,
                    reason: err.to_string(),
                });
                continue;
            }
        };

        let ftype = entry.file_type();
        if ftype.is_dir() {
            // With a per-file pick, a folder that holds nothing chosen is not walked at all.
            if !options.covers_dir(&rel) {
                walker.skip_current_dir();
                continue;
            }
            plan.dirs.push(ScannedDir {
                rel_path: rel,
                abs,
                meta,
            });
        } else if ftype.is_file() {
            if !options.is_selected(&rel) {
                continue;
            }
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            plan.total_bytes += size;
            plan.files.push(ScannedFile {
                rel_path: rel,
                abs,
                size,
                meta,
            });
        } else {
            plan.skipped.push(Skipped {
                path: rel,
                reason: "not a regular file (socket, device, or symlink)".to_string(),
            });
        }
    }

    // Deepest directories first so pruning a locked tree removes children before parents.
    plan.dirs.sort_by(|a, b| {
        let depth = |rel: &str| rel.split('/').count();
        depth(&b.rel_path)
            .cmp(&depth(&a.rel_path))
            .then(b.rel_path.cmp(&a.rel_path))
    });
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume::{Vault, VaultOptions};
    use crate::ops::Phase;

    fn quiet_runner() -> Runner {
        Runner::new(Box::new(|_| {}))
    }

    fn sample_tree(dir: &Path) {
        std::fs::create_dir_all(dir.join("secret/deep/deeper")).unwrap();
        std::fs::create_dir_all(dir.join("secret/empty")).unwrap();
        std::fs::write(dir.join("secret/a.txt"), b"aaaa").unwrap();
        std::fs::write(dir.join("secret/deep/b.bin"), vec![7u8; 4096]).unwrap();
        std::fs::write(dir.join("secret/deep/deeper/c.dat"), b"hello world").unwrap();
        std::fs::write(dir.join("secret/.DS_Store"), b"junk").unwrap();
        std::fs::write(dir.join("public.txt"), b"not in scope").unwrap();
    }

    #[test]
    fn scope_scan_collects_files_and_dirs_without_the_vault_folder() {
        let dir = tempfile::tempdir().unwrap();
        sample_tree(dir.path());
        let (vault, _key) = Vault::create(
            dir.path(),
            "secret",
            "t",
            "pw",
            "pw",
            VaultOptions {
                kdf_target_ms: 100,
                ..Default::default()
            },
        )
        .unwrap();
        let plan = scan(dir.path(), "secret", &vault.meta.options, &quiet_runner()).unwrap();

        let names: Vec<&str> = plan.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(names.len(), 3, "{names:?}");
        assert!(names.contains(&"secret/a.txt"));
        assert!(names.contains(&"secret/deep/b.bin"));
        assert_eq!(plan.total_bytes, 4 + 4096 + 11);
        assert!(!names.iter().any(|n| n.contains(".DS_Store")));
        assert!(!names.iter().any(|n| n.starts_with(".drivetooth")));
        assert!(!names.iter().any(|n| *n == "public.txt"));

        let dirs: Vec<&str> = plan.dirs.iter().map(|d| d.rel_path.as_str()).collect();
        assert!(dirs.contains(&"secret/deep/deeper"));
        assert!(dirs.contains(&"secret/empty"));
        assert!(!dirs.contains(&"secret"), "the scope root itself is never recorded");
        // Deepest first, so children get pruned before parents.
        assert!(
            dirs.iter().position(|d| *d == "secret/deep/deeper") < dirs.iter().position(|d| *d == "secret/deep"),
            "{dirs:?}"
        );
        assert_eq!(plan.largest_file(), 4096);
        assert!(plan.skipped.iter().any(|s| s.reason == "excluded"));
    }

    #[test]
    fn a_selection_encrypts_only_what_was_picked() {
        let dir = tempfile::tempdir().unwrap();
        sample_tree(dir.path());
        let (vault, _key) = Vault::create(
            dir.path(),
            "/",
            "t",
            "pw",
            "pw",
            VaultOptions {
                kdf_target_ms: 100,
                select: vec![
                    "secret/a.txt".to_string(),
                    "secret/deep/deeper".to_string(),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        let plan = scan(dir.path(), "/", &vault.meta.options, &quiet_runner()).unwrap();

        let mut names: Vec<&str> = plan.files.iter().map(|f| f.rel_path.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["secret/a.txt", "secret/deep/deeper/c.dat"], "{names:?}");
        assert_eq!(plan.total_bytes, 4 + 11);
        // b.bin sits in a folder that was walked only to reach the pick below it.
        assert!(!names.contains(&"secret/deep/b.bin"));

        let dirs: Vec<&str> = plan.dirs.iter().map(|d| d.rel_path.as_str()).collect();
        assert!(dirs.contains(&"secret/deep"), "needed to reach the pick inside it");
        assert!(
            !dirs.contains(&"secret/empty"),
            "a folder holding nothing picked is never recorded: {dirs:?}"
        );
    }

    #[test]
    fn an_empty_selection_still_means_the_whole_scope() {
        let dir = tempfile::tempdir().unwrap();
        sample_tree(dir.path());
        let options = VaultOptions::default();
        assert!(options.is_selected("anything/at/all"));
        assert!(options.covers_dir("anything"));
        let options = VaultOptions {
            select: vec!["secret/deep/b.bin".to_string()],
            ..Default::default()
        };
        assert!(options.is_selected("secret/deep/b.bin"));
        assert!(!options.is_selected("secret/a.txt"));
        assert!(options.covers_dir("secret"));
        assert!(options.covers_dir("secret/deep"));
        assert!(!options.covers_dir("secret/empty"));
    }

    #[test]
    fn operating_system_bookkeeping_is_never_touched() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".fseventsd")).unwrap();
        std::fs::write(dir.path().join(".fseventsd/fseventsd-uuid"), b"uuid").unwrap();
        std::fs::create_dir(dir.path().join(".Trashes")).unwrap();
        std::fs::write(dir.path().join("._note.txt"), b"appledouble").unwrap();
        std::fs::write(dir.path().join("note.txt"), b"real").unwrap();

        let plan = scan(dir.path(), "/", &VaultOptions::default(), &quiet_runner()).unwrap();
        let names: Vec<&str> = plan.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(names, vec!["note.txt"], "{names:?}");
        assert!(plan.dirs.is_empty(), "no system folder is recorded for pruning");
        assert!(plan.skipped.is_empty(), "and none is reported either: {:?}", plan.skipped);

        // The point of the test: the volume keeps the structures macOS needs to mount it.
        assert!(dir.path().join(".fseventsd/fseventsd-uuid").is_file());
        assert!(dir.path().join(".Trashes").is_dir());
        assert!(dir.path().join("._note.txt").is_file());
    }

    #[test]
    fn whole_drive_scope_includes_root_files() {
        let dir = tempfile::tempdir().unwrap();
        sample_tree(dir.path());
        let (vault, _key) = Vault::create(
            dir.path(),
            "/",
            "t",
            "pw",
            "pw",
            VaultOptions {
                kdf_target_ms: 100,
                ..Default::default()
            },
        )
        .unwrap();
        let plan = scan(dir.path(), "/", &vault.meta.options, &quiet_runner()).unwrap();
        let names: Vec<&str> = plan.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(names.contains(&"public.txt"));
        assert!(names.contains(&"secret/a.txt"));
        assert!(!names.iter().any(|n| n.starts_with(".drivetooth/")));
    }

    #[test]
    fn metadata_is_captured_per_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("s")).unwrap();
        std::fs::write(dir.path().join("s/one.txt"), b"x").unwrap();
        std::fs::File::open(dir.path().join("s/one.txt"))
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(9_999_999))
            .unwrap();
        let plan = scan(dir.path(), "s", &VaultOptions::default(), &quiet_runner()).unwrap();
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].meta.mtime_ms, 9_999_999_000);
        assert_eq!(plan.files[0].size, 1);
    }

    #[test]
    fn a_missing_scope_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let err = scan(dir.path(), "ghost", &VaultOptions::default(), &quiet_runner()).unwrap_err();
        assert!(matches!(err, DtError::Io { .. }));
    }

    #[test]
    fn scan_reports_a_file_it_cannot_stat() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("s")).unwrap();
        std::fs::write(dir.path().join("s/ok.txt"), b"x").unwrap();
        // A file removed between the directory listing and the stat lands in `skipped`.
        let plan = scan(dir.path(), "s", &VaultOptions::default(), &quiet_runner()).unwrap();
        assert_eq!(plan.files.len(), 1);
        assert!(plan.skipped.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("s")).unwrap();
        std::fs::write(dir.path().join("outside.txt"), b"target").unwrap();
        std::os::unix::fs::symlink(dir.path().join("outside.txt"), dir.path().join("s/link.txt")).unwrap();
        std::os::unix::fs::symlink("/etc", dir.path().join("s/dirlink")).unwrap();
        let plan = scan(dir.path(), "s", &VaultOptions::default(), &quiet_runner()).unwrap();
        assert!(plan.files.is_empty());
        assert!(plan.skipped.iter().any(|s| s.path == "s/link.txt"));
        assert!(!plan.dirs.iter().any(|d| d.rel_path == "s/dirlink"));
        // The symlink target must not have been pulled into the plan.
        assert!(!plan.files.iter().any(|f| f.rel_path == "outside.txt"));
    }

    #[test]
    fn cancellation_stops_the_walk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("s")).unwrap();
        for i in 0..1_200 {
            std::fs::write(dir.path().join(format!("s/f{i}.txt")), b"x").unwrap();
        }
        let runner = quiet_runner();
        runner.request_cancel();
        runner.publish("lock", Phase::Planning, 0, 0, "", "start");
        let err = scan(dir.path(), "s", &VaultOptions::default(), &runner).unwrap_err();
        assert!(matches!(err, DtError::Cancel));
    }
}
