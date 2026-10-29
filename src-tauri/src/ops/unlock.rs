//! Unlock: sealed blobs back to a browsable tree.

use std::path::PathBuf;

use crate::crypto::envelope;
use crate::crypto::kdf::Secret;
use crate::error::{DtError, DtResult, IoCtx};
use crate::volume::journal::{Journal, JournalPhase, OpKind};
use crate::volume::manifest::{join_rel, name_key, Entry, EntryKind, Manifest};
use crate::volume::{fs, Vault, VaultState, TEMP_SUFFIX};

use super::{require_space, Phase, Runner, Skipped, Summary, SPACE_MARGIN};

struct Restored {
    id: String,
    target: PathBuf,
    blob: PathBuf,
}

pub fn unlock(vault: &mut Vault, key: &Secret, runner: &Runner) -> DtResult<Summary> {
    let mount = vault.mount.clone();
    let started = runner.started.elapsed().as_millis() as u64;
    let mut manifest = Manifest::load(vault, key)?;
    if manifest.paths_are_sealed() {
        manifest.reveal_paths(&name_key(key)?)?;
    }
    let files: Vec<Entry> = manifest
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::File)
        .cloned()
        .collect();
    let dirs: Vec<Entry> = manifest
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::Dir)
        .cloned()
        .collect();
    if files.is_empty() && dirs.is_empty() {
        return Err(DtError::Other(
            "nothing is encrypted on this drive".to_string(),
        ));
    }

    // Each blob is freed right after its file is restored, so the peak extra requirement
    // is the largest single file rather than the whole set.
    let largest = files.iter().map(|f| f.size).max().unwrap_or(0);
    require_space(&mount, largest + SPACE_MARGIN)?;

    // Recreate the skeleton first so every target parent exists.
    let mut ordered_dirs = dirs.clone();
    ordered_dirs.sort_by_key(|e| e.path.clone().unwrap_or_default().split('/').count());
    for entry in &ordered_dirs {
        let path = entry.abs(&mount);
        std::fs::create_dir_all(&path).ctx(&path)?;
    }

    let mut journal = Journal::new(vault, OpKind::Unlock, JournalPhase::Prepared, files.len() as u64, {
        files.iter().map(|f| f.size).sum()
    });
    journal.save(vault)?;
    vault.set_state(VaultState::Recovering, "")?;

    let total_bytes: u64 = files.iter().map(|f| f.size).sum();
    let mut restored: Vec<Restored> = Vec::with_capacity(files.len());
    let mut skipped: Vec<Skipped> = Vec::new();

    // ---- phase one: write plaintext alongside the blobs. Reversible. ----
    let outcome = (|| -> DtResult<()> {
        for (index, entry) in files.iter().enumerate() {
            runner.checkpoint()?;
            let rel = entry
                .path
                .clone()
                .ok_or_else(|| DtError::Format("entry has no revealed path".into()))?;
            let target = join_rel(&mount, &rel);
            let id_bytes = entry.id_bytes()?;
            let blob = vault.blob_path(&entry.id);
            if index % 20 == 0 {
                runner.publish(
                    "unlock",
                    Phase::Writing,
                    files.len() as u64,
                    total_bytes,
                    &rel,
                    "decrypting",
                );
            }

            if !blob.exists() {
                if std::fs::metadata(&target).is_ok() {
                    // Already restored by a previous pass that died before cleanup.
                    restored.push(Restored {
                        id: entry.id.clone(),
                        target,
                        blob,
                    });
                    continue;
                }
                return Err(DtError::Format(format!(
                    "blob {} is missing and {} was never restored",
                    entry.id, rel
                )));
            }

            let parent = target
                .parent()
                .ok_or_else(|| DtError::Other(format!("{} has no parent", rel)))?;
            std::fs::create_dir_all(parent).ctx(parent)?;
            let temp = parent.join(format!("{}.dttmp", entry.id));
            let header = envelope::decrypt_file(&blob, &temp, key, Some(id_bytes), &|| {
                runner.checkpoint()
            })
            .map_err(|err| {
                let _ = std::fs::remove_file(&temp);
                err
            })?;
            if header.plaintext_len != entry.size {
                let _ = std::fs::remove_file(&temp);
                return Err(DtError::Format(format!(
                    "{} holds {} bytes but the manifest says {}",
                    entry.id, header.plaintext_len, entry.size
                )));
            }
            {
                let synced = std::fs::File::open(&temp).ctx(&temp)?;
                synced.sync_all().ctx(&temp)?;
            }
            std::fs::rename(&temp, &target).ctx(&target)?;
            let _ = fs::fsync_dir(parent);
            restored.push(Restored {
                id: entry.id.clone(),
                target,
                blob,
            });
            runner.add_progress(entry.size);
        }
        Ok(())
    })();

    if let Err(err) = outcome {
        // Roll back: every file we completed still has its blob, so dropping the plaintext
        // copies returns the drive to a locked state without losing anything.
        rollback(&restored);
        Journal::clear(vault)?;
        vault.set_state(VaultState::Locked, "unlock rolled back")?;
        return Err(err);
    }

    // ---- commit point ----
    runner.publish(
        "unlock",
        Phase::Committing,
        files.len() as u64,
        total_bytes,
        "",
        "committing",
    );
    journal.advance(vault, JournalPhase::Destructive)?;
    runner
        .past_point_of_no_return
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // ---- phase two: drop the blobs, then fix up metadata. ----
    for entry in &restored {
        match std::fs::remove_file(&entry.blob) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => skipped.push(Skipped {
                path: entry.id.clone(),
                reason: format!("blob remains on the drive: {err}"),
            }),
        }
    }
    let _ = fs::fsync_dir(&vault.blobs_dir());

    let by_id: std::collections::HashMap<String, &Entry> = manifest
        .entries
        .iter()
        .map(|e| (e.id.clone(), e))
        .collect();
    for entry in &restored {
        if let Some(record) = by_id.get(&entry.id) {
            if let Err(err) = fs::restore_meta(&entry.target, &fs::StoredMeta {
                mtime_ms: record.mtime_ms,
                mode: record.mode,
                readonly: record.readonly,
            }) {
                skipped.push(Skipped {
                    path: entry.id.clone(),
                    reason: format!("metadata not restored: {err}"),
                });
            }
        }
    }
    // Directory times last: setting them earlier would be overwritten by their children.
    for entry in &ordered_dirs {
        let path = entry.abs(&mount);
        let _ = fs::restore_meta(
            &path,
            &fs::StoredMeta {
                mtime_ms: entry.mtime_ms,
                mode: entry.mode,
                readonly: entry.readonly,
            },
        );
    }

    let path = vault.manifest_path();
    if path.exists() {
        std::fs::remove_file(&path).ctx(&path)?;
    }
    let leftovers = std::fs::read_dir(vault.blobs_dir())
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    if leftovers {
        skipped.push(Skipped {
            path: format!("{}/{}", crate::volume::VAULT_DIR, crate::volume::BLOBS_DIR),
            reason: "unreferenced blobs remain on the drive; Recovery will clear them"
                .to_string(),
        });
    }
    Journal::clear(vault)?;
    vault.set_state(VaultState::Unlocked, "unlock")?;

    let mut summary = Summary::new("unlock");
    summary.files = restored.len() as u64;
    summary.dirs = ordered_dirs.len() as u64;
    summary.bytes = total_bytes;
    summary.skipped = skipped;
    summary.elapsed_ms = runner.started.elapsed().as_millis() as u64 - started;
    summary.message = format!("{} file(s) restored", summary.files);
    runner.publish(
        "unlock",
        Phase::Done,
        files.len() as u64,
        total_bytes,
        "",
        "drive is unlocked",
    );
    Ok(summary)
}

/// Remove plaintext copies produced by a pass that never committed. Each of them still
/// has an intact blob, so this is lossless.
fn rollback(restored: &[Restored]) {
    for entry in restored {
        let _ = std::fs::remove_file(&entry.target);
        if let Some(parent) = entry.target.parent() {
            let temp = parent.join(format!("{}{}", entry.id, TEMP_SUFFIX));
            let _ = std::fs::remove_file(temp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::lock::lock;
    use crate::ops::scan::scan;
    use crate::volume::VaultOptions;

    fn new_runner() -> Runner {
        Runner::new(Box::new(|_| {}))
    }

    fn snapshot(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for entry in walkdir::WalkDir::new(root).sort_by_file_name() {
            let entry = entry.unwrap();
            if !entry.file_type().is_file() {
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.starts_with(".drivetooth") {
                continue;
            }
            out.push((rel, std::fs::read(entry.path()).unwrap()));
        }
        out.sort();
        out
    }

    fn seeded(dir: &std::path::Path) -> (Vault, Secret) {
        std::fs::create_dir_all(dir.join("secret/nested/deeper")).unwrap();
        std::fs::write(dir.join("secret/notes.txt"), b"the launch codes are 1234").unwrap();
        std::fs::write(dir.join("secret/nested/big.bin"), vec![42u8; 300_000]).unwrap();
        std::fs::write(dir.join("secret/nested/deeper/empty.txt"), b"").unwrap();
        Vault::create(
            dir,
            "secret",
            "test drive",
            "pw",
            "pw",
            VaultOptions {
                kdf_target_ms: 100,
                chunk_exp: 14,
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn lock_then_unlock_restores_the_tree_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let before = snapshot(dir.path());
        let runner = new_runner();
        let plan = scan(dir.path(), "secret", &vault.meta.options.clone(), &runner).unwrap();
        lock(&mut vault, &key, &plan, &runner).unwrap();
        assert_eq!(vault.meta.state, VaultState::Locked);

        unlock(&mut vault, &key, &new_runner()).unwrap();
        assert_eq!(vault.meta.state, VaultState::Unlocked);
        assert_eq!(snapshot(dir.path()), before);
        assert!(!vault.manifest_path().exists());
        assert_eq!(
            std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count(),
            0
        );
    }

    #[test]
    fn timestamps_and_sizes_survive_a_full_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let file = dir.path().join("secret/notes.txt");
        std::fs::File::open(&file)
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_234_567))
            .unwrap();
        let mtime_before = fs::capture_meta(&file).unwrap().mtime_ms;
        let mode_before = fs::capture_meta(&file).unwrap().mode;

        let runner = new_runner();
        let plan = scan(dir.path(), "secret", &vault.meta.options.clone(), &runner).unwrap();
        lock(&mut vault, &key, &plan, &runner).unwrap();
        unlock(&mut vault, &key, &new_runner()).unwrap();

        let after = fs::capture_meta(&file).unwrap();
        assert_eq!(after.mtime_ms, mtime_before);
        #[cfg(unix)]
        assert_eq!(after.mode & 0o777, mode_before & 0o777);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "the launch codes are 1234");
    }

    #[test]
    fn empty_file_and_deep_directories_come_back() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let runner = new_runner();
        let plan = scan(dir.path(), "secret", &vault.meta.options.clone(), &runner).unwrap();
        lock(&mut vault, &key, &plan, &runner).unwrap();
        unlock(&mut vault, &key, &new_runner()).unwrap();
        assert_eq!(
            std::fs::metadata(dir.path().join("secret/nested/deeper/empty.txt"))
                .unwrap()
                .len(),
            0
        );
        assert!(dir.path().join("secret/nested/deeper").is_dir());
    }

    #[test]
    fn wrong_password_stops_before_any_write() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let runner = new_runner();
        let plan = scan(dir.path(), "secret", &vault.meta.options.clone(), &runner).unwrap();
        lock(&mut vault, &key, &plan, &runner).unwrap();
        let bad = vault.key_for("nope").unwrap_err();
        assert!(matches!(bad, DtError::WrongPassword));
        assert!(dir.path().join("secret/notes.txt").exists() == false);
    }

    #[test]
    fn unlock_of_an_unlocked_drive_is_a_no_op_error() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let err = unlock(&mut vault, &key, &new_runner()).unwrap_err();
        assert!(matches!(err, DtError::Other(_)), "{err:?}");
        assert_eq!(vault.meta.state, VaultState::Unlocked);
    }

    #[test]
    fn cancel_during_unlock_rolls_back_to_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let runner = new_runner();
        let plan = scan(dir.path(), "secret", &vault.meta.options.clone(), &runner).unwrap();
        lock(&mut vault, &key, &plan, &runner).unwrap();

        let before_blobs = std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count();
        let runner2 = new_runner();
        runner2.request_cancel();
        let err = unlock(&mut vault, &key, &runner2).unwrap_err();
        assert!(matches!(err, DtError::Cancel), "{err:?}");
        assert_eq!(vault.meta.state, VaultState::Locked);
        assert!(!dir.path().join("secret/notes.txt").exists());
        let after_blobs = std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count();
        assert_eq!(before_blobs, after_blobs);
        assert!(vault.manifest_path().exists());
    }

    #[test]
    fn a_crash_between_restore_and_blob_delete_recovers_forward() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let runner = new_runner();
        let plan = scan(dir.path(), "secret", &vault.meta.options.clone(), &runner).unwrap();
        lock(&mut vault, &key, &plan, &runner).unwrap();

        // Simulate: one file restored, its blob never deleted, journal says unlock was in
        // the destructive phase.
        let mut manifest = Manifest::load(&vault, &key).unwrap();
        manifest.reveal_paths(&name_key(&key).unwrap()).unwrap();
        let target = {
            let entry = manifest
                .entries
                .iter()
                .find(|e| e.kind == EntryKind::File)
                .unwrap()
                .clone();
            let path = entry.abs(dir.path());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            envelope::decrypt_file(
                &vault.blob_path(&entry.id),
                &path,
                &key,
                Some(entry.id_bytes().unwrap()),
                &|| Ok(()),
            )
            .unwrap();
            (path, entry)
        };
        Journal::new(&vault, OpKind::Unlock, JournalPhase::Destructive, 3, 0)
            .save(&vault)
            .unwrap();
        vault.set_state(VaultState::Recovering, "").unwrap();

        let summary = super::super::recover::recover(&mut vault, &key, &new_runner()).unwrap();
        assert_eq!(vault.meta.state, VaultState::Unlocked);
        assert!(target.0.exists());
        assert_eq!(
            std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count(),
            0,
            "leftover blobs cleaned, summary {summary:?}"
        );
    }

    #[test]
    fn tampered_blob_aborts_the_unlock_before_deleting_anything() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let runner = new_runner();
        let plan = scan(dir.path(), "secret", &vault.meta.options.clone(), &runner).unwrap();
        lock(&mut vault, &key, &plan, &runner).unwrap();

        let blobs: Vec<_> = std::fs::read_dir(vault.blobs_dir())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        let victim = blobs
            .iter()
            .find(|p| std::fs::metadata(p).unwrap().len() > 200)
            .unwrap()
            .clone();
        let mut bytes = std::fs::read(&victim).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&victim, &bytes).unwrap();

        let err = unlock(&mut vault, &key, &new_runner()).unwrap_err();
        assert!(matches!(err, DtError::Crypto(_)), "{err:?}");
        assert_eq!(vault.meta.state, VaultState::Locked);
        // Nothing was deleted: every blob is still present.
        assert_eq!(
            std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count(),
            blobs.len()
        );
    }
}
