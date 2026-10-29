//! Lock: plaintext tree to sealed blobs.

use std::path::PathBuf;

use crate::crypto::envelope;
use crate::crypto::kdf::Secret;
use crate::error::{DtError, DtResult, IoCtx};
use crate::volume::journal::{Journal, JournalPhase, OpKind};
use crate::volume::manifest::{name_key, Manifest};
use crate::volume::{fs, Vault, VaultState, VAULT_DIR};

use super::scan::ScanPlan;
use super::{require_space, Phase, Runner, Skipped, Summary, SPACE_MARGIN};

struct Written {
    id: String,
    original: PathBuf,
    blob: PathBuf,
    size: u64,
}

pub fn lock(vault: &mut Vault, key: &Secret, plan: &ScanPlan, runner: &Runner) -> DtResult<Summary> {
    let mount = vault.mount.clone();
    let scope_rel = vault.meta.scope.clone();
    let chunk_exp = vault.meta.options.chunk_exp;
    let verify = vault.meta.options.verify_after_encrypt;
    let started = runner.started.elapsed().as_millis() as u64;

    if plan.files.is_empty() && plan.dirs.is_empty() {
        return Err(DtError::Other(format!(
            "nothing to encrypt inside {}",
            vault.scope_root().display()
        )));
    }

    // Blobs live inside the vault, so the pass needs room for a second copy of everything
    // until each original is unlinked.
    let slack = plan.files.len() as u64 * (1 << chunk_exp.min(12)) + SPACE_MARGIN;
    require_space(&mount, plan.total_bytes + slack)?;

    std::fs::create_dir_all(vault.blobs_dir()).ctx(&vault.blobs_dir())?;
    let _ = fs::set_hidden(&vault.vault_dir(), true);

    let mut manifest = Manifest::load(vault, key)?;
    if manifest.paths_are_sealed() {
        manifest.reveal_paths(&name_key(key)?)?;
    }
    manifest.prune_missing(&mount, &scope_rel);

    for file in &plan.files {
        if manifest.has_path(&file.rel_path) {
            return Err(DtError::State(format!(
                "{} is already listed in the manifest; run Recovery first",
                file.rel_path
            )));
        }
    }

    let mut journal = Journal::new(
        vault,
        OpKind::Lock,
        JournalPhase::Prepared,
        plan.files.len() as u64,
        plan.total_bytes,
    );
    journal.save(vault)?;
    vault.set_state(VaultState::Recovering, "")?;

    let name_key_secret = name_key(key)?;
    let mut written: Vec<Written> = Vec::with_capacity(plan.files.len());
    let mut skipped: Vec<Skipped> = plan.skipped.clone();

    // ---- phase one: write and authenticate every blob. Fully reversible. ----
    let outcome = (|| -> DtResult<()> {
        for (index, file) in plan.files.iter().enumerate() {
            runner.checkpoint()?;
            if index % 20 == 0 {
                runner.publish(
                    "lock",
                    Phase::Writing,
                    plan.files.len() as u64,
                    plan.total_bytes,
                    &file.rel_path,
                    "encrypting",
                );
            }
            let id = manifest.file_entry(&file.rel_path, file.size, 0, &file.meta)?;
            let id_bytes = manifest
                .get(&id)
                .ok_or_else(|| DtError::Other("entry vanished".into()))?
                .id_bytes()?;
            let blob = vault.blob_path(&id);
            let tmp = blob.with_extension("dtc.dttmp");

            let header = envelope::encrypt_file(
                &file.abs,
                &tmp,
                key,
                id_bytes,
                file.size,
                chunk_exp,
                &|| runner.checkpoint(),
            )
            .map_err(|err| {
                let _ = std::fs::remove_file(&tmp);
                err
            })?;

            {
                let synced = std::fs::File::open(&tmp).ctx(&tmp)?;
                synced.sync_all().ctx(&tmp)?;
            }
            std::fs::rename(&tmp, &blob).ctx(&blob)?;
            let _ = fs::fsync_dir(&vault.blobs_dir());

            let idx = manifest
                .index_of(&id)
                .ok_or_else(|| DtError::Other("entry vanished".into()))?;
            manifest.entries[idx].blob_len = header.blob_len();

            if verify {
                envelope::verify_blob(&blob, key, id_bytes).map_err(|err| {
                    let _ = std::fs::remove_file(&blob);
                    err
                })?;
            } else {
                let actual = std::fs::metadata(&blob).ctx(&blob)?.len();
                if actual != header.blob_len() {
                    let _ = std::fs::remove_file(&blob);
                    return Err(DtError::Format(format!(
                        "blob for {} is {actual} bytes, header implies {}",
                        file.rel_path,
                        header.blob_len()
                    )));
                }
            }

            written.push(Written {
                id,
                original: file.abs.clone(),
                blob,
                size: file.size,
            });
            runner.add_progress(file.size);
        }

        if verify {
            runner.publish(
                "lock",
                Phase::Verifying,
                plan.files.len() as u64,
                plan.total_bytes,
                "",
                "all blobs authenticated",
            );
        }

        // Directories get manifest entries but no blob: the entries are what lets unlock
        // rebuild the tree. The scope folder itself is included when it is not the mount
        // root, so a locked drive shows no trace of the structure inside it.
        for dir in &plan.dirs {
            if !manifest.has_dir(&dir.rel_path) {
                manifest.dir_entry(&dir.rel_path, &dir.meta)?;
            }
        }
        if let Some(root) = scope_root_entry(vault, &scope_rel) {
            if !manifest.has_dir(&scope_rel) {
                manifest.dir_entry(&scope_rel, &root)?;
            }
        }
        Ok(())
    })();

    if let Err(err) = outcome {
        // Roll back: the blobs we made are deleted and the manifest on disk was never
        // rewritten, so the plaintext tree is exactly as it was found.
        rollback(vault, &written);
        Journal::clear(vault)?;
        vault.set_state(VaultState::Unlocked, "lock rolled back")?;
        return Err(err);
    }

    // ---- commit point: the manifest now describes the locked tree. ----
    runner.publish(
        "lock",
        Phase::Committing,
        plan.files.len() as u64,
        plan.total_bytes,
        "",
        "committing manifest",
    );
    manifest.seal_paths(&name_key_secret)?;
    manifest.save(vault, key)?;
    journal.advance(vault, JournalPhase::Destructive)?;
    runner
        .past_point_of_no_return
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // ---- phase two: remove the plaintext. Cannot be cancelled safely. ----
    let mut summary = Summary::new("lock");
    for entry in &written {
        match std::fs::remove_file(&entry.original) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => skipped.push(Skipped {
                path: entry.id.clone(),
                reason: format!("plaintext could not be removed: {err}"),
            }),
        }
        runner.add_bytes(entry.size);
    }
    summary.files = written.len() as u64;
    summary.bytes = plan.total_bytes;

    // Empty out the scope: directories are recreated on unlock from their manifest entries.
    let mut pruned = 0usize;
    for dir in &plan.dirs {
        match std::fs::remove_dir(&dir.abs) {
            Ok(_) => pruned += 1,
            // Non-empty (excluded files left behind) or already gone: leave it in place.
            Err(_) => {}
        }
    }
    if scope_root_entry(vault, &scope_rel).is_some() {
        if std::fs::remove_dir(vault.scope_root()).is_ok() {
            pruned += 1;
        }
    }
    summary.dirs = pruned as u64;

    vault.set_state(VaultState::Locked, "lock")?;
    Journal::clear(vault)?;
    runner.publish(
        "lock",
        Phase::Done,
        plan.files.len() as u64,
        plan.total_bytes,
        "",
        "drive is locked",
    );
    summary.elapsed_ms = runner.started.elapsed().as_millis() as u64 - started;
    summary.skipped = skipped;
    summary.message = format!(
        "{} file(s) and {} directory(ies) encrypted into /{VAULT_DIR}",
        summary.files, summary.dirs
    );
    Ok(summary)
}

/// The scope folder's own metadata, when that folder is part of the sealed tree. A
/// whole-drive lock has no such folder: the mount root stays where it is.
fn scope_root_entry(vault: &Vault, scope_rel: &str) -> Option<fs::StoredMeta> {
    if scope_rel == "/" || scope_rel.is_empty() {
        return None;
    }
    fs::capture_meta(&vault.scope_root()).ok()
}

/// Delete blobs produced by a pass that never reached its commit point.
fn rollback(vault: &Vault, written: &[Written]) {
    for entry in written {
        let _ = std::fs::remove_file(&entry.blob);
        let _ = std::fs::remove_file(entry.blob.with_extension("dtc.dttmp"));
    }
    let _ = fs::fsync_dir(&vault.blobs_dir());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume::VaultOptions;
    use crate::ops::scan::scan;

    fn runner() -> Runner {
        Runner::new(Box::new(|_| {}))
    }

    fn seeded(dir: &std::path::Path) -> (Vault, Secret) {
        std::fs::create_dir_all(dir.join("secret/nested")).unwrap();
        std::fs::write(dir.join("secret/notes.txt"), b"the launch codes are 1234").unwrap();
        std::fs::write(dir.join("secret/nested/big.bin"), vec![42u8; 300_000]).unwrap();
        std::fs::write(dir.join("secret/empty.txt"), b"").unwrap();
        std::fs::write(dir.join("secret/.DS_Store"), b"finder junk").unwrap();
        std::fs::write(dir.join("loose.txt"), b"outside the scope").unwrap();
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

    fn do_lock(vault: &mut Vault, key: &Secret, dir: &std::path::Path) -> DtResult<Summary> {
        let runner = runner();
        let plan = scan(dir, &vault.meta.scope.clone(), &vault.meta.options.clone(), &runner).unwrap();
        lock(vault, key, &plan, &runner)
    }

    #[test]
    fn locking_leaves_only_the_vault_folder_in_scope() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let summary = do_lock(&mut vault, &key, dir.path()).unwrap();

        assert_eq!(summary.files, 3);
        assert_eq!(vault.meta.state, VaultState::Locked);
        assert!(!dir.path().join("secret/notes.txt").exists());
        assert!(!dir.path().join("secret/nested").exists());
        // Files outside the scope are untouched.
        assert!(dir.path().join("loose.txt").exists());
        // The scope folder itself is pruned, but an excluded file keeps its parent alive.
        assert!(dir.path().join("secret").is_dir());
        assert!(dir.path().join("secret/.DS_Store").exists());
        assert_eq!(
            std::fs::read_dir(dir.path().join("secret"))
                .unwrap()
                .flatten()
                .count(),
            1,
            "only the excluded file is left"
        );
        let blobs: Vec<_> = std::fs::read_dir(vault.blobs_dir())
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(blobs.len(), 3);
        assert!(!vault.journal_path().exists());
    }

    #[test]
    fn an_emptied_scope_folder_disappears_but_the_mount_root_never_does() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("vault/deep")).unwrap();
        std::fs::write(dir.path().join("vault/deep/file.bin"), vec![1u8; 4096]).unwrap();
        let (mut vault, key) = Vault::create(
            dir.path(),
            "vault",
            "t",
            "pw",
            "pw",
            VaultOptions {
                kdf_target_ms: 100,
                chunk_exp: 14,
                ..Default::default()
            },
        )
        .unwrap();
        do_lock(&mut vault, &key, dir.path()).unwrap();
        assert!(
            !dir.path().join("vault").exists(),
            "a sealed folder leaves no trace of its name"
        );
        assert!(dir.path().join(".drivetooth").is_dir());

        // A whole-drive scope has no folder to hide: only the files go.
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("top.txt"), b"top secret").unwrap();
        let (mut vault, key) = Vault::create(
            root.path(),
            "/",
            "t",
            "pw",
            "pw",
            VaultOptions {
                kdf_target_ms: 100,
                chunk_exp: 14,
                ..Default::default()
            },
        )
        .unwrap();
        do_lock(&mut vault, &key, root.path()).unwrap();
        assert!(!root.path().join("top.txt").exists());
        assert!(root.path().is_dir(), "the mount root is never removed");

        // Both skeletons come back on unlock, including the pruned scope folder.
        super::super::unlock::unlock(&mut vault, &key, &runner()).unwrap();
        assert_eq!(std::fs::read(root.path().join("top.txt")).unwrap(), b"top secret");
        let other = dir.path();
        let mut vault2 = Vault::detect(other).unwrap().unwrap();
        vault2.key_for("pw").unwrap();
        let key2 = vault2.key_for("pw").unwrap();
        super::super::unlock::unlock(&mut vault2, &key2, &runner()).unwrap();
        assert_eq!(
            std::fs::read(other.join("vault/deep/file.bin")).unwrap(),
            vec![1u8; 4096]
        );
    }

    #[test]
    fn no_plaintext_marker_survives_a_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        do_lock(&mut vault, &key, dir.path()).unwrap();
        let marker = b"the launch codes are 1234";
        for path in walkdir::WalkDir::new(dir.path()) {
            let path = path.unwrap();
            if !path.file_type().is_file() {
                continue;
            }
            let bytes = std::fs::read(path.path()).unwrap();
            if path.path().ends_with("volume.json") || path.path().ends_with("manifest.dt") {
                continue;
            }
            assert!(
                !bytes.windows(marker.len()).any(|w| w == marker),
                "plaintext survives in {}",
                path.path().display()
            );
        }
    }

    #[test]
    fn locking_twice_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        do_lock(&mut vault, &key, dir.path()).unwrap();
        let err = do_lock(&mut vault, &key, dir.path()).unwrap_err();
        assert!(matches!(err, DtError::Other(_)), "{err:?}");
    }

    #[test]
    fn cancel_before_the_commit_point_rolls_back_completely() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let runner = runner();
        runner.request_cancel();
        let plan = scan(dir.path(), "secret", &vault.meta.options.clone(), &runner).unwrap();
        let err = lock(&mut vault, &key, &plan, &runner).unwrap_err();
        assert!(matches!(err, DtError::Cancel), "{err:?}");
        assert_eq!(vault.meta.state, VaultState::Unlocked);
        assert!(dir.path().join("secret/notes.txt").exists());
        assert!(dir.path().join("secret/nested/big.bin").exists());
        let leftovers: Vec<_> = std::fs::read_dir(vault.blobs_dir())
            .unwrap()
            .flatten()
            .collect();
        assert!(leftovers.is_empty(), "blob debris after rollback");
        assert!(!vault.journal_path().exists());
        assert!(!vault.manifest_path().exists());
    }

    #[test]
    fn an_interrupted_lock_can_be_resumed_forward() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let runner = runner();
        let plan = scan(dir.path(), "secret", &vault.meta.options.clone(), &runner).unwrap();

        // Simulate a crash between the commit point and the removal of the plaintext:
        // manifest says locked, originals are still there.
        {
            let mut manifest = Manifest::load(&vault, &key).unwrap();
            for file in &plan.files {
                let id = manifest.file_entry(&file.rel_path, file.size, 0, &file.meta).unwrap();
                let id_bytes = manifest.get(&id).unwrap().id_bytes().unwrap();
                let blob = vault.blob_path(&id);
                let header =
                    envelope::encrypt_file(&file.abs, &blob, &key, id_bytes, file.size, 14, &|| Ok(()))
                        .unwrap();
                let idx = manifest.index_of(&id).unwrap();
                manifest.entries[idx].blob_len = header.blob_len();
            }
            manifest.seal_paths(&name_key(&key).unwrap()).unwrap();
            manifest.save(&vault, &key).unwrap();
        }
        let journal = Journal::new(&vault, OpKind::Lock, JournalPhase::Destructive, 3, plan.total_bytes);
        journal.save(&vault).unwrap();
        vault.set_state(VaultState::Recovering, "").unwrap();

        let report = super::super::recover::recover(&mut vault, &key, &runner).unwrap();
        assert_eq!(report.op, "recover");
        assert_eq!(vault.meta.state, VaultState::Locked);
        assert!(!dir.path().join("secret/notes.txt").exists());
        assert!(!vault.journal_path().exists());
        let blobs = std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count();
        assert_eq!(blobs, 3);
    }

    #[test]
    fn a_lock_that_never_committed_rolls_back_on_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        // Blobs exist but the manifest on disk is still the empty pre-lock one.
        std::fs::create_dir_all(vault.blobs_dir()).unwrap();
        let orphan = vault.blob_path("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let notes = dir.path().join("secret/notes.txt");
        let size = std::fs::metadata(&notes).unwrap().len();
        let mut manifest = Manifest::new(&vault.meta.uuid);
        let id = manifest
            .file_entry("secret/notes.txt", size, 0, &fs::StoredMeta {
                mtime_ms: 1,
                mode: 0o644,
                readonly: false,
            })
            .unwrap();
        envelope::encrypt_file(
            &notes,
            &orphan,
            &key,
            manifest.get(&id).unwrap().id_bytes().unwrap(),
            size,
            14,
            &|| Ok(()),
        )
        .unwrap();
        drop(manifest);
        Journal::new(&vault, OpKind::Lock, JournalPhase::BlobWrites, 1, size)
            .save(&vault)
            .unwrap();
        vault.set_state(VaultState::Recovering, "").unwrap();

        let runner = runner();
        super::super::recover::recover(&mut vault, &key, &runner).unwrap();
        assert_eq!(vault.meta.state, VaultState::Unlocked);
        assert!(dir.path().join("secret/notes.txt").exists());
        assert_eq!(std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count(), 0);
    }

    #[test]
    fn free_space_shortage_is_reported_before_any_write() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = seeded(dir.path());
        let mut plan = scan(dir.path(), "secret", &vault.meta.options.clone(), &runner()).unwrap();
        plan.total_bytes = u64::MAX / 2;
        let err = lock(&mut vault, &key, &plan, &runner()).unwrap_err();
        assert!(matches!(err, DtError::Space { .. }), "{err:?}");
        assert_eq!(vault.meta.state, VaultState::Unlocked);
        assert!(!vault.journal_path().exists());
    }

    #[test]
    fn verify_disabled_still_checks_blob_length() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("secret")).unwrap();
        std::fs::write(dir.path().join("secret/x.txt"), b"abcde").unwrap();
        let (mut vault, key) = Vault::create(
            dir.path(),
            "secret",
            "t",
            "pw",
            "pw",
            VaultOptions {
                kdf_target_ms: 100,
                verify_after_encrypt: false,
                chunk_exp: 12,
                ..Default::default()
            },
        )
        .unwrap();
        let summary = do_lock(&mut vault, &key, dir.path()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(summary.files, 1);
        assert!(!dir.path().join("secret/x.txt").exists());
    }
}
