//! Recovery: after a crash, an unplug, or a cancelled destructive pass, reconcile the
//! drive against the committed manifest.
//!
//! There is no operation log to replay. For every manifest entry we look at what is on
//! disk — a blob, a plaintext file, both, or neither — and keep the copy that is proven
//! authentic. A blob is only trusted after its GCM tags have actually been checked, so a
//! half-written blob is never used as a reason to delete a readable plaintext file. Blobs
//! the manifest does not reference are debris from a pass that never committed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::crypto::envelope;
use crate::crypto::kdf::Secret;
use crate::error::{DtError, DtResult, IoCtx};
use crate::volume::journal::{Journal, OpKind};
use crate::volume::manifest::{join_rel, name_key, Entry, EntryKind, Manifest};
use crate::volume::{fs, Vault, VaultState, TEMP_SUFFIX};

use super::{Phase, Runner, Summary};

#[derive(Debug, Clone)]
struct OnDisk {
    blob_present: bool,
    /// The blob exists, has the length the manifest promises, and every chunk tag opens.
    blob_authentic: bool,
    plain_present: bool,
    plain_size_ok: bool,
}

pub fn recover(vault: &mut Vault, key: &Secret, runner: &Runner) -> DtResult<Summary> {
    let mount = vault.mount.clone();
    let journal = Journal::load(vault)?;
    let mut summary = Summary::new("recover");
    // The manifest is the commit point, so a drive with no manifest at all was never
    // committed. When the journal says a lock pass was still in its reversible phase, the
    // blobs on disk are debris and the plaintext tree is untouched: discard them. Anything
    // else (a Locked drive that lost its manifest) is genuine data loss and must not be
    // "repaired" by deleting blobs.
    if !vault.manifest_path().exists() {
        let uncommitted_lock = journal
            .as_ref()
            .map(|j| j.op == OpKind::Lock && !j.is_destructive())
            .unwrap_or(false);
        if !uncommitted_lock {
            return Err(DtError::State(
                "this drive is marked locked but its manifest is missing".into(),
            ));
        }
        return abandon_partial_lock(vault, runner, summary);
    }

    let (op, was_destructive) = match journal.as_ref() {
        Some(journal) => (journal.op, journal.is_destructive()),
        // No marker: sealed names in the manifest mean the lock pass had already committed.
        None => {
            let probe = Manifest::load(vault, key)?;
            (
                if probe.paths_are_sealed() {
                    OpKind::Lock
                } else {
                    OpKind::Unlock
                },
                true,
            )
        }
    };

    let mut manifest = Manifest::load(vault, key)?;
    if manifest.paths_are_sealed() {
        manifest.reveal_paths(&name_key(key)?)?;
    }
    let entries = manifest.entries.clone();
    let file_total = entries.iter().filter(|e| e.kind == EntryKind::File).count();
    runner.publish(
        "recover",
        Phase::Verifying,
        file_total as u64,
        0,
        "",
        "reconciling the drive with its manifest",
    );

    let mut referenced: HashSet<String> = HashSet::new();
    let mut touched = 0u64;

    for entry in &entries {
        runner.checkpoint()?;
        let target = entry.abs(&mount);
        if entry.kind == EntryKind::Dir {
            if !target.exists() {
                std::fs::create_dir_all(&target).ctx(&target)?;
            }
            referenced.insert(entry.id.clone());
            continue;
        }
        let rel = entry
            .path
            .clone()
            .ok_or_else(|| DtError::Format("entry has no revealed path".into()))?;
        let target = join_rel(&mount, &rel);
        let blob = vault.blob_path(&entry.id);
        referenced.insert(entry.id.clone());

        let disk = on_disk(entry, &blob, &target, key)?;
        finish(op, was_destructive, entry, &blob, &target, &disk, key, vault, runner)?;

        // A temp left by an interrupted restore is never authoritative: it was written
        // before its tags could be re-checked, and the blob it came from is still here or
        // the plaintext rename already happened.
        if let Some(temp) = temp_path(&target, &entry.id) {
            if temp.exists() && (disk.blob_authentic || disk.plain_size_ok) {
                let _ = std::fs::remove_file(&temp);
            }
        }
        summary.bytes += entry.size;
        touched += 1;
    }

    let mut orphans = 0usize;
    for orphan in orphan_blobs(vault, &referenced)? {
        std::fs::remove_file(&orphan).ctx(&orphan)?;
        orphans += 1;
    }

    let blobs_left = std::fs::read_dir(vault.blobs_dir())
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    if blobs_left {
        vault.set_state(VaultState::Locked, "recovered: locked")?;
    } else {
        let path = vault.manifest_path();
        if path.exists() {
            std::fs::remove_file(&path).ctx(&path)?;
        }
        vault.set_state(VaultState::Unlocked, "recovered: unlocked")?;
    }
    Journal::clear(vault)?;
    summary.files = touched;
    summary.message = format!(
        "reconciled {touched} of {} record(s); drive is now {}{}",
        entries.len(),
        if blobs_left { "locked" } else { "unlocked" },
        if orphans > 0 {
            format!(", {orphans} stale blob(s) removed")
        } else {
            String::new()
        }
    );
    runner.publish("recover", Phase::Done, file_total as u64, summary.bytes, "", &summary.message);
    Ok(summary)
}

/// Discard the blobs of a lock pass that never committed its manifest. The plaintext tree
/// was still untouched at that point, so nothing of the user's is lost.
fn abandon_partial_lock(vault: &mut Vault, runner: &Runner, mut summary: Summary) -> DtResult<Summary> {
    let dir = vault.blobs_dir();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                std::fs::remove_file(&path).ctx(&path)?;
                summary.files += 1;
            }
        }
    }
    let _ = fs::fsync_dir(&dir);
    Journal::clear(vault)?;
    vault.set_state(VaultState::Unlocked, "recovered: lock rolled back")?;
    runner.publish(
        "recover",
        Phase::Done,
        summary.files,
        0,
        "",
        "no manifest was committed, so nothing had been encrypted yet",
    );
    summary.message = format!(
        "discarded {} blob(s) from a lock pass that never committed",
        summary.files
    );
    Ok(summary)
}

fn temp_path(target: &Path, id: &str) -> Option<PathBuf> {
    target
        .parent()
        .map(|parent| parent.join(format!("{id}{TEMP_SUFFIX}")))
}

fn on_disk(entry: &Entry, blob: &Path, target: &Path, key: &Secret) -> DtResult<OnDisk> {
    let blob_present = blob.exists();
    let mut blob_authentic = false;
    if blob_present {
        let len = std::fs::metadata(blob).ctx(blob)?.len();
        if len == entry.blob_len && entry.blob_len > 0 {
            blob_authentic = envelope::verify_blob(blob, key, entry.id_bytes()?).is_ok();
        }
    }
    let plain_present = target.exists();
    let plain_size_ok = plain_present
        && std::fs::metadata(target)
            .map(|m| m.len() == entry.size)
            .unwrap_or(false);
    Ok(OnDisk {
        blob_present,
        blob_authentic,
        plain_present,
        plain_size_ok,
    })
}

/// Bring one record to the state the interrupted operation was heading for.
#[allow(clippy::too_many_arguments)]
fn finish(
    op: OpKind,
    was_destructive: bool,
    entry: &Entry,
    blob: &Path,
    target: &Path,
    disk: &OnDisk,
    key: &Secret,
    vault: &Vault,
    runner: &Runner,
) -> DtResult<()> {
    let id_bytes = entry.id_bytes()?;
    match op {
        OpKind::Lock => {
            if disk.blob_authentic {
                // The blob is proven; the plaintext, if any, is the leftover.
                if disk.plain_present {
                    std::fs::remove_file(target).ctx(target)?;
                }
                return Ok(());
            }
            if disk.plain_present && disk.plain_size_ok {
                if disk.blob_present {
                    // A corrupt or truncated blob with readable plaintext: replace it.
                    std::fs::remove_file(blob).ctx(blob)?;
                }
                return seal_now(entry, blob, target, id_bytes, key, vault, runner);
            }
            if disk.plain_present {
                return Err(DtError::Format(format!(
                    "{} is {} bytes but the manifest expects {}; refusing to touch either copy",
                    target.display(),
                    fs_size(target),
                    entry.size
                )));
            }
            Err(DtError::Format(format!(
                "record {} ({}) has no valid blob and no plaintext copy",
                entry.id,
                entry.path.clone().unwrap_or_default()
            )))
        }
        OpKind::Unlock => {
            if disk.plain_size_ok {
                if disk.blob_present {
                    std::fs::remove_file(blob).ctx(blob)?;
                }
                return Ok(());
            }
            if disk.blob_authentic {
                return open_now(entry, blob, target, id_bytes, key, runner);
            }
            if was_destructive && disk.plain_present {
                return Err(DtError::Format(format!(
                    "record {} was being restored but its plaintext is the wrong size and the blob failed authentication",
                    entry.id
                )));
            }
            Err(DtError::Format(format!(
                "record {} ({}) has no valid blob and nothing restored",
                entry.id,
                entry.path.clone().unwrap_or_default()
            )))
        }
    }
}

fn fs_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn seal_now(
    entry: &Entry,
    blob: &Path,
    target: &Path,
    id_bytes: [u8; 16],
    key: &Secret,
    vault: &Vault,
    runner: &Runner,
) -> DtResult<()> {
    let tmp = blob.with_extension("dtc.dttmp");
    let header = envelope::encrypt_file(
        target,
        &tmp,
        key,
        id_bytes,
        entry.size,
        vault.meta.options.chunk_exp,
        &|| runner.checkpoint(),
    )
    .map_err(|err| {
        let _ = std::fs::remove_file(&tmp);
        err
    })?;
    if header.blob_len() != entry.blob_len {
        let _ = std::fs::remove_file(&tmp);
        return Err(DtError::Format(format!(
            "re-encrypting {} made {} bytes but the manifest says {}",
            entry.path.clone().unwrap_or_default(),
            header.blob_len(),
            entry.blob_len
        )));
    }
    std::fs::rename(&tmp, blob).ctx(blob)?;
    let _ = fs::fsync_dir(&vault.blobs_dir());
    envelope::verify_blob(blob, key, id_bytes)?;
    std::fs::remove_file(target).ctx(target)?;
    runner.add_progress(entry.size);
    Ok(())
}

fn open_now(
    entry: &Entry,
    blob: &Path,
    target: &Path,
    id_bytes: [u8; 16],
    key: &Secret,
    runner: &Runner,
) -> DtResult<()> {
    let parent = target
        .parent()
        .ok_or_else(|| DtError::Other("restore target has no parent".into()))?;
    std::fs::create_dir_all(parent).ctx(parent)?;
    let temp = parent.join(format!("{}{}", entry.id, TEMP_SUFFIX));
    let header = envelope::decrypt_file(blob, &temp, key, Some(id_bytes), &|| runner.checkpoint())
        .map_err(|err| {
            let _ = std::fs::remove_file(&temp);
            err
        })?;
    if header.plaintext_len != entry.size {
        let _ = std::fs::remove_file(&temp);
        return Err(DtError::Format(format!(
            "restoring {} gave {} bytes but the manifest says {}",
            entry.path.clone().unwrap_or_default(),
            header.plaintext_len,
            entry.size
        )));
    }
    std::fs::rename(&temp, target).ctx(target)?;
    let _ = fs::fsync_dir(parent);
    std::fs::remove_file(blob).ctx(blob)?;
    fs::restore_meta(
        target,
        &fs::StoredMeta {
            mtime_ms: entry.mtime_ms,
            mode: entry.mode,
            readonly: entry.readonly,
        },
    )?;
    runner.add_progress(entry.size);
    Ok(())
}

fn orphan_blobs(vault: &Vault, referenced: &HashSet<String>) -> DtResult<Vec<PathBuf>> {
    let mut out = Vec::new();
    let dir = vault.blobs_dir();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&dir).ctx(&dir)? {
        let entry = entry.ctx(&dir)?;
        let path = entry.path();
        let name = path.to_string_lossy().to_string();
        let stem = path.file_stem().map(|s| s.to_string_lossy().to_string());
        let is_blob = name.ends_with(".dtc") || name.ends_with(".dtc.dttmp");
        if is_blob && !stem.map(|s| referenced.contains(&s)).unwrap_or(false) {
            out.push(path);
        }
    }
    Ok(out)
}

/// Forget the vault around an already-decrypted drive. Refuses unless the plaintext is back
/// and no blob remains, so it can never strand data inside `.drivetooth`.
pub fn erase(vault: &Vault) -> DtResult<()> {
    if vault.meta.state != VaultState::Unlocked {
        return Err(DtError::State(
            "unlock the drive before removing its vault".to_string(),
        ));
    }
    if Journal::load(vault)?.is_some() {
        return Err(DtError::State(
            "an interrupted operation must be recovered first".to_string(),
        ));
    }
    let blobs = vault.blobs_dir();
    if blobs.exists() {
        let mut entries = std::fs::read_dir(&blobs).ctx(&blobs)?;
        if entries.next().is_some() {
            return Err(DtError::State(
                "the vault still holds encrypted records".to_string(),
            ));
        }
    }
    let _ = fs::set_hidden(&vault.vault_dir(), false);
    std::fs::remove_dir_all(vault.vault_dir()).ctx(&vault.vault_dir())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::lock::lock;
    use crate::ops::scan::scan;
    use crate::volume::journal::JournalPhase;
    use crate::volume::VaultOptions;

    fn runner() -> Runner {
        Runner::new(Box::new(|_| {}))
    }

    fn locked(dir: &Path) -> (Vault, Secret) {
        std::fs::create_dir_all(dir.join("secret/nested")).unwrap();
        std::fs::write(dir.join("secret/a.txt"), b"alpha content").unwrap();
        std::fs::write(dir.join("secret/nested/b.bin"), vec![3u8; 90_000]).unwrap();
        std::fs::write(dir.join("secret/empty.txt"), b"").unwrap();
        let (mut vault, key) = Vault::create(
            dir,
            "secret",
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
        let runner = runner();
        let plan = scan(dir, "secret", &vault.meta.options.clone(), &runner).unwrap();
        lock(&mut vault, &key, &plan, &runner).unwrap();
        (vault, key)
    }

    fn first_file(manifest: &Manifest) -> Entry {
        manifest
            .entries
            .iter()
            .find(|e| e.kind == EntryKind::File)
            .unwrap()
            .clone()
    }

    /// Needs a revealed manifest: the tests below probe this file's bytes.
    fn file_at(manifest: &Manifest, rel: &str) -> Entry {
        manifest
            .entries
            .iter()
            .find(|e| e.kind == EntryKind::File && e.path.as_deref() == Some(rel))
            .unwrap_or_else(|| panic!("{rel} is not in the manifest"))
            .clone()
    }

    #[test]
    fn recovering_a_healthy_locked_drive_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = locked(dir.path());
        let blobs_before = std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count();
        let summary = recover(&mut vault, &key, &runner()).unwrap();
        assert_eq!(vault.meta.state, VaultState::Locked);
        assert_eq!(
            std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count(),
            blobs_before
        );
        assert!(summary.message.contains("locked"), "{}", summary.message);
    }

    #[test]
    fn recovering_a_lock_died_mid_removal_re_seals_the_stray_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = locked(dir.path());
        let mut manifest = Manifest::load(&vault, &key).unwrap();
        manifest.reveal_paths(&name_key(&key).unwrap()).unwrap();
        let victim = file_at(&manifest, "secret/a.txt");
        let blob = vault.blob_path(&victim.id);
        let target = victim.abs(dir.path());
        // The lock pass pruned the folder, so recreate it the way a half-finished
        // plaintext removal would have left it.
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        envelope::decrypt_file(&blob, &target, &key, Some(victim.id_bytes().unwrap()), &|| Ok(()))
            .unwrap();
        std::fs::remove_file(&blob).unwrap();
        vault.set_state(VaultState::Recovering, "").unwrap();

        recover(&mut vault, &key, &runner()).unwrap();
        assert_eq!(vault.meta.state, VaultState::Locked);
        assert!(!target.exists());
        assert!(vault.blob_path(&victim.id).exists());
        // The re-sealed blob still holds the original bytes.
        let probe = dir.path().join("probe.out");
        envelope::decrypt_file(
            &vault.blob_path(&victim.id),
            &probe,
            &key,
            Some(victim.id_bytes().unwrap()),
            &|| Ok(()),
        )
        .unwrap();
        assert_eq!(std::fs::read(&probe).unwrap(), b"alpha content");
    }

    #[test]
    fn recovery_never_deletes_plaintext_for_a_corrupt_blob() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = locked(dir.path());
        let mut manifest = Manifest::load(&vault, &key).unwrap();
        manifest.reveal_paths(&name_key(&key).unwrap()).unwrap();
        let victim = file_at(&manifest, "secret/a.txt");
        let blob = vault.blob_path(&victim.id);
        let target = victim.abs(dir.path());

        // Put the plaintext back and corrupt the blob so it is the wrong length: the blob
        // must not be treated as authentic.
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        envelope::decrypt_file(&blob, &target, &key, Some(victim.id_bytes().unwrap()), &|| Ok(()))
            .unwrap();
        std::fs::write(&blob, b"DTC1 truncated").unwrap();
        vault.set_state(VaultState::Recovering, "").unwrap();

        recover(&mut vault, &key, &runner()).unwrap();
        assert!(!target.exists(), "the blob was replaced, so the plaintext is redundant");
        let probe = dir.path().join("probe.out");
        envelope::decrypt_file(&blob, &probe, &key, Some(victim.id_bytes().unwrap()), &|| Ok(()))
            .unwrap();
        assert_eq!(std::fs::read(&probe).unwrap(), b"alpha content");
    }

    #[test]
    fn recovering_an_unlock_died_before_blob_cleanup_finishes_it() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = locked(dir.path());
        let mut manifest = Manifest::load(&vault, &key).unwrap();
        manifest.reveal_paths(&name_key(&key).unwrap()).unwrap();
        let victim = file_at(&manifest, "secret/a.txt");
        let target = victim.abs(dir.path());
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        envelope::decrypt_file(
            &vault.blob_path(&victim.id),
            &target,
            &key,
            Some(victim.id_bytes().unwrap()),
            &|| Ok(()),
        )
        .unwrap();
        Journal::new(&vault, OpKind::Unlock, JournalPhase::Restores, 3, 0)
            .save(&vault)
            .unwrap();
        vault.set_state(VaultState::Recovering, "").unwrap();

        recover(&mut vault, &key, &runner()).unwrap();
        assert!(target.exists());
        assert!(!vault.blob_path(&victim.id).exists());
        assert!(!vault.journal_path().exists());
    }

    #[test]
    fn a_full_unlock_then_recovery_leaves_the_vault_ready_to_erase() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = locked(dir.path());
        crate::ops::unlock::unlock(&mut vault, &key, &runner()).unwrap();
        erase(&vault).unwrap();
        assert!(!vault.vault_dir().exists());
        assert_eq!(
            std::fs::read(dir.path().join("secret/a.txt")).unwrap(),
            b"alpha content"
        );
        assert!(dir.path().join("secret/nested/b.bin").exists());
    }

    #[test]
    fn erase_refuses_a_locked_drive_and_keeps_everything() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key) = locked(dir.path());
        assert!(matches!(erase(&vault), Err(DtError::State(_))));
        assert!(vault.manifest_path().exists());
        assert!(vault.blob_path(&first_file(&Manifest::load(&vault, &key).unwrap()).id).exists());
    }

    #[test]
    fn a_record_with_no_copy_anywhere_is_reported_not_guessed() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = locked(dir.path());
        let victim_id = first_file(&Manifest::load(&vault, &key).unwrap()).id.clone();
        let blobs_before = std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count();
        std::fs::remove_file(vault.blob_path(&victim_id)).unwrap();
        let err = recover(&mut vault, &key, &runner()).unwrap_err();
        assert!(matches!(err, DtError::Format(_)), "{err:?}");
        assert_eq!(
            std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count(),
            blobs_before - 1,
            "the other blobs must survive a failed recovery"
        );
    }

    #[test]
    fn stale_blobs_from_an_uncommitted_pass_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = locked(dir.path());
        let held = std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count();
        std::fs::write(
            vault.blob_path("deadbeefdeadbeefdeadbeefdeadbeef"),
            b"DTC1 junk that was never committed",
        )
        .unwrap();
        Journal::new(&vault, OpKind::Lock, JournalPhase::BlobWrites, 1, 1)
            .save(&vault)
            .unwrap();
        vault.set_state(VaultState::Recovering, "").unwrap();

        let summary = recover(&mut vault, &key, &runner()).unwrap();
        assert_eq!(
            std::fs::read_dir(vault.blobs_dir()).unwrap().flatten().count(),
            held
        );
        assert!(summary.message.contains("stale blob"), "{}", summary.message);
    }

    #[test]
    fn missing_directories_are_recreated_during_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = locked(dir.path());
        // The state an interrupted unlock leaves behind when the folder tree is gone: the
        // blobs are intact but every target parent is missing, so recovery has to rebuild
        // the skeleton from the manifest instead of failing with ENOENT.
        std::fs::remove_dir_all(dir.path().join("secret")).ok();
        Journal::new(&vault, OpKind::Unlock, JournalPhase::Restores, 3, 0)
            .save(&vault)
            .unwrap();
        vault.set_state(VaultState::Recovering, "").unwrap();
        let summary = recover(&mut vault, &key, &runner()).unwrap();
        assert!(dir.path().join("secret/nested").is_dir(), "{summary:?}");
        assert!(dir.path().join("secret/a.txt").exists(), "{summary:?}");
        assert!(dir.path().join("secret/nested/b.bin").exists(), "{summary:?}");
        assert_eq!(vault.meta.state, VaultState::Unlocked);
    }
}
