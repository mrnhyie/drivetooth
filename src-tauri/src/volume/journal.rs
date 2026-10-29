//! A tiny crash-recovery marker.
//!
//! Recovery does not replay an operation log: the committed manifest is the single source
//! of truth, so the journal only records *which* operation was running and how far it got.
//! After an interruption the engine compares each manifest entry against what exists on
//! disk and either finishes forward or rolls back, with no per-file bookkeeping to keep in
//! sync (which would cost a rewrite of the whole journal for every file).

use serde::{Deserialize, Serialize};

use crate::error::{DtError, DtResult, IoCtx};

use super::{now_ms, Vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpKind {
    Lock,
    Unlock,
}

/// Coarse progress marker. `BlobWrites`/`Restores` are the reversible half of an
/// operation; `Destructive` means the step that removes one side of each copy has begun
/// and the pass must be finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalPhase {
    Prepared,
    BlobWrites,
    Restores,
    Destructive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Journal {
    pub format: u32,
    pub op: OpKind,
    pub phase: JournalPhase,
    pub uuid: String,
    pub started_ms: i64,
    pub updated_ms: i64,
    pub files_total: u64,
    pub bytes_total: u64,
}

impl Journal {
    pub fn new(vault: &Vault, op: OpKind, phase: JournalPhase, files: u64, bytes: u64) -> Journal {
        Journal {
            format: super::FORMAT,
            op,
            phase,
            uuid: vault.meta.uuid.clone(),
            started_ms: now_ms(),
            updated_ms: now_ms(),
            files_total: files,
            bytes_total: bytes,
        }
    }

    pub fn load(vault: &Vault) -> DtResult<Option<Journal>> {
        let path = vault.journal_path();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read(&path).ctx(&path)?;
        let journal: Journal = serde_json::from_slice(&raw)
            .map_err(|e| DtError::Format(format!("unreadable journal: {e}")))?;
        if journal.uuid != vault.meta.uuid {
            return Err(DtError::Format(
                "journal does not match this volume's uuid".into(),
            ));
        }
        Ok(Some(journal))
    }

    pub fn save(&self, vault: &Vault) -> DtResult<()> {
        let mut fresh = self.clone();
        fresh.updated_ms = now_ms();
        let bytes = serde_json::to_vec_pretty(&fresh)
            .map_err(|e| DtError::Other(format!("cannot serialise journal: {e}")))?;
        super::write_atomic(&vault.journal_path(), &bytes)
    }

    pub fn advance(&mut self, vault: &Vault, phase: JournalPhase) -> DtResult<()> {
        self.phase = phase;
        self.save(vault)
    }

    pub fn clear(vault: &Vault) -> DtResult<()> {
        let path = vault.journal_path();
        if path.exists() {
            std::fs::remove_file(&path).ctx(&path)?;
        }
        Ok(())
    }

    /// True once the pass that deletes one side of every copy has started. Before that a
    /// cancelled operation can be rolled back cleanly.
    pub fn is_destructive(&self) -> bool {
        self.phase == JournalPhase::Destructive
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume::{manifest::Manifest, VaultOptions, VaultState};
    use std::path::Path;

    fn vault_in(dir: &Path) -> (Vault, crate::crypto::kdf::Secret) {
        std::fs::create_dir_all(dir.join("secret")).unwrap();
        Vault::create(
            dir,
            "secret",
            "t",
            "pw",
            "pw",
            VaultOptions {
                kdf_target_ms: 100,
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn journal_absent_means_no_recovery_needed() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _key) = vault_in(dir.path());
        assert!(Journal::load(&vault).unwrap().is_none());
    }

    #[test]
    fn journal_roundtrips_and_tracks_phase() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _key) = vault_in(dir.path());
        let journal = Journal::new(&vault, OpKind::Lock, JournalPhase::Prepared, 12, 4096);
        journal.save(&vault).unwrap();
        let loaded = Journal::load(&vault).unwrap().unwrap();
        assert_eq!(loaded.op, OpKind::Lock);
        assert_eq!(loaded.phase, JournalPhase::Prepared);
        assert!(!loaded.is_destructive());
        assert_eq!(loaded.files_total, 12);

        let mut advanced = loaded.clone();
        advanced.advance(&vault, JournalPhase::Destructive).unwrap();
        let reread = Journal::load(&vault).unwrap().unwrap();
        assert!(reread.is_destructive());
        assert!(reread.started_ms <= reread.updated_ms);
        assert_eq!(reread.started_ms, advanced.started_ms);

        Journal::clear(&vault).unwrap();
        assert!(Journal::load(&vault).unwrap().is_none());
        // Clearing twice is not an error.
        Journal::clear(&vault).unwrap();
    }

    #[test]
    fn journal_for_another_volume_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _key) = vault_in(dir.path());
        let journal = Journal::new(&vault, OpKind::Unlock, JournalPhase::Restores, 1, 1);
        journal.save(&vault).unwrap();
        vault.meta.uuid = "swapped-uuid".to_string();
        assert!(matches!(
            Journal::load(&vault),
            Err(DtError::Format(_))
        ));
    }

    #[test]
    fn recovery_state_is_only_marked_when_a_journal_exists() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = vault_in(dir.path());
        // An interrupted lock leaves: recovering state, a journal, and a committed manifest
        // whose blobs have not all been written yet.
        let mut manifest = Manifest::new(&vault.meta.uuid);
        manifest.file_entry("secret/a.txt", 3, 100, &crate::volume::fs::StoredMeta {
            mtime_ms: now_ms(),
            mode: 0o644,
            readonly: false,
        }).unwrap();
        manifest.save(&vault, &key).unwrap();
        vault.set_state(VaultState::Recovering, "lock interrupted").unwrap();
        Journal::new(&vault, OpKind::Lock, JournalPhase::BlobWrites, 1, 3)
            .save(&vault)
            .unwrap();

        let reopened = Vault::detect(&vault.mount).unwrap().unwrap();
        assert_eq!(reopened.meta.state, VaultState::Recovering);
        let journal = Journal::load(&reopened).unwrap().unwrap();
        assert_eq!(journal.op, OpKind::Lock);
        assert!(!journal.is_destructive());
        assert!(Manifest::load(&reopened, &reopened.key_for("pw").unwrap()).is_ok());
    }
}
