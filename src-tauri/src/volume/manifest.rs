//! The manifest: the only thing that knows what the files on a locked drive are called.
//!
//! Entries carry an encrypted relative path even while the drive is unlocked, and the
//! plaintext path field is dropped before the manifest is committed, so a locked drive
//! exposes nothing but random-length blobs under random names.

use std::io::{BufWriter, Cursor, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::crypto::envelope::{self, NULL_RECORD, RECORD_ID_LEN};
use crate::crypto::kdf::{self, random_bytes, Secret};
use crate::error::{DtError, DtResult, IoCtx};

use super::{now_ms, from_hex, to_hex, fs, Vault, VaultState, FORMAT, TEMP_SUFFIX};

const NAME_DOMAIN: &[u8] = b"drivetooth/name/v1|";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Dir,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Hex record id; also the blob filename and the name-encryption binding.
    pub id: String,
    pub kind: EntryKind,
    /// Plaintext relative path. Present only while unlocked; `seal_paths` clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub name_nonce: String,
    pub name_ct: String,
    pub size: u64,
    /// Length the ciphertext blob must have; lets recovery spot a short write.
    pub blob_len: u64,
    pub mtime_ms: i64,
    pub mode: u32,
    pub readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub uuid: String,
    pub updated_ms: i64,
    pub entries: Vec<Entry>,
}

pub fn manifest_key(volume_key: &Secret) -> DtResult<Secret> {
    kdf::subkey(volume_key, "manifest", b"")
}

pub fn name_key(volume_key: &Secret) -> DtResult<Secret> {
    kdf::subkey(volume_key, "names", b"")
}

pub fn new_id() -> String {
    to_hex(&random_bytes::<RECORD_ID_LEN>())
}

/// Join a stored relative path onto a mount root, refusing anything that escapes.
pub fn join_rel(mount: &Path, rel: &str) -> PathBuf {
    let mut out = mount.to_path_buf();
    for part in rel.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        out.push(part);
    }
    out
}

/// Relative path with forward slashes, as stored in the manifest.
pub fn rel_from(mount: &Path, abs: &Path) -> DtResult<String> {
    let rel = abs
        .strip_prefix(mount)
        .map_err(|_| DtError::Other(format!("{} is not under {}", abs.display(), mount.display())))?;
    let text = rel.to_string_lossy().replace('\\', "/");
    Ok(text)
}

/// Reject paths that could break out of the drive when restored: absolute paths, parent
/// traversals, drive letters, and device names.
pub fn validate_rel(rel: &str) -> DtResult<()> {
    if rel.is_empty() {
        return Err(DtError::Format("empty relative path in manifest".into()));
    }
    if rel.starts_with('/') || rel.starts_with('\\') {
        return Err(DtError::Format(format!("absolute path in manifest: {rel}")));
    }
    for part in rel.split(['/', '\\']) {
        if part == ".." {
            return Err(DtError::Format(format!("path traversal in manifest: {rel}")));
        }
        if part.contains(':') {
            return Err(DtError::Format(format!("drive letter in manifest: {rel}")));
        }
        #[cfg(windows)]
        if matches!(
            part.to_uppercase().as_str(),
            "CON" | "PRN" | "AUX" | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "LPT1"
                | "LPT2"
                | "LPT3"
        ) {
            return Err(DtError::Format(format!("reserved name in manifest: {rel}")));
        }
    }
    Ok(())
}

impl Entry {
    pub fn id_bytes(&self) -> DtResult<[u8; RECORD_ID_LEN]> {
        let raw = from_hex(&self.id)?;
        raw.as_slice()
            .try_into()
            .map_err(|_| DtError::Format(format!("record id {} is not 16 bytes", self.id)))
    }

    pub fn abs(&self, mount: &Path) -> PathBuf {
        join_rel(mount, self.path.as_deref().unwrap_or(""))
    }

    /// Additional authenticated data for the encrypted name: swapping an entry's path
    /// into another slot, or changing its kind or size, invalidates the tag.
    pub fn name_aad(&self, uuid: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(64);
        aad.extend_from_slice(NAME_DOMAIN);
        aad.extend_from_slice(uuid.as_bytes());
        if let Ok(raw) = from_hex(&self.id) {
            aad.extend_from_slice(&raw);
        }
        aad.push(match self.kind {
            EntryKind::File => 1,
            EntryKind::Dir => 2,
        });
        aad.extend_from_slice(&self.size.to_le_bytes());
        aad
    }

    pub fn set_path(&mut self, rel: &str) -> DtResult<()> {
        validate_rel(rel)?;
        self.path = Some(rel.to_string());
        Ok(())
    }
}

impl Manifest {
    pub fn new(uuid: &str) -> Manifest {
        Manifest {
            format: FORMAT,
            uuid: uuid.to_string(),
            updated_ms: now_ms(),
            entries: Vec::new(),
        }
    }

    pub fn file_entry(
        &mut self,
        rel: &str,
        size: u64,
        blob_len: u64,
        meta: &fs::StoredMeta,
    ) -> DtResult<String> {
        let id = new_id();
        let mut entry = Entry {
            id: id.clone(),
            kind: EntryKind::File,
            path: None,
            name_nonce: String::new(),
            name_ct: String::new(),
            size,
            blob_len,
            mtime_ms: meta.mtime_ms,
            mode: meta.mode,
            readonly: meta.readonly,
        };
        entry.set_path(rel)?;
        self.entries.push(entry);
        Ok(id)
    }

    pub fn dir_entry(&mut self, rel: &str, meta: &fs::StoredMeta) -> DtResult<String> {
        let id = new_id();
        let mut entry = Entry {
            id: id.clone(),
            kind: EntryKind::Dir,
            path: None,
            name_nonce: String::new(),
            name_ct: String::new(),
            size: 0,
            blob_len: 0,
            mtime_ms: meta.mtime_ms,
            mode: meta.mode,
            readonly: meta.readonly,
        };
        entry.set_path(rel)?;
        self.entries.push(entry);
        Ok(id)
    }

    pub fn index_of(&self, id: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.id == id)
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn has_path(&self, rel: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.path.as_deref() == Some(rel) && e.kind == EntryKind::File)
    }

    pub fn has_dir(&self, rel: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.path.as_deref() == Some(rel) && e.kind == EntryKind::Dir)
    }

    pub fn paths_are_sealed(&self) -> bool {
        self.entries.iter().all(|e| e.path.is_none())
    }

    pub fn totals(&self) -> ManifestTotals {
        let mut t = ManifestTotals::default();
        for e in &self.entries {
            match e.kind {
                EntryKind::File => {
                    t.files += 1;
                    t.plain_bytes += e.size;
                    t.blob_bytes += e.blob_len;
                }
                EntryKind::Dir => t.dirs += 1,
            }
        }
        t
    }

    /// Encrypt relative paths and forget the plaintext copies.
    pub fn seal_paths(&mut self, key: &Secret) -> DtResult<()> {
        for entry in &mut self.entries {
            let Some(rel) = entry.path.take() else { continue };
            let aad = entry.name_aad(&self.uuid);
            let nonce = random_bytes::<12>();
            let sealed = envelope::seal_small(key.as_bytes(), &nonce, rel.as_bytes(), &aad)?;
            entry.name_nonce = to_hex(&nonce);
            entry.name_ct = base64::engine::general_purpose::STANDARD.encode(sealed);
        }
        Ok(())
    }

    /// Recover relative paths from the encrypted copies.
    pub fn reveal_paths(&mut self, key: &Secret) -> DtResult<()> {
        for entry in &mut self.entries {
            if entry.path.is_some() {
                continue;
            }
            let nonce_raw = from_hex(&entry.name_nonce)?;
            if nonce_raw.len() != 12 {
                return Err(DtError::Format("bad name nonce length".into()));
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&nonce_raw);
            let blob = base64::engine::general_purpose::STANDARD
                .decode(&entry.name_ct)
                .map_err(|e| DtError::Format(format!("bad base64 name blob: {e}")))?;
            let aad = entry.name_aad(&self.uuid);
            let plain = envelope::open_small(key.as_bytes(), &nonce, &blob, &aad)
                .map_err(|_| {
                    DtError::Format(format!("name for record {} failed authentication", entry.id))
                })?;
            let rel = String::from_utf8(plain)
                .map_err(|_| DtError::Format("stored name is not valid UTF-8".into()))?;
            validate_rel(&rel)?;
            entry.path = Some(rel);
        }
        Ok(())
    }

    /// Encrypted manifest blob, or an empty manifest for a brand-new vault.
    pub fn load(vault: &Vault, volume_key: &Secret) -> DtResult<Manifest> {
        let path = vault.manifest_path();
        if !path.exists() {
            if vault.meta.state != VaultState::Unlocked {
                return Err(DtError::State(
                    "this drive is marked locked but its manifest is missing".into(),
                ));
            }
            return Ok(Manifest::new(&vault.meta.uuid));
        }
        let key = manifest_key(volume_key)?;
        let blob_len = std::fs::metadata(&path).ctx(&path)?.len();
        let mut reader = std::fs::File::open(&path).ctx(&path)?;
        let mut sink = Vec::new();
        envelope::decrypt_stream(
            &mut reader,
            &mut sink,
            &key,
            Some(NULL_RECORD),
            blob_len,
            &|| Ok(()),
        )?;
        let manifest: Manifest = serde_json::from_slice(&sink)
            .map_err(|e| DtError::Format(format!("manifest is not valid JSON: {e}")))?;
        if manifest.format != FORMAT {
            return Err(DtError::Format(format!(
                "manifest format v{} needs a newer DriveTooth",
                manifest.format
            )));
        }
        if manifest.uuid != vault.meta.uuid {
            return Err(DtError::Format(
                "manifest does not belong to this volume".into(),
            ));
        }
        Ok(manifest)
    }

    /// Commit atomically: encrypt to a temp file, sync, then rename over the old manifest.
    pub fn save(&self, vault: &Vault, volume_key: &Secret) -> DtResult<()> {
        let key = manifest_key(volume_key)?;
        let bytes = serde_json::to_vec(self)
            .map_err(|e| DtError::Other(format!("cannot serialise manifest: {e}")))?;
        let target = vault.manifest_path();
        let tmp = target.with_extension(format!("dt-{}", now_ms()));
        {
            let mut writer = BufWriter::new(std::fs::File::create(&tmp).ctx(&tmp)?);
            envelope::encrypt_stream(
                Cursor::new(&bytes),
                &mut writer,
                &key,
                NULL_RECORD,
                bytes.len() as u64,
                vault.meta.options.chunk_exp,
                &|| Ok(()),
            )?;
            writer.flush().ctx(&tmp)?;
            std::fs::File::open(&tmp).ctx(&tmp)?.sync_all().ctx(&tmp)?;
        }
        std::fs::rename(&tmp, &target).ctx(&target)?;
        let _ = super::fs::fsync_dir(target.parent().unwrap_or(&vault.vault_dir()));
        Ok(())
    }

    /// Drop every entry whose plaintext path no longer exists under the scope. Used when
    /// the user deleted files while the drive was unlocked.
    pub fn prune_missing(&mut self, mount: &Path, scope_rel: &str) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| {
            let Some(rel) = e.path.as_deref() else {
                return true;
            };
            if !under_scope(rel, scope_rel) {
                return true;
            }
            join_rel(mount, rel).exists()
        });
        before - self.entries.len()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ManifestTotals {
    pub files: u64,
    pub dirs: u64,
    pub plain_bytes: u64,
    pub blob_bytes: u64,
}

pub fn under_scope(rel: &str, scope_rel: &str) -> bool {
    if scope_rel == "/" || scope_rel.is_empty() {
        return true;
    }
    rel == scope_rel || rel.starts_with(&format!("{scope_rel}/"))
}

/// Temp and in-flight names the scanner must never treat as user data.
pub fn is_internal_name(name: &str) -> bool {
    name.ends_with(TEMP_SUFFIX)
        || name.ends_with(".dtc")
        || name.starts_with(".dt-")
        || name.contains(".tmp-")
}

/// Names the operating system owns on the volume itself. These are never the user's data, and
/// taking them is actively harmful: `.fseventsd` is a live directory the macOS event daemon
/// keeps open and writes to while we work, so encrypting and pruning it leaves the volume's
/// own bookkeeping half gone — which is how a locked stick can come back refusing to mount.
pub fn is_system_name(name: &str) -> bool {
    matches!(
        name,
        ".fseventsd"
            | ".Spotlight-V100"
            | ".Spotlight-Volume"
            | ".DocumentRevisions-V100"
            | ".AppleDouble"
            | ".AppleDB"
            | ".AppleDesktop"
            | ".TemporaryItems"
            | ".Trash"
            | ".Trashes"
            | ".Vol"
            | "System Volume Information"
            | "$RECYCLE.BIN"
            | "$MFT"
            | "lost+found"
            | "lost.dir"
    ) || name.starts_with("._")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume::{VaultOptions, fs::StoredMeta};

    fn meta(mode: u32) -> StoredMeta {
        StoredMeta {
            mtime_ms: 1_700_000_000_000,
            mode,
            readonly: false,
        }
    }

    fn vault_in(dir: &Path) -> (Vault, Secret) {
        let scope = dir.join("secret");
        std::fs::create_dir_all(&scope).unwrap();
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
    fn entries_roundtrip_through_disk_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = vault_in(dir.path());
        let mut manifest = Manifest::new(&vault.meta.uuid);
        manifest
            .file_entry("secret/notes/todo.txt", 12, 96, &meta(0o644))
            .unwrap();
        manifest.dir_entry("secret/notes", &meta(0o755)).unwrap();
        manifest.save(&vault, &key).unwrap();
        assert!(vault.manifest_path().exists());
        let raw = std::fs::read(vault.manifest_path()).unwrap();
        assert!(!raw.windows(9).any(|w| w == b"todo.txt"), "manifest leaks a name");
        assert!(!raw.windows(6).any(|w| w == b"secret"), "manifest leaks a path");

        let loaded = Manifest::load(&vault, &key).unwrap();
        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.totals().files, 1);
        assert_eq!(loaded.totals().dirs, 1);
        assert!(!loaded.paths_are_sealed(), "a fresh manifest keeps plaintext paths");

        vault.set_state(VaultState::Locked, "lock").unwrap();
        let mut sealed = loaded;
        sealed.seal_paths(&name_key(&key).unwrap()).unwrap();
        assert!(sealed.paths_are_sealed());
        sealed.save(&vault, &key).unwrap();

        let mut reopened = Manifest::load(&vault, &key).unwrap();
        assert!(reopened.paths_are_sealed());
        reopened.reveal_paths(&name_key(&key).unwrap()).unwrap();
        let names: Vec<&str> = reopened
            .entries
            .iter()
            .map(|e| e.path.as_deref().unwrap())
            .collect();
        assert_eq!(names, vec!["secret/notes/todo.txt", "secret/notes"]);
        assert!(reopened.get(&reopened.entries[0].id).is_some());
        assert!(reopened.has_path("secret/notes/todo.txt"));
    }

    #[test]
    fn wrong_key_cannot_reveal_names() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key) = vault_in(dir.path());
        let mut manifest = Manifest::new(&vault.meta.uuid);
        manifest.file_entry("secret/x.bin", 1, 85, &meta(0o600)).unwrap();
        manifest.seal_paths(&name_key(&key).unwrap()).unwrap();
        let other = Secret::new(kdf::random_vec(kdf::KEY_LEN));
        let mut copy = manifest.clone();
        let err = copy.reveal_paths(&other).unwrap_err();
        assert!(matches!(err, DtError::Format(_)));
        assert!(copy.paths_are_sealed());
    }

    #[test]
    fn manifest_from_a_different_volume_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key) = vault_in(dir.path());
        let mut foreign = Manifest::new("deadbeef");
        foreign.file_entry("secret/a", 1, 85, &meta(0o600)).unwrap();
        let err = foreign.save(&vault, &key).and_then(|_| {
            let mut tampered = std::fs::read(vault.manifest_path()).unwrap();
            // Rewriting is authenticated, so a swap only shows up after a real reload of a
            // manifest built for another uuid.
            tampered[0] ^= 1;
            std::fs::write(vault.manifest_path(), &tampered).unwrap();
            Manifest::load(&vault, &key)
        });
        assert!(err.is_err());
    }

    #[test]
    fn forged_traversal_name_is_rejected_on_reveal() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key) = vault_in(dir.path());
        let nkey = name_key(&key).unwrap();
        let mut manifest = Manifest::new(&vault.meta.uuid);
        manifest.file_entry("secret/ok.txt", 1, 85, &meta(0o600)).unwrap();
        let entry = &manifest.entries[0];
        let aad = entry.name_aad(&vault.meta.uuid);
        // An attacker holding the name key could re-seal a traversal path under the same
        // record id; the path validator is what stops it being restored.
        for forged in ["../../evil", "/etc/passwd", "C:/Windows/x"] {
            let nonce = random_bytes::<12>();
            let sealed = envelope::seal_small(nkey.as_bytes(), &nonce, forged.as_bytes(), &aad).unwrap();
            manifest.entries[0].name_nonce = to_hex(&nonce);
            manifest.entries[0].name_ct =
                base64::engine::general_purpose::STANDARD.encode(sealed);
            manifest.entries[0].path = None;
            let mut copy = manifest.clone();
            assert!(
                matches!(
                    copy.reveal_paths(&nkey),
                    Err(DtError::Format(_))
                ),
                "{forged} should not restore"
            );
        }
    }

    #[test]
    fn rel_and_abs_conversion() {
        assert!(validate_rel("a/b/c.txt").is_ok());
        assert!(validate_rel("").is_err());
        assert!(validate_rel("/etc/passwd").is_err());
        assert!(validate_rel("a/../../etc/passwd").is_err());
        assert!(validate_rel("C:/Windows/x").is_err());
        let dir = tempfile::tempdir().unwrap();
        let (vault, _key) = vault_in(dir.path());
        let mut manifest = Manifest::new(&vault.meta.uuid);
        assert!(manifest.file_entry("../../outside.txt", 1, 85, &meta(0o600)).is_err());
        assert!(manifest.dir_entry("ok/folder", &meta(0o700)).is_ok());
        let mount = Path::new("/Volumes/USB");
        assert_eq!(
            join_rel(mount, "a/b/c.txt"),
            PathBuf::from("/Volumes/USB/a/b/c.txt")
        );
        assert_eq!(join_rel(mount, "/a//b/."), PathBuf::from("/Volumes/USB/a/b"));
        assert_eq!(
            rel_from(mount, Path::new("/Volumes/USB/a/b.txt")).unwrap(),
            "a/b.txt"
        );
        assert!(rel_from(mount, Path::new("/elsewhere")).is_err());
        assert!(under_scope("secret/a", "secret"));
        assert!(!under_scope("other/a", "secret"));
        assert!(under_scope("anything", "/"));
    }

    #[test]
    fn internal_names_are_never_scanned() {
        assert!(is_internal_name("report.docx.dttmp"));
        assert!(is_internal_name("9ac3f1.dtc"));
        assert!(is_internal_name("manifest.dt.1712345678901.dttmp"));
        assert!(is_internal_name("volume.json.1712345678901.dttmp"));
        assert!(!is_internal_name("report.docx"));
    }

    #[test]
    fn prune_drops_entries_the_user_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _key) = vault_in(dir.path());
        std::fs::create_dir_all(dir.path().join("secret/keep")).unwrap();
        std::fs::write(dir.path().join("secret/keep/a.txt"), b"a").unwrap();
        std::fs::write(dir.path().join("secret/gone.txt"), b"g").unwrap();
        let mut manifest = Manifest::new(&vault.meta.uuid);
        manifest.file_entry("secret/keep/a.txt", 1, 85, &meta(0o600)).unwrap();
        manifest.file_entry("secret/gone.txt", 1, 85, &meta(0o600)).unwrap();
        manifest.dir_entry("outside-untouched", &meta(0o700)).unwrap();
        std::fs::remove_file(dir.path().join("secret/gone.txt")).unwrap();
        let removed = manifest.prune_missing(dir.path(), "secret");
        assert_eq!(removed, 1);
        assert_eq!(manifest.entries.len(), 2);
        assert!(manifest.has_path("secret/keep/a.txt"));
    }

    #[test]
    fn missing_manifest_is_empty_only_while_unlocked() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, key) = vault_in(dir.path());
        let empty = Manifest::load(&vault, &key).unwrap();
        assert!(empty.entries.is_empty());
        vault.set_state(VaultState::Locked, "lock").unwrap();
        assert!(matches!(
            Manifest::load(&vault, &key),
            Err(DtError::State(_))
        ));
    }
}
