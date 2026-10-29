//! Vault layout and volume metadata. Everything DriveTooth writes to a drive lives under
//! `.drivetooth/` at the mount root, which is why locking hides the whole tree: the drive
//! root is left holding only opaque blobs.

pub mod fs;
pub mod inventory;
pub mod journal;
pub mod manifest;

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::crypto::kdf::{self, KdfParams, Secret};
use crate::error::{DtError, DtResult, IoCtx};

pub const VAULT_DIR: &str = ".drivetooth";
pub const VOLUME_FILE: &str = "volume.json";
pub const MANIFEST_FILE: &str = "manifest.dt";
pub const JOURNAL_FILE: &str = "journal.json";
pub const BLOBS_DIR: &str = "blobs";
pub const BLOB_EXT: &str = "dtc";
/// Suffix for in-flight temp files. Never encrypted, always safe to delete if an operation
/// finished or was rolled back.
pub const TEMP_SUFFIX: &str = ".dttmp";
pub const FORMAT: u32 = 1;
/// Password hashing target. `volume.json` carries a verifier, so anyone holding the drive can
/// guess at the password offline forever; this is the one number that sets the price per guess.
pub const KDF_TARGET_MS: u64 = 1000;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn from_hex(text: &str) -> DtResult<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(DtError::Format("hex string has odd length".into()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2])
            .map_err(|_| DtError::Format("non-ascii hex".into()))?;
        out.push(
            u8::from_str_radix(pair, 16)
                .map_err(|_| DtError::Format(format!("invalid hex byte '{pair}'")))?,
        );
        i += 2;
    }
    Ok(out)
}

/// Filesystem state of a volume. `Recovering` means an operation was interrupted and the
/// drive may hold both plaintext and ciphertext; it must be resolved before new work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultState {
    Unlocked,
    Locked,
    Recovering,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultOptions {
    /// Re-open every blob after writing it, before the plaintext is removed.
    pub verify_after_encrypt: bool,
    pub chunk_exp: u32,
    pub kdf_target_ms: u64,
    /// Names or extensions never to encrypt (e.g. `.DS_Store`, `Thumbs.db`).
    pub exclude: Vec<String>,
    /// Paths the user picked, relative to the mount root. Empty means everything inside the
    /// scope; a folder entry stands for that folder and all of its contents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub select: Vec<String>,
}

impl Default for VaultOptions {
    fn default() -> Self {
        VaultOptions {
            verify_after_encrypt: true,
            chunk_exp: crate::crypto::envelope::DEFAULT_CHUNK_EXP,
            kdf_target_ms: KDF_TARGET_MS,
            exclude: vec![
                ".DS_Store".to_string(),
                "Thumbs.db".to_string(),
                "desktop.ini".to_string(),
            ],
            select: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExclusionMatch {
    pub name: String,
    pub reason: String,
}

impl VaultOptions {
    pub fn is_excluded(&self, name: &str) -> bool {
        self.exclude.iter().any(|p| pattern_hits(p, name))
    }

    fn picks(&self) -> impl Iterator<Item = &str> {
        self.select
            .iter()
            .map(|p| p.trim_matches(|c| c == '/' || c == '\\'))
            .filter(|p| !p.is_empty())
    }

    /// Whether a scanned file is inside the user's pick. An empty selection covers the whole
    /// scope, which is what a vault set up before per-file picking still expects.
    pub fn is_selected(&self, rel: &str) -> bool {
        self.select.is_empty()
            || self.picks().any(|p| rel == p || rel.starts_with(&format!("{p}/")))
    }

    /// Whether a folder holds, or is, something picked. Lets a selection skip whole
    /// subtrees instead of walking them and dropping every file.
    pub fn covers_dir(&self, rel: &str) -> bool {
        self.select.is_empty()
            || self.picks().any(|p| p == rel || p.starts_with(&format!("{rel}/")))
    }

    pub fn excluded_names(&self) -> Vec<String> {
        self.exclude.clone()
    }
}

/// Supports `*.ext`, `name`, `dir/` and bare-component patterns.
fn pattern_hits(pattern: &str, name: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return name.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    let pattern = pattern.trim_end_matches('/');
    name == pattern
        || name
            .split(|c| c == '/' || c == '\\')
            .any(|component| component == pattern)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMeta {
    pub format: u32,
    pub uuid: String,
    pub label: String,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub kdf: KdfParams,
    pub salt_hex: String,
    pub verifier_hex: String,
    /// The real volume key is random and stored wrapped by a password-derived key, so
    /// changing the password re-wraps 32 bytes instead of re-encrypting the drive.
    pub wrap_nonce_hex: String,
    pub wrapped_key_hex: String,
    /// Scope relative to the mount root, `/` for the whole drive. Kept in the clear on
    /// purpose so the app can tell you what is protected without a password.
    pub scope: String,
    pub state: VaultState,
    pub options: VaultOptions,
    pub last_op_ms: i64,
    pub last_op: String,
}

#[derive(Debug, Clone)]
pub struct Vault {
    pub mount: PathBuf,
    pub meta: VolumeMeta,
}

/// The scope exactly as it is stored: relative to the mount root, no leading or trailing
/// separator, and "/" for the whole drive. Anything else the caller typed would stop
/// matching the manifest's own relative paths, which is how a folder fails to be pruned.
fn normalize_scope(scope: &str) -> DtResult<String> {
    let slashed = scope.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for part in slashed.split('/') {
        let part = part.trim();
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(DtError::State(format!("{scope} escapes the drive")));
        }
        if part.contains(':') {
            return Err(DtError::State(format!("{scope} is not inside one drive")));
        }
        parts.push(part);
    }
    Ok(if parts.is_empty() { "/".into() } else { parts.join("/") })
}

/// Each pick in the same shape `normalize_scope` produces, minus the ones naming the whole
/// drive: an empty `select` already means "everything", and a literal "/" would read as
/// "everything" to a person but as "nothing" to the matcher.
pub fn normalize_picks(list: &[String]) -> DtResult<Vec<String>> {
    let mut out = Vec::with_capacity(list.len());
    for pick in list {
        let pick = normalize_scope(pick)?;
        if pick != "/" && !out.contains(&pick) {
            out.push(pick);
        }
    }
    Ok(out)
}

impl Vault {
    pub fn vault_dir(&self) -> PathBuf {
        self.mount.join(VAULT_DIR)
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.vault_dir().join(BLOBS_DIR)
    }

    pub fn volume_path(&self) -> PathBuf {
        self.vault_dir().join(VOLUME_FILE)
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.vault_dir().join(MANIFEST_FILE)
    }

    pub fn journal_path(&self) -> PathBuf {
        self.vault_dir().join(JOURNAL_FILE)
    }

    pub fn blob_path(&self, id_hex: &str) -> PathBuf {
        self.blobs_dir().join(format!("{id_hex}.{BLOB_EXT}"))
    }

    pub fn scope_root(&self) -> PathBuf {
        if self.meta.scope == "/" || self.meta.scope.is_empty() {
            self.mount.clone()
        } else {
            manifest::join_rel(&self.mount, &self.meta.scope)
        }
    }

    /// `None` when the drive has never been initialised by DriveTooth.
    pub fn detect(mount: &Path) -> DtResult<Option<Vault>> {
        let path = mount.join(VAULT_DIR).join(VOLUME_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read(&path).ctx(&path)?;
        let meta: VolumeMeta = serde_json::from_slice(&raw)
            .map_err(|e| DtError::Format(format!("unreadable volume.json: {e}")))?;
        if meta.format != FORMAT {
            return Err(DtError::Format(format!(
                "volume format v{} needs a newer DriveTooth",
                meta.format
            )));
        }
        Ok(Some(Vault {
            mount: mount.to_path_buf(),
            meta,
        }))
    }

    pub fn exists(mount: &Path) -> bool {
        mount.join(VAULT_DIR).join(VOLUME_FILE).exists()
    }

    /// Create `.drivetooth/` and commit the first `volume.json`. Requires a fresh password
    /// check so a mistyped confirmation never produces a vault nobody can open.
    pub fn create(
        mount: &Path,
        scope: &str,
        label: &str,
        password: &str,
        password_again: &str,
        mut options: VaultOptions,
    ) -> DtResult<(Vault, Secret)> {
        if password.is_empty() {
            return Err(DtError::Other("the password is empty".into()));
        }
        if password != password_again {
            return Err(DtError::Other("the two passwords do not match".into()));
        }
        if fs::is_system_mount(mount) {
            return Err(DtError::State(
                "DriveTooth seals volumes you carry, not the one your system runs from".into(),
            ));
        }
        let scope = normalize_scope(scope)?;
        options.select = normalize_picks(&options.select)?;
        let scope_root = manifest::join_rel(mount, &scope);
        if !scope_root.exists() {
            return Err(DtError::State(format!(
                "there is no folder {} on this drive",
                scope_root.display()
            )));
        }
        let md = std::fs::metadata(&scope_root).ctx(&scope_root)?;
        if !md.is_dir() {
            return Err(DtError::State(format!(
                "scope {} is not a folder",
                scope_root.display()
            )));
        }
        if Self::exists(mount) {
            return Err(DtError::State(format!(
                "{} already holds a vault",
                mount.display()
            )));
        }

        if options.kdf_target_ms == 0 {
            options.kdf_target_ms = KDF_TARGET_MS;
        }
        let params = kdf::calibrate(options.kdf_target_ms);
        let salt = kdf::random_bytes::<{ kdf::SALT_LEN }>();
        let password_key = kdf::derive_master(password, &salt, &params)?;
        let verifier = kdf::compute_verifier(&password_key)?;
        let volume_key = Secret::new(kdf::random_vec(kdf::KEY_LEN));
        let (wrapped, wrap_nonce) = wrap_volume_key(&password_key, &volume_key, &salt)?;

        let uuid = uuid::Builder::from_random_bytes(kdf::random_bytes::<16>())
            .into_uuid()
            .simple()
            .to_string();
        let vault = Vault {
            mount: mount.to_path_buf(),
            meta: VolumeMeta {
                format: FORMAT,
                uuid,
                label: label.to_string(),
                created_ms: now_ms(),
                updated_ms: now_ms(),
                kdf: params,
                salt_hex: to_hex(&salt),
                verifier_hex: to_hex(&verifier),
                wrap_nonce_hex: to_hex(&wrap_nonce),
                wrapped_key_hex: to_hex(&wrapped),
                scope,
                state: VaultState::Unlocked,
                options,
                last_op_ms: 0,
                last_op: String::new(),
            },
        };
        std::fs::create_dir_all(vault.blobs_dir()).ctx(&vault.vault_dir())?;
        vault.save_meta()?;
        Ok((vault, volume_key))
    }

    pub fn save_meta(&self) -> DtResult<()> {
        let path = self.volume_path();
        let bytes = serde_json::to_vec_pretty(&self.meta)
            .map_err(|e| DtError::Other(format!("cannot serialise volume.json: {e}")))?;
        write_atomic(&path, &bytes)
    }

    pub fn set_state(&mut self, state: VaultState, op: &str) -> DtResult<()> {
        self.meta.state = state;
        self.meta.updated_ms = now_ms();
        if !op.is_empty() {
            self.meta.last_op = op.to_string();
            self.meta.last_op_ms = now_ms();
        }
        self.save_meta()
    }

    /// Turn a password back into the volume key, rejecting a wrong one twice over: the
    /// verifier first (cheap), then the authenticated unwrap.
    pub fn key_for(&self, password: &str) -> DtResult<Secret> {
        let salt = from_hex(&self.meta.salt_hex)?;
        let stored_verifier = from_hex(&self.meta.verifier_hex)?;
        let nonce = from_hex(&self.meta.wrap_nonce_hex)?;
        let wrapped = from_hex(&self.meta.wrapped_key_hex)?;
        if nonce.len() != 12 {
            return Err(DtError::Format("bad wrap nonce length".into()));
        }
        let password_key = kdf::derive_master(password, &salt, &self.meta.kdf)?;
        kdf::check_verifier(&password_key, &stored_verifier)?;
        let mut n = [0u8; 12];
        n.copy_from_slice(&nonce);
        unwrap_volume_key(&password_key, &wrapped, &n, &salt)
    }

    /// Re-wrap the volume key under a new password. Ciphertext on the drive is untouched.
    pub fn set_password(&mut self, current: &str, next: &str, next_again: &str) -> DtResult<Secret> {
        if next.is_empty() {
            return Err(DtError::Other("the new password is empty".into()));
        }
        if next != next_again {
            return Err(DtError::Other("the new passwords do not match".into()));
        }
        let volume_key = self.key_for(current)?;
        let salt = kdf::random_bytes::<{ kdf::SALT_LEN }>();
        // A vault set up before the floor moved keeps its cheaper parameters until the next
        // password change, which is the one moment re-deriving costs nothing extra.
        let params = kdf::calibrate(self.meta.options.kdf_target_ms.max(KDF_TARGET_MS));
        let password_key = kdf::derive_master(next, &salt, &params)?;
        let verifier = kdf::compute_verifier(&password_key)?;
        let (wrapped, nonce) = wrap_volume_key(&password_key, &volume_key, &salt)?;
        self.meta.kdf = params;
        self.meta.salt_hex = to_hex(&salt);
        self.meta.verifier_hex = to_hex(&verifier);
        self.meta.wrap_nonce_hex = to_hex(&nonce);
        self.meta.wrapped_key_hex = to_hex(&wrapped);
        self.meta.updated_ms = now_ms();
        self.save_meta()?;
        Ok(volume_key)
    }
}

pub fn wrap_volume_key(
    password_key: &Secret,
    volume_key: &Secret,
    salt: &[u8],
) -> DtResult<(Vec<u8>, [u8; 12])> {
    let wrap_key = kdf::subkey(password_key, "wrap", salt)?;
    let nonce = kdf::random_bytes::<12>();
    let wrapped = crate::crypto::envelope::seal_small(
        wrap_key.as_bytes(),
        &nonce,
        volume_key.as_bytes(),
        salt,
    )?;
    Ok((wrapped, nonce))
}

pub fn unwrap_volume_key(
    password_key: &Secret,
    wrapped: &[u8],
    nonce: &[u8; 12],
    salt: &[u8],
) -> DtResult<Secret> {
    let wrap_key = kdf::subkey(password_key, "wrap", salt)?;
    let raw = crate::crypto::envelope::open_small(wrap_key.as_bytes(), nonce, wrapped, salt)
        .map_err(|_| DtError::WrongPassword)?;
    if raw.len() != kdf::KEY_LEN {
        return Err(DtError::Format("unwrapped key has the wrong length".into()));
    }
    Ok(Secret::new(raw))
}

/// Write bytes through a temp file and rename, so a crash never leaves a half-written
/// metadata file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> DtResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| DtError::Other("metadata path has no parent".into()))?;
    std::fs::create_dir_all(parent).ctx(parent)?;
    let name = path
        .file_name()
        .ok_or_else(|| DtError::Other("metadata path has no file name".into()))?
        .to_string_lossy();
    // The stamp keeps a crashed pass's leftover temp from being overwritten by the next one,
    // and the `.dttmp` suffix keeps the scanner from ever treating it as user data.
    let tmp = parent.join(format!("{name}.{}.dttmp", now_ms()));
    {
        let mut file = File::create(&tmp).ctx(&tmp)?;
        file.write_all(bytes).ctx(&tmp)?;
        file.flush().ctx(&tmp)?;
        file.sync_all().ctx(&tmp)?;
    }
    std::fs::rename(&tmp, path).ctx(&path)?;
    let _ = fs::fsync_dir(parent);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips() {
        let bytes = [0u8, 1, 15, 16, 254, 255];
        let hex = to_hex(&bytes);
        assert_eq!(hex, "00010f10feff");
        assert_eq!(from_hex(&hex).unwrap(), bytes.to_vec());
        assert!(from_hex("0").is_err());
        assert!(from_hex("zz").is_err());
    }

    #[test]
    fn exclusion_patterns() {
        let opts = VaultOptions {
            exclude: vec!["*.tmp".into(), ".DS_Store".into(), "node_modules/".into()],
            ..Default::default()
        };
        assert!(opts.is_excluded("session.tmp"));
        assert!(!opts.is_excluded("session.txt"));
        assert!(opts.is_excluded(".DS_Store"));
        assert!(opts.is_excluded("project/node_modules/lib.js"));
        assert!(!opts.is_excluded("src/main.rs"));
    }

    #[test]
    fn detect_returns_none_for_a_plain_drive() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Vault::detect(dir.path()).unwrap().is_none());
    }

    #[test]
    fn create_writes_a_verifiable_volume_and_rejects_a_second_vault() {
        let dir = tempfile::tempdir().unwrap();
        let scope = dir.path().join("secret");
        std::fs::create_dir(&scope).unwrap();
        let (vault, _master) = Vault::create(
            dir.path(),
            "secret",
            "test drive",
            "right horse battery",
            "right horse battery",
            VaultOptions {
                kdf_target_ms: 0,
                ..Default::default()
            },
        )
        .unwrap();
        // A fast KDF is expected in tests; the ladder is capped at 100 ms there.
        assert_eq!(vault.meta.scope, "secret");
        assert_eq!(vault.meta.state, VaultState::Unlocked);
        assert!(vault.blob_path("aa").ends_with("aa.dtc"));
        assert!(vault.scope_root().ends_with("secret"));
        assert!(vault.key_for("right horse battery").is_ok());
        assert!(matches!(
            vault.key_for("wrong"),
            Err(DtError::WrongPassword)
        ));
        assert!(matches!(
            Vault::create(dir.path(), "secret", "x", "a", "a", Default::default()),
            Err(DtError::State(_))
        ));
        assert!(matches!(
            Vault::create(dir.path(), "secret", "x", "a", "b", Default::default()),
            Err(DtError::Other(_))
        ));
        assert!(matches!(
            Vault::create(dir.path(), "missing-folder", "x", "a", "a", Default::default()),
            Err(DtError::State(_))
        ));
    }

    #[test]
    fn scope_is_stored_drive_relative() {
        assert_eq!(normalize_scope("/").unwrap(), "/");
        assert_eq!(normalize_scope("").unwrap(), "/");
        assert_eq!(normalize_scope("  ").unwrap(), "/");
        assert_eq!(normalize_scope("/secret/").unwrap(), "secret");
        assert_eq!(normalize_scope("./a/.").unwrap(), "a");
        assert_eq!(normalize_scope("a\\b\\c").unwrap(), "a/b/c");
        assert!(matches!(normalize_scope("../x"), Err(DtError::State(_))));
        assert!(matches!(normalize_scope("C:/x"), Err(DtError::State(_))));
    }

    #[test]
    fn picks_are_stored_relative_and_a_whole_drive_pick_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("secret")).unwrap();
        let (vault, _key) = Vault::create(
            dir.path(),
            "/",
            "t",
            "pw",
            "pw",
            VaultOptions {
                kdf_target_ms: 100,
                select: vec![
                    "/secret/a.txt/".to_string(),
                    "\\".to_string(),
                    "b\\c.dat".to_string(),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(vault.meta.options.select, vec!["secret/a.txt", "b/c.dat"]);

        let fresh = tempfile::tempdir().unwrap();
        assert!(matches!(
            Vault::create(
                fresh.path(),
                "/",
                "t",
                "pw",
                "pw",
                VaultOptions {
                    kdf_target_ms: 100,
                    select: vec!["../escape".to_string()],
                    ..Default::default()
                },
            ),
            Err(DtError::State(_))
        ));
    }

    #[test]
    fn a_slashed_scope_names_the_same_vault_as_a_plain_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("secret")).unwrap();
        let (vault, _key) = Vault::create(
            dir.path(),
            "/secret/",
            "t",
            "pw",
            "pw",
            VaultOptions {
                kdf_target_ms: 100,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(vault.meta.scope, "secret");
        assert_eq!(vault.scope_root(), dir.path().join("secret"));
    }

    #[test]
    fn atomic_write_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/meta.json");
        write_atomic(&path, b"{\"ok\":true}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"ok\":true}");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("nested"))
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().to_string()))
            .filter(|n| n.starts_with("meta.json"))
            .collect();
        assert_eq!(leftovers, vec!["meta.json".to_string()]);
    }
}
