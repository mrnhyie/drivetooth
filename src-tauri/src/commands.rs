//! Tauri command surface. One long-running entry point handles every mutating operation so
//! the UI has a single progress stream and a single cancellation switch to reason about.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

use crate::crypto::kdf::Secret;
use crate::error::{DtError, DtResult, IoCtx};
use crate::ops::lock::lock;
use crate::ops::recover::{erase, recover};
use crate::ops::scan::scan;
use crate::ops::unlock::unlock as unlock_drive;
use crate::ops::{Runner, Summary};
use crate::volume::journal::Journal;
use crate::volume::inventory::{Inventory, Item};
use crate::volume::manifest::{
    is_internal_name, is_system_name, name_key, validate_rel, EntryKind, Manifest,
};
use crate::volume::{fs, Vault, VaultOptions, VaultState, VAULT_DIR};

pub const PROGRESS_EVENT: &str = "dt-progress";
/// How long an unlocked drive keeps its volume key in memory before the UI asks again.
pub const SESSION_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Default)]
pub struct Session {
    key: Option<Arc<Secret>>,
    uuid: Option<String>,
    mount: Option<String>,
    derived_at: Option<Instant>,
}

impl Session {
    pub fn key_for(&self, uuid: &str) -> Option<Arc<Secret>> {
        let fresh = self
            .derived_at
            .map(|at| at.elapsed() < SESSION_TTL)
            .unwrap_or(false);
        if fresh && self.uuid.as_deref() == Some(uuid) {
            self.key.clone()
        } else {
            None
        }
    }

    pub fn store(&mut self, uuid: &str, mount: &Path, key: Arc<Secret>) {
        self.uuid = Some(uuid.to_string());
        self.mount = Some(mount.to_string_lossy().to_string());
        self.key = Some(key);
        self.derived_at = Some(Instant::now());
    }

    pub fn clear(&mut self) {
        self.key = None;
        self.uuid = None;
        self.mount = None;
        self.derived_at = None;
    }
}

#[derive(Debug, Default)]
pub struct AppState {
    session: std::sync::Mutex<Session>,
    runner: std::sync::Mutex<Option<Arc<Runner>>>,
}

impl AppState {
    pub fn clear_session(&self) {
        self.session.lock().unwrap().clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum OpRequest {
    /// First-time setup: create the vault, encrypt everything in scope, then lock.
    Init {
        mount: String,
        scope: String,
        label: String,
        password: String,
        password_again: String,
        options: Option<VaultOptions>,
    },
    Lock {
        mount: String,
        password: Option<String>,
        /// Replaces the stored pick list when present, so the choice is not write-once.
        /// `None` keeps whatever the vault already holds.
        select: Option<Vec<String>>,
    },
    Unlock {
        mount: String,
        password: Option<String>,
    },
    Recover {
        mount: String,
        password: String,
    },
    SetPassword {
        mount: String,
        current: String,
        next: String,
        next_again: String,
    },
    Erase {
        mount: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct MountView {
    #[serde(flatten)]
    pub info: fs::MountInfo,
    pub readable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeReport {
    pub mount: String,
    pub initialised: bool,
    pub meta: Option<crate::volume::VolumeMeta>,
    pub blobs: u64,
    pub blob_bytes: u64,
    pub journal: Option<Journal>,
    pub session_ready: bool,
    /// A locked vault with no key in this session: it can show nothing of its own, because
    /// everything it holds is sealed behind the password. The UI gates on this rather than
    /// guessing from the state, so the rule lives in one place.
    pub sealed: bool,
    pub error: Option<String>,
}

#[tauri::command]
pub fn list_mounts() -> Vec<MountView> {
    fs::list_mounts()
        .into_iter()
        .map(|info| {
            let path = Path::new(&info.path);
            MountView {
                readable: std::fs::read_dir(path).is_ok(),
                writable: !info.read_only_mount && probe_writable(path),
                info,
            }
        })
        .collect()
}

fn probe_writable(path: &Path) -> bool {
    let probe = path.join(format!(".drivetooth-probe-{}", std::process::id()));
    let ok = std::fs::write(&probe, b"ok").is_ok();
    if ok {
        let _ = std::fs::remove_file(&probe);
    }
    ok
}

#[tauri::command]
pub fn inspect_volume(app: AppHandle, mount: String) -> VolumeReport {
    let path = Path::new(&mount);
    let mut report = VolumeReport {
        mount: mount.clone(),
        initialised: false,
        meta: None,
        blobs: 0,
        blob_bytes: 0,
        journal: None,
        session_ready: false,
        sealed: false,
        error: None,
    };
    match Vault::detect(path) {
        Ok(Some(vault)) => {
            report.initialised = true;
            let (blobs, blob_bytes) = count_blobs(&vault);
            report.blobs = blobs;
            report.blob_bytes = blob_bytes;
            report.journal = Journal::load(&vault).ok().flatten();
            report.session_ready = app
                .state::<AppState>()
                .session
                .lock()
                .unwrap()
                .key_for(&vault.meta.uuid)
                .is_some();
            report.sealed = vault.meta.state == VaultState::Locked && !report.session_ready;
            report.meta = Some(vault.meta);
        }
        Ok(None) => {}
        Err(err) => {
            report.error = Some(err.to_string());
            report.initialised = path.join(crate::volume::VAULT_DIR).exists();
        }
    }
    report
}

fn count_blobs(vault: &Vault) -> (u64, u64) {
    let Ok(entries) = std::fs::read_dir(vault.blobs_dir()) else {
        return (0, 0);
    };
    let mut count = 0u64;
    let mut bytes = 0u64;
    for entry in entries.flatten() {
        count += 1;
        bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
    }
    (count, bytes)
}

#[tauri::command]
pub fn cancel_operation(app: AppHandle) -> bool {
    let state = app.state::<AppState>();
    let guard = state.runner.lock().unwrap();
    match guard.as_ref() {
        Some(runner) => {
            runner.request_cancel();
            true
        }
        None => false,
    }
}

#[tauri::command]
pub fn forget_session(app: AppHandle) {
    app.state::<AppState>().session.lock().unwrap().clear();
}

#[tauri::command]
pub async fn run_operation(app: AppHandle, op: OpRequest) -> Result<Summary, String> {
    {
        let state = app.state::<AppState>();
        let mut guard = state.runner.lock().unwrap();
        if guard.is_some() {
            return Err("another operation is already running".to_string());
        }
        let emit_app = app.clone();
        let runner = Arc::new(Runner::new(Box::new(move |progress| {
            let _ = emit_app.emit(PROGRESS_EVENT, &progress);
        })));
        *guard = Some(runner);
    }

    let thread_app = app.clone();
    let joined = tauri::async_runtime::spawn_blocking(move || {
        let outcome = dispatch(&op, &thread_app);
        thread_app
            .state::<AppState>()
            .runner
            .lock()
            .unwrap()
            .take();
        outcome
    })
    .await;

    match joined {
        Ok(Ok(summary)) => Ok(summary),
        Ok(Err(err)) => Err(err.to_string()),
        Err(err) => Err(format!("the operation thread failed: {err}")),
    }
}

fn dispatch(op: &OpRequest, app: &AppHandle) -> DtResult<Summary> {
    let state = app.state::<AppState>();
    let runner = current_runner(app)?;
    match op {
        OpRequest::Init {
            mount,
            scope,
            label,
            password,
            password_again,
            options,
        } => {
            let path = Path::new(mount);
            let (mut vault, key) =
                Vault::create(path, scope, label, password, password_again, options.clone().unwrap_or_default())?;
            let plan = scan(path, &vault.meta.scope.clone(), &vault.meta.options.clone(), &runner)?;
            let mut summary = lock(&mut vault, &key, &plan, &runner)?;
            summary.op = "init".to_string();
            state.session.lock().unwrap().clear();
            Ok(summary)
        }
        OpRequest::Lock {
            mount,
            password,
            select,
        } => {
            let path = Path::new(mount);
            let mut vault = require_vault(path)?;
            if vault.meta.state == VaultState::Recovering {
                return Err(DtError::State(
                    "recover the interrupted operation before locking again".into(),
                ));
            }
            let key = session_or_password(app, &vault, password.as_deref())?;
            let mut options = vault.meta.options.clone();
            if let Some(select) = select {
                options.select = crate::volume::normalize_picks(&select)?;
                vault.meta.options = options.clone();
                vault.save_meta()?;
            }
            let plan = scan(path, &vault.meta.scope.clone(), &options, &runner)?;
            let summary = lock(&mut vault, &key, &plan, &runner)?;
            state.session.lock().unwrap().clear();
            Ok(summary)
        }
        OpRequest::Unlock { mount, password } => {
            let path = Path::new(mount);
            let mut vault = require_vault(path)?;
            let key = session_or_password(app, &vault, password.as_deref())?;
            let summary = unlock_drive(&mut vault, &key, &runner)?;
            // Keep the key: a password change on the now-visible tree should not cost a
            // second typing.
            state.session.lock().unwrap().store(&vault.meta.uuid, path, key);
            Ok(summary)
        }
        OpRequest::Recover { mount, password } => {
            let path = Path::new(mount);
            let mut vault = require_vault(path)?;
            let key = vault.key_for(password)?;
            let summary = recover(&mut vault, &key, &runner)?;
            state.session.lock().unwrap().clear();
            Ok(summary)
        }
        OpRequest::SetPassword {
            mount,
            current,
            next,
            next_again,
        } => {
            let path = Path::new(mount);
            let mut vault = require_vault(path)?;
            let volume_key = vault.key_for(current)?;
            let spot = spot_check_blob(&vault, &volume_key)?;
            let fresh = vault.set_password(current, next, next_again)?;
            if vault.key_for(next).is_err() {
                return Err(DtError::Crypto(
                    "the new password does not unlock the vault it just made".into(),
                ));
            }
            // Ciphertext must not have moved: only the 32-byte wrap changed.
            if let Some((id, bytes)) = &spot {
                let now = std::fs::read(vault.blob_path(id)).unwrap_or_default();
                if &now != bytes {
                    return Err(DtError::Crypto(format!(
                        "record {id} changed on disk during a password change"
                    )));
                }
            }
            let mut summary = Summary::new("set-password");
            summary.files = count_blobs(&vault).0;
            summary.message = format!(
                "password changed; {} blob(s) left untouched",
                summary.files
            );
            state
                .session
                .lock()
                .unwrap()
                .store(&vault.meta.uuid, path, Arc::new(fresh));
            Ok(summary)
        }
        OpRequest::Erase { mount } => {
            let path = Path::new(mount);
            let vault = require_vault(path)?;
            erase(&vault)?;
            state.session.lock().unwrap().clear();
            let mut summary = Summary::new("erase");
            summary.message = format!("vault removed from {}", path.display());
            Ok(summary)
        }
    }
}

/// Read one blob's bytes and prove it authenticates, so a password change can be verified
/// without touching the rest of the drive.
fn spot_check_blob(vault: &Vault, key: &Secret) -> DtResult<Option<(String, Vec<u8>)>> {
    let Some(id) = first_blob_id(vault) else {
        return Ok(None);
    };
    let path = vault.blob_path(&id);
    let bytes = std::fs::read(&path).ctx(&path)?;
    let raw = crate::volume::from_hex(&id)?;
    let id_bytes = <[u8; 16]>::try_from(raw.as_slice())
        .map_err(|_| DtError::Format("blob name is not a record id".into()))?;
    crate::crypto::envelope::verify_blob(&path, key, id_bytes)?;
    Ok(Some((id, bytes)))
}

fn require_vault(path: &Path) -> DtResult<Vault> {
    Vault::detect(path)?
        .ok_or_else(|| DtError::State(format!("{} has no DriveTooth vault", path.display())))
}

fn session_or_password(
    app: &AppHandle,
    vault: &Vault,
    password: Option<&str>,
) -> DtResult<Arc<Secret>> {
    let state = app.state::<AppState>();
    if let Some(key) = state.session.lock().unwrap().key_for(&vault.meta.uuid) {
        return Ok(key);
    }
    let password = password.ok_or_else(|| {
        DtError::State("this drive has been idle too long; re-enter the password".to_string())
    })?;
    vault.key_for(password).map(Arc::new)
}

fn current_runner(app: &AppHandle) -> DtResult<Arc<Runner>> {
    let state = app.state::<AppState>();
    let guard = state.runner.lock().unwrap();
    guard
        .as_ref()
        .cloned()
        .ok_or_else(|| DtError::Other("no operation is bound to this request".into()))
}

fn first_blob_id(vault: &Vault) -> Option<String> {
    let entries = std::fs::read_dir(vault.blobs_dir()).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(stem) = name.strip_suffix(".dtc") {
            if entry.path().is_file() {
                return Some(stem.to_string());
            }
        }
    }
    None
}

/// Reveal what a locked drive holds. The sealed names are only readable with the key, so this
/// is a password check as much as it is a listing — the one way to see what is in the vault
/// without rebuilding the whole plaintext tree first. A verified password is kept in the
/// session, so a drive clicked twice does not need it typed again.
#[tauri::command]
pub fn describe_contents(
    app: AppHandle,
    mount: String,
    password: Option<String>,
) -> Result<serde_json::Value, String> {
    let path = Path::new(&mount);
    let vault = require_vault(path).map_err(|e| e.to_string())?;
    let held = app
        .state::<AppState>()
        .session
        .lock()
        .unwrap()
        .key_for(&vault.meta.uuid);
    let key = match held {
        Some(key) => key,
        None => {
            let Some(password) = password else {
                return Err("the password is what unseals the names on this drive".to_string());
            };
            let key = Arc::new(vault.key_for(&password).map_err(|e| e.to_string())?);
            app.state::<AppState>()
                .session
                .lock()
                .unwrap()
                .store(&vault.meta.uuid, path, key.clone());
            key
        }
    };
    let mut manifest = Manifest::load(&vault, &key).map_err(|e| e.to_string())?;
    if manifest.paths_are_sealed() {
        manifest
            .reveal_paths(&name_key(&key).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    }
    let totals = manifest.totals();
    let items: Vec<Item> = manifest
        .entries
        .iter()
        .filter_map(|e| {
            let rel = e.path.clone()?;
            Some(Item {
                rel,
                size: e.size,
                mtime_ms: e.mtime_ms,
                dir: e.kind == EntryKind::Dir,
            })
        })
        .collect();
    Ok(Inventory::from_items(items).payload("vault", totals.blob_bytes))
}

/// The drive exactly as this computer can see it, no key involved. An unlocked or plain drive
/// answers "what is on it?" the moment it is clicked, which is the same question the sealed
/// manifest answers for a locked one.
#[tauri::command]
pub fn describe_tree(mount: String) -> Result<serde_json::Value, String> {
    let path = Path::new(&mount);
    let vault = Vault::detect(path).map_err(|e| e.to_string())?;
    let scope = vault.as_ref().map(|v| v.meta.scope.clone()).unwrap_or_else(|| "/".into());
    let blob_bytes = vault.as_ref().map(count_blobs).unwrap_or((0, 0)).1;
    let census = Inventory::walk(path, &scope).map_err(|e| e.to_string())?;
    Ok(census.payload("tree", blob_bytes))
}

/// One folder of a mounted drive, for browsing and for choosing what to encrypt. It reads
/// only what the file manager already shows — no key, no blob is ever opened — so a locked
/// drive simply has nothing outside `.drivetooth` to list.
#[tauri::command]
pub fn list_dir(mount: String, path: String) -> Result<serde_json::Value, String> {
    const LIMIT: usize = 600;
    let root = Path::new(&mount);
    let rel = path.trim_matches(|c| c == '/' || c == '\\');
    if !rel.is_empty() {
        validate_rel(rel).map_err(|e| e.to_string())?;
    }
    if rel.split(['/', '\\']).any(|part| part == VAULT_DIR) {
        return Err("the vault folder holds ciphertext, not files".to_string());
    }
    let target = crate::volume::manifest::join_rel(root, rel);
    let entries = std::fs::read_dir(&target).map_err(|e| format!("{}: {e}", target.display()))?;

    let mut rows: Vec<serde_json::Value> = Vec::new();
    let mut truncated = false;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // The vault folder is not part of the user's files, and neither is the operating
        // system's own bookkeeping on the volume.
        if is_internal_name(&name) || is_system_name(&name) || name == VAULT_DIR {
            continue;
        }
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let metadata = entry.metadata().ok();
        rows.push(serde_json::json!({
            "name": name,
            "rel": if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") },
            "dir": is_dir,
            "bytes": if is_dir { 0 } else { metadata.as_ref().map(|m| m.len()).unwrap_or(0) },
            "mtimeMs": metadata
                .as_ref()
                .and_then(|m| m.modified().ok())
                .map(|t| t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0))
                .unwrap_or(0),
        }));
    }
    rows.sort_by(|a, b| {
        let key = |row: &serde_json::Value| {
            (
                !row["dir"].as_bool().unwrap_or(false),
                row["name"].as_str().unwrap_or("").to_lowercase(),
            )
        };
        key(a).cmp(&key(b))
    });
    if rows.len() > LIMIT {
        truncated = true;
        rows.truncate(LIMIT);
    }
    Ok(serde_json::json!({ "path": rel, "entries": rows, "truncated": truncated }))
}

/// How often the plug watcher looks for a drive that has just appeared.
const PLUG_POLL: Duration = Duration::from_secs(3);

/// Watch for a sealed drive being plugged in, so the window can ask for the password before
/// the user goes looking for the drive. A vault that was already there when the app started is
/// announced once too; one that stays locked and is ignored is not announced again until it is
/// unplugged and reinserted.
pub fn watch_for_plugs(app: AppHandle) {
    std::thread::spawn(move || {
        let mut announced: Vec<String> = Vec::new();
        loop {
            let mut present = Vec::new();
            for path in fs::mount_candidates() {
                // One stat per volume on the common pass; the metadata is only read when
                // something new appears.
                if !Vault::exists(&path) {
                    continue;
                }
                let text = path.to_string_lossy().to_string();
                present.push(text.clone());
                if announced.contains(&text) {
                    continue;
                }
                let locked = matches!(Vault::detect(&path), Ok(Some(vault))
                    if vault.meta.state == VaultState::Locked);
                if !locked {
                    continue;
                }
                announced.push(text.clone());
                let _ = app.emit(
                    "dt-plug",
                    serde_json::json!({ "mount": text, "name": fs::mount_name(&path) }),
                );
            }
            announced.retain(|mount| present.contains(mount));
            std::thread::sleep(PLUG_POLL);
        }
    });
}
