//! The engine that moves bytes between the drive tree and the vault.
//!
//! Every operation is two-phase. Phase one creates the new copy (a blob, or a restored
//! file) and can be cancelled and rolled back at any moment. Only after every new copy has
//! been read back and authenticated does phase two remove the old one, and from then on the
//! pass must be finished. That ordering is what makes an unplugged drive recoverable.

pub mod lock;
pub mod recover;
pub mod scan;
pub mod unlock;

use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

use crate::error::{DtError, DtResult};

pub type Emit = dyn Fn(Progress) + Send + Sync;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Planning,
    Writing,
    Verifying,
    Removing,
    Committing,
    Done,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Planning => "planning",
            Phase::Writing => "encrypting",
            Phase::Verifying => "verifying",
            Phase::Removing => "removing plaintext",
            Phase::Committing => "committing",
            Phase::Done => "done",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    pub op: String,
    pub phase: String,
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// Rate in bytes per second over the whole pass so far.
    pub rate_bps: f64,
    pub eta_secs: u64,
    pub elapsed_ms: u64,
    /// Display-only hint; never persisted, so a leaked UI string cannot expose a name.
    pub current: String,
    pub message: String,
    pub done: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Unrecoverable {
    pub record_id: String,
    pub path: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub op: String,
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub elapsed_ms: u64,
    pub skipped: Vec<Skipped>,
    pub unrecoverable: Vec<Unrecoverable>,
    pub message: String,
}

impl Summary {
    pub fn new(op: &str) -> Summary {
        Summary {
            op: op.to_string(),
            files: 0,
            dirs: 0,
            bytes: 0,
            elapsed_ms: 0,
            skipped: Vec::new(),
            unrecoverable: Vec::new(),
            message: String::new(),
        }
    }
}

/// Shared cancellation flag plus progress emission for one running operation.
pub struct Runner {
    pub cancel: AtomicBool,
    /// Set once phase two has begun; after this, a cancel request is recorded but the pass
    /// runs to completion.
    pub past_point_of_no_return: AtomicBool,
    pub started: std::time::Instant,
    pub bytes_done: std::sync::atomic::AtomicU64,
    pub files_done: std::sync::atomic::AtomicU64,
    pub emit: Box<Emit>,
}

/// The progress sink is an opaque closure, so `Debug` reports the counters only.
impl std::fmt::Debug for Runner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runner")
            .field("cancel", &self.cancel_requested())
            .field("final", &self.lock_is_final())
            .field("files_done", &self.files_done.load(Ordering::SeqCst))
            .field("bytes_done", &self.bytes_done.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Runner {
    pub fn new(emit: Box<Emit>) -> Runner {
        Runner {
            cancel: AtomicBool::new(false),
            past_point_of_no_return: AtomicBool::new(false),
            started: std::time::Instant::now(),
            bytes_done: std::sync::atomic::AtomicU64::new(0),
            files_done: std::sync::atomic::AtomicU64::new(0),
            emit,
        }
    }

    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    pub fn cancel_requested(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    pub fn lock_is_final(&self) -> bool {
        self.past_point_of_no_return.load(Ordering::SeqCst)
    }

    /// Checked between chunks inside a file, so a 40 GiB video does not have to finish
    /// before a cancel takes effect.
    pub fn checkpoint(&self) -> DtResult<()> {
        if self.cancel_requested() && !self.lock_is_final() {
            Err(DtError::Cancel)
        } else {
            Ok(())
        }
    }

    pub fn publish(
        &self,
        op: &str,
        phase: Phase,
        files_total: u64,
        bytes_total: u64,
        current: &str,
        message: &str,
    ) {
        let bytes_done = self.bytes_done.load(Ordering::Relaxed);
        let elapsed = self.started.elapsed().as_secs_f64().max(0.001);
        let rate = bytes_done as f64 / elapsed;
        let remaining = bytes_total.saturating_sub(bytes_done) as f64;
        let eta = if rate > 1.0 { (remaining / rate) as u64 } else { 0 };
        (self.emit)(Progress {
            op: op.to_string(),
            phase: phase.label().to_string(),
            files_done: self.files_done.load(Ordering::Relaxed),
            files_total,
            bytes_done,
            bytes_total,
            rate_bps: rate,
            eta_secs: eta,
            elapsed_ms: (elapsed * 1000.0) as u64,
            current: current.to_string(),
            message: message.to_string(),
            done: phase == Phase::Done,
        });
    }

    pub fn add_progress(&self, bytes: u64) {
        self.bytes_done.fetch_add(bytes, Ordering::Relaxed);
        self.files_done.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, bytes: u64) {
        self.bytes_done.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// Space that must be available before an operation starts.
pub fn require_space(mount: &std::path::Path, need_bytes: u64) -> DtResult<()> {
    let (total, free) = crate::volume::fs::free_space(mount)?;
    let _ = total;
    if free >= need_bytes {
        Ok(())
    } else {
        Err(DtError::Space {
            need_mb: need_bytes / (1024 * 1024),
            free_mb: free / (1024 * 1024),
            mount: mount.to_string_lossy().to_string(),
        })
    }
}

/// The margin kept free so the drive stays usable and the filesystem does not run out of
/// space for its own metadata while we are mid-operation.
pub const SPACE_MARGIN: u64 = 64 * 1024 * 1024;
