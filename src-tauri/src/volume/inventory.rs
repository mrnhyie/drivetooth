//! A read-only census of a volume: what the computer can see on it right now, or what a
//! sealed vault says it holds. Nothing in here writes, hashes or opens a file's contents, so
//! the UI can answer "what is on this drive?" the moment a drive is clicked.
//!
//! The grouping by content family exists for display only; it has no bearing on what gets
//! encrypted.

use std::fs::Metadata;
use std::path::Path;
use std::time::UNIX_EPOCH;
use serde::Serialize;
use walkdir::WalkDir;

use crate::error::{DtError, DtResult};
use crate::volume::manifest::{is_internal_name, is_system_name, join_rel, rel_from};
use crate::volume::VAULT_DIR;

/// How many paths the census names. A drive can hold far more than this; the counts stay
/// exact and the caller is told the list was cut.
pub const PATH_LIMIT: usize = 400;
pub const RECENT_LIMIT: usize = 8;
/// A walk of a pathological tree must not run unbounded in front of the UI.
const VISIT_LIMIT: usize = 50_000;

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub rel: String,
    pub size: u64,
    pub mtime_ms: i64,
    pub dir: bool,
}

#[derive(Debug, Default, Clone)]
pub struct Inventory {
    pub items: Vec<Item>,
    pub truncated: bool,
}

impl Inventory {
    /// Every entry the drive itself exposes, one folder at a time, excluding the vault and
    /// the operating system's own bookkeeping. `scope_rel` is where the vault's own view of
    /// the drive begins.
    pub fn walk(mount: &Path, scope_rel: &str) -> DtResult<Inventory> {
        let root = join_rel(mount, scope_rel);
        let root_meta = std::fs::metadata(&root).map_err(|e| {
            DtError::State(format!("{} is not readable: {e}", root.display()))
        })?;
        if !root_meta.is_dir() {
            return Err(DtError::State(format!(
                "scope {} is not a folder",
                root.display()
            )));
        }

        let vault_dir = mount.join(VAULT_DIR);
        let mut items = Vec::new();
        let mut truncated = false;
        let mut seen = 0usize;

        let mut walker = WalkDir::new(&root)
            .follow_links(false)
            .contents_first(false)
            .min_depth(1)
            .into_iter();

        while let Some(next) = walker.next() {
            if seen >= VISIT_LIMIT {
                truncated = true;
                break;
            }
            seen += 1;
            // A listing must not be spoiled by one unreadable corner of the tree.
            let Ok(entry) = next else { continue };
            let abs = entry.path();
            if abs.starts_with(&vault_dir) {
                if entry.file_type().is_dir() {
                    walker.skip_current_dir();
                }
                continue;
            }
            let Some(name) = entry.file_name().to_str() else {
                continue;
            };
            if is_internal_name(name) || is_system_name(name) {
                if entry.file_type().is_dir() {
                    walker.skip_current_dir();
                }
                continue;
            }
            let Ok(rel) = rel_from(mount, abs) else { continue };
            let is_dir = entry.file_type().is_dir();
            let meta = entry.metadata().ok();
            items.push(Item {
                rel,
                size: if is_dir { 0 } else { meta.as_ref().map(|m| m.len()).unwrap_or(0) },
                mtime_ms: meta.as_ref().map(mtime_of).unwrap_or(0),
                dir: is_dir,
            });
        }
        Ok(Inventory { items, truncated })
    }

    pub fn from_items(items: Vec<Item>) -> Inventory {
        Inventory {
            items,
            truncated: false,
        }
    }

    pub fn files(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| !i.dir)
    }

    /// The shape the contents panel draws, for either source of census.
    pub fn payload(&self, source: &str, blob_bytes: u64) -> serde_json::Value {
        let mut plain_bytes = 0u64;
        let mut dirs = 0u64;
        let mut kinds: std::collections::BTreeMap<&'static str, (u64, u64)> = Default::default();
        for item in &self.items {
            if item.dir {
                dirs += 1;
                continue;
            }
            plain_bytes += item.size;
            let slot = kinds.entry(content_kind(&item.rel)).or_insert((0, 0));
            slot.0 += 1;
            slot.1 += item.size;
        }
        let files = self.items.len() as u64 - dirs;

        let mut by_name: Vec<&Item> = self.files().collect();
        by_name.sort_by(|a, b| a.rel.cmp(&b.rel));
        let shown: Vec<&Item> = by_name.iter().copied().take(PATH_LIMIT).collect();

        let mut by_newest: Vec<&Item> = self.files().collect();
        by_newest.sort_by(|a, b| b.mtime_ms.cmp(&a.mtime_ms).then(a.rel.cmp(&b.rel)));

        serde_json::json!({
            "source": source,
            "files": files,
            "dirs": dirs,
            "plainBytes": plain_bytes,
            "blobBytes": blob_bytes,
            "kinds": kinds
                .into_iter()
                .map(|(kind, (count, size))| {
                    serde_json::json!({ "kind": kind, "files": count, "bytes": size })
                })
                .collect::<Vec<_>>(),
            "paths": shown.iter().map(|i| i.rel.clone()).collect::<Vec<_>>(),
            "recent": by_newest
                .iter()
                .take(RECENT_LIMIT)
                .map(|i| {
                    serde_json::json!({
                        "path": i.rel,
                        "bytes": i.size,
                        "mtimeMs": i.mtime_ms,
                        "kind": content_kind(&i.rel),
                    })
                })
                .collect::<Vec<_>>(),
            "truncated": self.truncated || by_name.len() > shown.len(),
        })
    }
}

/// Coarse content family for a stored path, used only to group a drive's contents for
/// display.
pub fn content_kind(rel: &str) -> &'static str {
    let ext = std::path::Path::new(rel)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "pdf" | "doc" | "docx" | "odt" | "rtf" | "txt" | "md" | "pages" | "xls" | "xlsx"
        | "ods" | "csv" | "numbers" | "ppt" | "pptx" | "key" => "documents",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "heic" | "tif" | "tiff" | "bmp" | "svg"
        | "raw" | "cr2" | "nef" | "dng" | "psd" | "ai" => "images",
        "mp4" | "mov" | "mkv" | "avi" | "wmv" | "flv" | "webm" | "m4v" | "mts" => "videos",
        "mp3" | "wav" | "aac" | "flac" | "m4a" | "ogg" | "opus" | "aif" | "aiff" => "audio",
        "zip" | "7z" | "rar" | "gz" | "tar" | "bz2" | "xz" | "dmg" | "iso" => "archives",
        _ => "other",
    }
}

fn mtime_of(meta: &Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_grouping_is_case_insensitive_and_total() {
        assert_eq!(content_kind("a/b/Report.DOCX"), "documents");
        assert_eq!(content_kind("photo.JPG"), "images");
        assert_eq!(content_kind("clip.MP4"), "videos");
        assert_eq!(content_kind("track.flac"), "audio");
        assert_eq!(content_kind("backup.tar.gz"), "archives");
        assert_eq!(content_kind("LICENSE"), "other");
        assert_eq!(content_kind("no/such/name"), "other");
    }

    #[test]
    fn a_walked_drive_is_censused_without_touching_the_vault_or_the_os_junk() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("notes.md"), b"hello").unwrap();
        std::fs::create_dir_all(root.join("pics")).unwrap();
        std::fs::write(root.join("pics/a.png"), [0u8; 120]).unwrap();
        std::fs::create_dir_all(root.join(".drivetooth/blobs")).unwrap();
        std::fs::write(root.join(".drivetooth/blobs/deadbeef.dtc"), [0u8; 900]).unwrap();
        std::fs::create_dir_all(root.join(".fseventsd")).unwrap();
        std::fs::write(root.join(".fseventsd/fseventsd-uuid"), b"x").unwrap();
        std::fs::write(root.join("._notes.md"), b"x").unwrap();

        let census = Inventory::walk(root, "/").unwrap();
        let mut paths: Vec<&str> = census.items.iter().map(|i| i.rel.as_str()).collect();
        paths.sort();
        assert_eq!(paths, ["notes.md", "pics", "pics/a.png"]);

        let payload = census.payload("tree", 0);
        assert_eq!(payload["files"], 2);
        assert_eq!(payload["dirs"], 1);
        assert_eq!(payload["plainBytes"], 5 + 120);
        assert_eq!(payload["truncated"], false);
        let kinds = payload["kinds"].as_array().unwrap().clone();
        assert_eq!(kinds.len(), 2);
        assert_eq!(kinds[0]["kind"], "documents");
        assert_eq!(kinds[1]["kind"], "images");
        assert_eq!(kinds[1]["bytes"], 120);
        assert_eq!(payload["recent"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn a_scope_census_sees_only_its_own_folder() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("in")).unwrap();
        std::fs::write(dir.path().join("in/keep.txt"), b"1").unwrap();
        std::fs::write(dir.path().join("out.txt"), b"1").unwrap();
        let census = Inventory::walk(dir.path(), "in").unwrap();
        assert_eq!(census.items.len(), 1);
        assert_eq!(census.items[0].rel, "in/keep.txt");
    }

    #[test]
    fn a_missing_scope_says_so_rather_than_reporting_an_empty_drive() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Inventory::walk(dir.path(), "gone").is_err());
    }
}
