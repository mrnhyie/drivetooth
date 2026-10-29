/* Stubbed Tauri API for scripts/harness.html: enough of `core.invoke` and `event.listen`
   to click through the real front end in a browser. Every call is recorded on
   window.__calls so a check can assert what the UI actually sent. */

const DRIVES = {
  boot: {
    path: "/System/Volumes/Data",
    name: "Macintosh HD",
    fs_type: "apfs",
    removable: false,
    read_only_mount: false,
    is_boot: true,
    total_bytes: 995_322_000_000,
    free_bytes: 214_500_000_000,
    readable: true,
    writable: true,
    drive_tooth: null,
    vault: null,
  },
  stick: {
    path: "/Volumes/USB-STICK",
    name: "USB-STICK",
    fs_type: "exfat",
    removable: true,
    read_only_mount: false,
    is_boot: false,
    total_bytes: 31_000_000_000,
    free_bytes: 12_400_000_000,
    readable: true,
    writable: true,
    drive_tooth: null,
    vault: null,
  },
  backup: {
    path: "/Volumes/BACKUP",
    name: "BACKUP",
    fs_type: "ntfs",
    removable: true,
    read_only_mount: false,
    is_boot: false,
    total_bytes: 999_000_000_000,
    free_bytes: 40_000_000_000,
    readable: true,
    writable: true,
    drive_tooth: { state: "locked", scope: "secret", label: "law office", uuid: "aa11" },
    vault: { state: "locked", scope: "secret", label: "law office", blobs: 1_204, blob_bytes: 38_400_000_000, session_ready: false },
  },
  work: {
    path: "/Volumes/WORK",
    name: "WORK",
    fs_type: "hfsplus",
    removable: false,
    read_only_mount: false,
    is_boot: false,
    total_bytes: 499_000_000_000,
    free_bytes: 88_000_000_000,
    readable: true,
    writable: true,
    drive_tooth: { state: "unlocked", scope: "/", label: "work", uuid: "bb22" },
    vault: { state: "unlocked", scope: "/", label: "work", blobs: 0, blob_bytes: 0, session_ready: true, select: ["live/archive"] },
  },
  broken: {
    path: "/Volumes/BROKEN",
    name: "BROKEN",
    fs_type: "vfat",
    removable: true,
    read_only_mount: false,
    is_boot: false,
    total_bytes: 15_000_000_000,
    free_bytes: 2_000_000_000,
    readable: true,
    writable: true,
    drive_tooth: { state: "recovering", scope: "vault", label: "field", uuid: "cc33" },
    vault: {
      state: "recovering",
      scope: "vault",
      label: "field",
      blobs: 12,
      blob_bytes: 90_000_000,
      session_ready: false,
      journal: { op: "lock", phase: "destructive", files_total: 12, bytes_total: 88_000_000 },
    },
  },
  readonly: {
    path: "/Volumes/DVD",
    name: "DVD",
    fs_type: "udf",
    removable: true,
    read_only_mount: true,
    is_boot: false,
    total_bytes: 4_700_000_000,
    free_bytes: 0,
    readable: true,
    writable: false,
    drive_tooth: null,
    vault: null,
  },
};

window.__calls = [];

/* The drive as it physically stands, which is what `list_dir` walks. Folders are pruned on a
   locked drive, so only the plain and unlocked ones have anything to show. */
const TREES = {
  "/Volumes/USB-STICK": {
    "": [
      ["Documents", true],
      ["Project Phoenix — Legal Hold 2024", true],
      ["Photos", true],
      ["readme.txt", false, 1240],
      ["2024-Annual-Report-Draft-Final-Review-Comments.docx", false, 842_112],
      [".DS_Store", false, 6_148],
    ],
    Documents: [
      ["2024", true],
      ["deposition.docx", false, 184_320],
      ["invoices.xlsx", false, 1_204_992],
    ],
    "Documents/2024": [["january.pdf", false, 402_112], ["february.pdf", false, 388_004]],
    "Project Phoenix — Legal Hold 2024": [["chain of custody.txt", false, 2_400], ["raw", true]],
    "Project Phoenix — Legal Hold 2024/raw": [["site-04.jpg", false, 4_400_000]],
    Photos: [["site-04.jpg", false, 4_400_000], ["walkthrough.mov", false, 812_000_000]],
  },
  "/Volumes/WORK": {
    "": [
      [".drivetooth", true],
      ["live", true],
      ["scratch.bin", false, 51_200],
    ],
    live: [["plan.md", false, 3_120], ["archive", true]],
    "live/archive": [["2019.tar.gz", false, 620_000_000]],
  },
};

function reportOf(drive) {
  if (!drive.vault) {
    return { mount: drive.path, initialised: false, meta: null, blobs: 0, blob_bytes: 0, journal: null, session_ready: false, sealed: false, error: null };
  }
  const v = drive.vault;
  // A real vault reports a stable timestamp until an operation moves it; the front end uses
  // that to tell "nothing changed" from "rebuild the pane".
  v.stamp ??= Date.now() - 60_000;
  return {
    mount: drive.path,
    initialised: true,
    meta: {
      format: 1,
      uuid: "aa11bb22cc33dd44",
      label: v.label,
      scope: v.scope,
      state: v.state,
      kdf: { algo: "argon2id", m_kib: 19_456, t: 2, p: 1 },
      options: {
        verify_after_encrypt: true,
        chunk_exp: 20,
        kdf_target_ms: 1000,
        exclude: [".DS_Store", "Thumbs.db", "desktop.ini"],
        ...(v.select?.length ? { select: v.select } : {}),
      },
      last_op: v.state === "locked" ? "lock" : "unlock",
      updated_ms: v.stamp,
    },
    blobs: v.blobs,
    blob_bytes: v.blob_bytes,
    journal: v.journal ?? null,
    session_ready: v.session_ready,
    sealed: v.state === "locked" && !v.session_ready,
    error: null,
  };
}

/* The same two censuses the engine builds: what the drive physically holds, and what a sealed
   manifest says it holds. */
const KIND_OF = (name) => {
  const ext = (name.split(".").pop() ?? "").toLowerCase();
  if (["pdf", "doc", "docx", "txt", "md", "xls", "xlsx", "csv"].includes(ext)) return "documents";
  if (["png", "jpg", "jpeg", "gif", "heic", "svg"].includes(ext)) return "images";
  if (["mp4", "mov", "mkv", "webm"].includes(ext)) return "videos";
  if (["mp3", "wav", "flac", "m4a"].includes(ext)) return "audio";
  if (["zip", "gz", "tar", "7z", "dmg", "iso"].includes(ext)) return "archives";
  return "other";
};

function censusPayload(items, source, blobBytes) {
  const files = items.filter((i) => !i.dir);
  const kinds = new Map();
  for (const item of files) {
    const kind = KIND_OF(item.rel);
    const slot = kinds.get(kind) ?? { kind, files: 0, bytes: 0 };
    slot.files += 1;
    slot.bytes += item.size;
    kinds.set(kind, slot);
  }
  return {
    source,
    files: files.length,
    dirs: items.length - files.length,
    plainBytes: files.reduce((sum, i) => sum + i.size, 0),
    blobBytes,
    kinds: [...kinds.values()],
    paths: files.map((i) => i.rel).sort().slice(0, 400),
    recent: [...files]
      .sort((a, b) => b.mtimeMs - a.mtimeMs)
      .slice(0, 8)
      .map((i) => ({ path: i.rel, bytes: i.size, mtimeMs: i.mtimeMs, kind: KIND_OF(i.rel) })),
    truncated: false,
  };
}

function treeOf(mount) {
  const tree = TREES[mount.replace(/\\/g, "/")] ?? {};
  const items = [];
  const walk = (rel) => {
    for (const [name, dir, size] of tree[rel] ?? []) {
      if (name === ".drivetooth" || name === ".DS_Store" || name.endsWith(".dtc")) continue;
      const path = rel ? `${rel}/${name}` : name;
      items.push({ rel: path, dir, size: dir ? 0 : size, mtimeMs: Date.now() - 86_400_000 });
      if (dir) walk(path);
    }
  };
  walk("");
  return items;
}

const SEALED = [
  ["secret/2024/deposition.docx", 842_112, 1],
  ["secret/2024/invoices.xlsx", 1_204_992, 3],
  ["secret/notes.txt", 2_400, 9],
  ["secret/photos/site-04.jpg", 4_400_000, 21],
  ["secret/video/walkthrough.mov", 812_000_000, 40],
  ["secret/backups/2023.tar.gz", 620_000_000, 200],
].map(([rel, size, days]) => ({ rel, dir: false, size, mtimeMs: Date.now() - days * 86_400_000 }));

function view(drive) {
  const { vault, ...rest } = drive;
  return rest;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function runOperation(op) {
  const drive = DRIVES[op.mount.replace(/\\/g, "/")] ?? Object.values(DRIVES).find((d) => d.path === op.mount);
  const total = 240_000_000;
  const emit = (phase, done, message) =>
    window.__emit("dt-progress", {
      op: op.kind,
      phase,
      files_done: done,
      files_total: 12,
      bytes_done: Math.round((done / 12) * total),
      bytes_total: total,
      rate_bps: 42_000_000,
      eta_secs: 5,
      elapsed_ms: 900,
      current: "",
      message,
      done: phase === "done",
    });

  emit("planning", 0, "walking the folder");
  await sleep(120);
  emit("encrypting", 6, "");
  await sleep(120);
  emit("verifying", 12, "all blobs authenticated");
  await sleep(120);
  emit("removing plaintext", 12, "committing manifest");
  await sleep(120);

  if (op.kind === "init" || op.kind === "lock") {
    drive.vault = { state: "locked", scope: op.kind === "init" ? op.scope : drive.vault?.scope ?? "/", label: op.kind === "init" ? op.label : drive.vault?.label, blobs: 12, blob_bytes: 240_000_000, session_ready: false };
    drive.drive_tooth = { state: "locked", scope: drive.vault.scope, label: drive.vault.label, uuid: "aa11" };
  } else if (op.kind === "unlock") {
    drive.vault = { state: "unlocked", scope: drive.vault.scope, label: drive.vault.label, blobs: 0, blob_bytes: 0, session_ready: true };
    drive.drive_tooth = { state: "unlocked", scope: drive.vault.scope, label: drive.vault.label, uuid: "aa11" };
  } else if (op.kind === "recover") {
    drive.vault = { ...drive.vault, state: "locked", session_ready: false, journal: null };
    drive.drive_tooth = { state: "locked", scope: drive.vault.scope, label: drive.vault.label, uuid: "aa11" };
  }

  return {
    op: op.kind,
    files: 12,
    dirs: 3,
    bytes: total,
    elapsed_ms: 6_400,
    skipped: [{ path: ".DS_Store", reason: "excluded" }],
    unrecoverable: [],
    message: `12 file(s) and 3 directory(ies) encrypted into .drivetooth`,
  };
}

window.__TAURI__ = {
  core: {
    async invoke(cmd, args) {
      window.__calls.push({ cmd, args });
      switch (cmd) {
        case "list_mounts":
          return Object.values(DRIVES).map(view);
        case "inspect_volume": {
          const drive = Object.values(DRIVES).find((d) => d.path === args.mount);
          if (!drive) throw new Error(`unknown mount ${args.mount}`);
          return reportOf(drive);
        }
        case "list_dir": {
          const rel = String(args.path ?? "").replace(/^\/+|\/+$/g, "");
          if (rel.split("/").includes(".drivetooth")) throw new Error("the vault folder holds ciphertext, not files");
          const tree = TREES[args.mount.replace(/\\/g, "/")] ?? {};
          const rows = (tree[rel] ?? [])
            .filter(([name]) => name !== ".drivetooth" && !name.endsWith(".dtc"))
            .map(([name, dir, bytes]) => ({
              name,
              rel: rel ? `${rel}/${name}` : name,
              dir,
              bytes: dir ? 0 : bytes,
              mtimeMs: Date.now() - 86_400_000,
            }));
          return { path: rel, entries: rows, truncated: false };
        }
        case "describe_contents": {
          const drive = Object.values(DRIVES).find((d) => d.path === args.mount);
          if (!drive?.vault?.session_ready && args.password !== "correct horse") {
            throw new Error("wrong password");
          }
          // The engine keeps a verified key in the session, so the next inspect reports the
          // drive as no longer sealed.
          if (drive?.vault) drive.vault.session_ready = true;
          return censusPayload(SEALED, "vault", drive?.vault?.blob_bytes ?? 0);
        }
        case "describe_tree": {
          const drive = Object.values(DRIVES).find((d) => d.path === args.mount);
          if (drive?.vault?.state === "locked") throw new Error("sealed vault: no plaintext tree to list");
          return censusPayload(treeOf(args.mount), "tree", drive?.vault?.blob_bytes ?? 0);
        }
        case "run_operation":
          return runOperation(args.op);
        case "cancel_operation":
          return true;
        case "forget_session":
          return null;
        default:
          throw new Error(`harness has no handler for ${cmd}`);
      }
    },
  },
  event: {
    async listen(name, handler) {
      (window.__listeners ??= {})[name] = handler;
      return () => {};
    },
  },
};

window.__emit = (name, payload) => window.__listeners?.[name]?.({ payload });
