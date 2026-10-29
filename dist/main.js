/* DriveTooth front end. No bundler, no framework: this file is loaded as-is by the
   webview and talks to Rust through the global Tauri API.

   Field naming: OpRequest is a plain serde enum, so its variant fields keep their Rust
   spelling (password_again, kdf_target_ms). Only the top-level command arguments are
   managed by Tauri, and those are all single words. */

const tauri = window.__TAURI__;
if (!tauri?.core) {
  document.body.innerHTML =
    '<p style="padding:24px;font-family:monospace">This page must run inside the DriveTooth desktop app.</p>';
  throw new Error("tauri api missing");
}

const { invoke } = tauri.core;
const { listen } = tauri.event;

const els = {
  driveList: document.getElementById("drive-list"),
  driveCount: document.getElementById("drives-count"),
  drivesEmpty: document.getElementById("drives-empty"),
  detailHeading: document.getElementById("detail-heading"),
  detailSub: document.getElementById("detail-sub"),
  detailState: document.getElementById("detail-state"),
  detailBody: document.getElementById("detail-body"),
  spaceCard: document.getElementById("space-card"),
  spaceStats: document.getElementById("space-stats"),
  spaceBar: document.getElementById("space-bar"),
  spaceLegend: document.getElementById("space-legend"),
  contentsCard: document.getElementById("contents-card"),
  contentsTitle: document.getElementById("contents-title"),
  contentsMeta: document.getElementById("contents-meta"),
  recentCaption: document.getElementById("recent-caption"),
  pathsCaption: document.getElementById("paths-caption"),
  kindTiles: document.getElementById("kind-tiles"),
  recentList: document.getElementById("recent-list"),
  pathList: document.getElementById("path-list"),
  progress: document.getElementById("progress-panel"),
  progressOp: document.getElementById("progress-op"),
  progressPhase: document.getElementById("progress-phase"),
  progressMetrics: document.getElementById("progress-metrics"),
  progressFill: document.getElementById("progress-fill"),
  progressCurrent: document.getElementById("progress-current"),
  cancel: document.getElementById("cancel-op"),
  log: document.getElementById("log"),
  logHome: document.getElementById("log-home"),
  activityCard: document.getElementById("activity-card"),
  sheet: document.getElementById("action-sheet"),
  sheetBody: document.getElementById("sheet-body"),
  sheetClose: document.getElementById("sheet-close"),
  themeToggle: document.getElementById("theme-toggle"),
};

const state = {
  mounts: [],
  selected: null,
  report: null,
  sig: "",
  sigMount: null,
  busy: false,
  preview: null,
};

/* ---------- formatting and tiny dom helpers ---------- */

function bytes(n) {
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log2(n) / 10));
  const value = n / 2 ** (10 * i);
  return `${value >= 100 || i === 0 ? Math.round(value) : value.toFixed(1)} ${units[i]}`;
}

function duration(secs) {
  if (!Number.isFinite(secs) || secs <= 0) return "--";
  if (secs < 60) return `${Math.round(secs)}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  return `${(secs / 3600).toFixed(1)}h`;
}

function clock() {
  return new Date().toTimeString().slice(0, 8);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function group(className, children) {
  const node = el("div", className);
  for (const child of children) if (child) node.append(child);
  return node;
}

/* Twelve hand-written paths; an icon library would be a build step for no benefit. */
const ICONS = {
  drive: ["M3 8h18v9H3z", "M7 12.5h.01", "M11 12.5h6"],
  /* One padlock drawn twice: same body, same keyhole, and only the hoop differs. A closed
     shackle that reaches the body on both sides is locked; a hoop whose left side stops in
     the air is unlocked. Anything else would be two unrelated objects. */
  lock: ["M6.5 10.5h11v9.5h-11z", "M9 10.5V7.6a3 3 0 0 1 6 0v2.9", "M12 13.8v2.8"],
  unlock: ["M6.5 10.5h11v9.5h-11z", "M9 7.6a3 3 0 0 1 6 0v2.9", "M12 13.8v2.8"],
  moon: ["M20 14.6A8.6 8.6 0 0 1 9.4 4 8.6 8.6 0 1 0 20 14.6z"],
  sun: [
    "M12 7.6a4.4 4.4 0 1 0 0 8.8 4.4 4.4 0 0 0 0-8.8z",
    "M12 2.4v2.2",
    "M12 19.4v2.2",
    "M2.4 12h2.2",
    "M19.4 12h2.2",
    "M5.1 5.1l1.6 1.6",
    "M17.3 17.3l1.6 1.6",
    "M18.9 5.1l-1.6 1.6",
    "M6.7 17.3l-1.6 1.6",
  ],
  documents: ["M7 3h7l4 4v14H7z", "M13.8 3v4.2H18"],
  images: ["M4 5h16v14H4z", "M15.5 5h-13v9", "M8.5 10.5a1.4 1.4 0 1 0 0-2.8 1.4 1.4 0 0 0 0 2.8z", "M4.5 17l4.5-4.5 3.5 3.5 3-2.5 4 4"],
  videos: ["M4 5h16v14H4z", "M10.5 8.8l5.6 3.2-5.6 3.2z"],
  audio: ["M9 17V5.4l10-1.9V15", "M9 17.4a2.4 2.4 0 1 1-4.8 0 2.4 2.4 0 0 1 4.8 0z", "M19 15.4a2.4 2.4 0 1 1-4.8 0 2.4 2.4 0 0 1 4.8 0z"],
  archives: ["M4 8h16v12H4z", "M4 8l2.6-4h10.8L20 8", "M9.5 12.5h5"],
  other: ["M5 5h6v6H5z", "M14 8h5v5h-5z", "M6 14h5v5H6z"],
};

const KINDS = {
  documents: "Documents",
  images: "Images",
  videos: "Videos",
  audio: "Audio",
  archives: "Archives",
  other: "Other",
};

function icon(name, extraClass) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.6");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", `svg ${extraClass ?? ""}`.trim());
  for (const d of ICONS[name] ?? ICONS.other) {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}

function logLine(kind, msg) {
  const li = el("li", kind);
  li.append(el("time", null, clock()), el("span", "msg", msg));
  els.log.prepend(li);
  while (els.log.children.length > 200) els.log.lastChild.remove();
}

function showError(node, text) {
  node.className = "err";
  node.textContent = text;
}

/* ---------- password strength ---------- */

/* Entropy from the character classes actually present, which is the most a local meter can
   claim without a wordlist. The real cost is Argon2id's, not ours. */
function strength(pw) {
  if (!pw) return { bits: 0, tier: 0 };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  const bits = pw.length * Math.log2(pool || 1);
  const tier = bits >= 90 ? 4 : bits >= 60 ? 3 : bits >= 40 ? 2 : 1;
  return { bits: Math.round(bits), tier };
}

function strengthMeter() {
  const bars = group("meter", [el("i"), el("i"), el("i"), el("i")]);
  const label = el("span", "hint");
  const paint = (pw) => {
    const { bits, tier } = strength(pw);
    bars.className = `meter s${tier}`;
    [...bars.children].forEach((bar, i) => bar.classList.toggle("on", i < tier));
    label.textContent = pw
      ? `${bits} bits — ${["too short", "weak", "fair", "good", "strong"][tier]}`
      : "pick something you will still remember in a year";
  };
  paint("");
  return { node: bars, label, paint };
}

function field(labelText, type, value) {
  const input = el("input");
  input.type = type;
  input.value = value ?? "";
  if (type === "password") {
    input.autocomplete = "new-password";
    input.spellcheck = false;
  }
  return { node: wrapLabel(labelText, input), input };
}

/* A field is a <label> so clicking the caption focuses the input. */
function wrapLabel(labelText, input) {
  const label = el("label", "field");
  label.append(el("span", null, labelText), input);
  return label;
}

function checkbox(text, checked) {
  const box = el("input");
  box.type = "checkbox";
  box.checked = !!checked;
  const label = el("label", "check");
  label.append(box, el("span", null, text));
  return { node: label, box };
}

function card(title, body) {
  const node = el("section", "card");
  const head = el("header");
  head.append(el("h3", null, title));
  node.append(head);
  node.append(group("body", body));
  return node;
}

function facts(pairs) {
  const dl = el("dl", "facts");
  for (const [key, value] of pairs) {
    if (value === undefined || value === null || value === "") continue;
    dl.append(el("dt", null, key), el("dd", null, String(value)));
  }
  return dl;
}

/* ---------- action tabs ---------- */

/* What a drive can be asked to do sits behind one click each: the pane paints a strip of tabs
   and a tab opens its card in a sheet. Cards are built when they are opened, not before,
   because two of them walk the drive's folder tree and the drive may have changed since the
   strip was drawn. */
function tabStrip(items) {
  const nav = el("nav", "tabs");
  for (const item of items) {
    const btn = el("button", "tab");
    btn.type = "button";
    btn.append(el("span", "tab-name", item.label));
    if (item.hint) btn.append(el("span", "tab-hint", item.hint));
    btn.addEventListener("click", () => openSheet(item));
    nav.append(btn);
  }
  return nav;
}

function openSheet(item) {
  settleSheet();
  els.sheetBody.append(item.build());
  els.sheet.showModal();
}

function closeSheet() {
  if (!els.sheet.open) return;
  els.sheet.close();
  settleSheet();
}

/* The Activity tab hosts the live log, so closing the sheet has to put that element back
   rather than rebuild it. Every path out of the sheet runs this, including the one where
   Escape closed the dialog on its own — opening a sheet settles the previous one first. */
function settleSheet() {
  els.sheetBody.replaceChildren();
  els.logHome.append(els.activityCard);
}

els.sheetClose.addEventListener("click", closeSheet);
els.sheet.addEventListener("cancel", () => setTimeout(settleSheet, 0));

/* ---------- drive list ---------- */

const STATE_TEXT = {
  locked: "locked",
  unlocked: "unlocked",
  recovering: "needs recovery",
  plain: "not encrypted",
  error: "unreadable vault",
};

/* A padlock in the list says what the row is for; a drive glyph on an ordinary volume says
   there is nothing to open. */
const DRIVE_GLYPH = {
  locked: "lock",
  unlocked: "unlock",
  recovering: "lock",
  error: "drive",
  plain: "drive",
};

function stateOf(report) {
  if (!report?.initialised) return "plain";
  if (report.error) return "error";
  return report.meta?.state ?? "plain";
}

async function rescan(keepSelection = true) {
  if (state.busy) return;
  try {
    state.mounts = await invoke("list_mounts");
  } catch (err) {
    logLine("bad", `rescan failed: ${err}`);
    return;
  }
  if (!keepSelection || !state.mounts.some((m) => m.path === state.selected)) {
    state.selected = null;
  }
  renderDrives();
  if (!state.selected) return clearDetail();

  let report;
  try {
    report = await invoke("inspect_volume", { mount: state.selected });
  } catch (err) {
    logLine("bad", `inspect failed: ${err}`);
    return;
  }
  const mount = state.mounts.find((m) => m.path === state.selected);
  const same = state.sig === signature(report);
  state.report = report;
  if (same && state.sigMount === report.mount) {
    // Nothing changed about the vault, so only the numbers are refreshed. Rebuilding the
    // pane every few seconds would wipe the form being typed into and the folders opened.
    renderSpace(mount, report);
    return;
  }
  await showDrive(state.selected);
}

/* What the detail pane is built from: any change here means the cards must be rebuilt.
   Free space is deliberately absent, since it moves constantly. */
function signature(report) {
  if (!report) return "";
  return [
    report.mount,
    report.initialised,
    stateOf(report),
    report.blobs,
    report.error ?? "",
    report.meta?.updated_ms ?? 0,
    report.session_ready,
    report.journal ? report.journal.op : "",
  ].join("|");
}

function renderDrives() {
  els.driveList.replaceChildren();
  els.driveCount.textContent = String(state.mounts.length);
  els.drivesEmpty.classList.toggle("hidden", state.mounts.length > 0);

  for (const mount of state.mounts) {
    const li = el("li");
    li.dataset.path = mount.path;
    li.setAttribute("role", "option");
    li.setAttribute("aria-selected", String(mount.path === state.selected));
    li.tabIndex = 0;

    const vault = mount.drive_tooth;
    const st = vault ? vault.state : "plain";
    li.title = mount.path;
    li.append(icon(DRIVE_GLYPH[st] ?? "drive", `state-${st}`), el("span", "drive-name", mount.name));

    const bits = [];
    if (mount.is_boot) bits.push("system");
    if (mount.removable) bits.push("removable");
    if (mount.fs_type) bits.push(mount.fs_type);
    if (!mount.writable) bits.push(mount.read_only_mount ? "read-only" : "no write access");
    bits.push(`${bytes(mount.free_bytes)} free of ${bytes(mount.total_bytes)}`);
    // The scope is a folder name from inside the vault, so it stays out of the list: the row
    // is drawn for every drive, including one nobody has authenticated to yet.
    li.append(
      group("drive-meta", [el("span", `badge ${st}`, STATE_TEXT[st] ?? st), el("span", "drive-sub", bits.join(" · "))]),
    );

    li.addEventListener("click", () => select(mount.path));
    li.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        select(mount.path);
      }
    });
    els.driveList.append(li);
  }
}

async function select(path) {
  state.selected = path;
  renderDrives();
  await showDrive(path);
}

function clearDetail() {
  closeSheet();
  state.report = null;
  state.sig = "";
  state.sigMount = null;
  els.detailHeading.textContent = "No drive selected";
  els.detailSub.textContent = "Pick a drive on the left.";
  els.detailState.textContent = "";
  els.detailState.className = "badge";
  els.spaceCard.classList.add("hidden");
  els.contentsCard.classList.add("hidden");
  els.detailBody.replaceChildren();
}

async function showDrive(path) {
  state.preview = null;
  let report;
  try {
    report = await invoke("inspect_volume", { mount: path });
  } catch (err) {
    logLine("bad", `inspect failed: ${err}`);
    return;
  }
  state.report = report;
  state.sig = signature(report);
  state.sigMount = report.mount;
  const mount = state.mounts.find((m) => m.path === path);
  els.detailHeading.textContent = mount?.name ?? path;
  const st = stateOf(report);
  els.detailState.textContent = STATE_TEXT[st] ?? st;
  els.detailState.className = `badge ${st}`;
  const bits = [];
  if (mount?.fs_type) bits.push(mount.fs_type);
  if (mount && !mount.writable) bits.push(mount.read_only_mount ? "read-only" : "no write access");
  if (report.meta && !report.sealed) bits.push(`scope ${report.meta.scope}`);
  els.detailSub.textContent = [report.mount, ...bits].join(" · ");
  renderSpace(mount, report);
  renderContents();
  els.detailBody.replaceChildren(...renderDetail(report, mount, st));
  if (report.sealed) els.detailBody.querySelector("input[type=password]")?.focus();
  // The census is the slow part of a first click — a big drive is a full walk — so the pane
  // is already on screen by the time it lands, and the two read-only panels fill in.
  await loadContents(report);
  if (state.selected !== report.mount) return;
  renderSpace(mount, report);
  renderContents();
}

/* The census shown on first click, from whichever source is allowed to answer. A sealed drive
   has no answer: its names are ciphertext, and the only way to read them is the key. */
async function loadContents(report) {
  const st = stateOf(report);
  let census = null;
  try {
    if (st === "unlocked" || st === "plain") {
      census = await invoke("describe_tree", { mount: report.mount });
    } else if (st === "locked" && report.session_ready) {
      census = await invoke("describe_contents", { mount: report.mount });
    }
  } catch (err) {
    logLine("note", `could not list ${report.mount}: ${err}`);
  }
  // A drive that was unplugged, or clicked past, while the walk ran must not paint over the
  // drive the user is now looking at.
  if (state.selected === report.mount) state.preview = census;
}

/* ---------- drive space ---------- */

function renderSpace(mount, report) {
  if (!mount || !mount.total_bytes) return void els.spaceCard.classList.add("hidden");
  els.spaceCard.classList.remove("hidden");

  const total = mount.total_bytes;
  const free = Math.min(mount.free_bytes ?? 0, total);
  const used = Math.max(0, total - free);
  const encrypted = report?.blob_bytes ?? 0;

  const stats = [["Total", total], ["Used", used], ["Free", free]];
  if (encrypted) stats.push(["Encrypted", encrypted]);
  els.spaceStats.replaceChildren(
    ...stats.map(([label, value]) =>
      group("stat", [el("span", null, label), el("span", null, bytes(value))])
    )
  );

  /* The used region is coloured by content family, which is only an honest thing to claim
     about a drive whose files are readable: those are the sizes actually on disk. A sealed
     drive keeps its one encrypted block, because ciphertext volume is the only fact it has. */
  const segments = [];
  if (state.preview?.source === "tree") {
    const order = Object.keys(KINDS);
    for (const kind of (state.preview.kinds ?? []).slice().sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind))) {
      segments.push({ cls: kind.kind, label: KINDS[kind.kind] ?? kind.kind, size: kind.bytes });
    }
  } else if (encrypted) {
    segments.push({ cls: "enc", label: "encrypted blobs", size: encrypted });
  }
  const named = segments.reduce((sum, s) => sum + s.size, 0);
  if (used > named) segments.push({ cls: "used", label: "other used", size: used - named });
  segments.push({ cls: "free", label: "free", size: free });

  els.spaceBar.replaceChildren(
    ...segments.map((s) => {
      const pct = (s.size / total) * 100;
      const node = el("span", `seg ${s.cls}`, pct >= 8 ? bytes(s.size) : "");
      node.style.flex = `${pct} 0 0%`;
      node.title = `${s.label}: ${bytes(s.size)}`;
      return node;
    })
  );

  els.spaceLegend.replaceChildren(
    ...segments.map((s) => {
      const node = el("span");
      node.append(el("i", s.cls), document.createTextNode(`${s.label} ${bytes(s.size)}`));
      return node;
    })
  );
}

/* ---------- what the vault holds ---------- */

function renderContents() {
  const preview = state.preview;
  if (!preview) {
    els.contentsCard.classList.add("hidden");
    // Revealed names must not linger in the DOM once the drive they belong to is off screen.
    els.kindTiles.replaceChildren();
    els.recentList.replaceChildren();
    els.pathList.replaceChildren();
    return;
  }
  els.contentsCard.classList.remove("hidden");
  const sealed = preview.source === "vault";

  els.contentsTitle.textContent = sealed ? "Sealed contents" : "Contents";
  els.contentsMeta.textContent = `${count(preview.files)} file(s) in ${count(preview.dirs)} folder(s) · ${bytes(
    preview.plainBytes
  )} ${sealed ? "of plaintext behind the password · nothing was written" : "as this computer sees the drive"}`;
  els.recentCaption.textContent = sealed ? "Newest inside the vault" : "Newest files";
  els.pathsCaption.textContent = sealed ? "Sealed paths" : "Paths";

  const order = Object.keys(KINDS);
  const kinds = (preview.kinds ?? []).slice().sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind));
  els.kindTiles.replaceChildren(
    ...kinds.map((k) => {
      const tile = el("div", `tile ${k.kind}`);
      tile.append(group("glyph", [icon(k.kind)]));
      tile.append(el("p", "tile-name", KINDS[k.kind] ?? k.kind));
      tile.append(el("p", "tile-files", `${count(k.files)} file(s)`));
      tile.append(el("p", "tile-bytes", bytes(k.bytes)));
      return tile;
    })
  );

  els.recentList.replaceChildren(
    ...(preview.recent ?? []).map((entry) => {
      const li = el("li");
      const name = entry.path.split("/").pop() || entry.path;
      const ext = name.includes(".") ? name.split(".").pop() : name;
      li.append(el("span", `mono ${entry.kind ?? "other"}`, ext.slice(0, 3)));
      const col = el("div");
      col.append(el("p", "recent-name", name), el("p", "recent-date", new Date(entry.mtimeMs).toLocaleDateString()));
      li.append(col, el("span", "recent-size", bytes(entry.bytes)));
      return li;
    })
  );

  const paths = preview.paths ?? [];
  els.pathList.replaceChildren(...paths.map((p) => el("li", null, p)));
  if (preview.truncated) {
    els.pathList.append(el("li", null, `… ${count(Number(preview.files) - paths.length)} more`));
  }
}

function count(n) {
  return Number(n ?? 0).toLocaleString();
}

/* ---------- file browser ---------- */

/* The drive exactly as it physically stands, one folder at a time, with a tick box on every
   entry. A locked drive has no such view: its files are blobs and its folders are pruned.
   Ticking a folder selects its whole subtree with one path, which is what the engine's
   `select` matcher understands. */
function fileBrowser(mount, pick) {
  const wrap = el("div", "browser");
  const tree = el("ul", "tree");
  const summary = el("p", "hint browser-summary");
  wrap.append(tree, summary);
  const boxes = new Map();

  const covered = (rel) => [...pick].some((p) => rel === p || rel.startsWith(`${p}/`));
  const pickedBelow = (rel) => [...pick].some((p) => p.startsWith(`${rel}/`));

  function paintSummary() {
    summary.textContent =
      pick.size === 0
        ? "Nothing ticked, so everything on the drive is encrypted."
        : `${pick.size} item(s) ticked. A folder covers everything inside it; anything else stays a plain file.`;
  }

  function repaint() {
    for (const [rel, box] of boxes) {
      box.checked = covered(rel);
      box.indeterminate = !box.checked && pickedBelow(rel);
      box.disabled = covered(rel) && [...pick].some((p) => p !== rel && rel.startsWith(`${p}/`));
    }
  }

  function build(entry) {
    const li = el("li", `node ${entry.dir ? "dir" : "file"}`);
    li.dataset.rel = entry.rel;

    if (entry.dir) {
      const twist = el("button", "twist");
      twist.type = "button";
      twist.setAttribute("aria-label", `Show what is inside ${entry.name}`);
      twist.addEventListener("click", () => expand(entry, li, twist));
      li.append(twist);
    } else {
      li.append(el("span", "twist leaf"));
    }

    const name = el("span", "node-name", entry.name);
    const box = el("input");
    box.type = "checkbox";
    boxes.set(entry.rel, box);
    const label = el("label", "pick");
    label.append(box, name);
    box.addEventListener("change", () => {
      if (box.checked) {
        for (const p of [...pick]) {
          if (p === entry.rel || p.startsWith(`${entry.rel}/`)) pick.delete(p);
        }
        pick.add(entry.rel);
      } else {
        pick.delete(entry.rel);
      }
      repaint();
      paintSummary();
    });
    li.append(label);
    li.append(el("span", "node-meta", entry.dir ? "" : bytes(entry.bytes)));
    return li;
  }

  async function expand(entry, li, twist) {
    const kids = li.querySelector(":scope > ul");
    if (kids) {
      kids.classList.toggle("hidden");
      li.classList.toggle("open", !kids.classList.contains("hidden"));
      return;
    }
    twist.classList.add("busy");
    try {
      li.append(await branch(entry.rel));
      li.classList.add("open");
    } catch (err) {
      showError(summary, String(err));
    } finally {
      twist.classList.remove("busy");
    }
  }

  async function branch(path) {
    const listing = await invoke("list_dir", { mount, path });
    const ul = el("ul", "tree");
    for (const entry of listing.entries) ul.append(build(entry));
    if (!listing.entries.length) {
      ul.append(el("li", "node empty", "empty folder"));
    }
    if (listing.truncated) {
      ul.append(el("li", "node more", "folder holds more than 600 items — only the first are shown"));
    }
    // Rows born after a tick would otherwise render unchecked inside a checked folder.
    repaint();
    return ul;
  }

  const refresh = async () => {
    tree.replaceChildren();
    try {
      const root = await branch("");
      for (const child of [...root.children]) tree.append(child);
    } catch (err) {
      tree.append(el("li", "node empty", String(err)));
    }
    repaint();
    paintSummary();
  };

  refresh();
  return wrap;
}

/* ---------- panes ---------- */

function renderDetail(report, mount, st) {
  const driveFacts = [];
  const meta = report.meta;
  if (meta) {
    driveFacts.push(
      ["label", meta.label],
      ["format", `v${meta.format}`],
      ["ciphertext", `${count(report.blobs)} blob(s) · ${bytes(report.blob_bytes)}`],
      ["key derivation", `argon2id ${meta.kdf.m_kib} KiB, t=${meta.kdf.t}, p=${meta.kdf.p}`],
      ["last operation", meta.last_op ? `${meta.last_op} at ${new Date(meta.updated_ms).toLocaleString()}` : undefined]
    );
  }

  const blocks = [];
  if (report.error) {
    blocks.push(
      card("Problem", [
        el("p", "err", report.error),
        el(
          "p",
          "warn",
          "If this drive was mid-operation, run Recovery once you have the password. Never delete .drivetooth while blobs remain."
        ),
      ])
    );
  }

  /* A sealed drive says nothing about itself first: not its label, not its key derivation,
     not how many blobs it holds. The password is what turns the rest of this pane on. */
  if (report.sealed) {
    if (report.journal) {
      blocks.push(
        card("Interrupted operation", [
          el(
            "p",
            "warn",
            `A ${report.journal.op} pass stopped at phase "${report.journal.phase}". Unlock will offer to resolve it first.`
          ),
        ])
      );
    }
    blocks.push(unlockCard(report));
    return blocks;
  }

  if (driveFacts.length) blocks.push(card("Vault", [facts(driveFacts)]));

  if (report.journal) {
    blocks.push(
      card("Interrupted operation", [
        el(
          "p",
          "warn",
          `A ${report.journal.op} pass stopped at phase "${report.journal.phase}" after ${report.journal.files_total} file(s). Resolve it before anything else runs on this drive.`
        ),
      ])
    );
  }

  const actions = [];
  if (st === "plain") {
    actions.push(
      mount && !mount.writable
        ? {
            label: "Set up encryption",
            hint: "this drive is not writable",
            build: () =>
              card("Cannot set up", [el("p", "err", "This drive is not writable, so it cannot hold encrypted files.")]),
          }
        : { label: "Encrypt files", hint: "nothing here is protected yet", build: () => setupCard(report) }
    );
  } else if (st === "recovering") {
    actions.push({ label: "Recover", hint: "an operation stopped mid-way", build: () => recoverCard(report) });
  } else if (st === "locked") {
    actions.push(
      { label: "Unlock", hint: "rebuild the tree in place", build: () => unlockCard(report) },
      { label: "Change password", hint: "instant, no ciphertext moves", build: () => passwordCard(report) },
      { label: "Remove vault", hint: "needs the key first", build: () => eraseCard(report, true) }
    );
  } else if (st === "unlocked") {
    actions.push(
      {
        label: "Lock",
        hint: report.session_ready ? "key is in this session" : "encrypt what you tick",
        build: () => lockCard(report),
      },
      { label: "Change password", hint: "instant, no ciphertext moves", build: () => passwordCard(report) },
      { label: "Remove vault", hint: "deletes .drivetooth only", build: () => eraseCard(report, false) }
    );
  }
  actions.push({ label: "Activity", hint: "everything this app has done", build: () => els.activityCard });
  blocks.push(tabStrip(actions));
  return blocks;
}

function setupCard(report) {
  const label = field("Drive label", "text", "encrypted drive");
  const pw = field("Password", "password");
  const again = field("Repeat password", "password");
  const meter = strengthMeter();
  pw.input.addEventListener("input", () => meter.paint(pw.input.value));

  const verify = checkbox("re-read and authenticate every blob before its plaintext is deleted", true);
  const kdf = field("Password hashing target (ms)", "text", "1000");
  const exclude = field("Never encrypt these names", "text", ".DS_Store, Thumbs.db, desktop.ini");
  const advanced = el("details");
  advanced.append(el("summary", "hint", "Advanced"), group("body", [verify.node, kdf.node, exclude.node]));

  const picks = new Set();
  const browser = fileBrowser(report.mount, picks);
  const status = el(
    "p",
    "hint",
    "Tick what to encrypt. Everything ticked becomes an opaque blob under .drivetooth and its folder tree disappears until you unlock; unticked files stay exactly as they are."
  );

  const submit = el("button", "primary", "Encrypt and lock");
  submit.addEventListener("click", async () => {
    const problems = [];
    if (pw.input.value.length < 8) problems.push("Use at least 8 characters.");
    if (pw.input.value !== again.input.value) problems.push("The two passwords do not match.");
    if (problems.length) return void showError(status, problems.join(" "));

    await runOp(report.mount, {
      kind: "init",
      mount: report.mount,
      scope: "/",
      label: label.input.value.trim() || "encrypted drive",
      password: pw.input.value,
      password_again: pw.input.value,
      options: {
        verify_after_encrypt: verify.box.checked,
        chunk_exp: 20,
        kdf_target_ms: Number(kdf.input.value) || 300,
        exclude: exclude.input.value.split(",").map((s) => s.trim()).filter(Boolean),
        select: [...picks],
      },
    });
    pw.input.value = "";
    again.input.value = "";
    meter.paint("");
  });

  return card("Set up encryption", [
    label.node,
    el("p", "caption", "Files on this drive"),
    browser,
    pw.node,
    group("row", [meter.node, meter.label]),
    again.node,
    advanced,
    status,
    group("actions", [submit]),
  ]);
}

function unlockCard(report) {
  const pw = field("Password", "password");
  const status = el(
    "p",
    "hint",
    report.sealed
      ? "Nothing about this drive is shown until the password is verified. Unlocking rebuilds the tree in place; the key then stays in memory for 15 minutes, so locking again needs no password."
      : "Unlocking rebuilds the tree in place. The key stays in memory for 15 minutes, so locking again needs no password."
  );
  const unlockBtn = el("button", "primary", "Unlock");
  const previewBtn = el("button", "ghost", "Show contents");

  const preview = async () => {
    if (!pw.input.value) return void showError(status, "Enter the password first.");
    previewBtn.disabled = true;
    try {
      state.preview = await invoke("describe_contents", {
        mount: report.mount,
        password: pw.input.value,
      });
      renderSpace(state.mounts.find((m) => m.path === report.mount), report);
      renderContents();
      status.className = "hint";
      status.textContent = `${count(state.preview.files)} file(s) in ${count(state.preview.dirs)} folder(s), ${bytes(
        state.preview.plainBytes
      )} of plaintext. Nothing was written to the drive.`;
      // Only the two read-only panels update: rebuilding this card would wipe the password
      // that was just typed and proved correct.
    } catch (err) {
      showError(status, String(err));
    } finally {
      previewBtn.disabled = false;
    }
  };

  const unlock = async () => {
    if (!pw.input.value) return void showError(status, "Enter the password first.");
    await runOp(report.mount, { kind: "unlock", mount: report.mount, password: pw.input.value });
    pw.input.value = "";
  };

  previewBtn.addEventListener("click", preview);
  unlockBtn.addEventListener("click", unlock);
  pw.input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") unlock();
  });

  const body = [pw.node, status, group("actions", [unlockBtn, previewBtn])];
  return card("Unlock", body);
}

function lockCard(report) {
  const pw = field("Password", "password");
  const picks = new Set(report.meta?.options?.select ?? []);
  const browser = fileBrowser(report.mount, picks);
  const status = el("p", "hint", "Tick what to encrypt. Anything added or changed inside a ticked item is encrypted now.");
  if (report.session_ready) {
    pw.node.classList.add("hidden");
    status.textContent = "The key is still in this session, so locking needs no password.";
  }
  const btn = el("button", "primary", "Encrypt and lock now");
  btn.addEventListener("click", () => {
    const password = report.session_ready ? null : pw.input.value || null;
    if (!report.session_ready && !password) return void showError(status, "Enter the password.");
    runOp(report.mount, {
      kind: "lock",
      mount: report.mount,
      password,
      select: [...picks],
    });
  });
  return card("Lock", [
    pw.node,
    el("p", "caption", "Files on this drive"),
    browser,
    status,
    group("actions", [btn]),
  ]);
}

function recoverCard(report) {
  const pw = field("Password", "password");
  const status = el(
    "p",
    "warn",
    "Recovery reads what is actually on the disk and finishes or undoes the interrupted pass. A blob is only trusted once its authentication tags check out, so it never deletes readable data on a guess."
  );
  const btn = el("button", "primary", "Recover");
  btn.addEventListener("click", () => {
    if (!pw.input.value) return void showError(status, "Enter the password.");
    runOp(report.mount, { kind: "recover", mount: report.mount, password: pw.input.value });
  });
  return card("Recover", [pw.node, status, group("actions", [btn])]);
}

function passwordCard(report) {
  const cur = field("Current password", "password");
  const next = field("New password", "password");
  const again = field("Repeat new password", "password");
  const status = el(
    "p",
    "hint",
    "Only the 32-byte key wrap is rewritten, so no ciphertext moves and this is instant whatever the drive holds."
  );
  const btn = el("button", "ghost", "Change password");
  btn.addEventListener("click", async () => {
    if (next.input.value !== again.input.value) return void showError(status, "The new passwords do not match.");
    if (next.input.value.length < 8) return void showError(status, "Use at least 8 characters.");
    if (!cur.input.value) return void showError(status, "Enter the current password.");
    await runOp(report.mount, {
      kind: "setPassword",
      mount: report.mount,
      current: cur.input.value,
      next: next.input.value,
      next_again: again.input.value,
    });
    cur.input.value = next.input.value = again.input.value = "";
  });
  return card("Change password", [cur.node, next.node, again.node, status, group("actions", [btn])]);
}

function eraseCard(report, locked) {
  const status = el(
    "p",
    "hint",
    locked
      ? "Erase is offered only while the drive is unlocked, so ciphertext can never be destroyed by a mistyped confirmation."
      : "Deletes .drivetooth. The files are already plaintext here, so nothing of yours is removed."
  );
  const agree = checkbox("I understand", false);
  const btn = el("button", "danger", "Remove vault");
  btn.disabled = true;
  agree.box.addEventListener("change", () => {
    btn.disabled = !agree.box.checked;
  });
  btn.addEventListener("click", () => runOp(report.mount, { kind: "erase", mount: report.mount }));
  return card("Remove vault", [status, agree.node, group("actions", [btn])]);
}

/* ---------- operations ---------- */

async function runOp(mount, op) {
  if (state.busy) return void logLine("note", "an operation is already running");
  // The sheet holds a form about a drive that is about to change state; the rebuilt pane will
  // offer it again once the operation lands.
  closeSheet();
  state.busy = true;
  state.selected = mount;
  els.progress.classList.remove("hidden");
  els.progressFill.style.width = "0%";
  els.progressFill.classList.remove("final");
  els.progressOp.textContent = op.kind;
  els.progressPhase.textContent = "starting";
  els.progressMetrics.textContent = "";
  els.progressCurrent.textContent = "";
  els.cancel.disabled = false;

  try {
    const summary = await invoke("run_operation", { op });
    els.progressFill.style.width = "100%";
    els.progressFill.classList.add("final");
    els.progressPhase.textContent = "done";
    logLine("ok", summary.message);
    if (summary.skipped?.length) {
      const head = summary.skipped.slice(0, 3).map((s) => `${s.path} (${s.reason})`).join(", ");
      logLine("note", `${summary.skipped.length} item(s) left exactly as they were: ${head}`);
    }
    if (summary.unrecoverable?.length) {
      const head = summary.unrecoverable.map((u) => u.path ?? u.record_id).join(", ");
      logLine("bad", `${summary.unrecoverable.length} record(s) could not be reconciled: ${head}`);
    }
    state.preview = null;
  } catch (err) {
    logLine("bad", `${op.kind} stopped: ${err}`);
  } finally {
    state.busy = false;
    els.cancel.disabled = true;
    setTimeout(() => els.progress.classList.add("hidden"), 1400);
    await rescan();
  }
}

els.cancel.addEventListener("click", async () => {
  if (!(await invoke("cancel_operation"))) return;
  els.cancel.disabled = true;
  els.progressPhase.textContent = "cancelling";
});

listen("dt-progress", ({ payload }) => {
  const pct = payload.bytes_total > 0 ? (payload.bytes_done / payload.bytes_total) * 100 : 0;
  els.progressFill.style.width = `${Math.min(100, pct).toFixed(1)}%`;
  els.progressOp.textContent = payload.op;
  const final = payload.phase === "removing plaintext" || payload.phase === "committing";
  els.progressPhase.textContent = final ? `${payload.phase} — cannot be cancelled` : payload.phase;
  els.progressMetrics.textContent = [
    `${payload.files_done}/${payload.files_total} files`,
    `${bytes(payload.bytes_done)} / ${bytes(payload.bytes_total)}`,
    payload.rate_bps > 0 ? `${bytes(payload.rate_bps)}/s` : "",
    payload.eta_secs ? `eta ${duration(payload.eta_secs)}` : "",
  ]
    .filter(Boolean)
    .join(" · ");
  els.progressCurrent.textContent = payload.message || payload.current || "";
});

/* A sealed drive being plugged in is the moment to ask for the password, not the moment to
   wait until someone goes looking for the drive. The back end emits this once per insertion. */
listen("dt-plug", ({ payload }) => {
  if (state.busy) return;
  logLine("note", `${payload.name} was plugged in locked`);
  surface();
  select(payload.mount);
});

async function surface() {
  const win = tauri.window?.getCurrentWindow?.();
  if (!win) return;
  try {
    await win.unminimize();
    await win.show();
    await win.setFocus();
  } catch {
    // Denied by the window layer is still a prompt the user can see on next focus.
  }
}

/* Light or dark is a preference with nothing secret in it, so it lives in localStorage and
   theme.js has already applied it before this runs. The glyph shows what the click gives you. */
const THEME = window.drivetoothTheme;

function paintThemeToggle() {
  const dark = document.documentElement.dataset.theme === "dark";
  els.themeToggle.replaceChildren(icon(dark ? "sun" : "moon"));
  els.themeToggle.setAttribute("aria-pressed", String(dark));
  els.themeToggle.title = dark ? "Switch to the light theme" : "Switch to the dark theme";
}

els.themeToggle.addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  THEME.paintTheme(next);
  try {
    localStorage.setItem(THEME.THEME_KEY, next);
  } catch {
    // Storage refused: the theme still changes for this run.
  }
  paintThemeToggle();
});

paintThemeToggle();

document.getElementById("refresh-drives").addEventListener("click", () => rescan(false));document.getElementById("clear-log").addEventListener("click", () => els.log.replaceChildren());

/* A drive can be unplugged at any moment, so the list is re-read while the window is in
   the foreground; it never polls over a running operation. */
setInterval(() => {
  if (!state.busy && document.visibilityState === "visible") rescan();
}, 5000);

logLine("note", "ready");
await rescan(false);
