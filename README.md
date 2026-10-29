# DriveTooth

*A holistic tooth for drives.*

Password-gated, in-place encryption for USB and external drives. Every file inside the
chosen folder is rewritten as an opaque blob under `.drivetooth/`, and the folder tree
itself is removed until you unlock the drive inside the app. Nothing is uploaded, nothing
phones home, and there is no account: the whole program is one desktop app and one folder
on the drive.

## What it is not

No user-level application can make macOS or Windows ask for a password *before* a drive
opens — that decision belongs to the operating system. What DriveTooth does instead is
make the question moot: a locked drive shows only `.drivetooth/` full of identically named
hex blobs, so opening it in Finder or Explorer reveals nothing readable. Files become
readable only after you type the password inside DriveTooth.

## Run it

```bash
npm install
npm run dev          # Tauri dev window (macOS / Windows / Linux)
npm run build        # distributable bundle
npm run test:engine  # cargo test --no-default-features: the whole engine, no webview
```

The Rust core is one crate with an optional `gui` feature. `cargo test` covers the engine
and the command surface; `cargo test --no-default-features` proves the encryption, volume
and operation layers compile and pass with no Tauri dependency at all.

`src-tauri/examples/dt_pass.rs` is the same engine without a window — create, lock, unlock a
volume from a terminal, which is how a drive that will not open in the GUI gets diagnosed. It
takes the password as an argument, so it is for a machine you own:

```bash
cargo run --manifest-path src-tauri/Cargo.toml --no-default-features \
  --example dt_pass -- /Volumes/USB-STICK "password"
```

Pass `unlock` in place of the scope to rebuild a locked volume instead of sealing it.

The taskbar/Dock icon is the logo padded into the macOS icon grid, so it is never two commands
away from a rebuild:

```bash
swift scripts/app-icon.swift && npx tauri icon assets/app-icon.png
```

`docs/index.html` is the project's landing page — one self-contained file, no build step, with
the same palette as the app. On GitHub Pages, point the site at `main` / `docs`, and it serves at
`https://<owner>.github.io/drivetooth/`. Every download and source link is built from the `REPO`
constant at the bottom of that file, so a fork changes one line.

## Publishing a release

The download buttons on the landing page point at `v0.1.0` release assets with fixed names
(`DriveTooth_0.1.0_universal.dmg`, `DriveTooth_0.1.0_x64-setup.exe`,
`drivetooth_0.1.0_amd64.deb`). `.github/workflows/release.yml` builds exactly those on a tag push:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

The workflow runs the engine tests, then publishes a *draft* release per platform — check the
three assets landed before pressing publish. Bumping the version means editing it in
`src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`, `package.json`, and the `data-suffix`
attributes in `docs/index.html`.

## How a vault is laid out

```
/Volumes/USB-STICK/
├── .drivetooth/
│   ├── volume.json          # KDF params, verifier, wrapped volume key, state, scope
│   ├── manifest.dt          # encrypted record list — the single commit point
│   ├── journal.dt           # {op, phase} while a pass is in flight
│   └── blobs/<16-byte id>.dtc
└── secret/                  # exists only while unlocked
```

- **Key hierarchy.** Argon2id turns the password into a key-wrapping key, calibrated to the
  machine (about a second by default — `KDF_TARGET_MS`; changing the password on an older vault
  raises it to that floor). A random 32-byte volume key is wrapped with it. HKDF
  derives separate domain keys for the manifest, for name encryption, and per record id for
  content. Changing the password re-wraps those 32 bytes and moves no ciphertext.
- **Envelope.** AES-256-GCM over 1 MiB chunks. The 68-byte header is the AAD for every
  chunk, and each chunk nonce is bound to its position and the record id, so truncation,
  reordering, and copying a blob to another name all fail authentication.
- **Names.** Relative paths are encrypted with their own key and bound to the record id,
  size and kind, so a locked drive leaks neither names nor folder structure.

## Why unplugging is survivable

Every mutating operation runs in two phases. Phase one creates the new copies — blobs, or
restored files — and can be cancelled and rolled back at any point. Only after every new
copy has been read back and authenticated does phase two delete the old one, and the
manifest write is the commit. From that moment the pass cannot be cancelled; if the drive
is pulled, the journal marker and the manifest say exactly which side of the commit point
the volume is on, and **Recover** finishes or undoes the pass. Recovery trusts nothing it
cannot verify: a blob is only treated as good once its tag checks out, so it never deletes
readable data on a guess.

Read-only mounts, missing scope folders, and a lost manifest on a genuinely locked drive
all stop with an explanation rather than a repair that could cost data.

## Interface

A single window, no login, no telemetry:

- **Drives** (left) — every mounted volume, its filesystem, free space and vault state,
  with the full mount path as the tooltip. The row glyph is a padlock once a vault exists —
  closed while sealed, open while the key is in this session — and an ordinary drive keeps the
  drive glyph. Re-read every five seconds while the window is in
  the foreground, never during a pass; a refresh that finds nothing changed only updates the
  numbers, so the folder tree you opened and the password you are typing are not wiped.
- **Light and dark** — the switch in the brand row follows the system until you touch it, then
  your choice is stored in `localStorage`. `dist/theme.js` applies it before the shell paints so
  there is no white flash, and it is loaded by `src` rather than inline because the app's CSP is
  `default-src 'self'` with no script exception. Every colour the themes differ on is a token.
- **Drive space** — total, used, free, and how much of it is ciphertext. Once the drive's
  contents are visible, the used region is split into the same content families the tiles use.
- **Contents, on the first click** — clicking a drive answers "what is on it?" with no further
  button: an unlocked or plain drive is censused from the filesystem itself, and a locked drive
  whose key is still in this session is censused from its manifest. Tiles group the files by
  content family with counts and sizes, newest files first, then the paths.
- **The gate** — a locked drive with no key in this session shows nothing about itself: not its
  label, key derivation, blob count or names, because those live in the vault and the app will
  not read them before you prove the password. The pane is the password field, and it takes
  focus. Plugging such a drive in is itself an event: a background thread notices the sealed
  volume and raises the window, once per insertion.
- **Action tabs, one click each** — the drive's actions (set up, unlock, lock, recover, change
  password, remove the vault) sit in a strip under the summary, and a tab opens its card in a
  sheet over the page rather than stacking another card on it. Cards are built when their tab is
  opened, so the file browser is not walked for a pane nobody looks at. Set up and lock carry a
  file browser over the drive as it physically stands: tick a folder to take it and everything
  under it, or tick single files, and anything left unticked stays a plain file. The tick list is
  stored in the vault, so a later lock starts from what you chose last time. A locked drive offers
  no browsing at all, because there is nothing there to show. Erase is offered only while
  unlocked, so a mistyped confirmation cannot destroy ciphertext.
- **Progress** — phase, files, bytes, rate, ETA, and a cancel button that disables itself
  once the pass is past the point of no return.
- **Activity** — what happened, locally, in this window. It is a tab too: the log element moves
  into the sheet and back, so opening it never rebuilds or trims the history.

## Platform notes

Built for the drives people actually carry: exFAT and FAT32 sticks, NTFS, HFS+ and APFS.
Only file contents, names and mtimes are preserved — no extended attributes, ACLs,
resource forks or hard links, because the common removable formats do not have them.
Permissions are restored as the readable/writable pair the filesystem supports. Windows
support uses no `windows` crate: the two kernel32 calls needed are declared by hand.

The operating system's own bookkeeping on a volume — `.fseventsd`, the Spotlight and Trash
folders, `._*` AppleDouble metadata, `System Volume Information` — is never scanned, moved
or deleted, and does not even appear as a skipped item. Those are live directories the OS
holds open while we work; taking them can leave a stick that the OS afterwards refuses to
mount. DriveTooth also refuses to seal the volume the system runs from, so a mis-click cannot
lock the disk you are sitting on.

## Limits worth knowing

- The password is the only secret. There is no reset, no recovery box, no support channel.
  Lose it and the blobs are ciphertext forever.
- No operating system will prompt for a password before mounting an exFAT stick: that needs
  block-level encryption (FileVault, BitLocker, LUKS), which cannot travel as plain files.
  What DriveTooth does instead is leave nothing to prompt *about* — a locked drive exposes
  only `.drivetooth/blobs/*.dtc`, and the names, folder structure and dates inside them are
  encrypted. What that does **not** hide: each blob starts with a 68-byte plaintext header
  carrying the file's exact length, so the number of files and their sizes are readable by
  anyone who has the drive, as is the date it was locked. The volume's own label and free
  space are filesystem metadata and stay visible too. Padding blobs to coarse size buckets is
  on the roadmap; until then, treat file sizes as public.
- A locked drive resists theft and loss; it does not resist a running, logged-in machine
  with your key in memory. The session key is cleared on lock and stops being accepted
  after 15 minutes idle, when it asks for the password again.
- Filenames are visible while unlocked, because that is what an unlocked drive is for.
- This is a v0.1 personal-security tool: the crypto is standard primitives composed
  carefully and covered by 84 tests, and it has had no external audit.
- There is no `LICENSE` file. The repository is public, so anyone can read it, but that is not
  the same as an open-source grant: no one has the right to redistribute or fork it. Landing-page
  copy is worded to match — if that changes, add `LICENSE` and restore the two claims.
