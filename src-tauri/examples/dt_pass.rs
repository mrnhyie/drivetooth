//! Headless driver for debugging: run a real create + scan + lock pass against a mounted
//! volume, with no webview involved.
//!
//! cargo run --manifest-path src-tauri/Cargo.toml --no-default-features --example dt_pass \
//!   -- /Volumes/DTTEST pw [folder-relative-scope]

use std::path::Path;

use drivetooth_lib::ops::lock::lock;
use drivetooth_lib::ops::scan::scan;
use drivetooth_lib::ops::Runner;
use drivetooth_lib::volume::{Vault, VaultOptions};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(mount) = args.first() else {
        eprintln!("usage: dt_pass <mount> <password> [scope]");
        std::process::exit(2);
    };
    let Some(password) = args.get(1) else {
        eprintln!("usage: dt_pass <mount> <password> [scope]");
        std::process::exit(2);
    };
    let scope = args.get(2).map(|s| s.as_str()).unwrap_or("/");
    let path = Path::new(mount);

    let runner = Runner::new(Box::new(|p| {
        eprintln!("{} {} {}/{} files {}", p.op, p.phase, p.files_done, p.files_total, p.message);
    }));

    if scope == "unlock" {
        let mut vault = Vault::detect(path)
            .expect("detect")
            .expect("no vault on this volume");
        let key = vault.key_for(password).expect("wrong password");
        let summary = drivetooth_lib::ops::unlock::unlock(&mut vault, &key, &runner).expect("unlock");
        println!("unlocked: {} file(s), {} dir(s)", summary.files, summary.dirs);
        for s in &summary.skipped {
            println!("  skipped {} ({})", s.path, s.reason);
        }
        return;
    }

    let (mut vault, key) = Vault::create(path, scope, "debug", password, password, VaultOptions {
        kdf_target_ms: 100,
        ..Default::default()
    })
    .expect("create");
    let plan = scan(path, &vault.meta.scope.clone(), &vault.meta.options.clone(), &runner).expect("scan");
    println!(
        "plan: {} file(s) {} dir(s) {} byte(s); skipped {:?}",
        plan.files.len(),
        plan.dirs.len(),
        plan.total_bytes,
        plan.skipped.iter().map(|s| format!("{}: {}", s.path, s.reason)).collect::<Vec<_>>()
    );
    for f in &plan.files {
        println!("  file {}", f.rel_path);
    }
    for d in &plan.dirs {
        println!("  dir  {}", d.rel_path);
    }
    let summary = lock(&mut vault, &key, &plan, &runner).expect("lock");
    println!("locked: {} file(s), {} dir(s)", summary.files, summary.dirs);
    for s in &summary.skipped {
        println!("  skipped {} ({})", s.path, s.reason);
    }
}
