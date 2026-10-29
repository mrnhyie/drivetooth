fn main() {
    // The Tauri build machinery expects to run under the Tauri CLI, so headless core
    // builds (`cargo test --no-default-features`) skip it entirely.
    if std::env::var_os("CARGO_FEATURE_GUI").is_some() {
        tauri_build::build();
    } else {
        println!("cargo:rustc-check-cfg=cfg(gui)");
    }
}
