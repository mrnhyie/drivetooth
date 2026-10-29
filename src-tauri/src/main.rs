// Prevents an extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(feature = "gui")]
    drivetooth_lib::run();

    #[cfg(not(feature = "gui"))]
    {
        eprintln!("DriveTooth was built without the `gui` feature.");
        eprintln!("Run `cargo run` with default features, or use the Tauri app bundle.");
    }
}
