//! DriveTooth: password-gated, in-place file encryption for removable drives.

pub mod crypto;
pub mod error;
pub mod ops;
pub mod volume;

#[cfg(feature = "gui")]
pub mod commands;

/// The encryption engine has no webview dependency; only this entry point does.
#[cfg(feature = "gui")]
pub fn run() {
    use tauri::{Manager, RunEvent, WindowEvent};

    use crate::commands::{
        cancel_operation, describe_contents, describe_tree, forget_session, inspect_volume,
        list_dir, list_mounts, run_operation, watch_for_plugs, AppState,
    };

    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            list_mounts,
            inspect_volume,
            run_operation,
            cancel_operation,
            forget_session,
            describe_contents,
            describe_tree,
            list_dir
        ])
        .setup(|app| {
            watch_for_plugs(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { .. } = event {
                window.app_handle().state::<AppState>().clear_session();
            }
        })
        .build(tauri::generate_context!())
        .expect("DriveTooth failed to start")
        .run(|app_handle, event| {
            // Belt and braces: no volume key survives process exit.
            if let RunEvent::Exit = event {
                app_handle.state::<AppState>().clear_session();
            }
        });
}
