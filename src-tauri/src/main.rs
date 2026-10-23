// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod engine;

use commands::AppState;
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Same location as Tauri's app_data_dir for normal users; a
            // root-owned directory when elevated on Linux (never a
            // user-controlled $HOME). Unsafe directories abort startup.
            let data_dir = panoptic_core::workspace::default_data_dir();
            app.manage(AppState::new(data_dir)?);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_system_info,
            commands::scan_system,
            commands::cancel_scan,
            commands::terminate_process,
            commands::suspend_process,
            commands::resume_process,
            commands::export_report,
            commands::get_history,
            commands::load_report,
            commands::delete_report,
            commands::save_baseline,
            commands::clear_baseline,
            commands::get_suppressions,
            commands::set_suppressions,
            commands::set_finding_suppressed,
            commands::relaunch_as_admin,
            commands::get_settings,
            commands::save_settings,
            commands::environment_checks,
            commands::schedule_status,
            commands::set_schedule,
            commands::export_asff,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Panoptic");
}
