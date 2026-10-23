//! Tauri IPC adapters. All behaviour lives in `panoptic_core::workspace`,
//! shared with the local web server (`panoptic-cli serve`).

use crate::engine::traits::ProcessAction;
use panoptic_core::schedule::{ScheduleConfig, ScheduleStatus};
use panoptic_core::settings::AppSettings;
use panoptic_core::workspace::{EnvCheck, HistoryEntry, SettingsPayload, SystemInfo, Workspace};
use panoptic_core::{ScanOptions, ScanReport, Suppressions};
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{command, AppHandle, Emitter, State};

pub struct AppState(pub Arc<Workspace>);

impl AppState {
    pub fn new(data_dir: PathBuf) -> Result<Self, String> {
        Ok(AppState(Workspace::new(data_dir, cli_path())?))
    }
}

/// Bundled headless scanner, installed next to the GUI executable.
fn cli_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let name = if cfg!(windows) { "panoptic-cli.exe" } else { "panoptic-cli" };
    Some(exe.parent()?.join(name))
}

/// Run blocking workspace calls off the IPC thread.
async fn blocking<T: Send + 'static>(ws: &Arc<Workspace>, f: impl FnOnce(&Workspace) -> Result<T, String> + Send + 'static) -> Result<T, String> {
    let ws = ws.clone();
    tauri::async_runtime::spawn_blocking(move || f(&ws)).await.map_err(|e| format!("worker failed: {e}"))?
}

#[command]
pub fn get_system_info(state: State<'_, AppState>) -> SystemInfo {
    state.0.system_info()
}

#[command]
pub async fn scan_system(app: AppHandle, state: State<'_, AppState>, options: Option<ScanOptions>) -> Result<ScanReport, String> {
    blocking(&state.0, move |ws| {
        ws.scan(options, &|p| {
            let _ = app.emit("scan-progress", &p);
        })
    })
    .await
}

#[command]
pub fn cancel_scan(state: State<'_, AppState>) -> bool {
    state.0.cancel_scan()
}

#[command]
pub async fn terminate_process(state: State<'_, AppState>, pid: u32, start_time: Option<u64>) -> Result<(), String> {
    state.0.process_action(pid, start_time, ProcessAction::Terminate)
}

#[command]
pub async fn suspend_process(state: State<'_, AppState>, pid: u32, start_time: Option<u64>) -> Result<(), String> {
    state.0.process_action(pid, start_time, ProcessAction::Suspend)
}

#[command]
pub async fn resume_process(state: State<'_, AppState>, pid: u32, start_time: Option<u64>) -> Result<(), String> {
    state.0.process_action(pid, start_time, ProcessAction::Resume)
}

#[command]
pub async fn export_report(state: State<'_, AppState>, path: String, format: String, scan_id: Option<String>) -> Result<String, String> {
    state.0.export_to_path(&path, &format, scan_id.as_deref())
}

#[command]
pub async fn get_history(state: State<'_, AppState>) -> Result<Vec<HistoryEntry>, String> {
    blocking(&state.0, |ws| Ok(ws.history())).await
}

#[command]
pub async fn load_report(state: State<'_, AppState>, scan_id: String) -> Result<ScanReport, String> {
    state.0.load_report(&scan_id)
}

#[command]
pub async fn delete_report(state: State<'_, AppState>, scan_id: String) -> Result<(), String> {
    state.0.delete_report(&scan_id)
}

#[command]
pub async fn save_baseline(state: State<'_, AppState>) -> Result<u64, String> {
    state.0.save_baseline()
}

#[command]
pub async fn clear_baseline(state: State<'_, AppState>) -> Result<(), String> {
    state.0.clear_baseline()
}

#[command]
pub async fn get_suppressions(state: State<'_, AppState>) -> Result<Suppressions, String> {
    state.0.get_suppressions()
}

#[command]
pub async fn set_suppressions(state: State<'_, AppState>, suppressions: Suppressions) -> Result<(), String> {
    state.0.set_suppressions(&suppressions)
}

#[command]
pub async fn set_finding_suppressed(state: State<'_, AppState>, finding_id: String, suppressed: bool) -> Result<ScanReport, String> {
    state.0.set_finding_suppressed(&finding_id, suppressed)
}

#[command]
pub async fn get_settings(state: State<'_, AppState>) -> Result<SettingsPayload, String> {
    Ok(state.0.get_settings())
}

#[command]
pub async fn save_settings(state: State<'_, AppState>, settings: AppSettings) -> Result<AppSettings, String> {
    state.0.save_settings(settings)
}

#[command]
pub async fn environment_checks(state: State<'_, AppState>) -> Result<Vec<EnvCheck>, String> {
    blocking(&state.0, |ws| Ok(ws.environment_checks())).await
}

#[command]
pub async fn schedule_status(state: State<'_, AppState>) -> Result<ScheduleStatus, String> {
    blocking(&state.0, |ws| ws.schedule_status()).await
}

#[command]
pub async fn set_schedule(state: State<'_, AppState>, config: ScheduleConfig) -> Result<ScheduleStatus, String> {
    blocking(&state.0, move |ws| ws.set_schedule(config)).await
}

#[command]
pub async fn export_asff(state: State<'_, AppState>, path: String, scan_id: Option<String>, min_severity: Option<String>) -> Result<Vec<String>, String> {
    state.0.export_asff_to_path(&path, scan_id.as_deref(), min_severity.as_deref())
}

#[command]
pub fn relaunch_as_admin(app: AppHandle) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        panoptic_core::engine::windows_engine::relaunch_elevated(&exe, "").map_err(|e| e.to_string())?;
        app.exit(0);
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
        Err("Restart Panoptic as root (for example `sudo panoptic` or via pkexec) to grant full privileges.".into())
    }
}
