//! Application layer shared by the desktop shell (Tauri IPC) and the local
//! web server (`panoptic-cli serve`). Both front ends call exactly the same
//! operations, so behaviour cannot drift between them.

use crate::engine::anomaly::AnomalyAnalyzer;
use crate::engine::ProcessAction;
use crate::model::{HostInfo, ScanReport, ScanSummary, Severity};
use crate::schedule::{self, ScheduleConfig, ScheduleStatus};
use crate::settings::AppSettings;
use crate::{asff, config::write_atomic, report, Baseline, CancelToken, Progress, ScanOptions, Scanner, Suppressions};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const HISTORY_LIMIT: usize = 25;
/// Bundle identifier; must match `identifier` in tauri.conf.json so the
/// desktop app and the local server share settings and history.
pub const APP_IDENTIFIER: &str = "io.panoptic.desktop";

pub type OpResult<T> = Result<T, String>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SystemInfo {
    pub host: HostInfo,
    pub elevated: bool,
    pub engine: String,
    pub version: String,
    pub platform: String,
    pub data_dir: String,
    pub has_baseline: bool,
    pub baseline_created_at: Option<u64>,
    pub scanning: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HistoryEntry {
    pub scan_id: String,
    pub started_at: u64,
    pub duration_ms: u64,
    pub risk_score: u8,
    pub elevated: bool,
    pub cancelled: bool,
    pub summary: ScanSummary,
}

#[derive(Serialize, Debug, Clone)]
pub struct SettingsPayload {
    pub settings: AppSettings,
    pub warning: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct EnvCheck {
    pub id: String,
    pub ok: bool,
    pub detail: String,
}

/// A rendered export ready to be written to disk or streamed to a browser.
pub struct Rendered {
    pub body: Vec<u8>,
    pub mime: &'static str,
    pub extension: &'static str,
}

/// Root-owned data directory used whenever Panoptic runs as root on Linux.
pub const ROOT_DATA_DIR: &str = "/var/lib/panoptic";

/// Platform data directory (matches Tauri's `app_data_dir()` for normal users).
///
/// When running as root on Linux, `$HOME`/`$XDG_DATA_HOME` may still point at
/// an unprivileged user's directory (e.g. under `sudo -E`). Writing there as
/// root would let that user redirect our writes with symlinks, so root always
/// uses a root-owned directory instead.
pub fn default_data_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return PathBuf::from(ROOT_DATA_DIR);
    }
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));
    base.unwrap_or_else(std::env::temp_dir).join(APP_IDENTIFIER)
}

/// Create (if needed) and validate the data directory: it must be a real
/// directory, not a symlink, owned by the effective user and private (0700)
/// on Unix. Refuses rather than writing into a directory someone else controls.
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => return Err(format!("refusing to use data directory {}: it is a symlink", dir.display())),
        Ok(m) if !m.is_dir() => return Err(format!("data directory {} is not a directory", dir.display())),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir).map_err(|e| format!("could not create data directory {}: {e}", dir.display()))?;
        }
        Err(e) => return Err(format!("could not inspect data directory {}: {e}", dir.display())),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let m = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if m.uid() != euid {
            return Err(format!("refusing to use data directory {}: owned by uid {}, not {euid}", dir.display(), m.uid()));
        }
        if m.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub fn valid_scan_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

struct ScanGuard<'a>(&'a AtomicBool);
impl Drop for ScanGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

pub struct Workspace {
    scanner: Scanner,
    cancel: CancelToken,
    scanning: AtomicBool,
    last_report: Mutex<Option<ScanReport>>,
    progress: Mutex<Option<Progress>>,
    data_dir: PathBuf,
    cli_path: Option<PathBuf>,
}

impl Workspace {
    /// Fails if the data directory is unsafe to write to (see `ensure_private_dir`).
    pub fn new(data_dir: PathBuf, cli_path: Option<PathBuf>) -> Result<Arc<Self>, String> {
        ensure_private_dir(&data_dir)?;
        Ok(Arc::new(Workspace {
            scanner: Scanner::new(),
            cancel: CancelToken::new(),
            scanning: AtomicBool::new(false),
            last_report: Mutex::new(None),
            progress: Mutex::new(None),
            data_dir,
            cli_path,
        }))
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
    pub fn is_elevated(&self) -> bool {
        self.scanner.engine().is_elevated()
    }
    fn path(&self, name: &str) -> PathBuf {
        self.data_dir.join(name)
    }
    fn history_dir(&self) -> PathBuf {
        self.path("history")
    }
    fn suppressions(&self) -> OpResult<Suppressions> {
        Suppressions::load(&self.path("suppressions.json")).map_err(|e| format!("Could not read suppressions: {e}"))
    }
    fn settings(&self) -> AppSettings {
        AppSettings::load(&self.path("settings.json")).0
    }

    // ------------------------------------------------------------ scanning

    pub fn system_info(&self) -> SystemInfo {
        let baseline = Baseline::load(&self.path("baseline.json")).ok();
        SystemInfo {
            host: crate::scanner::host_info(),
            elevated: self.is_elevated(),
            engine: self.scanner.engine().name().into(),
            version: crate::VERSION.into(),
            platform: std::env::consts::OS.into(),
            data_dir: self.data_dir.display().to_string(),
            has_baseline: baseline.is_some(),
            baseline_created_at: baseline.map(|b| b.created_at),
            scanning: self.scanning.load(Ordering::SeqCst),
        }
    }

    /// Blocking full scan. `on_progress` receives live updates; the latest one
    /// is also kept for clients that poll (`progress()`).
    pub fn scan(&self, options: Option<ScanOptions>, on_progress: &(dyn Fn(Progress) + Sync)) -> OpResult<ScanReport> {
        if self.scanning.swap(true, Ordering::SeqCst) {
            return Err("A scan is already running".into());
        }
        let _guard = ScanGuard(&self.scanning);
        self.cancel.reset();
        let opts = options.unwrap_or_else(|| self.settings().scan_options);
        let suppressions = self.suppressions()?;
        let baseline = Baseline::load(&self.path("baseline.json")).ok();
        let r = self.scanner.run(&opts, &suppressions, baseline.as_ref(), &self.cancel, &|p| {
            if let Ok(mut g) = self.progress.lock() {
                *g = Some(p.clone());
            }
            on_progress(p);
        });
        if let Err(e) = self.save_history(&r) {
            eprintln!("panoptic: could not persist scan history: {e}");
        }
        *self.last_report.lock().map_err(|_| "state poisoned")? = Some(r.clone());
        if let Ok(mut g) = self.progress.lock() {
            *g = None;
        }
        Ok(r)
    }

    pub fn progress(&self) -> Option<Progress> {
        if !self.scanning.load(Ordering::SeqCst) {
            return None;
        }
        self.progress.lock().ok().and_then(|g| g.clone())
    }

    pub fn cancel_scan(&self) -> bool {
        let running = self.scanning.load(Ordering::SeqCst);
        if running {
            self.cancel.cancel();
        }
        running
    }

    pub fn process_action(&self, pid: u32, start_time: Option<u64>, action: ProcessAction) -> OpResult<()> {
        self.scanner.engine().act_on_process(pid, start_time.unwrap_or(0), action).map_err(|e| e.to_string())
    }

    // ------------------------------------------------------------ reports & history

    fn save_history(&self, r: &ScanReport) -> std::io::Result<()> {
        let dir = self.history_dir();
        std::fs::create_dir_all(&dir)?;
        write_atomic(&dir.join(format!("{}.json", r.scan_id)), report::to_json(r).as_bytes())?;
        let mut files: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&dir)?
            .flatten()
            .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
            .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
            .collect();
        files.sort();
        while files.len() > HISTORY_LIMIT {
            let (_, p) = files.remove(0);
            let _ = std::fs::remove_file(p);
        }
        Ok(())
    }

    pub fn report_for(&self, scan_id: Option<&str>) -> OpResult<ScanReport> {
        match scan_id {
            Some(id) => {
                if !valid_scan_id(id) {
                    return Err("Invalid scan id".into());
                }
                let s = std::fs::read_to_string(self.history_dir().join(format!("{id}.json"))).map_err(|e| format!("Scan {id} not found: {e}"))?;
                report::from_json(&s).map_err(|e| format!("Corrupt report: {e}"))
            }
            None => self.last_report.lock().map_err(|_| "state poisoned")?.clone().ok_or_else(|| "No scan has been run yet".to_string()),
        }
    }

    pub fn render(&self, format: &str, scan_id: Option<&str>) -> OpResult<Rendered> {
        let r = self.report_for(scan_id)?;
        let (body, mime, extension) = match format {
            "json" => (report::to_json(&r), "application/json", "json"),
            "html" => (report::to_html(&r), "text/html; charset=utf-8", "html"),
            "csv" => (report::to_csv(&r), "text/csv; charset=utf-8", "csv"),
            "txt" | "text" => (report::to_text(&r, Severity::Info), "text/plain; charset=utf-8", "txt"),
            other => return Err(format!("Unsupported format `{other}`")),
        };
        Ok(Rendered { body: body.into_bytes(), mime, extension })
    }

    pub fn export_to_path(&self, path: &str, format: &str, scan_id: Option<&str>) -> OpResult<String> {
        let rendered = self.render(format, scan_id)?;
        let p = PathBuf::from(path);
        write_atomic(&p, &rendered.body).map_err(|e| format!("Could not write {path}: {e}"))?;
        Ok(p.display().to_string())
    }

    pub fn history(&self) -> Vec<HistoryEntry> {
        let Ok(rd) = std::fs::read_dir(self.history_dir()) else { return vec![] };
        let mut out: Vec<HistoryEntry> = rd
            .flatten()
            .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .filter_map(|s| report::from_json(&s).ok())
            .map(|r| HistoryEntry {
                scan_id: r.scan_id,
                started_at: r.started_at,
                duration_ms: r.duration_ms,
                risk_score: r.risk_score,
                elevated: r.elevated,
                cancelled: r.cancelled,
                summary: r.summary,
            })
            .collect();
        out.sort_by_key(|e| std::cmp::Reverse(e.started_at));
        out
    }

    pub fn load_report(&self, scan_id: &str) -> OpResult<ScanReport> {
        let r = self.report_for(Some(scan_id))?;
        *self.last_report.lock().map_err(|_| "state poisoned")? = Some(r.clone());
        Ok(r)
    }

    pub fn delete_report(&self, scan_id: &str) -> OpResult<()> {
        if !valid_scan_id(scan_id) {
            return Err("Invalid scan id".into());
        }
        std::fs::remove_file(self.history_dir().join(format!("{scan_id}.json"))).map_err(|e| e.to_string())
    }

    // ------------------------------------------------------------ baseline & tuning

    pub fn save_baseline(&self) -> OpResult<u64> {
        let r = self.report_for(None)?;
        if r.cancelled {
            return Err("Cannot baseline a cancelled (partial) scan".into());
        }
        let b = Baseline::from_report(&r);
        b.save(&self.path("baseline.json")).map_err(|e| e.to_string())?;
        Ok(b.created_at)
    }

    pub fn clear_baseline(&self) -> OpResult<()> {
        match std::fs::remove_file(self.path("baseline.json")) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn get_suppressions(&self) -> OpResult<Suppressions> {
        self.suppressions()
    }

    pub fn set_suppressions(&self, s: &Suppressions) -> OpResult<()> {
        s.save(&self.path("suppressions.json")).map_err(|e| e.to_string())
    }

    pub fn set_finding_suppressed(&self, finding_id: &str, suppressed: bool) -> OpResult<ScanReport> {
        let mut s = self.suppressions()?;
        if suppressed {
            s.finding_ids.insert(finding_id.to_string());
        } else {
            s.finding_ids.remove(finding_id);
        }
        self.set_suppressions(&s)?;
        let mut guard = self.last_report.lock().map_err(|_| "state poisoned")?;
        let r = guard.as_mut().ok_or("No scan loaded")?;
        s.apply(&mut r.findings);
        r.risk_score = AnomalyAnalyzer::risk_score(&r.findings);
        r.summary = crate::scanner::summarize(&r.processes, &r.sockets, &r.persistence, &r.modules, &r.findings);
        Ok(r.clone())
    }

    // ------------------------------------------------------------ settings, onboarding, automation

    pub fn get_settings(&self) -> SettingsPayload {
        let (settings, warning) = AppSettings::load(&self.path("settings.json"));
        SettingsPayload { settings, warning }
    }

    pub fn save_settings(&self, settings: AppSettings) -> OpResult<AppSettings> {
        settings.validate()?;
        settings.save(&self.path("settings.json")).map_err(|e| format!("Could not save settings: {e}"))?;
        Ok(settings)
    }

    pub fn environment_checks(&self) -> Vec<EnvCheck> {
        let engine = self.scanner.engine();
        let elevated = engine.is_elevated();
        let mut out = vec![
            EnvCheck {
                id: "elevation".into(),
                ok: elevated,
                detail: if elevated { "Running with full privileges".into() } else { "Limited privileges: some kernel views are unavailable".into() },
            },
            EnvCheck { id: "engine".into(), ok: true, detail: format!("{} engine on {} {}", engine.name(), std::env::consts::OS, std::env::consts::ARCH) },
        ];
        let probe = self.path(".write-test");
        let writable = std::fs::write(&probe, b"ok").and_then(|_| std::fs::remove_file(&probe)).is_ok();
        out.push(EnvCheck { id: "storage".into(), ok: writable, detail: self.data_dir.display().to_string() });
        out.push(match &self.cli_path {
            Some(p) if p.exists() => EnvCheck { id: "cli".into(), ok: true, detail: p.display().to_string() },
            _ => EnvCheck { id: "cli".into(), ok: false, detail: "panoptic-cli was not found next to the app (development build?)".into() },
        });
        let scheduler = if cfg!(windows) { "schtasks.exe" } else { "systemctl" };
        let has_scheduler = cfg!(windows) || std::process::Command::new(scheduler).arg("--version").output().is_ok();
        out.push(EnvCheck {
            id: "scheduler".into(),
            ok: has_scheduler,
            detail: if has_scheduler { format!("{scheduler} available") } else { format!("{scheduler} not found") },
        });
        out
    }

    pub fn schedule_status(&self) -> OpResult<ScheduleStatus> {
        schedule::status()
    }

    pub fn set_schedule(&self, config: ScheduleConfig) -> OpResult<ScheduleStatus> {
        config.validate()?;
        let history = self.history_dir();
        std::fs::create_dir_all(&history).map_err(|e| e.to_string())?;
        let status = if config.enabled {
            let cli =
                self.cli_path.as_ref().filter(|p| p.exists()).ok_or("The bundled panoptic-cli was not found; scheduled scans need an installed build.")?;
            schedule::install(&config, cli, &history, self.is_elevated())?
        } else {
            schedule::remove()?;
            schedule::status()?
        };
        let mut s = self.settings();
        s.schedule = ScheduleConfig { enabled: status.installed, ..config };
        let _ = s.save(&self.path("settings.json"));
        Ok(status)
    }

    pub fn asff_batches(&self, scan_id: Option<&str>, min: Option<&str>) -> OpResult<Vec<Vec<Value>>> {
        let target = self.settings().aws.ok_or("Enable the AWS Security Hub integration in Settings first")?;
        let r = self.report_for(scan_id)?;
        let min = min.and_then(Severity::parse).unwrap_or(Severity::Low);
        let findings = asff::to_asff(&r, &target, min)?;
        let batches = asff::chunks(&findings);
        if batches.is_empty() {
            return Err("No findings at or above the selected severity to export".into());
        }
        Ok(batches)
    }

    pub fn export_asff_to_path(&self, path: &str, scan_id: Option<&str>, min: Option<&str>) -> OpResult<Vec<String>> {
        let base = PathBuf::from(path);
        let mut written = Vec::new();
        for (i, batch) in self.asff_batches(scan_id, min)?.iter().enumerate() {
            let p = if i == 0 {
                base.clone()
            } else {
                let stem = base.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                base.with_file_name(format!("{stem}-{}.json", i + 1))
            };
            let body = serde_json::to_vec_pretty(batch).map_err(|e| e.to_string())?;
            write_atomic(&p, &body).map_err(|e| format!("Could not write {}: {e}", p.display()))?;
            written.push(p.display().to_string());
        }
        Ok(written)
    }

    // ------------------------------------------------------------ generic dispatch (HTTP transport)

    /// Execute a command by name with Tauri-style camelCase arguments. Commands
    /// that need the native shell (file dialogs, window control) are not here.
    pub fn dispatch(&self, cmd: &str, args: &Value) -> OpResult<Value> {
        let s = |k: &str| args.get(k).and_then(Value::as_str).map(str::to_string);
        let req = |k: &str| s(k).ok_or_else(|| format!("missing argument `{k}`"));
        let u64_ = |k: &str| args.get(k).and_then(Value::as_u64);
        let pid = || u64_("pid").and_then(|v| u32::try_from(v).ok()).ok_or_else(|| "missing or invalid argument `pid`".to_string());
        let to = |v: &dyn erased::Ser| v.to_value();
        let parse = |k: &str| -> OpResult<Value> { args.get(k).cloned().ok_or_else(|| format!("missing argument `{k}`")) };
        Ok(match cmd {
            "get_system_info" => to(&self.system_info()),
            "scan_system" => {
                let opts = match args.get("options") {
                    Some(Value::Null) | None => None,
                    Some(v) => Some(serde_json::from_value(v.clone()).map_err(|e| format!("invalid options: {e}"))?),
                };
                to(&self.scan(opts, &|_| {})?)
            }
            "cancel_scan" => json!(self.cancel_scan()),
            "scan_progress" => to(&self.progress()),
            "terminate_process" => to(&self.process_action(pid()?, u64_("startTime"), ProcessAction::Terminate)?),
            "suspend_process" => to(&self.process_action(pid()?, u64_("startTime"), ProcessAction::Suspend)?),
            "resume_process" => to(&self.process_action(pid()?, u64_("startTime"), ProcessAction::Resume)?),
            "get_history" => to(&self.history()),
            "load_report" => to(&self.load_report(&req("scanId")?)?),
            "delete_report" => to(&self.delete_report(&req("scanId")?)?),
            "save_baseline" => json!(self.save_baseline()?),
            "clear_baseline" => to(&self.clear_baseline()?),
            "get_suppressions" => to(&self.get_suppressions()?),
            "set_suppressions" => {
                let v: Suppressions = serde_json::from_value(parse("suppressions")?).map_err(|e| format!("invalid suppressions: {e}"))?;
                to(&self.set_suppressions(&v)?)
            }
            "set_finding_suppressed" => {
                let suppressed = args.get("suppressed").and_then(Value::as_bool).ok_or("missing argument `suppressed`")?;
                to(&self.set_finding_suppressed(&req("findingId")?, suppressed)?)
            }
            "get_settings" => to(&self.get_settings()),
            "save_settings" => {
                let v: AppSettings = serde_json::from_value(parse("settings")?).map_err(|e| format!("invalid settings: {e}"))?;
                to(&self.save_settings(v)?)
            }
            "environment_checks" => to(&self.environment_checks()),
            "schedule_status" => to(&self.schedule_status()?),
            "set_schedule" => {
                let v: ScheduleConfig = serde_json::from_value(parse("config")?).map_err(|e| format!("invalid schedule: {e}"))?;
                to(&self.set_schedule(v)?)
            }
            other => return Err(format!("unknown command `{other}`")),
        })
    }
}

/// Tiny helper so `dispatch` can serialise heterogeneous results uniformly.
mod erased {
    pub trait Ser {
        fn to_value(&self) -> serde_json::Value;
    }
    impl<T: serde::Serialize> Ser for T {
        fn to_value(&self) -> serde_json::Value {
            serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ws() -> (tempfile::TempDir, Arc<Workspace>) {
        let d = tempfile::tempdir().unwrap();
        let w = Workspace::new(d.path().to_path_buf(), None).unwrap();
        (d, w)
    }

    #[test]
    fn dispatch_round_trips_settings_and_validates() {
        let (_d, w) = ws();
        let got = w.dispatch("get_settings", &json!({})).unwrap();
        assert_eq!(got["settings"]["onboarding_completed"], false);
        let mut s = got["settings"].clone();
        s["onboarding_completed"] = json!(true);
        s["language"] = json!("ja");
        w.dispatch("save_settings", &json!({ "settings": s })).unwrap();
        assert_eq!(w.dispatch("get_settings", &json!({})).unwrap()["settings"]["language"], "ja");
        let mut bad = s.clone();
        bad["theme"] = json!("neon");
        assert!(w.dispatch("save_settings", &json!({ "settings": bad })).is_err());
    }

    #[test]
    fn dispatch_rejects_unknown_and_bad_input() {
        let (_d, w) = ws();
        assert!(w.dispatch("rm_rf", &json!({})).unwrap_err().contains("unknown command"));
        assert!(w.dispatch("load_report", &json!({ "scanId": "../../etc/passwd" })).unwrap_err().contains("Invalid scan id"));
        assert!(w.dispatch("terminate_process", &json!({})).unwrap_err().contains("pid"));
        assert!(w.dispatch("save_baseline", &json!({})).is_err(), "no scan yet");
    }

    #[test]
    fn info_and_checks() {
        let (d, w) = ws();
        let info = w.dispatch("get_system_info", &json!({})).unwrap();
        assert_eq!(info["data_dir"], d.path().display().to_string());
        assert!(!w.environment_checks().is_empty());
        assert!(w.progress().is_none());
    }

    #[test]
    fn data_dir_matches_tauri_identifier_or_root_dir() {
        let d = default_data_dir();
        #[cfg(target_os = "linux")]
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(d, PathBuf::from(ROOT_DATA_DIR));
            return;
        }
        assert!(d.ends_with(APP_IDENTIFIER));
    }

    #[test]
    fn refuses_symlinked_data_dir() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = d.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(windows)]
        if std::os::windows::fs::symlink_dir(&real, &link).is_err() {
            return; // creating symlinks needs Developer Mode / admin on Windows
        }
        assert!(ensure_private_dir(&link).unwrap_err().contains("symlink"));
        assert!(ensure_private_dir(&real).is_ok());
        assert!(ensure_private_dir(&d.path().join("new/nested")).is_ok());
    }
}
