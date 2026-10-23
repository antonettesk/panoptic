//! Opt-in scheduled background scans using the operating system's own
//! scheduler (Task Scheduler on Windows, a systemd user timer on Linux).
//! The scheduled job runs `panoptic-cli scan --history-dir <dir>` so results
//! appear in the desktop app's history.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Frequency {
    Hourly,
    #[default]
    Daily,
    Weekly,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct ScheduleConfig {
    pub enabled: bool,
    pub frequency: Frequency,
    /// Local time `HH:MM` (ignored for hourly).
    pub time: String,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        ScheduleConfig { enabled: false, frequency: Frequency::Daily, time: "09:00".into() }
    }
}

impl ScheduleConfig {
    pub fn validate(&self) -> Result<(), String> {
        let ok = self.time.len() == 5
            && self.time.as_bytes()[2] == b':'
            && self.time[..2].parse::<u8>().map(|h| h < 24).unwrap_or(false)
            && self.time[3..].parse::<u8>().map(|m| m < 60).unwrap_or(false);
        if ok {
            Ok(())
        } else {
            Err(format!("`{}` is not a valid HH:MM time", self.time))
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ScheduleStatus {
    pub installed: bool,
    pub detail: String,
}

pub const TASK_NAME: &str = "Panoptic\\Scheduled Scan";
pub const UNIT_NAME: &str = "panoptic-scan";

fn check_path(p: &Path) -> Result<String, String> {
    let s = p.to_string_lossy().into_owned();
    if s.contains('"') || s.contains('\n') || s.contains('%') {
        return Err(format!("unsupported characters in path {s}"));
    }
    Ok(s)
}

fn run(cmd: &mut Command) -> Result<String, String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = cmd.output().map_err(|e| format!("could not start {:?}: {e}", cmd.get_program()))?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)).trim().to_string();
    if out.status.success() {
        Ok(text)
    } else {
        Err(if text.is_empty() { format!("{:?} failed ({})", cmd.get_program(), out.status) } else { text })
    }
}

/// The scheduled command line (shared by both platforms; unit tested).
pub fn scan_command(cli: &Path, history_dir: &Path) -> Result<String, String> {
    Ok(format!("\"{}\" scan --history-dir \"{}\" --quiet --fail-on critical", check_path(cli)?, check_path(history_dir)?))
}

#[cfg(windows)]
pub fn install(cfg: &ScheduleConfig, cli: &Path, history_dir: &Path, elevated: bool) -> Result<ScheduleStatus, String> {
    cfg.validate()?;
    let tr = scan_command(cli, history_dir)?;
    if tr.len() > 261 {
        return Err("install path is too long for Task Scheduler (max 261 characters)".into());
    }
    let sc = match cfg.frequency {
        Frequency::Hourly => "HOURLY",
        Frequency::Daily => "DAILY",
        Frequency::Weekly => "WEEKLY",
    };
    let mut c = Command::new("schtasks.exe");
    c.args(["/Create", "/TN", TASK_NAME, "/TR", &tr, "/SC", sc, "/F", "/RL", if elevated { "HIGHEST" } else { "LIMITED" }]);
    if cfg.frequency != Frequency::Hourly {
        c.args(["/ST", &cfg.time]);
    }
    run(&mut c)?;
    status()
}

#[cfg(windows)]
pub fn remove() -> Result<(), String> {
    if !status()?.installed {
        return Ok(());
    }
    run(Command::new("schtasks.exe").args(["/Delete", "/TN", TASK_NAME, "/F"])).map(|_| ())
}

#[cfg(windows)]
pub fn status() -> Result<ScheduleStatus, String> {
    match run(Command::new("schtasks.exe").args(["/Query", "/TN", TASK_NAME, "/FO", "LIST"])) {
        Ok(text) => Ok(ScheduleStatus {
            installed: true,
            detail: text.lines().filter(|l| l.starts_with("Next Run Time") || l.starts_with("Status")).map(str::trim).collect::<Vec<_>>().join(" · "),
        }),
        Err(_) => Ok(ScheduleStatus { installed: false, detail: "not scheduled".into() }),
    }
}

#[cfg(target_os = "linux")]
fn unit_dir() -> Result<std::path::PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(std::path::PathBuf::from(home).join(".config/systemd/user"))
}

#[cfg(target_os = "linux")]
pub fn timer_unit(cfg: &ScheduleConfig) -> String {
    let cal = match cfg.frequency {
        Frequency::Hourly => "hourly".to_string(),
        Frequency::Daily => format!("*-*-* {}:00", cfg.time),
        Frequency::Weekly => format!("Mon *-*-* {}:00", cfg.time),
    };
    format!("[Unit]\nDescription=Panoptic scheduled threat hunting scan\n\n[Timer]\nOnCalendar={cal}\nPersistent=true\nRandomizedDelaySec=120\n\n[Install]\nWantedBy=timers.target\n")
}

#[cfg(target_os = "linux")]
pub fn install(cfg: &ScheduleConfig, cli: &Path, history_dir: &Path, _elevated: bool) -> Result<ScheduleStatus, String> {
    cfg.validate()?;
    let dir = unit_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let service = format!(
        "[Unit]\nDescription=Panoptic scheduled threat hunting scan\n\n[Service]\nType=oneshot\nExecStart={}\nNice=10\nIOSchedulingClass=idle\n",
        scan_command(cli, history_dir)?
    );
    crate::config::write_atomic(&dir.join(format!("{UNIT_NAME}.service")), service.as_bytes()).map_err(|e| e.to_string())?;
    crate::config::write_atomic(&dir.join(format!("{UNIT_NAME}.timer")), timer_unit(cfg).as_bytes()).map_err(|e| e.to_string())?;
    run(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
    run(Command::new("systemctl").args(["--user", "enable", "--now", &format!("{UNIT_NAME}.timer")]))?;
    status()
}

#[cfg(target_os = "linux")]
pub fn remove() -> Result<(), String> {
    let _ = run(Command::new("systemctl").args(["--user", "disable", "--now", &format!("{UNIT_NAME}.timer")]));
    let dir = unit_dir()?;
    for ext in ["service", "timer"] {
        let p = dir.join(format!("{UNIT_NAME}.{ext}"));
        if p.exists() {
            std::fs::remove_file(&p).map_err(|e| e.to_string())?;
        }
    }
    let _ = run(Command::new("systemctl").args(["--user", "daemon-reload"]));
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn status() -> Result<ScheduleStatus, String> {
    let installed = unit_dir()?.join(format!("{UNIT_NAME}.timer")).exists();
    let detail = if installed {
        run(Command::new("systemctl").args(["--user", "is-active", &format!("{UNIT_NAME}.timer")])).unwrap_or_else(|e| e)
    } else {
        "not scheduled".into()
    };
    Ok(ScheduleStatus { installed, detail })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_validation() {
        assert!(ScheduleConfig::default().validate().is_ok());
        for bad in ["9:00", "24:00", "12:60", "ab:cd", ""] {
            assert!(ScheduleConfig { time: bad.into(), ..Default::default() }.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn command_quotes_and_rejects_injection() {
        let c = scan_command(Path::new("/opt/panoptic/panoptic-cli"), Path::new("/home/a/.local/share/panoptic/history")).unwrap();
        assert_eq!(c, "\"/opt/panoptic/panoptic-cli\" scan --history-dir \"/home/a/.local/share/panoptic/history\" --quiet --fail-on critical");
        assert!(scan_command(Path::new("/x\" && evil \""), Path::new("/h")).is_err());
    }

    /// Creates and removes a real scheduled task / user timer. Run explicitly:
    /// `cargo test -p panoptic-core schedule_roundtrip -- --ignored`
    #[test]
    #[ignore]
    fn schedule_roundtrip() {
        let exe = std::env::current_exe().unwrap();
        let dir = std::env::temp_dir();
        let cfg = ScheduleConfig { enabled: true, frequency: Frequency::Daily, time: "03:17".into() };
        let st = install(&cfg, &exe, &dir, false).expect("install");
        assert!(st.installed, "{st:?}");
        assert!(status().unwrap().installed);
        remove().expect("remove");
        assert!(!status().unwrap().installed);
        remove().expect("remove is idempotent");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn timer_calendar() {
        let t = timer_unit(&ScheduleConfig { enabled: true, frequency: Frequency::Weekly, time: "07:30".into() });
        assert!(t.contains("OnCalendar=Mon *-*-* 07:30:00"));
    }
}
