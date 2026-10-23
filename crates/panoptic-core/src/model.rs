//! Data model shared by every engine, the CLI and the desktop shell.
//!
//! Everything here is `Serialize + Deserialize` so a `ScanReport` can be
//! exported to JSON, re-imported for baseline comparison and sent across the
//! Tauri IPC boundary unchanged.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Ordered severity scale. Ordering is meaningful: `Critical > High > ... > Info`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Contribution of one finding of this severity to the host risk score.
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 5,
            Severity::High => 15,
            Severity::Critical => 40,
        }
    }

    pub fn bump(self) -> Severity {
        match self {
            Severity::Info => Severity::Low,
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High | Severity::Critical => Severity::Critical,
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        f.write_str(s)
    }
}

/// Which layer(s) of the operating system could see a process.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Visibility {
    /// High-level enumeration API (libc `readdir` on `/proc`, Toolhelp32 / NtQuerySystemInformation).
    pub api: bool,
    /// Second, lower-level enumeration (raw `getdents64` syscall, `EnumProcesses`).
    pub syscall: bool,
    /// Brute-force probing of the PID space (`kill(pid, 0)`, `OpenProcess`).
    pub brute_force: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub cmdline: String,
    #[serde(default)]
    pub user: Option<String>,
    pub cpu_usage: f32,
    #[serde(default)]
    pub memory_bytes: u64,
    /// Seconds since the Unix epoch. Used to guard against PID reuse when acting on a process.
    #[serde(default)]
    pub start_time: u64,
    /// True when the process is visible to some layers but not others (a "ghost").
    pub is_discrepant: bool,
    #[serde(default)]
    pub visibility: Visibility,
    /// Human readable reasons this process was flagged (empty for clean processes).
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
    Raw,
    Packet,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Protocol::Tcp => "tcp",
            Protocol::Tcp6 => "tcp6",
            Protocol::Udp => "udp",
            Protocol::Udp6 => "udp6",
            Protocol::Raw => "raw",
            Protocol::Packet => "packet",
        };
        f.write_str(s)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocketInfo {
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub protocol: Protocol,
    /// TCP state (`LISTEN`, `ESTABLISHED`, ...) or `-` for connectionless sockets.
    pub state: String,
    /// Owning process. `None` when ownership could not be resolved (e.g. insufficient privilege).
    pub pid: Option<u32>,
    #[serde(default)]
    pub process_name: Option<String>,
    pub suspicious: bool,
    /// The port is bound in the kernel but absent from the socket table (hidden listener).
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PersistenceEntry {
    /// Mechanism family, e.g. `cron`, `systemd`, `registry-run`, `service`, `scheduled-task`.
    pub mechanism: String,
    /// Where the entry lives (file path or registry key + value name).
    pub location: String,
    /// The executable the entry launches, best effort.
    pub target_path: String,
    /// The full command / value text.
    #[serde(default)]
    pub command: String,
    pub risk_level: Severity,
    #[serde(default)]
    pub reasons: Vec<String>,
    /// Last modification of the backing file/key, seconds since epoch, when known.
    #[serde(default)]
    pub modified: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KernelModule {
    pub name: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub size: u64,
    /// Present in the primary listing (`/proc/modules`, `EnumDeviceDrivers`).
    pub listed: bool,
    /// Present in the secondary view (`/sys/module`, driver file on disk).
    pub corroborated: bool,
    pub hidden: bool,
    pub suspicious: bool,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum FindingCategory {
    HiddenProcess,
    ProcessAnomaly,
    HiddenSocket,
    SuspiciousSocket,
    Persistence,
    HiddenModule,
    KernelIntegrity,
    LoaderHijack,
    BaselineDrift,
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            FindingCategory::HiddenProcess => "hidden-process",
            FindingCategory::ProcessAnomaly => "process-anomaly",
            FindingCategory::HiddenSocket => "hidden-socket",
            FindingCategory::SuspiciousSocket => "suspicious-socket",
            FindingCategory::Persistence => "persistence",
            FindingCategory::HiddenModule => "hidden-module",
            FindingCategory::KernelIntegrity => "kernel-integrity",
            FindingCategory::LoaderHijack => "loader-hijack",
            FindingCategory::BaselineDrift => "baseline-drift",
        };
        f.write_str(s)
    }
}

/// A single actionable detection.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Finding {
    /// Stable identifier derived from category + subject so the same issue
    /// keeps its id across scans (used for suppression and diffing).
    pub id: String,
    pub category: FindingCategory,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub path: Option<String>,
    /// MITRE ATT&CK technique id, e.g. `T1014`.
    #[serde(default)]
    pub mitre: Option<String>,
    #[serde(default)]
    pub recommendation: String,
    #[serde(default)]
    pub suppressed: bool,
}

impl Finding {
    pub fn new(category: FindingCategory, severity: Severity, subject: &str, title: impl Into<String>, description: impl Into<String>) -> Self {
        Finding {
            id: finding_id(category, subject),
            category,
            severity,
            title: title.into(),
            description: description.into(),
            evidence: Vec::new(),
            pid: None,
            path: None,
            mitre: None,
            recommendation: String::new(),
            suppressed: false,
        }
    }

    pub fn evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence.push(e.into());
        self
    }

    pub fn evidences<I: IntoIterator<Item = S>, S: Into<String>>(mut self, it: I) -> Self {
        self.evidence.extend(it.into_iter().map(Into::into));
        self
    }

    pub fn pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        let p = path.into();
        if !p.is_empty() {
            self.path = Some(p);
        }
        self
    }

    pub fn mitre(mut self, technique: &str) -> Self {
        self.mitre = Some(technique.to_string());
        self
    }

    pub fn recommend(mut self, r: impl Into<String>) -> Self {
        self.recommendation = r.into();
        self
    }
}

/// FNV-1a 64-bit; deterministic across runs and platforms (unlike `DefaultHasher`).
pub fn stable_hash(input: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in input.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

pub fn finding_id(category: FindingCategory, subject: &str) -> String {
    format!("{}-{:016x}", category, stable_hash(&format!("{category}|{subject}")))
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub kernel_version: String,
    pub arch: String,
    pub uptime_secs: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ScanSummary {
    pub processes: usize,
    pub hidden_processes: usize,
    pub sockets: usize,
    pub listening: usize,
    pub hidden_sockets: usize,
    pub persistence_entries: usize,
    pub modules: usize,
    pub hidden_modules: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub suppressed: usize,
}

/// Outcome of one scan stage, so the UI can show partial-failure states
/// instead of silently presenting an incomplete picture as clean.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StageStatus {
    pub stage: String,
    pub ok: bool,
    pub duration_ms: u64,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ScanReport {
    pub scan_id: String,
    pub tool_version: String,
    /// Seconds since the Unix epoch.
    pub started_at: u64,
    pub duration_ms: u64,
    pub engine: String,
    pub elevated: bool,
    pub host: HostInfo,
    pub risk_score: u8,
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
    pub processes: Vec<ProcessInfo>,
    pub sockets: Vec<SocketInfo>,
    pub persistence: Vec<PersistenceEntry>,
    pub modules: Vec<KernelModule>,
    pub stages: Vec<StageStatus>,
    #[serde(default)]
    pub cancelled: bool,
}
