//! Known-good baselines: snapshot the autostart surface, listeners and
//! kernel modules of a clean host, then report drift on later scans.

use crate::config::write_atomic;
use crate::model::{Finding, FindingCategory, ScanReport, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct Baseline {
    pub created_at: u64,
    pub hostname: String,
    pub persistence: BTreeSet<String>,
    pub listeners: BTreeSet<String>,
    pub modules: BTreeSet<String>,
    #[serde(default)]
    pub executables: BTreeSet<String>,
}

fn persistence_key(location: &str, command: &str) -> String {
    format!("{location}|{command}")
}

impl Baseline {
    pub fn from_report(r: &ScanReport) -> Self {
        Baseline {
            created_at: r.started_at,
            hostname: r.host.hostname.clone(),
            persistence: r.persistence.iter().map(|p| persistence_key(&p.location, &p.command)).collect(),
            listeners: r
                .sockets
                .iter()
                .filter(|s| s.state == "LISTEN")
                .map(|s| format!("{}:{}:{}", s.protocol, s.local_port, s.process_name.clone().unwrap_or_default().to_ascii_lowercase()))
                .collect(),
            modules: r.modules.iter().map(|m| m.name.to_ascii_lowercase()).collect(),
            executables: r.processes.iter().filter(|p| !p.path.is_empty()).map(|p| p.path.to_ascii_lowercase()).collect(),
        }
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        serde_json::from_str(&s).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        write_atomic(path, serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?.as_slice())
    }

    /// Findings for everything present now that was absent from the baseline.
    pub fn drift(&self, r: &ScanReport) -> Vec<Finding> {
        let mut out = Vec::new();
        for p in &r.persistence {
            if !self.persistence.contains(&persistence_key(&p.location, &p.command)) {
                let sev = if p.risk_level >= Severity::Medium { Severity::High } else { Severity::Medium };
                out.push(
                    Finding::new(
                        FindingCategory::BaselineDrift,
                        sev,
                        &format!("drift-persist:{}|{}", p.location, p.command),
                        format!("New autostart entry since baseline: {}", p.mechanism),
                        "This persistence entry did not exist when the baseline was captured.",
                    )
                    .evidence(format!("location: {}", p.location))
                    .evidence(format!("command: {}", p.command))
                    .evidences(p.reasons.clone())
                    .path(p.target_path.clone())
                    .mitre("T1547")
                    .recommend("Confirm the change was authorised (software install, admin action). If not, remove it and investigate how it was created."),
                );
            }
        }
        for s in r.sockets.iter().filter(|s| s.state == "LISTEN") {
            let key = format!("{}:{}:{}", s.protocol, s.local_port, s.process_name.clone().unwrap_or_default().to_ascii_lowercase());
            if !self.listeners.contains(&key) && !s.is_loopback() {
                let mut f = Finding::new(
                    FindingCategory::BaselineDrift,
                    Severity::Low,
                    &format!("drift-listen:{key}"),
                    format!(
                        "New network listener since baseline: {}/{} ({})",
                        s.protocol,
                        s.local_port,
                        s.process_name.clone().unwrap_or_else(|| "unknown".into())
                    ),
                    "This listening socket was not present in the baseline.",
                )
                .evidence(format!("{}:{}", s.local_address, s.local_port))
                .mitre("T1571");
                if let Some(pid) = s.pid {
                    f = f.pid(pid);
                }
                out.push(f);
            }
        }
        for m in &r.modules {
            if !self.modules.contains(&m.name.to_ascii_lowercase()) {
                out.push(
                    Finding::new(
                        FindingCategory::BaselineDrift,
                        Severity::Medium,
                        &format!("drift-mod:{}", m.name.to_ascii_lowercase()),
                        format!("New kernel module/driver since baseline: {}", m.name),
                        "A kernel module or driver is loaded that was not present in the baseline.",
                    )
                    .path(m.path.clone().unwrap_or_default())
                    .mitre("T1547.006"),
                );
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{KernelModule, PersistenceEntry, Protocol, SocketInfo};

    fn report() -> ScanReport {
        ScanReport {
            persistence: vec![PersistenceEntry {
                mechanism: "cron".into(),
                location: "/etc/crontab".into(),
                target_path: "/x".into(),
                command: "/x".into(),
                risk_level: Severity::Info,
                reasons: vec![],
                modified: None,
            }],
            sockets: vec![SocketInfo {
                local_address: "0.0.0.0".into(),
                local_port: 22,
                remote_address: "0.0.0.0".into(),
                remote_port: 0,
                protocol: Protocol::Tcp,
                state: "LISTEN".into(),
                pid: Some(1),
                process_name: Some("sshd".into()),
                suspicious: false,
                hidden: false,
                reasons: vec![],
            }],
            modules: vec![KernelModule {
                name: "ext4".into(),
                path: None,
                size: 0,
                listed: true,
                corroborated: true,
                hidden: false,
                suspicious: false,
                reasons: vec![],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn drift_detects_new_items_only() {
        let r = report();
        let b = Baseline::from_report(&r);
        assert!(b.drift(&r).is_empty());
        let mut r2 = r.clone();
        r2.persistence.push(PersistenceEntry {
            mechanism: "systemd".into(),
            location: "/etc/systemd/system/evil.service".into(),
            target_path: "/tmp/e".into(),
            command: "/tmp/e".into(),
            risk_level: Severity::High,
            reasons: vec![],
            modified: None,
        });
        r2.modules.push(KernelModule {
            name: "diamorphine".into(),
            path: None,
            size: 0,
            listed: true,
            corroborated: true,
            hidden: false,
            suspicious: false,
            reasons: vec![],
        });
        let d = b.drift(&r2);
        assert_eq!(d.len(), 2);
        assert!(d.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn save_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("b.json");
        let b = Baseline::from_report(&report());
        b.save(&p).unwrap();
        assert_eq!(Baseline::load(&p).unwrap(), b);
    }
}
