//! Cross-Layer Truth Analysis: compare what each OS layer reports and turn
//! disagreements into findings.
//!
//! All functions here are pure so they can be unit tested without a live
//! system; race handling (re-verification) is driven by the scanner through
//! closures.

use super::heuristics::{self, NETCAT_NAMES, SHELL_NAMES};
use super::traits::{Finding, KernelModule, ProcessInfo, SocketInfo, Visibility};
use crate::model::{FindingCategory, Severity};
use std::collections::{HashMap, HashSet};

pub struct AnomalyAnalyzer;

/// Why a PID is considered hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhostKind {
    /// Missing from the libc/API view but present in the raw-syscall view:
    /// user-mode hooking (LD_PRELOAD, IAT/inline hooks).
    UserModeHook,
    /// Missing from every enumeration but provably alive: kernel-mode hiding
    /// (getdents hooks, DKOM unlinking).
    KernelHidden,
}

impl AnomalyAnalyzer {
    /// The blueprint's original primitive: kernel-visible processes absent
    /// from the user-space listing, marked discrepant.
    pub fn detect_ghost_processes(user_processes: &[ProcessInfo], kernel_processes: &[ProcessInfo]) -> Vec<ProcessInfo> {
        let user_pids: HashSet<u32> = user_processes.iter().map(|p| p.pid).collect();
        kernel_processes
            .iter()
            .filter(|kp| !user_pids.contains(&kp.pid))
            .map(|kp| {
                let mut ghost = kp.clone();
                ghost.is_discrepant = true;
                ghost
            })
            .collect()
    }

    /// Classify every PID seen by any layer. Returns `(pid, kind)` for
    /// candidates; the caller must confirm them (`confirm_ghosts`) because a
    /// process can legitimately start between two snapshots.
    pub fn classify_ghosts(api: &HashSet<u32>, syscall: &HashSet<u32>, brute: &HashSet<u32>, syscall_view_available: bool) -> Vec<(u32, GhostKind)> {
        let mut out: Vec<(u32, GhostKind)> = Vec::new();
        for &pid in brute.iter().chain(syscall.iter()) {
            if pid == 0 || api.contains(&pid) || out.iter().any(|(p, _)| *p == pid) {
                continue;
            }
            let kind = if syscall_view_available && syscall.contains(&pid) { GhostKind::UserModeHook } else { GhostKind::KernelHidden };
            out.push((pid, kind));
        }
        out.sort_unstable_by_key(|(p, _)| *p);
        out
    }

    /// Keep only candidates that are still alive and still missing after a
    /// fresh re-enumeration. Both checks are supplied by the engine.
    pub fn confirm_ghosts<A, R>(candidates: Vec<(u32, GhostKind)>, mut alive: A, mut reenumerate: R, rounds: usize) -> Vec<(u32, GhostKind)>
    where
        A: FnMut(u32) -> bool,
        R: FnMut() -> HashSet<u32>,
    {
        let mut remaining = candidates;
        for _ in 0..rounds {
            if remaining.is_empty() {
                break;
            }
            let fresh = reenumerate();
            remaining.retain(|(pid, _)| !fresh.contains(pid) && alive(*pid));
        }
        remaining
    }

    pub fn ghost_finding(p: &ProcessInfo, kind: GhostKind) -> Finding {
        let (title, desc, mitre) = match kind {
            GhostKind::UserModeHook => (
                format!("Process hidden from user-mode APIs: {} (PID {})", display_name(p), p.pid),
                "This process is visible through raw system calls but missing from the standard library / \
                 API enumeration. Something is hooking process listing in user mode (e.g. an LD_PRELOAD \
                 library or an injected API hook).",
                "T1574.006",
            ),
            GhostKind::KernelHidden => (
                format!("Kernel-hidden process: {} (PID {})", display_name(p), p.pid),
                "This PID answers direct probes of the PID space but is absent from every process \
                 enumeration. That is the signature of a kernel-mode rootkit (syscall table hooking or \
                 DKOM unlinking).",
                "T1014",
            ),
        };
        let mut f = Finding::new(FindingCategory::HiddenProcess, Severity::Critical, &format!("pid:{}:{}", p.pid, p.path), title, desc)
            .pid(p.pid)
            .path(p.path.clone())
            .mitre(mitre)
            .evidence(format!("visibility: api={} syscall={} brute_force={}", p.visibility.api, p.visibility.syscall, p.visibility.brute_force))
            .recommend(
                "Treat the host as compromised. Acquire memory and disk images before remediation, then \
                 rebuild from known-good media. Killing the process is a containment step only.",
            );
        if !p.cmdline.is_empty() {
            f = f.evidence(format!("cmdline: {}", p.cmdline));
        }
        if let Some(h) = &p.sha256 {
            f = f.evidence(format!("sha256: {h}"));
        }
        f
    }

    /// Merge views into one process list with visibility flags populated.
    pub fn merge_process_views(
        api: Vec<ProcessInfo>,
        syscall: &HashSet<u32>,
        brute: &HashSet<u32>,
        ghosts: &[(ProcessInfo, GhostKind)],
        syscall_view_available: bool,
    ) -> Vec<ProcessInfo> {
        let mut out: Vec<ProcessInfo> = api
            .into_iter()
            .map(|mut p| {
                p.visibility = Visibility {
                    api: true,
                    syscall: !syscall_view_available || syscall.contains(&p.pid),
                    brute_force: brute.is_empty() || brute.contains(&p.pid),
                };
                p
            })
            .collect();
        for (g, _) in ghosts {
            let mut g = g.clone();
            g.is_discrepant = true;
            g.visibility = Visibility { api: false, syscall: syscall.contains(&g.pid), brute_force: true };
            out.retain(|p| p.pid != g.pid);
            out.push(g);
        }
        out.sort_by(|a, b| b.is_discrepant.cmp(&a.is_discrepant).then(a.pid.cmp(&b.pid)));
        out
    }

    /// Socket heuristics: shells with sockets, netcat listeners, C2 ports,
    /// listeners owned by binaries in staging directories.
    pub fn analyze_sockets(sockets: &mut [SocketInfo], processes: &[ProcessInfo]) -> Vec<Finding> {
        let by_pid: HashMap<u32, &ProcessInfo> = processes.iter().map(|p| (p.pid, p)).collect();
        let mut findings = Vec::new();
        for s in sockets.iter_mut() {
            if s.process_name.is_none() {
                if let Some(p) = s.pid.and_then(|pid| by_pid.get(&pid)) {
                    s.process_name = Some(p.name.clone());
                }
            }
            if s.hidden {
                continue; // reported by `hidden_socket_findings`
            }
            let proc_ = s.pid.and_then(|pid| by_pid.get(&pid)).copied();
            let name = s.process_name.clone().unwrap_or_default().to_ascii_lowercase();
            let listening = s.state == "LISTEN" || (matches!(s.protocol, crate::model::Protocol::Udp | crate::model::Protocol::Udp6) && s.remote_port == 0);
            let established = s.state == "ESTABLISHED";
            let mut sev = Severity::Info;
            let mut mitre = "T1571";
            let mut reasons: Vec<String> = Vec::new();

            if SHELL_NAMES.contains(&name.as_str()) && (listening || established) && !s.is_loopback() {
                reasons.push(format!("command shell `{name}` owns a network socket (bind/reverse shell)"));
                sev = sev.max(Severity::Critical);
                mitre = "T1059";
            }
            if NETCAT_NAMES.contains(&name.as_str()) && (listening || established) {
                reasons.push(format!("`{name}` holding a network socket"));
                sev = sev.max(Severity::High);
                mitre = "T1059";
            }
            if established && !s.is_loopback() {
                if let Some(why) = heuristics::suspicious_remote_port(s.remote_port) {
                    reasons.push(format!("connected to remote port {} ({why})", s.remote_port));
                    sev = sev.max(Severity::Medium);
                }
            }
            if listening && !s.is_loopback() {
                if let Some(why) = heuristics::suspicious_listen_port(s.local_port) {
                    reasons.push(format!("listening on port {} ({why})", s.local_port));
                    sev = sev.max(Severity::High);
                }
            }
            if matches!(s.protocol, crate::model::Protocol::Packet | crate::model::Protocol::Raw) {
                let benign = [
                    "dhclient",
                    "dhcpcd",
                    "networkmanager",
                    "wpa_supplicant",
                    "systemd-network",
                    "tcpdump",
                    "dumpcap",
                    "wireshark",
                    "lldpd",
                    "keepalived",
                    "arping",
                    "ping",
                    "zeek",
                    "suricata",
                    "snort",
                    "udhcpc",
                    "systemd-networkd",
                    "dhcpd",
                    "avahi-autoipd",
                    "dnsmasq",
                    "hostapd",
                    "ladvd",
                    "chronyd",
                    "bird",
                    "ntpd",
                    "ndppd",
                    "ptp4l",
                ];
                if !benign.iter().any(|b| name.starts_with(b)) {
                    reasons.push(format!(
                        "{} socket held by `{}` — passive sniffing backdoors (e.g. BPFDoor) use raw/packet sockets to receive magic packets",
                        s.protocol,
                        if name.is_empty() { "unknown" } else { &name }
                    ));
                    sev = sev.max(Severity::High);
                    mitre = "T1205.002";
                }
            }
            if let Some(p) = proc_ {
                if listening || established {
                    let ind = if p.path.contains('\\') { heuristics::analyze_windows_path(&p.path) } else { heuristics::analyze_unix_path(&p.path) };
                    for i in ind.iter().filter(|i| i.severity >= Severity::Medium) {
                        reasons.push(format!("owning binary {}: {}", p.path, i.reason));
                        sev = sev.max(i.severity);
                    }
                    if p.path.ends_with(" (deleted)") {
                        reasons.push("owning binary has been deleted from disk".into());
                        sev = sev.max(Severity::High);
                    }
                }
            }

            if !reasons.is_empty() && sev >= Severity::Medium {
                s.suspicious = true;
                s.reasons = reasons.clone();
                let subject = format!("{}:{}:{}:{}", s.protocol, s.local_port, s.pid.unwrap_or(0), name);
                let mut f = Finding::new(
                    FindingCategory::SuspiciousSocket,
                    sev,
                    &subject,
                    format!(
                        "Suspicious {} socket {}:{} → {}:{} ({})",
                        s.protocol,
                        s.local_address,
                        s.local_port,
                        s.remote_address,
                        s.remote_port,
                        if name.is_empty() { "unknown process".to_string() } else { name.clone() }
                    ),
                    "A network socket matches indicators commonly associated with backdoors, remote shells or command-and-control traffic.",
                )
                .evidences(reasons)
                .mitre(mitre)
                .recommend(
                    "Identify the owning process and its parent chain, capture the connection (pcap), and block the remote endpoint if it is not expected.",
                );
                if let Some(pid) = s.pid {
                    f = f.pid(pid);
                }
                if let Some(p) = proc_ {
                    f = f.path(p.path.clone());
                }
                findings.push(f);
            }
        }
        findings
    }

    /// Ports the kernel reports as bound that no socket-table entry explains.
    pub fn hidden_ports(table: &[SocketInfo], bound: &[(crate::model::Protocol, u16)]) -> Vec<(crate::model::Protocol, u16)> {
        use crate::model::Protocol::*;
        let known: HashSet<(crate::model::Protocol, u16)> = table
            .iter()
            .filter_map(|s| match s.protocol {
                Tcp | Tcp6 => Some((Tcp, s.local_port)),
                Udp | Udp6 => Some((Udp, s.local_port)),
                _ => None,
            })
            .collect();
        bound
            .iter()
            .copied()
            .filter(|(proto, port)| {
                let fam = match proto {
                    Tcp | Tcp6 => Tcp,
                    Udp | Udp6 => Udp,
                    other => *other,
                };
                !known.contains(&(fam, *port))
            })
            .collect()
    }

    pub fn hidden_socket_finding(proto: crate::model::Protocol, port: u16) -> Finding {
        Finding::new(
            FindingCategory::HiddenSocket,
            Severity::Critical,
            &format!("{proto}:{port}"),
            format!("Hidden {} listener on port {}", proto, port),
            "The kernel refuses to bind this port because it is already in use, yet no entry in the system \
             socket table accounts for it. A rootkit is filtering the socket table to hide a listener.",
        )
        .evidence(format!("bind({proto} *:{port}) -> EADDRINUSE, absent from socket table on two consecutive reads"))
        .mitre("T1014")
        .recommend("Capture traffic to this port from another host (the local stack may be lying), then image the system for offline analysis.")
    }

    pub fn module_findings(modules: &[KernelModule]) -> Vec<Finding> {
        let mut out = Vec::new();
        for m in modules {
            if m.hidden {
                out.push(
                    Finding::new(
                        FindingCategory::HiddenModule,
                        Severity::Critical,
                        &format!("module:{}", m.name),
                        format!("Hidden kernel module: {}", m.name),
                        "This kernel module is present in one kernel view but removed from the primary module \
                         list — a classic loadable-kernel-module rootkit self-hiding technique.",
                    )
                    .evidences(m.reasons.clone())
                    .path(m.path.clone().unwrap_or_default())
                    .mitre("T1547.006")
                    .recommend("Reboot into trusted media and inspect the module on disk; do not trust the live kernel."),
                );
            } else if m.suspicious {
                let sev = if m.reasons.iter().any(|r| r.contains("staging") || r.contains("missing")) { Severity::High } else { Severity::Medium };
                out.push(
                    Finding::new(
                        FindingCategory::HiddenModule,
                        sev,
                        &format!("module-susp:{}", m.name),
                        format!("Suspicious kernel module/driver: {}", m.name),
                        "A loaded kernel module or driver has attributes that deviate from a normal, vendor-signed install.",
                    )
                    .evidences(m.reasons.clone())
                    .path(m.path.clone().unwrap_or_default())
                    .mitre("T1547.006")
                    .recommend("Verify the module/driver origin and signature; unload or blocklist it if it is not expected."),
                );
            }
        }
        out
    }

    /// 0..=100 risk score; any critical finding puts a host at >= 70.
    pub fn risk_score(findings: &[Finding]) -> u8 {
        let active = findings.iter().filter(|f| !f.suppressed);
        let mut total: u32 = 0;
        let mut has_critical = false;
        let mut has_high = false;
        for f in active {
            total += f.severity.weight();
            has_critical |= f.severity == Severity::Critical;
            has_high |= f.severity == Severity::High;
        }
        let mut score = total.min(100);
        if has_critical {
            score = score.max(70);
        } else if has_high {
            score = score.max(40);
        }
        score as u8
    }
}

fn display_name(p: &ProcessInfo) -> &str {
    if p.name.is_empty() {
        "<unknown>"
    } else {
        &p.name
    }
}

impl SocketInfo {
    pub fn is_loopback(&self) -> bool {
        let l = self.local_address.as_str();
        let loop_local = l.starts_with("127.") || l == "::1";
        let r = self.remote_address.as_str();
        let loop_remote = r.starts_with("127.") || r == "::1";
        loop_local && (self.state == "LISTEN" || loop_remote || self.remote_port == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;

    fn proc_(pid: u32, name: &str, path: &str) -> ProcessInfo {
        ProcessInfo { pid, name: name.into(), path: path.into(), ..Default::default() }
    }

    fn sock(proto: Protocol, port: u16, state: &str, pid: u32, rport: u16) -> SocketInfo {
        SocketInfo {
            local_address: "0.0.0.0".into(),
            local_port: port,
            remote_address: if rport == 0 { "0.0.0.0".into() } else { "203.0.113.7".into() },
            remote_port: rport,
            protocol: proto,
            state: state.into(),
            pid: Some(pid),
            process_name: None,
            suspicious: false,
            hidden: false,
            reasons: vec![],
        }
    }

    #[test]
    fn blueprint_ghost_detection() {
        let user = vec![proc_(1, "init", "/sbin/init")];
        let kernel = vec![proc_(1, "init", "/sbin/init"), proc_(1337, "phantom", "/tmp/p")];
        let ghosts = AnomalyAnalyzer::detect_ghost_processes(&user, &kernel);
        assert_eq!(ghosts.len(), 1);
        assert_eq!(ghosts[0].pid, 1337);
        assert!(ghosts[0].is_discrepant);
    }

    #[test]
    fn classify_and_confirm() {
        let api: HashSet<u32> = [1, 2, 3].into();
        let sys: HashSet<u32> = [1, 2, 3, 50].into();
        let brute: HashSet<u32> = [1, 2, 3, 50, 99, 100].into();
        let c = AnomalyAnalyzer::classify_ghosts(&api, &sys, &brute, true);
        assert_eq!(c, vec![(50, GhostKind::UserModeHook), (99, GhostKind::KernelHidden), (100, GhostKind::KernelHidden)]);
        // 100 exits, 99 shows up in a re-enumeration (was a race) -> only 50 survives.
        let confirmed = AnomalyAnalyzer::confirm_ghosts(c, |pid| pid != 100, || [1, 2, 3, 99].into(), 2);
        assert_eq!(confirmed, vec![(50, GhostKind::UserModeHook)]);
    }

    #[test]
    fn without_syscall_view_everything_is_kernel_hidden() {
        let api: HashSet<u32> = [4].into();
        let brute: HashSet<u32> = [4, 8].into();
        let c = AnomalyAnalyzer::classify_ghosts(&api, &HashSet::new(), &brute, false);
        assert_eq!(c, vec![(8, GhostKind::KernelHidden)]);
    }

    #[test]
    fn reverse_shell_socket_is_critical() {
        let procs = vec![proc_(10, "bash", "/usr/bin/bash"), proc_(11, "sshd", "/usr/sbin/sshd")];
        let mut socks = vec![sock(Protocol::Tcp, 40000, "ESTABLISHED", 10, 4444), sock(Protocol::Tcp, 22, "LISTEN", 11, 0)];
        let f = AnomalyAnalyzer::analyze_sockets(&mut socks, &procs);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(socks[0].suspicious && !socks[1].suspicious);
        assert_eq!(socks[1].process_name.as_deref(), Some("sshd"));
    }

    #[test]
    fn packet_socket_by_unknown_process() {
        let procs = vec![proc_(7, "kworkerd", "/usr/lib/kworkerd"), proc_(8, "dhclient", "/sbin/dhclient")];
        let mut socks = vec![sock(Protocol::Packet, 0, "-", 7, 0), sock(Protocol::Packet, 0, "-", 8, 0)];
        let f = AnomalyAnalyzer::analyze_sockets(&mut socks, &procs);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].pid, Some(7));
    }

    #[test]
    fn hidden_ports_ignore_known_and_family() {
        let table = vec![sock(Protocol::Tcp6, 22, "LISTEN", 1, 0), sock(Protocol::Udp, 53, "-", 2, 0)];
        let bound = vec![(Protocol::Tcp, 22), (Protocol::Tcp, 31337), (Protocol::Udp, 53), (Protocol::Udp, 9999)];
        assert_eq!(AnomalyAnalyzer::hidden_ports(&table, &bound), vec![(Protocol::Tcp, 31337), (Protocol::Udp, 9999)]);
    }

    #[test]
    fn risk_scores() {
        assert_eq!(AnomalyAnalyzer::risk_score(&[]), 0);
        let low = Finding::new(FindingCategory::Persistence, Severity::Low, "a", "t", "d");
        assert_eq!(AnomalyAnalyzer::risk_score(&[low]), 1);
        let crit = Finding::new(FindingCategory::HiddenProcess, Severity::Critical, "b", "t", "d");
        assert!(AnomalyAnalyzer::risk_score(std::slice::from_ref(&crit)) >= 70);
        let mut sup = crit;
        sup.suppressed = true;
        assert_eq!(AnomalyAnalyzer::risk_score(&[sup]), 0);
    }

    #[test]
    fn finding_ids_are_stable() {
        let a = Finding::new(FindingCategory::Persistence, Severity::Low, "x", "t", "d");
        let b = Finding::new(FindingCategory::Persistence, Severity::High, "x", "t2", "d2");
        assert_eq!(a.id, b.id);
        assert!(a.id.starts_with("persistence-"));
    }
}
