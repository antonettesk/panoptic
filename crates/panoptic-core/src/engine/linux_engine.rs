//! Linux implementation of Cross-Layer Truth Analysis.
//!
//! Process views:
//! * **api**     – `std::fs::read_dir("/proc")` → libc `readdir`; hookable by LD_PRELOAD.
//! * **syscall** – raw `openat` + `getdents64` syscalls; bypasses libc, hookable only in-kernel.
//! * **brute**   – `tgkill(pid, pid, 0)` across the whole PID space; answers truthfully
//!   for every live thread-group leader even when getdents is hooked by an LKM.
//!
//! Network truth: `/proc/net/*` vs. kernel `bind()` refusals.
//! Module truth: `/proc/modules` vs. `/sys/module/*/initstate`.

use super::heuristics::{self, analyze_command, analyze_unix_path, max_severity, Indicator};
use super::traits::*;
use crate::model::{FindingCategory, Severity};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct LinuxEngine {
    clk_tck: u64,
    page_size: u64,
}

impl Default for LinuxEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxEngine {
    pub fn new() -> Self {
        // SAFETY: sysconf is always safe to call.
        let clk = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        LinuxEngine { clk_tck: if clk > 0 { clk as u64 } else { 100 }, page_size: if page > 0 { page as u64 } else { 4096 } }
    }

    fn pid_max(&self) -> u32 {
        read_trim("/proc/sys/kernel/pid_max").and_then(|s| s.parse().ok()).unwrap_or(4_194_304).clamp(32_768, 4_194_304)
    }

    fn boot_time(&self) -> u64 {
        fs::read_to_string("/proc/stat").ok().and_then(|s| s.lines().find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse().ok()))).unwrap_or(0)
    }

    /// Build a ProcessInfo by reading `/proc/<pid>`. Returns `None` if the
    /// process vanished.
    fn read_process(&self, pid: u32, users: &HashMap<u32, String>, btime: u64) -> Option<(ProcessInfo, u64)> {
        let base = PathBuf::from(format!("/proc/{pid}"));
        let stat = fs::read_to_string(base.join("stat")).ok()?;
        let st = parse_stat(&stat)?;
        let exe = fs::read_link(base.join("exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let cmdline = fs::read(base.join("cmdline")).map(|b| cmdline_to_string(&b)).unwrap_or_default();
        let uid = fs::read_to_string(base.join("status"))
            .ok()
            .and_then(|s| status_field(&s, "Uid").and_then(|v| v.split_whitespace().next().and_then(|x| x.parse::<u32>().ok())));
        let rss_pages = fs::read_to_string(base.join("statm")).ok().and_then(|s| s.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok())).unwrap_or(0);
        let is_kthread = exe.is_empty() && cmdline.is_empty() && (st.ppid == 2 || pid == 2);
        let name = if is_kthread { format!("[{}]", st.comm) } else { st.comm.clone() };
        let info = ProcessInfo {
            pid,
            ppid: Some(st.ppid),
            name,
            path: exe,
            cmdline,
            user: uid.map(|u| users.get(&u).cloned().unwrap_or_else(|| u.to_string())),
            cpu_usage: 0.0,
            memory_bytes: rss_pages * self.page_size,
            start_time: btime + st.starttime / self.clk_tck,
            is_discrepant: false,
            visibility: Visibility::default(),
            flags: Vec::new(),
            sha256: None,
        };
        Some((info, st.utime + st.stime))
    }

    fn start_time_of(&self, pid: u32) -> Option<u64> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let st = parse_stat(&stat)?;
        Some(self.boot_time() + st.starttime / self.clk_tck)
    }

    fn socket_inode_owners(&self) -> HashMap<u64, u32> {
        let mut map = HashMap::new();
        let Ok(rd) = fs::read_dir("/proc") else { return map };
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            let Ok(fds) = fs::read_dir(e.path().join("fd")) else { continue };
            for fd in fds.flatten() {
                if let Ok(target) = fs::read_link(fd.path()) {
                    let t = target.to_string_lossy();
                    if let Some(inode) = t.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')).and_then(|n| n.parse::<u64>().ok()) {
                        map.entry(inode).or_insert(pid);
                    }
                }
            }
        }
        map
    }

    fn comm_of(&self, pid: u32) -> Option<String> {
        read_trim(&format!("/proc/{pid}/comm"))
    }
}

impl TruthEngine for LinuxEngine {
    fn name(&self) -> &'static str {
        "linux-procfs"
    }

    fn is_elevated(&self) -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    fn scan_user_space(&self) -> EngineResult<Vec<ProcessInfo>> {
        let users = passwd_users();
        let btime = self.boot_time();
        let pids: Vec<u32> = fs::read_dir("/proc")?.flatten().filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok())).collect();

        let t0 = Instant::now();
        let mut first: HashMap<u32, (ProcessInfo, u64)> = HashMap::with_capacity(pids.len());
        for pid in &pids {
            if let Some(v) = self.read_process(*pid, &users, btime) {
                first.insert(*pid, v);
            }
        }
        // Second CPU sample.
        std::thread::sleep(Duration::from_millis(250));
        let elapsed = t0.elapsed().as_secs_f32().max(0.001);
        let mut out = Vec::with_capacity(first.len());
        for (pid, (mut info, ticks0)) in first {
            if let Some(st) = fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| parse_stat(&s)) {
                let dt = (st.utime + st.stime).saturating_sub(ticks0) as f32;
                info.cpu_usage = (dt / self.clk_tck as f32) / elapsed * 100.0;
            }
            out.push(info);
        }
        out.sort_by_key(|p| p.pid);
        Ok(out)
    }

    fn api_pids(&self) -> EngineResult<Vec<u32>> {
        Ok(fs::read_dir("/proc")?.flatten().filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok())).collect())
    }

    fn scan_syscall_view(&self) -> EngineResult<Vec<u32>> {
        raw_getdents_pids("/proc\0")
    }

    fn scan_kernel_reality(&self, cancel: &CancelToken) -> EngineResult<Vec<ProcessInfo>> {
        let max = self.pid_max();
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 16) as u32;
        let chunk = max.div_ceil(threads);
        let mut pids: Vec<u32> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..threads)
                .map(|i| {
                    s.spawn(move || {
                        let mut v = Vec::new();
                        let start = (i * chunk).max(1);
                        let end = ((i + 1) * chunk).min(max + 1);
                        for pid in start..end {
                            if pid % 65_536 == 0 && cancel.is_cancelled() {
                                break;
                            }
                            if tgkill_probe(pid) {
                                v.push(pid);
                            }
                        }
                        v
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
        });
        cancel.check()?;
        pids.sort_unstable();
        let users = passwd_users();
        let btime = self.boot_time();
        Ok(pids
            .into_iter()
            .map(|pid| {
                self.read_process(pid, &users, btime).map(|(p, _)| p).unwrap_or(ProcessInfo {
                    pid,
                    name: self.comm_of(pid).unwrap_or_default(),
                    ..Default::default()
                })
            })
            .collect())
    }

    fn pid_alive(&self, pid: u32) -> bool {
        tgkill_probe(pid)
    }

    fn scan_network_sockets(&self) -> EngineResult<Vec<SocketInfo>> {
        let owners = self.socket_inode_owners();
        let mut out = Vec::new();
        let mut any_ok = false;
        for (file, proto) in [
            ("/proc/net/tcp", Protocol::Tcp),
            ("/proc/net/tcp6", Protocol::Tcp6),
            ("/proc/net/udp", Protocol::Udp),
            ("/proc/net/udp6", Protocol::Udp6),
            ("/proc/net/raw", Protocol::Raw),
            ("/proc/net/raw6", Protocol::Raw),
        ] {
            let Ok(content) = fs::read_to_string(file) else { continue };
            any_ok = true;
            for row in parse_proc_net(&content, proto) {
                let pid = owners.get(&row.inode).copied();
                out.push(SocketInfo {
                    local_address: row.local_ip,
                    local_port: row.local_port,
                    remote_address: row.remote_ip,
                    remote_port: row.remote_port,
                    protocol: proto,
                    state: row.state,
                    pid,
                    process_name: pid.and_then(|p| self.comm_of(p)),
                    suspicious: false,
                    hidden: false,
                    reasons: Vec::new(),
                });
            }
        }
        if let Ok(content) = fs::read_to_string("/proc/net/packet") {
            for inode in parse_packet_inodes(&content) {
                let pid = owners.get(&inode).copied();
                out.push(SocketInfo {
                    local_address: "*".into(),
                    local_port: 0,
                    remote_address: "*".into(),
                    remote_port: 0,
                    protocol: Protocol::Packet,
                    state: "-".into(),
                    pid,
                    process_name: pid.and_then(|p| self.comm_of(p)),
                    suspicious: false,
                    hidden: false,
                    reasons: Vec::new(),
                });
            }
        }
        if !any_ok {
            return Err(EngineError::ApiError("/proc/net is unreadable".into()));
        }
        Ok(out)
    }

    fn scan_persistence(&self) -> EngineResult<Vec<PersistenceEntry>> {
        let mut out = Vec::new();
        let homes = home_dirs();

        // --- cron
        for f in ["/etc/crontab", "/etc/anacrontab"] {
            cron_file(Path::new(f), "cron", true, &mut out);
        }
        for d in ["/etc/cron.d"] {
            for f in list_files(d) {
                cron_file(&f, "cron", true, &mut out);
            }
        }
        for d in ["/var/spool/cron/crontabs", "/var/spool/cron"] {
            for f in list_files(d) {
                cron_file(&f, "cron-user", false, &mut out);
            }
        }
        for d in ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"] {
            for f in list_files(d) {
                script_file(&f, "cron-periodic", &mut out);
            }
        }
        for f in list_files("/var/spool/cron/atjobs").into_iter().chain(list_files("/var/spool/at")) {
            script_file(&f, "at-job", &mut out);
        }

        // --- systemd (admin + user units; vendor units are checked only for suspicious content)
        let mut unit_dirs: Vec<PathBuf> =
            ["/etc/systemd/system", "/usr/local/lib/systemd/system", "/etc/systemd/user", "/run/systemd/system"].iter().map(PathBuf::from).collect();
        for h in &homes {
            unit_dirs.push(h.join(".config/systemd/user"));
        }
        for d in &unit_dirs {
            for f in walk(d, 3) {
                systemd_unit(&f, false, &mut out);
            }
        }
        for d in ["/lib/systemd/system", "/usr/lib/systemd/system"] {
            for f in walk(Path::new(d), 2) {
                systemd_unit(&f, true, &mut out);
            }
        }
        for f in walk(Path::new("/etc/systemd/system-generators"), 1).into_iter().chain(walk(Path::new("/usr/local/lib/systemd/system-generators"), 1)) {
            script_file(&f, "systemd-generator", &mut out);
        }

        // --- SysV / rc
        script_file(Path::new("/etc/rc.local"), "rc.local", &mut out);
        for f in list_files("/etc/init.d") {
            script_scan_only(&f, "init.d", &mut out);
        }

        // --- shell startup files
        let mut shell_files: Vec<PathBuf> =
            ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc", "/etc/zshrc", "/etc/environment"].iter().map(PathBuf::from).collect();
        shell_files.extend(list_files("/etc/profile.d"));
        for h in &homes {
            for f in [".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".bash_logout", ".config/fish/config.fish"] {
                shell_files.push(h.join(f));
            }
        }
        for f in shell_files {
            script_scan_only(&f, "shell-profile", &mut out);
        }

        // --- loader
        if let Some(c) = read_config(Path::new("/etc/ld.so.preload")) {
            for lib in c.split_whitespace().filter(|l| !l.starts_with('#')) {
                out.push(PersistenceEntry {
                    mechanism: "ld.so.preload".into(),
                    location: "/etc/ld.so.preload".into(),
                    target_path: lib.into(),
                    command: lib.into(),
                    risk_level: Severity::Critical,
                    reasons: vec!["library force-loaded into every dynamically linked process".into()],
                    modified: mtime(Path::new("/etc/ld.so.preload")),
                });
            }
        }

        // --- XDG autostart
        let mut autostart: Vec<PathBuf> = list_files("/etc/xdg/autostart");
        for h in &homes {
            autostart.extend(list_files(h.join(".config/autostart")));
        }
        for f in autostart {
            desktop_entry(&f, &mut out);
        }

        // --- SSH authorized_keys
        for h in &homes {
            let f = h.join(".ssh/authorized_keys");
            if let Some(c) = read_config(&f) {
                for line in c.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                    let mut reasons = Vec::new();
                    let mut risk = Severity::Info;
                    if line.contains("command=") {
                        reasons.push("forced command executes on login".into());
                        risk = Severity::Medium;
                    }
                    let mut ind = analyze_command(line);
                    if !ind.is_empty() {
                        risk = risk.max(max_severity(&ind));
                        reasons.extend(ind.drain(..).map(|i| i.reason));
                    }
                    let comment = line.split_whitespace().last().unwrap_or("");
                    out.push(PersistenceEntry {
                        mechanism: "ssh-authorized-key".into(),
                        location: f.display().to_string(),
                        target_path: comment.into(),
                        command: truncate(line, 160),
                        risk_level: risk,
                        reasons,
                        modified: mtime(&f),
                    });
                }
            }
        }

        // --- udev, motd, modules-load, PAM
        for f in list_files("/etc/udev/rules.d") {
            if let Some(c) = read_config(&f) {
                for line in c.lines().filter(|l| l.contains("RUN+=") || l.contains("RUN=") || l.contains("PROGRAM=")) {
                    let mut ind = analyze_command(line);
                    for p in extract_paths(line) {
                        ind.extend(analyze_unix_path(&p));
                    }
                    push_entry(&mut out, "udev-rule", &f, line.trim(), ind, Severity::Low);
                }
            }
        }
        for f in list_files("/etc/update-motd.d") {
            script_scan_only(&f, "motd", &mut out);
        }
        for f in std::iter::once(PathBuf::from("/etc/modules")).chain(list_files("/etc/modules-load.d")) {
            if let Some(c) = read_config(&f) {
                for m in c.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                    out.push(PersistenceEntry {
                        mechanism: "kernel-module-autoload".into(),
                        location: f.display().to_string(),
                        target_path: m.into(),
                        command: m.into(),
                        risk_level: Severity::Info,
                        reasons: vec![],
                        modified: mtime(&f),
                    });
                }
            }
        }
        for f in list_files("/etc/pam.d") {
            if let Some(c) = read_config(&f) {
                for line in c.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
                    let mut ind: Vec<Indicator> = Vec::new();
                    if line.contains("pam_exec.so") {
                        ind.push(Indicator { severity: Severity::Medium, reason: "pam_exec runs a program during authentication".into() });
                    }
                    for p in extract_paths(line).iter().filter(|p| p.ends_with(".so")) {
                        let std_dir = ["/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"].iter().any(|d| p.starts_with(d));
                        if !std_dir {
                            ind.push(Indicator { severity: Severity::High, reason: format!("PAM module loaded from non-standard path {p}") });
                        }
                    }
                    if !ind.is_empty() {
                        push_entry(&mut out, "pam", &f, line, ind, Severity::Info);
                    }
                }
            }
        }

        // Recency bump: anything touched in the last 7 days that already has
        // a reason gets one severity step.
        let now = now_secs();
        for e in &mut out {
            if let Some(m) = e.modified {
                if now.saturating_sub(m) < 7 * 86_400 && e.risk_level >= Severity::Low && e.risk_level < Severity::Critical {
                    e.risk_level = e.risk_level.bump();
                    e.reasons.push("modified within the last 7 days".into());
                }
            }
        }
        Ok(out)
    }

    fn scan_kernel_modules(&self) -> EngineResult<Vec<KernelModule>> {
        let content = fs::read_to_string("/proc/modules")?;
        let listed = parse_proc_modules(&content);
        let listed_names: HashSet<String> = listed.iter().map(|m| m.name.clone()).collect();
        let mut out = Vec::new();
        const VENDOR: &[&str] = &[
            "nvidia",
            "vbox",
            "zfs",
            "spl",
            "v4l2loopback",
            "wireguard",
            "vmw",
            "vmmon",
            "vmnet",
            "falcon",
            "crowdstrike",
            "sentinel",
            "evdi",
            "displaylink",
            "acpi_call",
            "tp_smapi",
            "rtl",
            "r8",
            "8821",
            "88x2",
            "bbswitch",
            "ddcci",
            "lttng",
            "sysdig",
            "scap",
            "openafs",
            "veeam",
            "blksnap",
            "dattobd",
            "xone",
            "hid_xpadneo",
        ];
        for m in &listed {
            let sys = Path::new("/sys/module").join(&m.name);
            let corroborated = sys.exists();
            let mut reasons = Vec::new();
            let mut suspicious = false;
            if !corroborated {
                reasons.push("listed in /proc/modules but has no /sys/module kobject (kobject removed)".into());
                suspicious = true;
            }
            let unsigned = m.taint.contains('E');
            let oot = m.taint.contains('O');
            if unsigned && oot && !VENDOR.iter().any(|v| m.name.starts_with(v)) {
                reasons.push(format!("unsigned out-of-tree module (taint flags `{}`)", m.taint));
                suspicious = true;
            }
            if m.taint.contains('F') {
                reasons.push("module was force-loaded".into());
                suspicious = true;
            }
            out.push(KernelModule { name: m.name.clone(), path: None, size: m.size, listed: true, corroborated, hidden: false, suspicious, reasons });
        }
        if let Ok(rd) = fs::read_dir("/sys/module") {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if listed_names.contains(&name) {
                    continue;
                }
                // Built-in modules have no initstate; loadable ones always do.
                if let Some(state) = read_trim(&e.path().join("initstate").to_string_lossy()) {
                    if state == "live" || state == "coming" {
                        let size = read_trim(&e.path().join("coresize").to_string_lossy()).and_then(|s| s.parse().ok()).unwrap_or(0);
                        out.push(KernelModule {
                            name: name.clone(),
                            path: None,
                            size,
                            listed: false,
                            corroborated: true,
                            hidden: true,
                            suspicious: true,
                            reasons: vec![format!("/sys/module/{name}/initstate = {state}, but the module is missing from /proc/modules")],
                        });
                    }
                }
            }
        }
        out.sort_by(|a, b| b.hidden.cmp(&a.hidden).then(b.suspicious.cmp(&a.suspicious)).then(a.name.cmp(&b.name)));
        Ok(out)
    }

    fn inspect_processes(&self, processes: &[ProcessInfo]) -> Vec<Finding> {
        let mut out = Vec::new();
        const KTHREAD_PREFIXES: &[&str] = &[
            "kworker",
            "ksoftirqd",
            "kthreadd",
            "migration/",
            "rcu_",
            "irq/",
            "watchdog",
            "kswapd",
            "jbd2/",
            "kauditd",
            "khungtaskd",
            "kblockd",
            "kcompactd",
            "cpuhp/",
            "kdevtmpfs",
        ];
        const PROTECTED: &[&str] = &[
            "sshd",
            "systemd",
            "cron",
            "crond",
            "init",
            "dbus-daemon",
            "rsyslogd",
            "nginx",
            "apache2",
            "httpd",
            "containerd",
            "dockerd",
            "agetty",
            "login",
            "polkitd",
            "auditd",
        ];
        for p in processes.iter().filter(|p| !p.is_discrepant) {
            let mut ind: Vec<Indicator> = Vec::new();
            let mut mitre = "T1036";
            let argv0 = p.cmdline.split(' ').next().unwrap_or("");
            let comm = p.name.trim_start_matches('[').trim_end_matches(']');

            if p.path.starts_with("/memfd:") || p.path.starts_with("memfd:") {
                ind.push(Indicator { severity: Severity::Critical, reason: format!("fileless: executing from anonymous memory ({})", p.path) });
                mitre = "T1620";
            } else if let Some(orig) = p.path.strip_suffix(" (deleted)") {
                let pkg = ["/usr/", "/opt/", "/snap/", "/lib/", "/bin/", "/sbin/"].iter().any(|d| orig.starts_with(d));
                if pkg {
                    ind.push(Indicator {
                        severity: Severity::Low,
                        reason: format!("binary {orig} was replaced on disk (likely a package upgrade; restart the service)"),
                    });
                } else {
                    ind.push(Indicator { severity: Severity::High, reason: format!("running binary {orig} has been deleted from disk") });
                    mitre = "T1070.004";
                }
                ind.extend(analyze_unix_path(orig));
            } else {
                ind.extend(analyze_unix_path(&p.path));
            }

            if !p.path.is_empty() {
                let looks_kthread = argv0.starts_with('[') && argv0.ends_with(']') || KTHREAD_PREFIXES.iter().any(|k| comm.starts_with(k));
                if looks_kthread {
                    ind.push(Indicator {
                        severity: Severity::Critical,
                        reason: format!("user-space process (exe {}) masquerading as kernel thread `{}`", p.path, p.name),
                    });
                    mitre = "T1036.004";
                }
                if PROTECTED.contains(&comm) {
                    let exe_name = heuristics::file_name(p.path.trim_end_matches(" (deleted)"));
                    if !exe_name.starts_with(comm) && !(comm == "init" && exe_name == "systemd") && !(comm == "systemd" && exe_name.starts_with("systemd")) {
                        ind.push(Indicator { severity: Severity::High, reason: format!("process named `{comm}` is actually {}", p.path) });
                        mitre = "T1036.005";
                    }
                }
            }

            for i in analyze_command(&p.cmdline) {
                if !ind.iter().any(|x| x.reason == i.reason) {
                    ind.push(i);
                }
            }

            // LD_PRELOAD in the environment and injected libraries.
            if let Ok(env) = fs::read(format!("/proc/{}/environ", p.pid)) {
                for var in env.split(|b| *b == 0) {
                    if let Some(v) = var.strip_prefix(b"LD_PRELOAD=") {
                        let v = String::from_utf8_lossy(v).into_owned();
                        if !v.trim().is_empty() && !v.contains("libgtk3-nocsd") && !v.contains("libfakeroot") && !v.contains("faketime") {
                            let sev = if v.split([':', ' ']).any(|l| !analyze_unix_path(l).is_empty()) { Severity::Critical } else { Severity::High };
                            ind.push(Indicator { severity: sev, reason: format!("LD_PRELOAD={v}") });
                            mitre = "T1574.006";
                        }
                    }
                }
            }
            if let Ok(maps) = fs::read_to_string(format!("/proc/{}/maps", p.pid)) {
                for lib in suspicious_mappings(&maps) {
                    ind.push(Indicator { severity: Severity::High, reason: format!("maps shared object from suspicious location: {lib}") });
                    mitre = "T1055";
                }
            }

            ind.dedup_by(|a, b| a.reason == b.reason);
            let sev = max_severity(&ind);
            if sev >= Severity::Medium {
                let mut f = Finding::new(
                    FindingCategory::ProcessAnomaly,
                    sev,
                    &format!("proc:{}:{}", p.name, p.path),
                    format!("Suspicious process: {} (PID {})", p.name, p.pid),
                    "This process exhibits behaviour associated with malware execution, masquerading or code injection.",
                )
                .pid(p.pid)
                .path(p.path.clone())
                .mitre(mitre)
                .evidences(ind.iter().map(|i| i.reason.clone()))
                .recommend("Review the process tree and binary. Suspend (SIGSTOP) it to preserve memory for forensics before terminating.");
                if !p.cmdline.is_empty() {
                    f = f.evidence(format!("cmdline: {}", truncate(&p.cmdline, 300)));
                }
                out.push(f);
            }
        }
        out
    }

    fn integrity_checks(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        if let Some(c) = read_config(Path::new("/etc/ld.so.preload")) {
            let libs: Vec<&str> = c.split_whitespace().filter(|l| !l.starts_with('#')).collect();
            if !libs.is_empty() {
                out.push(
                    Finding::new(
                        FindingCategory::LoaderHijack,
                        Severity::Critical,
                        "/etc/ld.so.preload",
                        "Global library preload configured (/etc/ld.so.preload)",
                        "Every dynamically linked program on this system loads these libraries first. This is the \
                         primary persistence and hiding mechanism of user-mode Linux rootkits (Jynx, Azazel, \
                         libprocesshider) and is almost never used legitimately.",
                    )
                    .evidences(libs.iter().map(|l| format!("preloaded: {l}")))
                    .path("/etc/ld.so.preload")
                    .mitre("T1574.006")
                    .recommend("Inspect the listed libraries from a static binary or trusted media, then remove the file."),
                );
            }
        }
        if let Ok(v) = std::env::var("LD_PRELOAD") {
            if !v.trim().is_empty() {
                out.push(
                    Finding::new(
                        FindingCategory::LoaderHijack,
                        Severity::High,
                        "self-ld-preload",
                        "Panoptic itself was started with LD_PRELOAD",
                        "A library was injected into the scanner. User-mode views may be falsified; rely on syscall and brute-force views.",
                    )
                    .evidence(format!("LD_PRELOAD={v}"))
                    .mitre("T1574.006"),
                );
            }
        }
        if let Some(t) = read_trim("/proc/sys/kernel/tainted").and_then(|s| s.parse::<u64>().ok()) {
            let flags = decode_taint(t);
            let serious: Vec<&str> = flags.iter().filter(|(bit, _)| matches!(bit, 1 | 12 | 13)).map(|(_, d)| *d).collect();
            if !serious.is_empty() {
                out.push(
                    Finding::new(
                        FindingCategory::KernelIntegrity,
                        Severity::Medium,
                        &format!("taint:{t}"),
                        format!("Kernel is tainted (value {t})"),
                        "The running kernel has loaded code outside the trusted, signed module set. LKM rootkits leave this trace even after hiding themselves.",
                    )
                    .evidences(flags.iter().map(|(b, d)| format!("bit {b}: {d}")))
                    .mitre("T1547.006")
                    .recommend("Correlate with the module list; if no known vendor driver explains the taint, investigate offline."),
                );
            }
        }
        // Known rootkit artefacts.
        const IOC_PATHS: &[(&str, &str)] = &[
            ("/reptile", "Reptile LKM rootkit directory"),
            ("/lib/udev/reptile", "Reptile LKM rootkit loader"),
            ("/XxJynx", "Jynx2 rootkit directory"),
            ("/lib/libselinux.so.1.so", "Azazel-style preload library"),
            ("/usr/lib/libgdi.so.0.8.2", "Kinsing/BPF malware library"),
            ("/dev/shm/kdevtmpfsi", "Kinsing cryptominer"),
            ("/tmp/kdevtmpfsi", "Kinsing cryptominer"),
            ("/tmp/kinsing", "Kinsing malware"),
            ("/var/tmp/kinsing", "Kinsing malware"),
            ("/dev/shm/kinsing", "Kinsing malware"),
            ("/var/run/haldrund.pid", "BPFDoor mutex file"),
            ("/var/run/hald-addon.pid", "BPFDoor mutex file"),
            ("/var/run/hald-smartd.pid", "BPFDoor mutex file"),
            ("/var/run/system.pid", "BPFDoor mutex file"),
            ("/var/run/xinetd.lock", "BPFDoor mutex file"),
            ("/var/run/kdevrund.pid", "BPFDoor mutex file"),
            ("/usr/bin/.sshd", "hidden sshd backdoor"),
            ("/dev/.udev/.lib", "Ebury/rootkit staging"),
        ];
        for (path, what) in IOC_PATHS {
            if Path::new(path).exists() {
                out.push(
                    Finding::new(
                        FindingCategory::KernelIntegrity,
                        Severity::Critical,
                        &format!("ioc:{path}"),
                        format!("Known malware artefact present: {path}"),
                        format!("{what} — a file path published as an indicator of compromise exists on this host."),
                    )
                    .path(*path)
                    .mitre("T1014")
                    .recommend("Isolate the host and perform full incident response."),
                );
            }
        }
        // Promiscuous interfaces => sniffing.
        if let Ok(rd) = fs::read_dir("/sys/class/net") {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if let Some(flags) = read_trim(&e.path().join("flags").to_string_lossy()).and_then(|f| u32::from_str_radix(f.trim_start_matches("0x"), 16).ok())
                {
                    if flags & 0x100 != 0 && !name.starts_with("veth") && !name.starts_with("docker") && !name.starts_with("br-") && !name.starts_with("virbr")
                    {
                        out.push(
                            Finding::new(
                                FindingCategory::KernelIntegrity,
                                Severity::Medium,
                                &format!("promisc:{name}"),
                                format!("Interface {name} is in promiscuous mode"),
                                "A network interface is capturing all traffic on its segment, indicating a sniffer.",
                            )
                            .evidence(format!("/sys/class/net/{name}/flags = {flags:#x}"))
                            .mitre("T1040"),
                        );
                    }
                }
            }
        }
        out
    }

    fn act_on_process(&self, pid: u32, expected_start_time: u64, action: ProcessAction) -> EngineResult<()> {
        if pid <= 2 {
            return Err(EngineError::Refused(format!("PID {pid} is a core system process")));
        }
        if pid == std::process::id() {
            return Err(EngineError::Refused("refusing to act on Panoptic itself".into()));
        }
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| parse_stat(&s));
        if let Some(st) = &stat {
            if st.ppid == 2 {
                return Err(EngineError::Refused(format!("PID {pid} is a kernel thread")));
            }
        } else if !tgkill_probe(pid) {
            return Err(EngineError::NotFound(pid));
        }
        if expected_start_time != 0 {
            if let Some(actual) = self.start_time_of(pid) {
                // starttime is in clock ticks; allow 1s of rounding.
                if actual.abs_diff(expected_start_time) > 1 {
                    return Err(EngineError::Refused(format!("PID {pid} was reused by a different process (start time changed)")));
                }
            }
        }
        let sig = match action {
            ProcessAction::Terminate => libc::SIGKILL,
            ProcessAction::Suspend => libc::SIGSTOP,
            ProcessAction::Resume => libc::SIGCONT,
        };
        // SAFETY: plain syscall; arguments are integers.
        let rc = unsafe { libc::syscall(libc::SYS_kill, pid as libc::pid_t, sig) };
        if rc == 0 {
            Ok(())
        } else {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EPERM) => Err(EngineError::PermissionDenied),
                Some(libc::ESRCH) => Err(EngineError::NotFound(pid)),
                _ => Err(EngineError::ApiError(std::io::Error::last_os_error().to_string())),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Low-level probes

/// True when `pid` is a live thread-group leader. `tgkill(pid, pid, 0)`
/// fails with ESRCH for non-existent PIDs *and* for plain thread IDs, so
/// threads (which `kill(tid, 0)` would accept) never show up as ghosts.
fn tgkill_probe(pid: u32) -> bool {
    // SAFETY: signal 0 performs only the existence/permission check.
    let rc = unsafe { libc::syscall(libc::SYS_tgkill, pid as libc::pid_t, pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Enumerate numeric directory entries of `path` with raw syscalls only.
fn raw_getdents_pids(path_nul: &str) -> EngineResult<Vec<u32>> {
    // SAFETY: path is NUL terminated; flags are valid; fd is closed below.
    let fd = unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path_nul.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC, 0) };
    if fd < 0 {
        return Err(EngineError::ApiError(format!("openat(/proc): {}", std::io::Error::last_os_error())));
    }
    let fd = fd as libc::c_int;
    let mut buf = vec![0u8; 64 * 1024];
    let mut pids = Vec::new();
    loop {
        // SAFETY: buf is valid for buf.len() bytes.
        let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::syscall(libc::SYS_close, fd) };
            return Err(EngineError::ApiError(format!("getdents64: {err}")));
        }
        if n == 0 {
            break;
        }
        pids.extend(parse_dirents(&buf[..n as usize]));
    }
    unsafe { libc::syscall(libc::SYS_close, fd) };
    pids.sort_unstable();
    Ok(pids)
}

/// Parse a `linux_dirent64` buffer and return numeric names.
fn parse_dirents(buf: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 19 <= buf.len() {
        let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
        if reclen == 0 || off + reclen > buf.len() {
            break;
        }
        let name_bytes = &buf[off + 19..off + reclen];
        let end = name_bytes.iter().position(|b| *b == 0).unwrap_or(name_bytes.len());
        if let Some(pid) = std::str::from_utf8(&name_bytes[..end]).ok().and_then(|s| s.parse::<u32>().ok()) {
            out.push(pid);
        }
        off += reclen;
    }
    out
}

// ---------------------------------------------------------------------------
// Pure parsers (unit tested)

#[derive(Debug, PartialEq)]
pub(crate) struct Stat {
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub utime: u64,
    pub stime: u64,
    pub starttime: u64,
}

/// Parse `/proc/<pid>/stat`. `comm` may contain spaces and parentheses, so
/// split on the *last* `)`.
pub(crate) fn parse_stat(s: &str) -> Option<Stat> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let comm = s.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = s.get(close + 2..)?.split_whitespace().collect();
    // rest[0] = state (field 3); utime = field 14 -> rest[11]; stime rest[12]; starttime field 22 -> rest[19]
    Some(Stat {
        comm,
        state: rest.first()?.chars().next()?,
        ppid: rest.get(1)?.parse().ok()?,
        utime: rest.get(11)?.parse().ok()?,
        stime: rest.get(12)?.parse().ok()?,
        starttime: rest.get(19)?.parse().ok()?,
    })
}

pub(crate) fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status.lines().find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(':')).map(str::trim))
}

pub(crate) fn cmdline_to_string(b: &[u8]) -> String {
    let s: Vec<String> = b.split(|c| *c == 0).filter(|p| !p.is_empty()).map(|p| String::from_utf8_lossy(p).into_owned()).collect();
    s.join(" ")
}

#[derive(Debug, PartialEq)]
pub(crate) struct NetRow {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
    pub inode: u64,
}

pub(crate) fn tcp_state(hex: &str, proto: Protocol) -> String {
    let code = u8::from_str_radix(hex, 16).unwrap_or(0);
    match proto {
        Protocol::Tcp | Protocol::Tcp6 => match code {
            0x01 => "ESTABLISHED",
            0x02 => "SYN_SENT",
            0x03 => "SYN_RECV",
            0x04 => "FIN_WAIT1",
            0x05 => "FIN_WAIT2",
            0x06 => "TIME_WAIT",
            0x07 => "CLOSE",
            0x08 => "CLOSE_WAIT",
            0x09 => "LAST_ACK",
            0x0A => "LISTEN",
            0x0B => "CLOSING",
            _ => "UNKNOWN",
        }
        .into(),
        _ => match code {
            0x01 => "ESTABLISHED".into(),
            _ => "-".into(),
        },
    }
}

/// Decode a `/proc/net` address `HEXIP:HEXPORT` (IP in host-order 32-bit words).
pub(crate) fn decode_addr(s: &str) -> Option<(String, u16)> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match ip.len() {
        8 => {
            let v = u32::from_str_radix(ip, 16).ok()?;
            // The kernel prints the in-memory (network order) word as a native integer.
            std::net::Ipv4Addr::from(v.to_ne_bytes()).to_string()
        }
        32 => {
            let mut bytes = [0u8; 16];
            for w in 0..4 {
                let word = u32::from_str_radix(&ip[w * 8..w * 8 + 8], 16).ok()?;
                bytes[w * 4..w * 4 + 4].copy_from_slice(&word.to_ne_bytes());
            }
            let v6 = std::net::Ipv6Addr::from(bytes);
            match v6.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => v6.to_string(),
            }
        }
        _ => return None,
    };
    Some((ip, port))
}

pub(crate) fn parse_proc_net(content: &str, proto: Protocol) -> Vec<NetRow> {
    content
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let (lip, lport) = decode_addr(f[1])?;
            let (rip, rport) = decode_addr(f[2])?;
            let (lport, state) = if proto == Protocol::Raw { (lport, "-".to_string()) } else { (lport, tcp_state(f[3], proto)) };
            Some(NetRow { local_ip: lip, local_port: lport, remote_ip: rip, remote_port: rport, state, inode: f[9].parse().ok()? })
        })
        .collect()
}

/// `/proc/net/packet`: `sk RefCnt Type Proto Iface R Rmem User Inode`.
pub(crate) fn parse_packet_inodes(content: &str) -> Vec<u64> {
    content.lines().skip(1).filter_map(|l| l.split_whitespace().nth(8).and_then(|v| v.parse().ok())).collect()
}

#[derive(Debug, PartialEq)]
pub(crate) struct ModRow {
    pub name: String,
    pub size: u64,
    pub taint: String,
}

pub(crate) fn parse_proc_modules(content: &str) -> Vec<ModRow> {
    content
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let name = f.first()?.to_string();
            let size = f.get(1)?.parse().ok()?;
            let taint = f.get(6).filter(|t| t.starts_with('(')).map(|t| t.trim_matches(|c| c == '(' || c == ')').to_string()).unwrap_or_default();
            Some(ModRow { name, size, taint })
        })
        .collect()
}

pub(crate) fn decode_taint(v: u64) -> Vec<(u32, &'static str)> {
    const BITS: &[(u32, &str)] = &[
        (0, "proprietary module loaded (P)"),
        (1, "module force-loaded (F)"),
        (2, "SMP kernel on unsupported CPU (S)"),
        (3, "module force-unloaded (R)"),
        (4, "machine check exception (M)"),
        (5, "bad page referenced (B)"),
        (6, "taint requested by userspace (U)"),
        (7, "kernel died recently / OOPS (D)"),
        (8, "ACPI table overridden (A)"),
        (9, "kernel warning (W)"),
        (10, "staging driver loaded (C)"),
        (11, "firmware workaround applied (I)"),
        (12, "out-of-tree module loaded (O)"),
        (13, "unsigned module loaded (E)"),
        (14, "soft lockup (L)"),
        (15, "kernel live patched (K)"),
        (16, "auxiliary taint (X)"),
        (17, "built with struct randomization plugin (T)"),
        (18, "in-kernel test (N)"),
    ];
    BITS.iter().filter(|(b, _)| v & (1 << b) != 0).copied().collect()
}

/// Shared objects mapped from staging dirs or deleted from disk.
pub(crate) fn suspicious_mappings(maps: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for l in maps.lines() {
        let Some(path) = l.split_whitespace().nth(5) else { continue };
        let full = l.split_once(path).map(|(_, rest)| format!("{path}{rest}")).unwrap_or_else(|| path.to_string());
        let is_so = path.contains(".so");
        if !is_so {
            continue;
        }
        let staged = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"].iter().any(|d| path.starts_with(d));
        let deleted = full.ends_with("(deleted)") && !["/usr/", "/lib", "/opt/", "/snap/", "/var/lib/"].iter().any(|d| path.starts_with(d));
        if (staged || deleted) && !out.contains(&full) {
            out.push(full);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Persistence helpers

/// Read an autostart/config file safely while running as root.
///
/// Many of these files live in user-writable places (home directories,
/// spool dirs). A user could plant a symlink or hard link there pointing at
/// a secret (e.g. `/etc/shadow`) and have root copy its lines into a report.
/// So:
///  * the file is opened with `O_NOFOLLOW` (no TOCTOU between check and read);
///  * a symlink is followed only when the link itself is root-owned — users
///    cannot create those, while systemd/etc use them legitimately;
///  * a root-owned regular file with extra hard links is refused;
///  * reads are capped at 1 MiB.
pub(crate) fn read_config(path: &Path) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    const MAX: u64 = 1 << 20;
    // A directory symlink earlier in the path (e.g. ~/.ssh -> /root/.ssh)
    // would escape the user's area even though the final component is a
    // regular file. Require the fully resolved path to stay inside the
    // user-writable root it was enumerated from (e.g. /home/alice).
    if is_user_writable_location(path) {
        let anchor: PathBuf = path.components().take(if path.starts_with("/home/") || path.starts_with("/run/user/") { 3 } else { 2 }).collect();
        let resolved = fs::canonicalize(path).ok()?;
        if !resolved.starts_with(&anchor) {
            return None;
        }
    }
    let open_nofollow = |p: &Path| fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(p);
    let file = match open_nofollow(path) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            let link = fs::symlink_metadata(path).ok()?;
            if link.uid() != 0 {
                return None; // user-planted symlink: never follow as root
            }
            fs::File::open(path).ok()?
        }
        Err(_) => return None,
    };
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX || (meta.uid() == 0 && meta.nlink() > 1 && is_user_writable_location(path)) {
        return None;
    }
    let mut s = String::new();
    file.take(MAX).read_to_string(&mut s).ok()?;
    Some(s)
}

/// Locations where unprivileged users can create entries.
fn is_user_writable_location(p: &Path) -> bool {
    ["/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/var/spool/", "/run/user/"].iter().any(|d| p.starts_with(d))
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn mtime(p: &Path) -> Option<u64> {
    fs::metadata(p).ok()?.modified().ok()?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

fn passwd_users() -> HashMap<u32, String> {
    fs::read_to_string("/etc/passwd")
        .map(|c| {
            c.lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    Some((f.get(2)?.parse().ok()?, f.first()?.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn home_dirs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_to_string("/etc/passwd")
        .map(|c| {
            c.lines()
                .filter_map(|l| l.split(':').nth(5).map(PathBuf::from))
                .filter(|p| p.starts_with("/home") || p.starts_with("/root") || p.starts_with("/var/lib"))
                .collect()
        })
        .unwrap_or_default();
    v.push(PathBuf::from("/root"));
    v.sort();
    v.dedup();
    v.retain(|p| p.is_dir());
    v
}

fn list_files(dir: impl AsRef<Path>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir.as_ref()).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect()).unwrap_or_default();
    v.sort();
    v
}

fn walk(dir: &Path, depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dir) else { return out };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() && depth > 0 {
            out.extend(walk(&p, depth - 1));
        } else if ft.is_file() || ft.is_symlink() {
            out.push(p);
        }
    }
    out.sort();
    out
}

fn extract_paths(s: &str) -> Vec<String> {
    s.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '=' || c == ';' || c == '`')
        .filter(|t| t.starts_with('/') && t.len() > 1)
        .map(|t| t.to_string())
        .collect()
}

fn push_entry(out: &mut Vec<PersistenceEntry>, mech: &str, file: &Path, command: &str, ind: Vec<Indicator>, floor: Severity) {
    let risk = max_severity(&ind).max(floor);
    let target = extract_paths(command).into_iter().next().unwrap_or_else(|| heuristics::command_program(command));
    out.push(PersistenceEntry {
        mechanism: mech.into(),
        location: file.display().to_string(),
        target_path: target,
        command: truncate(command, 400),
        risk_level: risk,
        reasons: ind.into_iter().map(|i| i.reason).collect(),
        modified: mtime(file),
    });
}

/// Command rules over the whole line; path rules only for the program that
/// is actually executed. Scripts routinely *mention* /tmp (mktemp, socket
/// dirs) without running anything from it.
fn line_indicators(line: &str) -> Vec<Indicator> {
    let mut ind = analyze_command(line);
    let mut words = line.split_whitespace().map(|w| w.trim_matches(|c| c == '"' || c == '\''));
    let mut prog = words.next().unwrap_or("");
    // Skip common wrappers so `nohup /tmp/x` and `exec /dev/shm/y` are caught.
    while ["exec", "nohup", "sudo", "setsid", "env", "nice", "/usr/bin/env", "/bin/sh", "/bin/bash", "sh", "bash"].contains(&prog) {
        prog = words.next().unwrap_or("");
    }
    if prog.starts_with('/') {
        for i in analyze_unix_path(prog) {
            if !ind.iter().any(|x| x.reason == i.reason) {
                ind.push(i);
            }
        }
    }
    ind
}

/// Crontab: every schedule line is an entry; `system` crontabs carry a user column.
fn cron_file(path: &Path, mech: &str, system: bool, out: &mut Vec<PersistenceEntry>) {
    let Some(c) = read_config(path) else { return };
    for line in c.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let first = line.split_whitespace().next().unwrap_or("");
        if first.contains('=') && !first.starts_with('@') {
            continue; // env assignment
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let skip = if first.starts_with('@') { 1 } else { 5 } + usize::from(system && path.file_name().map(|n| n != "anacrontab").unwrap_or(true));
        let cmd = if fields.len() > skip { fields[skip..].join(" ") } else { line.to_string() };
        let ind = line_indicators(&cmd);
        let floor = if mech == "cron-user" { Severity::Low } else { Severity::Info };
        push_entry(out, mech, path, &cmd, ind, floor);
    }
}

/// A script that *is* the persistence (cron.daily, rc.local, at job): always listed.
fn script_file(path: &Path, mech: &str, out: &mut Vec<PersistenceEntry>) {
    let Some(c) = read_config(path) else { return };
    let mut ind: Vec<Indicator> = Vec::new();
    for line in c.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        for i in line_indicators(line) {
            if !ind.iter().any(|x| x.reason == i.reason) {
                ind.push(i);
            }
        }
    }
    let summary = c.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("exit")).take(3).collect::<Vec<_>>().join(" ; ");
    let risk = max_severity(&ind);
    out.push(PersistenceEntry {
        mechanism: mech.into(),
        location: path.display().to_string(),
        target_path: path.display().to_string(),
        command: truncate(&summary, 400),
        risk_level: risk,
        reasons: ind.into_iter().map(|i| i.reason).collect(),
        modified: mtime(path),
    });
}

/// Files that are normally benign (shell rc, init.d): only listed when a line is suspicious.
fn script_scan_only(path: &Path, mech: &str, out: &mut Vec<PersistenceEntry>) {
    let Some(c) = read_config(path) else { return };
    for line in c.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let ind = line_indicators(line);
        if max_severity(&ind) >= Severity::Medium {
            push_entry(out, mech, path, line, ind, Severity::Info);
        }
    }
}

fn systemd_unit(path: &Path, vendor: bool, out: &mut Vec<PersistenceEntry>) {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if !(name.ends_with(".service") || name.ends_with(".timer") || name.ends_with(".path") || name.ends_with(".socket")) {
        return;
    }
    // Symlinks to /dev/null are masks, not persistence.
    if fs::read_link(path).map(|t| t == Path::new("/dev/null")).unwrap_or(false) {
        return;
    }
    let Some(c) = read_config(path) else { return };
    let execs: Vec<&str> = c
        .lines()
        .map(str::trim)
        .filter_map(|l| ["ExecStart=", "ExecStartPre=", "ExecStartPost=", "ExecStop=", "ExecReload="].iter().find_map(|k| l.strip_prefix(k)))
        .collect();
    for ex in execs {
        let cmd = ex.trim_start_matches(['-', '@', '+', '!', ':']);
        let mut ind = line_indicators(cmd);
        if vendor && max_severity(&ind) < Severity::Medium {
            continue;
        }
        // User-level units are a favourite low-privilege persistence spot.
        if path.to_string_lossy().contains("/.config/systemd/") {
            ind.push(Indicator { severity: Severity::Low, reason: "per-user systemd unit".into() });
        }
        push_entry(out, if vendor { "systemd-vendor" } else { "systemd" }, path, cmd, ind, Severity::Info);
    }
}

fn desktop_entry(path: &Path, out: &mut Vec<PersistenceEntry>) {
    let Some(c) = read_config(path) else { return };
    if let Some(exec) = c.lines().find_map(|l| l.trim().strip_prefix("Exec=")) {
        let hidden = c.lines().any(|l| l.trim() == "Hidden=true" || l.trim() == "NoDisplay=true");
        let mut ind = line_indicators(exec);
        if hidden && path.to_string_lossy().contains("/home/") {
            ind.push(Indicator { severity: Severity::Low, reason: "hidden user autostart entry".into() });
        }
        push_entry(out, "xdg-autostart", path, exec, ind, Severity::Info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_with_weird_comm() {
        let s = "1234 (evil) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 7 3 0 0 20 0 1 0 5000 1000 10 18446744073709551615";
        let st = parse_stat(s).unwrap();
        assert_eq!(st.comm, "evil) proc");
        assert_eq!(st.ppid, 1);
        assert_eq!(st.utime, 7);
        assert_eq!(st.stime, 3);
        assert_eq!(st.starttime, 5000);
    }

    #[test]
    fn decode_v4_v6() {
        assert_eq!(decode_addr("0100007F:1F90"), Some(("127.0.0.1".into(), 8080)));
        assert_eq!(decode_addr("00000000:0016"), Some(("0.0.0.0".into(), 22)));
        assert_eq!(decode_addr("00000000000000000000000001000000:0016"), Some(("::1".into(), 22)));
        assert_eq!(decode_addr("0000000000000000FFFF00000100007F:0050"), Some(("127.0.0.1".into(), 80)));
    }

    #[test]
    fn proc_net_parsing() {
        let c = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22841 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:8F2A 0100007F:115C 01 00000000:00000000 00:00000000 00000000  1000        0 99 1";
        let rows = parse_proc_net(c, Protocol::Tcp);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].state, "LISTEN");
        assert_eq!(rows[0].local_port, 22);
        assert_eq!(rows[0].inode, 22841);
        assert_eq!(rows[1].state, "ESTABLISHED");
        assert_eq!(rows[1].remote_port, 4444);
    }

    #[test]
    fn modules_and_taint() {
        let m = parse_proc_modules("nvidia 56823808 120 nvidia_modeset, Live 0xffffffffc1000000 (POE)\next4 999 1 - Live 0x0\n");
        assert_eq!(m[0].taint, "POE");
        assert_eq!(m[1].taint, "");
        let t = decode_taint((1 << 12) | (1 << 13));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn dirent_parsing() {
        // Build two linux_dirent64 records: "123" and "self".
        fn rec(name: &str) -> Vec<u8> {
            let mut v = vec![0u8; 19];
            v.extend_from_slice(name.as_bytes());
            v.push(0);
            while v.len() % 8 != 0 {
                v.push(0);
            }
            let len = v.len() as u16;
            v[16..18].copy_from_slice(&len.to_ne_bytes());
            v
        }
        let mut buf = rec("123");
        buf.extend(rec("self"));
        buf.extend(rec("4567"));
        assert_eq!(parse_dirents(&buf), vec![123, 4567]);
    }

    #[test]
    fn mentioned_tmp_paths_are_not_execution() {
        assert!(line_indicators("fn=\"$(mktemp /tmp/testwriteable.XXXXXXXXXX)\" || return 1").is_empty());
        assert!(line_indicators("if [ -d \"/tmp/$ICE_DIR\" ]; then").is_empty());
        assert!(!line_indicators("nohup /tmp/.x/miner -o pool").is_empty());
        assert!(!line_indicators("/dev/shm/payload").is_empty());
    }

    #[test]
    fn read_config_refuses_planted_links() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let secret = dir.path().join("secret");
        fs::write(&secret, "root-only").unwrap();
        // Regular file: readable.
        assert_eq!(read_config(&secret).as_deref(), Some("root-only"));
        // Symlink owned by an unprivileged user: never followed.
        let link = dir.path().join("authorized_keys");
        symlink(&secret, &link).unwrap();
        if unsafe { libc::geteuid() } == 0 {
            let c = std::ffi::CString::new(link.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::lchown(c.as_ptr(), 1000, 1000) }, 0);
            assert_eq!(read_config(&link), None);
            // Root-owned file with an extra hard link in a user-writable area: refused.
            let hard = dir.path().join("hardlink");
            fs::hard_link(&secret, &hard).unwrap();
            assert_eq!(read_config(&hard), None);
        }
        // A directory symlink escaping the user-writable root is refused.
        let outside = tempfile::Builder::new().tempdir_in("/var").unwrap_or_else(|_| tempfile::tempdir().unwrap());
        fs::write(outside.path().join("k"), "secret").unwrap();
        let via = dir.path().join("ssh");
        symlink(outside.path(), &via).unwrap();
        if !outside.path().starts_with("/tmp") {
            assert_eq!(read_config(&via.join("k")), None);
        }
    }

    #[test]
    fn maps() {
        let m = "7f00-7f01 r-xp 00000000 08:01 123 /usr/lib/libc.so.6\n7f02-7f03 r-xp 00000000 08:01 124 /tmp/.x/libhide.so\n7f04-7f05 r-xp 0 08:01 9 /home/u/evil.so (deleted)\n";
        let s = suspicious_mappings(m);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn live_views_agree_on_self() {
        let e = LinuxEngine::new();
        let me = std::process::id();
        assert!(e.pid_alive(me));
        assert!(e.scan_syscall_view().unwrap().contains(&me));
        let api = e.scan_user_space().unwrap();
        assert!(api.iter().any(|p| p.pid == me));
        // A thread id must not be reported as a process.
        let tid = std::thread::spawn(|| unsafe { libc::syscall(libc::SYS_gettid) } as u32).join().unwrap();
        assert!(!tgkill_probe(tid) || tid == me);
    }

    #[test]
    fn refuses_core_processes() {
        let e = LinuxEngine::new();
        assert!(matches!(e.act_on_process(1, 0, ProcessAction::Terminate), Err(EngineError::Refused(_))));
        assert!(matches!(e.act_on_process(std::process::id(), 0, ProcessAction::Terminate), Err(EngineError::Refused(_))));
    }

    #[test]
    fn suspend_resume_kill_child() {
        let e = LinuxEngine::new();
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let start = e.start_time_of(pid).unwrap();
        assert!(matches!(e.act_on_process(pid, start + 100, ProcessAction::Terminate), Err(EngineError::Refused(_))));
        e.act_on_process(pid, start, ProcessAction::Suspend).unwrap();
        e.act_on_process(pid, start, ProcessAction::Resume).unwrap();
        e.act_on_process(pid, start, ProcessAction::Terminate).unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
    }
}
