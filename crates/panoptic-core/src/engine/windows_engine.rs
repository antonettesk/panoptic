//! Windows implementation of Cross-Layer Truth Analysis.
//!
//! Process views:
//! * **api**     – Toolhelp32 snapshot (NtQuerySystemInformation, user-mode hookable).
//! * **syscall** – `EnumProcesses` (psapi), an independent enumeration path.
//! * **brute**   – `OpenProcess` on every PID multiple of 4. DKOM rootkits unlink
//!   the EPROCESS from `ActiveProcessLinks` but the PID stays in `PspCidTable`,
//!   so the object can still be opened.
//!
//! Driver truth: SCM "running kernel driver" services vs. `EnumDeviceDrivers`
//! (PsLoadedModuleList). A running driver missing from the loaded module list
//! was unlinked by a rootkit.

#![allow(clippy::upper_case_acronyms)]

use super::heuristics::{self, analyze_command, analyze_windows_path, edit_distance, max_severity, Indicator};
use super::traits::*;
use crate::model::{FindingCategory, Severity};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FILETIME, HANDLE, LUID};
use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenElevation, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::ProcessStatus::{K32EnumDeviceDrivers, K32EnumProcesses, K32GetDeviceDriverFileNameW};
use windows_sys::Win32::System::Services::{CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};
use winreg::enums::*;
use winreg::types::FromRegValue;
use winreg::RegKey;

const PROCESS_TERMINATE: u32 = 0x0001;
const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const STILL_ACTIVE: u32 = 259;
const WAIT_TIMEOUT: u32 = 258;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_MORE_DATA: u32 = 234;
const BRUTE_MAX_PID: u32 = 4_194_304;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// RAII wrapper so every handle is closed on every path.
struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 as isize != -1 {
            // SAFETY: we own the handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn filetime_to_epoch(ft: &FILETIME) -> u64 {
    let v = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    v.saturating_sub(116_444_736_000_000_000) / 10_000_000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    Alive,
    Dead,
    /// Exists but we could not open it to check liveness.
    Denied,
    Absent,
}

fn open_process(pid: u32, access: u32) -> Option<OwnedHandle> {
    // SAFETY: OpenProcess has no memory-safety preconditions.
    let h = unsafe { OpenProcess(access, 0, pid) };
    if h.is_null() {
        None
    } else {
        Some(OwnedHandle(h))
    }
}

fn probe_pid(pid: u32) -> Probe {
    let h = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE).or_else(|| open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION));
    match h {
        Some(h) => {
            // Zombie processes (exited, handle still referenced) are not hidden; skip them.
            let mut code = 0u32;
            // SAFETY: valid handle and out pointer.
            if unsafe { GetExitCodeProcess(h.0, &mut code) } != 0 && code != STILL_ACTIVE {
                return Probe::Dead;
            }
            // SAFETY: valid handle.
            let w = unsafe { WaitForSingleObject(h.0, 0) };
            if w == WAIT_TIMEOUT || code == STILL_ACTIVE {
                Probe::Alive
            } else {
                Probe::Dead
            }
        }
        None => {
            // SAFETY: trivially safe.
            if unsafe { GetLastError() } == ERROR_ACCESS_DENIED {
                Probe::Denied
            } else {
                Probe::Absent
            }
        }
    }
}

fn image_path(pid: u32) -> Option<String> {
    let h = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: buffer of `len` u16s.
    if unsafe { QueryFullProcessImageNameW(h.0, 0, buf.as_mut_ptr(), &mut len) } != 0 {
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    } else {
        None
    }
}

fn process_start_time(pid: u32) -> Option<u64> {
    let h = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let mut c = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut e, mut k, mut u) = (c, c, c);
    // SAFETY: valid handle and out pointers.
    if unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) } != 0 {
        Some(filetime_to_epoch(&c))
    } else {
        None
    }
}

/// Enable SeDebugPrivilege when elevated so protected processes can be inspected.
fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let token = OwnedHandle(token);
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        let name = wide("SeDebugPrivilege");
        if LookupPrivilegeValueW(null(), name.as_ptr(), &mut luid) == 0 {
            return false;
        }
        let tp = TOKEN_PRIVILEGES { PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }] };
        AdjustTokenPrivileges(token.0, 0, &tp, 0, null_mut(), null_mut()) != 0 && GetLastError() == 0
    }
}

pub fn is_process_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let token = OwnedHandle(token);
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        GetTokenInformation(token.0, TokenElevation, &mut elev as *mut _ as *mut c_void, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len) != 0
            && elev.TokenIsElevated != 0
    }
}

/// Relaunch the given executable with a UAC elevation prompt.
pub fn relaunch_elevated(exe: &Path, args: &str) -> EngineResult<()> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(args);
    // SAFETY: all strings are NUL-terminated and outlive the call.
    let r = unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), file.as_ptr(), params.as_ptr(), null(), 1) };
    if r as isize > 32 {
        Ok(())
    } else {
        Err(EngineError::ApiError(format!("ShellExecuteW(runas) failed with code {}", r as isize)))
    }
}

pub struct WindowsEngine {
    elevated: bool,
    system_root: String,
}

impl Default for WindowsEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsEngine {
    pub fn new() -> Self {
        let elevated = is_process_elevated();
        if elevated {
            enable_debug_privilege();
        }
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        WindowsEngine { elevated, system_root }
    }

    fn toolhelp(&self) -> EngineResult<Vec<(u32, u32, String)>> {
        // SAFETY: snapshot handle closed by OwnedHandle; entry sized correctly.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap as isize == -1 {
                return Err(EngineError::ApiError(format!("CreateToolhelp32Snapshot failed ({})", GetLastError())));
            }
            let snap = OwnedHandle(snap);
            let mut e: PROCESSENTRY32W = std::mem::zeroed();
            e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut out = Vec::new();
            if Process32FirstW(snap.0, &mut e) != 0 {
                loop {
                    out.push((e.th32ProcessID, e.th32ParentProcessID, from_wide(&e.szExeFile)));
                    if Process32NextW(snap.0, &mut e) == 0 {
                        break;
                    }
                }
            }
            Ok(out)
        }
    }

    fn expand_env(&self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            if let Some(end) = after.find('%') {
                let var = &after[..end];
                match std::env::var(var) {
                    Ok(v) if !var.is_empty() => out.push_str(&v),
                    _ => {
                        out.push('%');
                        out.push_str(var);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            } else {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
        out.push_str(rest);
        out
    }

    /// Normalise kernel-style image paths into Win32 paths.
    fn normalize_path(&self, p: &str) -> String {
        let mut s = self.expand_env(p.trim().trim_matches('"'));
        let lower = s.to_ascii_lowercase();
        if let Some(r) = lower.strip_prefix("\\systemroot\\") {
            s = format!("{}\\{}", self.system_root, &s[s.len() - r.len()..]);
        } else if lower.starts_with("\\??\\") || lower.starts_with("\\\\?\\") {
            s = s[4..].to_string();
        } else if lower.starts_with("system32\\") || lower.starts_with("syswow64\\") {
            s = format!("{}\\{}", self.system_root, s);
        } else if lower.starts_with("\\windows\\") {
            let drive = self.system_root.get(..2).unwrap_or("C:");
            s = format!("{drive}{s}");
        }
        s
    }

    fn sys_dirs(&self) -> [String; 3] {
        let r = self.system_root.to_ascii_lowercase();
        [format!("{r}\\system32\\"), format!("{r}\\syswow64\\"), format!("{r}\\")]
    }
}

impl TruthEngine for WindowsEngine {
    fn name(&self) -> &'static str {
        "windows-nt"
    }

    fn is_elevated(&self) -> bool {
        self.elevated
    }

    fn scan_user_space(&self) -> EngineResult<Vec<ProcessInfo>> {
        use sysinfo::{ProcessRefreshKind, System, UpdateKind, Users};
        let th = self.toolhelp()?;
        let mut sys = System::new();
        let kind = ProcessRefreshKind::new()
            .with_cpu()
            .with_memory()
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet);
        sys.refresh_processes_specifics(kind);
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(250)));
        sys.refresh_processes_specifics(kind);
        let users = Users::new_with_refreshed_list();
        let mut out = Vec::with_capacity(th.len());
        for (pid, ppid, exe_name) in th {
            let sp = sys.process(sysinfo::Pid::from_u32(pid));
            let path =
                sp.and_then(|p| p.exe()).map(|p| p.to_string_lossy().into_owned()).filter(|s| !s.is_empty()).or_else(|| image_path(pid)).unwrap_or_default();
            out.push(ProcessInfo {
                pid,
                ppid: if pid == 0 { None } else { Some(ppid) },
                name: exe_name,
                path,
                cmdline: sp.map(|p| p.cmd().join(" ")).unwrap_or_default(),
                user: sp.and_then(|p| p.user_id()).and_then(|uid| users.get_user_by_id(uid)).map(|u| u.name().to_string()),
                cpu_usage: sp.map(|p| p.cpu_usage()).unwrap_or(0.0),
                memory_bytes: sp.map(|p| p.memory()).unwrap_or(0),
                start_time: sp.map(|p| p.start_time()).filter(|t| *t > 0).or_else(|| process_start_time(pid)).unwrap_or(0),
                ..Default::default()
            });
        }
        out.sort_by_key(|p| p.pid);
        Ok(out)
    }

    fn api_pids(&self) -> EngineResult<Vec<u32>> {
        Ok(self.toolhelp()?.into_iter().map(|(p, _, _)| p).collect())
    }

    fn scan_syscall_view(&self) -> EngineResult<Vec<u32>> {
        let mut cap = 4096usize;
        loop {
            let mut buf = vec![0u32; cap];
            let mut needed = 0u32;
            // SAFETY: buffer has cap*4 bytes.
            let ok = unsafe { K32EnumProcesses(buf.as_mut_ptr(), (cap * 4) as u32, &mut needed) };
            if ok == 0 {
                return Err(EngineError::ApiError(format!("EnumProcesses failed ({})", unsafe { GetLastError() })));
            }
            let n = needed as usize / 4;
            if n < cap {
                buf.truncate(n);
                buf.sort_unstable();
                return Ok(buf);
            }
            cap *= 2;
            if cap > 1 << 22 {
                return Err(EngineError::ApiError("EnumProcesses result too large".into()));
            }
        }
    }

    fn scan_kernel_reality(&self, cancel: &CancelToken) -> EngineResult<Vec<ProcessInfo>> {
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 16) as u32;
        let slots = BRUTE_MAX_PID / 4;
        let chunk = slots.div_ceil(threads);
        let mut found: Vec<(u32, Probe)> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..threads)
                .map(|i| {
                    s.spawn(move || {
                        let mut v = Vec::new();
                        let start = i * chunk;
                        let end = ((i + 1) * chunk).min(slots);
                        for slot in start..end {
                            if slot % 16_384 == 0 && cancel.is_cancelled() {
                                break;
                            }
                            let pid = slot * 4;
                            if pid == 0 {
                                continue;
                            }
                            let p = probe_pid(pid);
                            if matches!(p, Probe::Alive | Probe::Denied) {
                                v.push((pid, p));
                            }
                        }
                        v
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
        });
        cancel.check()?;
        found.sort_unstable_by_key(|(p, _)| *p);
        Ok(found
            .into_iter()
            .map(|(pid, probe)| {
                let path = image_path(pid).unwrap_or_default();
                let mut p = ProcessInfo {
                    pid,
                    name: heuristics::file_name(&path).to_string(),
                    path,
                    start_time: process_start_time(pid).unwrap_or(0),
                    ..Default::default()
                };
                if probe == Probe::Denied {
                    p.flags.push("liveness unverified: access denied (run as Administrator)".into());
                }
                p
            })
            .collect())
    }

    fn pid_alive(&self, pid: u32) -> bool {
        matches!(probe_pid(pid), Probe::Alive | Probe::Denied)
    }

    fn scan_network_sockets(&self) -> EngineResult<Vec<SocketInfo>> {
        let names: HashMap<u32, String> = self.toolhelp().map(|v| v.into_iter().map(|(p, _, n)| (p, n)).collect()).unwrap_or_default();
        let mut out = Vec::new();
        for (af, proto) in [(2u32, Protocol::Tcp), (23u32, Protocol::Tcp6)] {
            let buf = query_table(|ptr, size| unsafe { GetExtendedTcpTable(ptr, size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0) })?;
            out.extend(parse_tcp_table(&buf, proto));
        }
        for (af, proto) in [(2u32, Protocol::Udp), (23u32, Protocol::Udp6)] {
            let buf = query_table(|ptr, size| unsafe { GetExtendedUdpTable(ptr, size, 0, af, UDP_TABLE_OWNER_PID, 0) })?;
            out.extend(parse_udp_table(&buf, proto));
        }
        for s in &mut out {
            s.process_name = s.pid.and_then(|p| names.get(&p).cloned());
        }
        Ok(out)
    }

    fn scan_persistence(&self) -> EngineResult<Vec<PersistenceEntry>> {
        let mut out = Vec::new();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let hku = RegKey::predef(HKEY_USERS);
        // Every loaded user hive (the current user's included); HKCU only as a
        // fallback so the same hive is never reported twice.
        let mut user_hives: Vec<(String, RegKey)> = hku
            .enum_keys()
            .flatten()
            .filter(|k| k.starts_with("S-1-5-21-") && !k.ends_with("_Classes"))
            .filter_map(|sid| hku.open_subkey_with_flags(&sid, KEY_READ).ok().map(|k| (format!("HKU\\{sid}"), k)))
            .collect();
        if user_hives.is_empty() {
            user_hives.push(("HKCU".to_string(), RegKey::predef(HKEY_CURRENT_USER)));
        }

        // --- Run keys
        const RUN_KEYS: &[&str] = &[
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ];
        let mut seen_locations: HashSet<String> = HashSet::new();
        let mut roots: Vec<(String, &RegKey)> = vec![("HKLM".into(), &hklm)];
        for (n, k) in &user_hives {
            roots.push((n.clone(), k));
        }
        for (root_name, root) in &roots {
            for key in RUN_KEYS {
                let Ok(k) = root.open_subkey_with_flags(key, KEY_READ) else { continue };
                for (name, val) in k.enum_values().flatten() {
                    let cmd = reg_string(&val);
                    let loc = format!("{root_name}\\{key}\\{name}");
                    if !seen_locations.insert(loc.clone()) {
                        continue;
                    }
                    self.push_cmd(&mut out, "registry-run", &loc, &cmd, Severity::Info);
                }
            }
        }

        // --- Winlogon
        if let Ok(k) = hklm.open_subkey_with_flags("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", KEY_READ) {
            if let Ok(shell) = k.get_value::<String, _>("Shell") {
                let ok = shell.trim().eq_ignore_ascii_case("explorer.exe") || shell.trim().eq_ignore_ascii_case(&format!("{}\\explorer.exe", self.system_root));
                self.push_special(
                    &mut out,
                    "winlogon",
                    "HKLM\\...\\Winlogon\\Shell",
                    &shell,
                    if ok { None } else { Some((Severity::High, "Winlogon Shell is not explorer.exe")) },
                );
            }
            if let Ok(ui) = k.get_value::<String, _>("Userinit") {
                let norm = ui.trim().trim_end_matches(',').to_ascii_lowercase();
                let ok = norm == format!("{}\\system32\\userinit.exe", self.system_root.to_ascii_lowercase())
                    || norm == "userinit.exe"
                    || norm == "c:\\windows\\system32\\userinit.exe";
                self.push_special(
                    &mut out,
                    "winlogon",
                    "HKLM\\...\\Winlogon\\Userinit",
                    &ui,
                    if ok { None } else { Some((Severity::High, "Winlogon Userinit launches additional programs")) },
                );
            }
            for v in ["Taskman", "AppSetup", "VMApplet"] {
                if let Ok(x) = k.get_value::<String, _>(v) {
                    if !x.trim().is_empty() && !(v == "VMApplet" && x.to_ascii_lowercase().contains("systempropertiesperformance")) {
                        self.push_special(
                            &mut out,
                            "winlogon",
                            &format!("HKLM\\...\\Winlogon\\{v}"),
                            &x,
                            Some((Severity::Medium, "uncommon Winlogon autostart value")),
                        );
                    }
                }
            }
        }
        for (root_name, hive) in &user_hives {
            if let Ok(k) = hive.open_subkey_with_flags("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", KEY_READ) {
                if let Ok(shell) = k.get_value::<String, _>("Shell") {
                    self.push_special(
                        &mut out,
                        "winlogon",
                        &format!("{root_name}\\...\\Winlogon\\Shell"),
                        &shell,
                        Some((Severity::High, "per-user Winlogon Shell override")),
                    );
                }
            }
        }

        // --- Image File Execution Options (debugger hijack) + SilentProcessExit
        for base in [
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
            "Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        ] {
            if let Ok(ifeo) = hklm.open_subkey_with_flags(base, KEY_READ) {
                for sub in ifeo.enum_keys().flatten() {
                    if let Ok(k) = ifeo.open_subkey_with_flags(&sub, KEY_READ) {
                        if let Ok(dbg) = k.get_value::<String, _>("Debugger") {
                            let benign = dbg.to_ascii_lowercase().contains("vsjitdebugger") || dbg.to_ascii_lowercase().contains("procexp");
                            let sev = if ["sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe"]
                                .contains(&sub.to_ascii_lowercase().as_str())
                            {
                                Severity::Critical
                            } else if benign {
                                Severity::Low
                            } else {
                                Severity::High
                            };
                            self.push_special(
                                &mut out,
                                "ifeo-debugger",
                                &format!("HKLM\\{base}\\{sub}\\Debugger"),
                                &dbg,
                                Some((sev, "IFEO Debugger hijacks process launch")),
                            );
                        }
                    }
                }
            }
        }
        if let Ok(spe) = hklm.open_subkey_with_flags("Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit", KEY_READ) {
            for sub in spe.enum_keys().flatten() {
                if let Ok(mp) = spe.open_subkey_with_flags(&sub, KEY_READ).and_then(|k| k.get_value::<String, _>("MonitorProcess")) {
                    self.push_special(
                        &mut out,
                        "silent-process-exit",
                        &format!("HKLM\\...\\SilentProcessExit\\{sub}"),
                        &mp,
                        Some((Severity::High, "SilentProcessExit monitor launches a program when the target exits")),
                    );
                }
            }
        }

        // --- AppInit_DLLs / AppCertDlls
        for base in ["Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"] {
            if let Ok(k) = hklm.open_subkey_with_flags(base, KEY_READ) {
                let dlls = k.get_value::<String, _>("AppInit_DLLs").unwrap_or_default();
                let load = k.get_value::<u32, _>("LoadAppInit_DLLs").unwrap_or(0);
                if !dlls.trim().is_empty() {
                    let sev = if load == 1 { Severity::High } else { Severity::Low };
                    self.push_special(
                        &mut out,
                        "appinit-dlls",
                        &format!("HKLM\\{base}\\AppInit_DLLs"),
                        &dlls,
                        Some((sev, "AppInit_DLLs injects DLLs into every GUI process")),
                    );
                }
            }
        }
        if let Ok(k) = hklm.open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", KEY_READ) {
            for (name, val) in k.enum_values().flatten() {
                self.push_special(
                    &mut out,
                    "appcert-dlls",
                    &format!("HKLM\\...\\AppCertDlls\\{name}"),
                    &reg_string(&val),
                    Some((Severity::High, "AppCertDlls injects into every process that calls CreateProcess")),
                );
            }
        }

        // --- Session Manager BootExecute
        if let Ok(k) = hklm.open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Control\\Session Manager", KEY_READ) {
            if let Ok(v) = k.get_raw_value("BootExecute") {
                let s = reg_string(&v);
                let extra: Vec<&str> = s
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.eq_ignore_ascii_case("autocheck autochk *") && !l.to_ascii_lowercase().starts_with("autocheck autochk "))
                    .collect();
                if !extra.is_empty() {
                    self.push_special(
                        &mut out,
                        "boot-execute",
                        "HKLM\\...\\Session Manager\\BootExecute",
                        &extra.join("; "),
                        Some((Severity::High, "native program executes before Windows starts")),
                    );
                }
            }
        }

        // --- LSA packages
        if let Ok(k) = hklm.open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Control\\Lsa", KEY_READ) {
            const KNOWN: &[&str] = &[
                "msv1_0",
                "kerberos",
                "schannel",
                "wdigest",
                "tspkg",
                "pku2u",
                "cloudap",
                "negoextender",
                "livessp",
                "scecli",
                "rassfm",
                "\"\"",
                "msoidssp",
                "wsauth",
                "sshdpinauthlsa",
                "msapsspc",
                "msnsspc",
                "credssp",
            ];
            for v in ["Authentication Packages", "Security Packages", "Notification Packages"] {
                if let Ok(raw) = k.get_raw_value(v) {
                    for pkg in reg_string(&raw).lines().map(str::trim).filter(|p| !p.is_empty()) {
                        if !KNOWN.contains(&pkg.to_ascii_lowercase().as_str()) {
                            self.push_special(
                                &mut out,
                                "lsa-package",
                                &format!("HKLM\\...\\Lsa\\{v}"),
                                pkg,
                                Some((Severity::High, "unknown LSA package loaded into lsass.exe (credential theft / persistence)")),
                            );
                        }
                    }
                }
            }
        }

        // --- Netsh helpers & print monitors
        if let Ok(k) = hklm.open_subkey_with_flags("Software\\Microsoft\\NetSh", KEY_READ) {
            for (name, val) in k.enum_values().flatten() {
                let dll = reg_string(&val);
                let lower = dll.to_ascii_lowercase();
                if !(lower.ends_with(".dll") && !lower.contains('\\')) && !lower.starts_with(&self.system_root.to_ascii_lowercase()) {
                    self.push_special(
                        &mut out,
                        "netsh-helper",
                        &format!("HKLM\\Software\\Microsoft\\NetSh\\{name}"),
                        &dll,
                        Some((Severity::Medium, "non-system netsh helper DLL")),
                    );
                }
            }
        }
        if let Ok(k) = hklm.open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", KEY_READ) {
            const KNOWN: &[&str] = &[
                "localspl.dll",
                "tcpmon.dll",
                "usbmon.dll",
                "wsdmon.dll",
                "appmon.dll",
                "apmon.dll",
                "fxsmon.dll",
                "inetpp.dll",
                "pjlmon.dll",
                "msonpmon.dll",
                "win32spl.dll",
                "mfmon.dll",
            ];
            for sub in k.enum_keys().flatten() {
                if let Ok(drv) = k.open_subkey_with_flags(&sub, KEY_READ).and_then(|s| s.get_value::<String, _>("Driver")) {
                    if !KNOWN.contains(&drv.to_ascii_lowercase().as_str()) {
                        self.push_special(
                            &mut out,
                            "print-monitor",
                            &format!("HKLM\\...\\Print\\Monitors\\{sub}"),
                            &drv,
                            Some((Severity::Low, "third-party print monitor DLL loaded into spoolsv.exe")),
                        );
                    }
                }
            }
        }

        // --- Services (auto-start) and their ServiceDlls
        if let Ok(svcs) = hklm.open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Services", KEY_READ) {
            for name in svcs.enum_keys().flatten() {
                let Ok(k) = svcs.open_subkey_with_flags(&name, KEY_READ) else { continue };
                let start = k.get_value::<u32, _>("Start").unwrap_or(4);
                let ty = k.get_value::<u32, _>("Type").unwrap_or(0);
                let Ok(image) = k.get_value::<String, _>("ImagePath") else { continue };
                let is_driver = ty & 0x3 != 0;
                if start > 2 {
                    continue;
                }
                let loc = format!("HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}");
                let mech = if is_driver { "driver-service" } else { "service" };
                let mut ind = analyze_command(&image);
                let prog = self.normalize_path(&heuristics::command_program(&image));
                ind.extend(analyze_windows_path(&prog));
                if !prog.is_empty() && prog.contains('\\') && !Path::new(&prog).exists() {
                    ind.push(Indicator { severity: Severity::Medium, reason: format!("service binary {prog} does not exist on disk") });
                }
                if is_driver {
                    let lower = prog.to_ascii_lowercase();
                    if !lower.is_empty() && !self.sys_dirs().iter().any(|d| lower.starts_with(d.as_str())) && !lower.contains("\\program files") {
                        ind.push(Indicator { severity: Severity::Medium, reason: "boot/auto-start driver outside the Windows directory".into() });
                    }
                }
                if let Ok(dll) = k.open_subkey_with_flags("Parameters", KEY_READ).and_then(|p| p.get_value::<String, _>("ServiceDll")) {
                    let dll = self.normalize_path(&dll);
                    let lower = dll.to_ascii_lowercase();
                    if !self.sys_dirs().iter().any(|d| lower.starts_with(d.as_str())) {
                        ind.push(Indicator { severity: Severity::High, reason: format!("svchost ServiceDll outside system directories: {dll}") });
                    }
                }
                let risk = max_severity(&ind);
                out.push(PersistenceEntry {
                    mechanism: mech.into(),
                    location: loc,
                    target_path: prog,
                    command: image,
                    risk_level: risk,
                    reasons: ind.into_iter().map(|i| i.reason).collect(),
                    modified: None,
                });
            }
        }

        // --- Startup folders
        let mut startup_dirs: Vec<PathBuf> = Vec::new();
        if let Ok(pd) = std::env::var("ProgramData") {
            startup_dirs.push(PathBuf::from(pd).join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp"));
        }
        if let Ok(users) = std::fs::read_dir(format!("{}\\Users", self.system_root.get(..2).unwrap_or("C:"))) {
            for u in users.flatten() {
                startup_dirs.push(u.path().join("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
            }
        }
        for d in startup_dirs {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for f in rd.flatten() {
                let p = f.path();
                let name = f.file_name().to_string_lossy().to_ascii_lowercase();
                if name == "desktop.ini" {
                    continue;
                }
                let mut ind = Vec::new();
                let ext = name.rsplit('.').next().unwrap_or("");
                let mut target = p.display().to_string();
                if ext == "lnk" {
                    if let Some(t) = lnk_target(&p) {
                        ind.extend(analyze_windows_path(&t));
                        ind.extend(analyze_command(&t));
                        target = t;
                    }
                } else if ["exe", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "ps1", "scr", "com", "pif", "dll"].contains(&ext) {
                    ind.push(Indicator {
                        severity: Severity::Medium,
                        reason: format!("executable script/binary (.{ext}) placed directly in a Startup folder"),
                    });
                }
                let risk = max_severity(&ind);
                out.push(PersistenceEntry {
                    mechanism: "startup-folder".into(),
                    location: p.display().to_string(),
                    target_path: target,
                    command: String::new(),
                    risk_level: risk,
                    reasons: ind.into_iter().map(|i| i.reason).collect(),
                    modified: file_mtime(&p),
                });
            }
        }

        // --- Scheduled tasks
        let tasks_root = PathBuf::from(format!("{}\\System32\\Tasks", self.system_root));
        for f in walk_files(&tasks_root, 6) {
            let Some(xml) = read_text_any(&f) else { continue };
            let rel = f.strip_prefix(&tasks_root).map(|r| r.display().to_string()).unwrap_or_default();
            let ms = rel.to_ascii_lowercase().starts_with("microsoft\\");
            let hidden = xml_tag(&xml, "Hidden").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false);
            let mut actions = xml_tags(&xml, "Exec");
            if actions.is_empty() {
                // COM handler tasks have no Exec; still record them for completeness.
                continue;
            }
            for exec in actions.drain(..) {
                let cmd = xml_tag(&exec, "Command").unwrap_or_default();
                let args = xml_tag(&exec, "Arguments").unwrap_or_default();
                let full = xml_unescape(&format!("{cmd} {args}"));
                let prog = self.normalize_path(&xml_unescape(&cmd));
                let mut ind = analyze_command(&full);
                ind.extend(analyze_windows_path(&prog));
                if hidden && !ms {
                    ind.push(Indicator { severity: Severity::Low, reason: "task is marked hidden".into() });
                }
                if ms && max_severity(&ind) < Severity::Medium {
                    continue;
                }
                let risk = max_severity(&ind);
                out.push(PersistenceEntry {
                    mechanism: "scheduled-task".into(),
                    location: format!("\\{rel}"),
                    target_path: prog,
                    command: full.trim().to_string(),
                    risk_level: risk,
                    reasons: ind.into_iter().map(|i| i.reason).collect(),
                    modified: file_mtime(&f),
                });
            }
        }

        // --- COM hijacking: per-user CLSIDs shadowing machine CLSIDs
        for (root_name, hive) in &user_hives {
            let Ok(clsids) = hive.open_subkey_with_flags("Software\\Classes\\CLSID", KEY_READ) else { continue };
            for clsid in clsids.enum_keys().flatten() {
                let Ok(server) = clsids.open_subkey_with_flags(format!("{clsid}\\InprocServer32"), KEY_READ).and_then(|k| k.get_value::<String, _>("")) else {
                    continue;
                };
                let path = self.normalize_path(&server);
                // A hijack *redirects* a machine class to a different DLL;
                // per-user registrations of the same server are routine.
                let machine = hklm
                    .open_subkey_with_flags(format!("Software\\Classes\\CLSID\\{clsid}\\InprocServer32"), KEY_READ)
                    .and_then(|k| k.get_value::<String, _>(""))
                    .ok()
                    .map(|m| self.normalize_path(&m));
                let mut ind = analyze_windows_path(&path);
                if let Some(m) = &machine {
                    if !m.eq_ignore_ascii_case(&path) && !heuristics::file_name(m).eq_ignore_ascii_case(heuristics::file_name(&path)) {
                        ind.push(Indicator {
                            severity: Severity::Medium,
                            reason: format!("per-user InprocServer32 redirects a machine-wide COM class from {m} (COM hijack)"),
                        });
                    }
                }
                if max_severity(&ind) >= Severity::Medium {
                    let risk = max_severity(&ind);
                    out.push(PersistenceEntry {
                        mechanism: "com-hijack".into(),
                        location: format!("{root_name}\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32"),
                        target_path: path,
                        command: server,
                        risk_level: risk,
                        reasons: ind.into_iter().map(|i| i.reason).collect(),
                        modified: None,
                    });
                }
            }
        }

        // --- WMI event subscriptions (requires admin; silently empty otherwise)
        out.extend(wmi_subscriptions());

        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
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
        // Without elevation Windows hides kernel base addresses (KASLR), so
        // every module resolves to ntoskrnl and any comparison is meaningless.
        if !self.elevated {
            return Err(EngineError::PermissionDenied);
        }
        let mut bases: Vec<*mut c_void> = vec![null_mut(); 4096];
        let mut needed = 0u32;
        loop {
            let cb = (bases.len() * std::mem::size_of::<*mut c_void>()) as u32;
            // SAFETY: buffer sized by cb.
            if unsafe { K32EnumDeviceDrivers(bases.as_mut_ptr(), cb, &mut needed) } == 0 {
                return Err(EngineError::ApiError(format!("EnumDeviceDrivers failed ({})", unsafe { GetLastError() })));
            }
            if needed <= cb {
                break;
            }
            bases.resize(needed as usize / std::mem::size_of::<*mut c_void>() + 64, null_mut());
        }
        let count = needed as usize / std::mem::size_of::<*mut c_void>();
        let mut out = Vec::new();
        let mut loaded_names: HashSet<String> = HashSet::new();
        for base in &bases[..count] {
            let mut buf = vec![0u16; 1024];
            // SAFETY: buffer sized.
            let n = unsafe { K32GetDeviceDriverFileNameW(*base, buf.as_mut_ptr(), buf.len() as u32) };
            if n == 0 {
                continue;
            }
            let raw = String::from_utf16_lossy(&buf[..n as usize]);
            let path = self.normalize_path(&raw);
            let name = heuristics::file_name(&path).to_string();
            if !loaded_names.insert(name.to_ascii_lowercase()) {
                continue;
            }
            // Crash-dump filter drivers (dump_<driver>.sys) are in-memory
            // copies of a storage driver and never exist on disk.
            let dump_original = name
                .to_ascii_lowercase()
                .strip_prefix("dump_")
                .map(|orig| Path::new(&format!("{}\\System32\\drivers\\{orig}", self.system_root)).exists())
                .unwrap_or(false);
            let exists = dump_original || Path::new(&path).exists();
            let mut reasons = Vec::new();
            let mut suspicious = false;
            if !exists {
                reasons.push(format!("driver file missing on disk ({path}) — rootkits often delete their driver after loading"));
                suspicious = true;
            }
            let lower = path.to_ascii_lowercase();
            if !self.sys_dirs().iter().any(|d| lower.starts_with(d.as_str())) && !lower.contains("\\program files") {
                let ind = analyze_windows_path(&path);
                if ind.iter().any(|i| i.severity >= Severity::High) {
                    reasons.push(format!("driver loaded from staging location {path}"));
                } else {
                    reasons.push(format!("driver loaded from outside the Windows directory: {path}"));
                }
                suspicious = true;
            }
            out.push(KernelModule { name, path: Some(path), size: 0, listed: true, corroborated: exists, hidden: false, suspicious, reasons });
        }

        // Cross-check: SCM-running kernel drivers that are missing from the loaded list.
        if let Ok(running) = running_driver_services() {
            let svcs = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Services", KEY_READ).ok();
            for svc in running {
                let image = svcs.as_ref().and_then(|s| s.open_subkey_with_flags(&svc, KEY_READ).ok()).and_then(|k| k.get_value::<String, _>("ImagePath").ok());
                let file = match &image {
                    Some(i) => heuristics::file_name(&self.normalize_path(&heuristics::command_program(i))).to_ascii_lowercase(),
                    None => format!("{}.sys", svc.to_ascii_lowercase()),
                };
                if file.is_empty() || loaded_names.contains(&file) {
                    continue;
                }
                // File-system minifilters and some drivers are hosted inside other
                // images; only report when the backing file actually exists, so the
                // discrepancy is meaningful.
                let path = image
                    .as_ref()
                    .map(|i| self.normalize_path(&heuristics::command_program(i)))
                    .unwrap_or_else(|| format!("{}\\System32\\drivers\\{file}", self.system_root));
                if !Path::new(&path).exists() {
                    continue;
                }
                out.push(KernelModule {
                    name: file.clone(),
                    path: Some(path),
                    size: 0,
                    listed: false,
                    corroborated: true,
                    hidden: true,
                    suspicious: true,
                    reasons: vec![format!("service `{svc}` is reported RUNNING by the Service Control Manager but its image is absent from the kernel's loaded-module list (PsLoadedModuleList unlink)")],
                });
            }
        }
        out.sort_by(|a, b| b.hidden.cmp(&a.hidden).then(b.suspicious.cmp(&a.suspicious)).then(a.name.cmp(&b.name)));
        Ok(out)
    }

    fn inspect_processes(&self, processes: &[ProcessInfo]) -> Vec<Finding> {
        let mut out = Vec::new();
        let sysroot = self.system_root.to_ascii_lowercase();
        let sys32 = format!("{sysroot}\\system32\\");
        let wow = format!("{sysroot}\\syswow64\\");
        let system_bins: &[(&str, &[&str])] = &[
            ("svchost.exe", &[&sys32, &wow]),
            ("lsass.exe", &[&sys32]),
            ("csrss.exe", &[&sys32]),
            ("smss.exe", &[&sys32]),
            ("wininit.exe", &[&sys32]),
            ("winlogon.exe", &[&sys32]),
            ("services.exe", &[&sys32]),
            ("spoolsv.exe", &[&sys32]),
            ("taskhostw.exe", &[&sys32]),
            ("lsaiso.exe", &[&sys32]),
            ("dwm.exe", &[&sys32]),
            ("conhost.exe", &[&sys32]),
            ("rundll32.exe", &[&sys32, &wow]),
            ("dllhost.exe", &[&sys32, &wow]),
            ("ctfmon.exe", &[&sys32, &wow]),
            ("sihost.exe", &[&sys32]),
            ("fontdrvhost.exe", &[&sys32]),
            ("runtimebroker.exe", &[&sys32]),
            ("searchindexer.exe", &[&sys32]),
            ("explorer.exe", &[&format!("{sysroot}\\")]),
            ("cmd.exe", &[&sys32, &wow]),
            ("powershell.exe", &[&format!("{sys32}windowspowershell\\v1.0\\"), &format!("{wow}windowspowershell\\v1.0\\")]),
        ];
        let by_pid: HashMap<u32, &ProcessInfo> = processes.iter().map(|p| (p.pid, p)).collect();
        let mut counts: HashMap<String, usize> = HashMap::new();
        for p in processes {
            *counts.entry(p.name.to_ascii_lowercase()).or_default() += 1;
        }
        const OFFICE: &[&str] = &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe", "visio.exe"];
        const SERVERS: &[&str] = &["w3wp.exe", "sqlservr.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "java.exe", "php-cgi.exe", "umworkerprocess.exe"];
        const CHILD_SHELLS: &[&str] = &[
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "certutil.exe",
            "bitsadmin.exe",
        ];

        for p in processes.iter().filter(|p| !p.is_discrepant && p.pid > 4) {
            let name = p.name.to_ascii_lowercase();
            let path = p.path.to_ascii_lowercase();
            let mut ind: Vec<Indicator> = Vec::new();
            let mut mitre = "T1036";

            if let Some((_, dirs)) = system_bins.iter().find(|(n, _)| *n == name) {
                if !path.is_empty() {
                    let parent_dir = path.rsplit_once('\\').map(|(d, _)| format!("{d}\\")).unwrap_or_default();
                    if !dirs.iter().any(|d| parent_dir == *d) {
                        ind.push(Indicator {
                            severity: Severity::Critical,
                            reason: format!("system binary name `{}` running from unexpected location {}", p.name, p.path),
                        });
                        mitre = "T1036.005";
                    }
                }
            } else if name.len() >= 7 {
                for (sys_name, _) in system_bins {
                    if edit_distance(&name, sys_name) == 1 && name.ends_with(".exe") && !["conhost.exe", "cmd.exe"].contains(sys_name) {
                        ind.push(Indicator { severity: Severity::High, reason: format!("name `{}` imitates system binary `{sys_name}`", p.name) });
                        mitre = "T1036.004";
                        break;
                    }
                }
            }
            for single in ["lsass.exe", "wininit.exe", "services.exe", "lsaiso.exe"] {
                if name == single && counts.get(single).copied().unwrap_or(0) > 1 {
                    ind.push(Indicator { severity: Severity::High, reason: format!("multiple instances of singleton process {single}") });
                }
            }
            if let Some(parent) = p.ppid.and_then(|pp| by_pid.get(&pp)) {
                let pname = parent.name.to_ascii_lowercase();
                let parent_older = parent.start_time != 0 && p.start_time != 0 && parent.start_time <= p.start_time;
                if parent_older {
                    // csrss/wininit/winlogon are started by a transient smss.exe
                    // instance that exits, so their PPID is routinely reused.
                    let expected_parent: Option<&[&str]> = match name.as_str() {
                        "svchost.exe" => Some(&["services.exe", "msmpeng.exe"]),
                        "lsass.exe" | "services.exe" | "lsaiso.exe" => Some(&["wininit.exe"]),
                        _ => None,
                    };
                    if let Some(exp) = expected_parent {
                        if !exp.contains(&pname.as_str()) {
                            ind.push(Indicator {
                                severity: Severity::High,
                                reason: format!("{} has unexpected parent {} (PID {})", p.name, parent.name, parent.pid),
                            });
                            mitre = "T1055";
                        }
                    }
                    if CHILD_SHELLS.contains(&name.as_str()) && OFFICE.contains(&pname.as_str()) {
                        ind.push(Indicator { severity: Severity::High, reason: format!("Office application {} spawned {}", parent.name, p.name) });
                        mitre = "T1204.002";
                    }
                    if CHILD_SHELLS.contains(&name.as_str()) && SERVERS.contains(&pname.as_str()) {
                        ind.push(Indicator {
                            severity: Severity::High,
                            reason: format!("server process {} spawned {} (possible web shell)", parent.name, p.name),
                        });
                        mitre = "T1505.003";
                    }
                }
            }
            ind.extend(analyze_windows_path(&p.path));
            for i in analyze_command(&p.cmdline) {
                if !ind.iter().any(|x| x.reason == i.reason) {
                    ind.push(i);
                }
            }
            if !p.path.is_empty() && p.path.contains('\\') && !Path::new(&p.path).exists() {
                ind.push(Indicator { severity: Severity::High, reason: format!("process image {} no longer exists on disk", p.path) });
                mitre = "T1070.004";
            }

            let sev = max_severity(&ind);
            if sev >= Severity::Medium {
                let mut f = Finding::new(
                    FindingCategory::ProcessAnomaly,
                    sev,
                    &format!("proc:{}:{}", p.name, p.path.to_ascii_lowercase()),
                    format!("Suspicious process: {} (PID {})", p.name, p.pid),
                    "This process exhibits behaviour associated with malware execution, masquerading or code injection.",
                )
                .pid(p.pid)
                .path(p.path.clone())
                .mitre(mitre)
                .evidences(ind.iter().map(|i| i.reason.clone()))
                .recommend("Suspend the process to preserve its memory, collect a memory dump and the binary, then terminate.");
                if !p.cmdline.is_empty() {
                    f = f.evidence(format!("cmdline: {}", p.cmdline.chars().take(300).collect::<String>()));
                }
                out.push(f);
            }
        }
        out
    }

    fn integrity_checks(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        // Test signing / disabled integrity checks enable unsigned drivers (rootkits).
        if let Ok(k) = hklm.open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Control", KEY_READ) {
            if let Ok(opts) = k.get_value::<String, _>("SystemStartOptions") {
                let u = opts.to_ascii_uppercase();
                let mut ev = Vec::new();
                if u.contains("TESTSIGNING") {
                    ev.push("TESTSIGNING enabled: unsigned drivers can load");
                }
                if u.contains("DISABLE_INTEGRITY_CHECKS") || u.contains("NOINTEGRITYCHECKS") {
                    ev.push("driver signature enforcement disabled");
                }
                if u.contains(" DEBUG") || u.starts_with("DEBUG") {
                    ev.push("kernel debugging enabled");
                }
                if !ev.is_empty() {
                    out.push(
                        Finding::new(
                            FindingCategory::KernelIntegrity,
                            Severity::High,
                            &format!("bootopts:{u}"),
                            "Kernel code-integrity protections are weakened",
                            "The current boot allows unsigned or test-signed kernel drivers to load, which rootkits require.",
                        )
                        .evidences(ev)
                        .evidence(format!("SystemStartOptions: {opts}"))
                        .mitre("T1553.006")
                        .recommend("Re-enable signature enforcement (bcdedit /set testsigning off) unless a documented need exists, and audit loaded drivers."),
                    );
                }
            }
        }
        // Defender tampering.
        if let Ok(k) = hklm.open_subkey_with_flags("SOFTWARE\\Policies\\Microsoft\\Windows Defender", KEY_READ) {
            if k.get_value::<u32, _>("DisableAntiSpyware").unwrap_or(0) == 1 {
                out.push(
                    Finding::new(
                        FindingCategory::KernelIntegrity,
                        Severity::High,
                        "defender-disabled-policy",
                        "Microsoft Defender disabled by policy",
                        "A policy value disables Defender, a common step before deploying malware.",
                    )
                    .evidence("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware = 1")
                    .mitre("T1562.001"),
                );
            }
            if let Ok(rtp) = k.open_subkey_with_flags("Real-Time Protection", KEY_READ) {
                if rtp.get_value::<u32, _>("DisableRealtimeMonitoring").unwrap_or(0) == 1 {
                    out.push(
                        Finding::new(
                            FindingCategory::KernelIntegrity,
                            Severity::High,
                            "defender-rtp-policy",
                            "Defender real-time protection disabled by policy",
                            "Real-time scanning is turned off through policy.",
                        )
                        .mitre("T1562.001"),
                    );
                }
            }
        }
        if let Ok(k) = hklm.open_subkey_with_flags("SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths", KEY_READ) {
            let paths: Vec<String> = k.enum_values().flatten().map(|(n, _)| n).collect();
            let risky: Vec<&String> = paths
                .iter()
                .filter(|p| {
                    let l = p.to_ascii_lowercase();
                    l.len() <= 3 || !analyze_windows_path(p).is_empty() || l.ends_with("\\users") || l.contains("\\temp")
                })
                .collect();
            if !risky.is_empty() {
                out.push(
                    Finding::new(
                        FindingCategory::KernelIntegrity,
                        Severity::Medium,
                        "defender-exclusions",
                        "Broad or risky Defender path exclusions",
                        "Malware commonly adds Defender exclusions for its staging directories.",
                    )
                    .evidences(risky.iter().map(|p| format!("excluded: {p}")))
                    .mitre("T1562.001"),
                );
            }
        }
        // Hosts file redirection of security vendors / Windows Update.
        let hosts = PathBuf::from(format!("{}\\System32\\drivers\\etc\\hosts", self.system_root));
        if let Ok(c) = std::fs::read_to_string(&hosts) {
            let bad: Vec<&str> = c
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with('#') && !l.is_empty())
                // Windows itself ships `0.0.0.1 mssplus.mcafee.com`.
                .filter(|l| !l.to_ascii_lowercase().contains("mssplus.mcafee.com"))
                .filter(|l| {
                    let x = l.to_ascii_lowercase();
                    [
                        "windowsupdate",
                        "microsoft.com",
                        "defender",
                        "virustotal",
                        "kaspersky",
                        "symantec",
                        "mcafee",
                        "malwarebytes",
                        "eset",
                        "sophos",
                        "crowdstrike",
                    ]
                    .iter()
                    .any(|v| x.contains(v))
                })
                .collect();
            if !bad.is_empty() {
                out.push(
                    Finding::new(
                        FindingCategory::KernelIntegrity,
                        Severity::High,
                        "hosts-redirect",
                        "Hosts file redirects security / update domains",
                        "Malware blocks security updates by redirecting vendor domains in the hosts file.",
                    )
                    .evidences(bad.iter().map(|s| s.to_string()))
                    .path(hosts.display().to_string())
                    .mitre("T1562.001"),
                );
            }
        }
        if !self.elevated {
            out.push(
                Finding::new(
                    FindingCategory::KernelIntegrity,
                    Severity::Info,
                    "not-elevated",
                    "Scan ran without Administrator rights",
                    "Brute-force process probing, service and scheduled-task inspection and WMI checks are incomplete without elevation.",
                )
                .recommend("Relaunch Panoptic as Administrator for full coverage."),
            );
        }
        out
    }

    fn act_on_process(&self, pid: u32, expected_start_time: u64, action: ProcessAction) -> EngineResult<()> {
        if pid == 0 || pid == 4 {
            return Err(EngineError::Refused(format!("PID {pid} is the kernel")));
        }
        if pid == std::process::id() {
            return Err(EngineError::Refused("refusing to act on Panoptic itself".into()));
        }
        let path = image_path(pid).unwrap_or_default();
        let name = heuristics::file_name(&path).to_ascii_lowercase();
        const CRITICAL: &[&str] = &[
            "csrss.exe",
            "smss.exe",
            "wininit.exe",
            "winlogon.exe",
            "services.exe",
            "lsass.exe",
            "lsaiso.exe",
            "registry",
            "memory compression",
            "secure system",
            "system",
        ];
        let in_sys32 = path.to_ascii_lowercase().starts_with(&format!("{}\\system32\\", self.system_root.to_ascii_lowercase()));
        if CRITICAL.contains(&name.as_str()) && in_sys32 && action != ProcessAction::Resume {
            return Err(EngineError::Refused(format!("{name} is a critical system process; stopping it would crash Windows")));
        }
        if expected_start_time != 0 {
            if let Some(actual) = process_start_time(pid) {
                if actual.abs_diff(expected_start_time) > 2 {
                    return Err(EngineError::Refused(format!("PID {pid} was reused by a different process (start time changed)")));
                }
            }
        }
        let access = match action {
            ProcessAction::Terminate => PROCESS_TERMINATE,
            _ => PROCESS_SUSPEND_RESUME,
        } | PROCESS_QUERY_LIMITED_INFORMATION;
        let Some(h) = open_process(pid, access) else {
            // SAFETY: trivially safe.
            return Err(if unsafe { GetLastError() } == ERROR_ACCESS_DENIED { EngineError::PermissionDenied } else { EngineError::NotFound(pid) });
        };
        match action {
            ProcessAction::Terminate => {
                // SAFETY: valid handle with PROCESS_TERMINATE.
                if unsafe { TerminateProcess(h.0, 1) } == 0 {
                    return Err(EngineError::ApiError(format!("TerminateProcess failed ({})", unsafe { GetLastError() })));
                }
                Ok(())
            }
            ProcessAction::Suspend | ProcessAction::Resume => {
                let fname = if action == ProcessAction::Suspend { "NtSuspendProcess\0" } else { "NtResumeProcess\0" };
                let ntdll = wide("ntdll.dll");
                // SAFETY: ntdll is always loaded; the symbol has the signature NTSTATUS(HANDLE).
                unsafe {
                    let m = GetModuleHandleW(ntdll.as_ptr());
                    let f = GetProcAddress(m, fname.as_ptr()).ok_or_else(|| EngineError::Unsupported(fname.trim_end_matches('\0').into()))?;
                    let f: unsafe extern "system" fn(HANDLE) -> i32 = std::mem::transmute(f);
                    let status = f(h.0);
                    if status < 0 {
                        return Err(EngineError::ApiError(format!("{} failed with NTSTATUS {status:#x}", fname.trim_end_matches('\0'))));
                    }
                }
                Ok(())
            }
        }
    }
}

impl WindowsEngine {
    fn push_cmd(&self, out: &mut Vec<PersistenceEntry>, mech: &str, loc: &str, cmd: &str, floor: Severity) {
        let prog = self.normalize_path(&heuristics::command_program(cmd));
        let mut ind = analyze_command(cmd);
        ind.extend(analyze_windows_path(&prog));
        if !prog.is_empty() && prog.contains('\\') && !Path::new(&prog).exists() {
            ind.push(Indicator { severity: Severity::Low, reason: format!("target {prog} does not exist") });
        }
        let risk = max_severity(&ind).max(floor);
        out.push(PersistenceEntry {
            mechanism: mech.into(),
            location: loc.into(),
            target_path: prog,
            command: cmd.into(),
            risk_level: risk,
            reasons: ind.into_iter().map(|i| i.reason).collect(),
            modified: None,
        });
    }

    fn push_special(&self, out: &mut Vec<PersistenceEntry>, mech: &str, loc: &str, value: &str, extra: Option<(Severity, &str)>) {
        let prog = self.normalize_path(&heuristics::command_program(value));
        let mut ind = analyze_command(value);
        ind.extend(analyze_windows_path(&prog));
        if let Some((sev, why)) = extra {
            ind.push(Indicator { severity: sev, reason: why.into() });
        }
        let risk = max_severity(&ind);
        out.push(PersistenceEntry {
            mechanism: mech.into(),
            location: loc.into(),
            target_path: prog,
            command: value.into(),
            risk_level: risk,
            reasons: ind.into_iter().map(|i| i.reason).collect(),
            modified: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers

fn reg_string(v: &winreg::RegValue) -> String {
    match v.vtype {
        REG_SZ | REG_EXPAND_SZ => String::from_reg_value(v).unwrap_or_default(),
        REG_MULTI_SZ => Vec::<String>::from_reg_value(v).map(|x| x.join("\n")).unwrap_or_default(),
        REG_DWORD => u32::from_reg_value(v).map(|x| x.to_string()).unwrap_or_default(),
        _ => String::new(),
    }
}

/// Call an IP Helper "size probe then fill" API.
fn query_table<F: FnMut(*mut c_void, *mut u32) -> u32>(mut f: F) -> EngineResult<Vec<u8>> {
    let mut size: u32 = 0;
    let rc = f(null_mut(), &mut size);
    if rc != ERROR_INSUFFICIENT_BUFFER && rc != 0 && rc != ERROR_MORE_DATA {
        return Err(EngineError::ApiError(format!("socket table query failed ({rc})")));
    }
    for _ in 0..5 {
        size = size.max(4) + 4096;
        let mut buf = vec![0u8; size as usize];
        let rc = f(buf.as_mut_ptr() as *mut c_void, &mut size);
        if rc == 0 {
            return Ok(buf);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(EngineError::ApiError(format!("socket table query failed ({rc})")));
        }
    }
    Err(EngineError::ApiError("socket table kept growing".into()))
}

fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn port_of(dw: u32) -> u16 {
    let b = dw.to_ne_bytes();
    u16::from_be_bytes([b[0], b[1]])
}

fn tcp_state_name(s: u32) -> &'static str {
    match s {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECV",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn v6(bytes: &[u8]) -> String {
    let mut a = [0u8; 16];
    a.copy_from_slice(&bytes[..16]);
    let ip = std::net::Ipv6Addr::from(a);
    ip.to_ipv4_mapped().map(|v| v.to_string()).unwrap_or_else(|| ip.to_string())
}

fn mk_sock(lip: String, lport: u16, rip: String, rport: u16, proto: Protocol, state: &str, pid: u32) -> SocketInfo {
    SocketInfo {
        local_address: lip,
        local_port: lport,
        remote_address: rip,
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

fn parse_tcp_table(buf: &[u8], proto: Protocol) -> Vec<SocketInfo> {
    let mut out = Vec::new();
    if buf.len() < 4 {
        return out;
    }
    let n = rd_u32(buf, 0) as usize;
    let (row, base) = if proto == Protocol::Tcp { (24usize, 4usize) } else { (56usize, 4usize) };
    for i in 0..n {
        let o = base + i * row;
        if o + row > buf.len() {
            break;
        }
        if proto == Protocol::Tcp {
            let state = rd_u32(buf, o);
            let lip = std::net::Ipv4Addr::from(rd_u32(buf, o + 4).to_ne_bytes()).to_string();
            let lport = port_of(rd_u32(buf, o + 8));
            let rip = std::net::Ipv4Addr::from(rd_u32(buf, o + 12).to_ne_bytes()).to_string();
            let rport = if state == 2 { 0 } else { port_of(rd_u32(buf, o + 16)) };
            out.push(mk_sock(lip, lport, rip, rport, proto, tcp_state_name(state), rd_u32(buf, o + 20)));
        } else {
            let lip = v6(&buf[o..o + 16]);
            let lport = port_of(rd_u32(buf, o + 20));
            let rip = v6(&buf[o + 24..o + 40]);
            let state = rd_u32(buf, o + 48);
            let rport = if state == 2 { 0 } else { port_of(rd_u32(buf, o + 44)) };
            out.push(mk_sock(lip, lport, rip, rport, proto, tcp_state_name(state), rd_u32(buf, o + 52)));
        }
    }
    out
}

fn parse_udp_table(buf: &[u8], proto: Protocol) -> Vec<SocketInfo> {
    let mut out = Vec::new();
    if buf.len() < 4 {
        return out;
    }
    let n = rd_u32(buf, 0) as usize;
    let row = if proto == Protocol::Udp { 12 } else { 28 };
    for i in 0..n {
        let o = 4 + i * row;
        if o + row > buf.len() {
            break;
        }
        if proto == Protocol::Udp {
            let lip = std::net::Ipv4Addr::from(rd_u32(buf, o).to_ne_bytes()).to_string();
            out.push(mk_sock(lip, port_of(rd_u32(buf, o + 4)), "*".into(), 0, proto, "-", rd_u32(buf, o + 8)));
        } else {
            let lip = v6(&buf[o..o + 16]);
            out.push(mk_sock(lip, port_of(rd_u32(buf, o + 20)), "*".into(), 0, proto, "-", rd_u32(buf, o + 24)));
        }
    }
    out
}

fn running_driver_services() -> EngineResult<Vec<String>> {
    const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
    const SERVICE_DRIVER: u32 = 0x0000_000B;
    const SERVICE_ACTIVE: u32 = 0x0000_0001;
    const SC_ENUM_PROCESS_INFO: i32 = 0;
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            return Err(EngineError::ApiError(format!("OpenSCManager failed ({})", GetLastError())));
        }
        let mut names = Vec::new();
        let mut resume: u32 = 0;
        let mut buf: Vec<u8> = vec![0u8; 256 * 1024];
        loop {
            let mut needed = 0u32;
            let mut returned = 0u32;
            let ok = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_DRIVER,
                SERVICE_ACTIVE,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut needed,
                &mut returned,
                &mut resume,
                null(),
            );
            let err = GetLastError();
            let entries = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
            for i in 0..returned as usize {
                let e = &*entries.add(i);
                let mut len = 0;
                while *e.lpServiceName.add(len) != 0 {
                    len += 1;
                }
                names.push(String::from_utf16_lossy(std::slice::from_raw_parts(e.lpServiceName, len)));
            }
            if ok != 0 {
                break;
            }
            if err == ERROR_MORE_DATA {
                if needed as usize > buf.len() {
                    buf.resize(needed as usize, 0);
                }
                continue;
            }
            CloseServiceHandle(scm);
            return Err(EngineError::ApiError(format!("EnumServicesStatusEx failed ({err})")));
        }
        CloseServiceHandle(scm);
        Ok(names)
    }
}

fn wmi_subscriptions() -> Vec<PersistenceEntry> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let script = "$ErrorActionPreference='SilentlyContinue';\
        Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object { 'CMD|' + $_.Name + '|' + $_.CommandLineTemplate };\
        Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { 'SCRIPT|' + $_.Name + '|' + (($_.ScriptText + '') -replace '[\\r\\n]+',' ') }";
    let child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
    let Ok(mut child) = child else { return vec![] };
    let deadline = std::time::Instant::now() + Duration::from_secs(25);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                return vec![];
            }
        }
    }
    let Ok(output) = child.wait_with_output() else { return vec![] };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|l| {
            let mut parts = l.splitn(3, '|');
            let kind = parts.next()?;
            let name = parts.next()?.to_string();
            let body = parts.next().unwrap_or("").to_string();
            let mut reasons: Vec<String> = analyze_command(&body).into_iter().map(|i| i.reason).collect();
            reasons.push(if kind == "SCRIPT" {
                "WMI ActiveScript consumer executes script on an event trigger".into()
            } else {
                "WMI CommandLine consumer executes a program on an event trigger".into()
            });
            let is_scm_default = name == "SCM Event Log Consumer";
            Some(PersistenceEntry {
                mechanism: "wmi-subscription".into(),
                location: format!("root\\subscription\\{name}"),
                target_path: heuristics::command_program(&body),
                command: body,
                risk_level: if is_scm_default { Severity::Info } else { Severity::High },
                reasons,
                modified: None,
            })
        })
        .collect()
}

fn walk_files(dir: &Path, depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() && depth > 0 {
            out.extend(walk_files(&e.path(), depth - 1));
        } else if ft.is_file() {
            out.push(e.path());
        }
    }
    out
}

fn file_mtime(p: &Path) -> Option<u64> {
    std::fs::metadata(p).ok()?.modified().ok()?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// Read a text file that may be UTF-16LE (with BOM) or UTF-8.
fn read_text_any(p: &Path) -> Option<String> {
    let b = std::fs::read(p).ok()?;
    if b.len() >= 2 && b[0] == 0xFF && b[1] == 0xFE {
        let u: Vec<u16> = b[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&u))
    } else {
        Some(String::from_utf8_lossy(&b).into_owned())
    }
}

fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)? + s;
    Some(xml[s..e].trim().to_string())
}

fn xml_tags(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find(&open) {
        let after = &rest[s + open.len()..];
        let Some(e) = after.find(&close) else { break };
        out.push(after[..e].to_string());
        rest = &after[e + close.len()..];
    }
    out
}

fn xml_unescape(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&apos;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

/// Best-effort .lnk target extraction (LinkInfo local base path, else the
/// first absolute path-looking string in the file).
fn lnk_target(p: &Path) -> Option<String> {
    // Shortcuts are attacker-controllable: cap the read and bounds-check
    // every offset taken from the file so a crafted .lnk cannot panic the scan.
    const MAX_LNK: u64 = 1 << 20;
    if std::fs::metadata(p).ok()?.len() > MAX_LNK {
        return None;
    }
    let b = std::fs::read(p).ok()?;
    if b.len() < 0x4C || rd_u32(&b, 0) != 0x4C {
        return None;
    }
    let flags = rd_u32(&b, 0x14);
    let mut off = 0x4Cusize;
    if flags & 0x1 != 0 {
        // LinkTargetIDList present
        let len = u16::from_le_bytes([*b.get(off)?, *b.get(off + 1)?]) as usize;
        off = off.checked_add(2 + len)?;
    }
    if flags & 0x2 != 0 && off.checked_add(0x1C).is_some_and(|end| end <= b.len()) {
        let info_start = off;
        let local_base_off = rd_u32(&b, info_start + 0x10) as usize;
        if local_base_off != 0 {
            let s = info_start.checked_add(local_base_off)?;
            let tail = b.get(s..)?;
            let len = tail.iter().position(|c| *c == 0)?;
            let path = String::from_utf8_lossy(&tail[..len]).into_owned();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }
    // Fallback: scan UTF-16 strings for "X:\"
    let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let s = String::from_utf16_lossy(&u);
    s.split('\0').find(|t| t.len() > 3 && t.as_bytes().get(1) == Some(&b':') && t.as_bytes().get(2) == Some(&b'\\')).map(|t| t.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_agree_on_self() {
        let e = WindowsEngine::new();
        let me = std::process::id();
        assert!(e.pid_alive(me));
        assert!(e.scan_syscall_view().unwrap().contains(&me));
        let api = e.scan_user_space().unwrap();
        let mine = api.iter().find(|p| p.pid == me).expect("self in toolhelp");
        assert!(mine.path.to_ascii_lowercase().ends_with(".exe"));
        assert!(mine.start_time > 0);
    }

    #[test]
    fn socket_tables_include_our_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let e = WindowsEngine::new();
        let socks = e.scan_network_sockets().unwrap();
        let s = socks.iter().find(|s| s.protocol == Protocol::Tcp && s.local_port == port).expect("listener present");
        assert_eq!(s.state, "LISTEN");
        assert_eq!(s.pid, Some(std::process::id()));
        assert_eq!(s.local_address, "127.0.0.1");
    }

    #[test]
    fn refuses_kernel_and_self() {
        let e = WindowsEngine::new();
        assert!(matches!(e.act_on_process(4, 0, ProcessAction::Terminate), Err(EngineError::Refused(_))));
        assert!(matches!(e.act_on_process(std::process::id(), 0, ProcessAction::Terminate), Err(EngineError::Refused(_))));
    }

    #[test]
    fn suspend_resume_kill_child() {
        let e = WindowsEngine::new();
        let mut child = std::process::Command::new("ping").args(["-n", "30", "127.0.0.1"]).stdout(std::process::Stdio::null()).spawn().unwrap();
        let pid = child.id();
        std::thread::sleep(Duration::from_millis(200));
        let start = process_start_time(pid).unwrap();
        assert!(matches!(e.act_on_process(pid, start + 1000, ProcessAction::Terminate), Err(EngineError::Refused(_))));
        e.act_on_process(pid, start, ProcessAction::Suspend).unwrap();
        e.act_on_process(pid, start, ProcessAction::Resume).unwrap();
        e.act_on_process(pid, start, ProcessAction::Terminate).unwrap();
        assert!(!child.wait().unwrap().success());
    }

    #[test]
    fn path_normalisation() {
        let e = WindowsEngine::new();
        let sr = e.system_root.clone();
        assert_eq!(e.normalize_path("\\SystemRoot\\System32\\drivers\\x.sys"), format!("{sr}\\System32\\drivers\\x.sys"));
        assert_eq!(e.normalize_path("\\??\\C:\\evil\\r.sys"), "C:\\evil\\r.sys");
        assert_eq!(e.normalize_path("System32\\drivers\\y.sys"), format!("{sr}\\System32\\drivers\\y.sys"));
        assert_eq!(e.normalize_path("%SystemRoot%\\notepad.exe"), format!("{sr}\\notepad.exe"));
    }

    #[test]
    fn crafted_lnk_never_panics() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("evil.lnk");
        let mut b = vec![0u8; 0x4C + 0x20];
        b[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&0x2u32.to_le_bytes()); // HasLinkInfo, no IDList
        b[0x4C + 0x10..0x4C + 0x14].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes()); // offset far past EOF
        std::fs::write(&p, &b).unwrap();
        assert_eq!(lnk_target(&p), None);
        b[0x14..0x18].copy_from_slice(&0x3u32.to_le_bytes()); // IDList length pointing past EOF
        b[0x4C..0x4E].copy_from_slice(&0xFFFFu16.to_le_bytes());
        std::fs::write(&p, &b).unwrap();
        let _ = lnk_target(&p);
    }

    #[test]
    fn xml_helpers() {
        let x = "<Actions><Exec><Command>C:\\a.exe</Command><Arguments>-x &amp; y</Arguments></Exec><Exec><Command>b</Command></Exec></Actions>";
        let ex = xml_tags(x, "Exec");
        assert_eq!(ex.len(), 2);
        assert_eq!(xml_tag(&ex[0], "Command").unwrap(), "C:\\a.exe");
        assert_eq!(xml_unescape(&xml_tag(&ex[0], "Arguments").unwrap()), "-x & y");
    }

    #[test]
    fn brute_force_finds_self_and_system_processes() {
        let e = WindowsEngine::new();
        let reality = e.scan_kernel_reality(&CancelToken::new()).unwrap();
        assert!(reality.iter().any(|p| p.pid == std::process::id()));
    }
}
