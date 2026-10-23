# Detection catalog

Severity guide:
- **Critical**: two OS layers disagree, or an unambiguous attacker artefact exists.
- **High**: strong indicator.
- **Medium**: worth investigating.
- **Low/Info**: inventory and context.

## Cross-layer (both platforms)

| Detection | Technique | Severity | Notes |
|---|---|---|---|
| Kernel-hidden process | T1014 | Critical | Alive per brute-force probe; absent from every enumeration |
| User-mode-hidden process | T1574.006 | Critical | Visible to raw syscalls; hidden from libc/API |
| Hidden TCP/UDP listener | T1014 | Critical | Port bound in kernel, absent from the socket table, and accepts a connection (TCP) |
| Unlinked kernel module | T1547.006 | Critical | Linux: in `/sys/module` with `initstate`, missing from `/proc/modules`. Windows: SCM-running driver missing from the loaded-module list |

## Process heuristics

| Rule | Platform | Technique |
|---|---|---|
| Fileless execution (`memfd:`) | Linux | T1620 |
| Running binary deleted from disk (Low when it's a package upgrade under `/usr`) | Both | T1070.004 |
| Executable in staging dirs (`/tmp`, `/dev/shm`, `%TEMP%`, `Downloads`, `Users\Public`, …) | Both | T1036 |
| User process masquerading as a kernel thread (`[kworker]` with an exe) | Linux | T1036.004 |
| Protected daemon name with a foreign binary (`sshd`, `cron`, …) | Linux | T1036.005 |
| System binary name in the wrong directory (`svchost.exe` outside System32) | Windows | T1036.005 |
| Typosquatted system name (OSA distance 1, e.g. `scvhost.exe`) | Windows | T1036.004 |
| Multiple singleton instances (`lsass`, `wininit`, `services`) | Windows | T1036 |
| Impossible parent (`svchost`←`services`, `lsass`←`wininit`) | Windows | T1055 |
| Office app spawning a shell or LOLBin | Windows | T1204.002 |
| Web/SQL server spawning a shell (web shell) | Windows | T1505.003 |
| `LD_PRELOAD` in the environment; `.so` mapped from staging or deleted | Linux | T1574.006 / T1055 |
| Command-line rules: reverse shells, download cradles, encoded PowerShell, LOLBins, anti-forensics, ransomware prep | Both | various |

## Network heuristics

| Rule | Technique |
|---|---|
| Shell or interpreter owning a non-loopback socket (bind/reverse shell) | T1059 |
| netcat/socat holding a socket | T1059 |
| Connection to known C2 / RAT / miner / Tor ports | T1571 |
| Listener on classic backdoor ports (1337, 31337, 4444) | T1571 |
| Raw/packet socket held by an unexpected process (BPFDoor-style) | T1205.002 |
| Socket owned by a binary in a staging directory or deleted from disk | T1036 |

## Persistence

**Linux:**

| Mechanism | Technique |
|---|---|
| cron, anacron, user crontabs, `cron.*` dirs | T1053.003 |
| at jobs | T1053.002 |
| systemd units, timers and generators (system + user) | T1543.002 |
| rc.local, init.d | T1037.004 |
| Shell profiles | T1546.004 |
| `/etc/ld.so.preload` | T1574.006 |
| XDG autostart | T1547.013 |
| SSH `authorized_keys` forced commands | T1098.004 |
| udev `RUN+=` | T1546.017 |
| PAM `pam_exec` / non-standard modules | T1556.003 |
| motd scripts | T1037 |
| Module autoload | T1547.006 |

**Windows:**

| Mechanism | Technique |
|---|---|
| Run/RunOnce keys (all loaded user hives, WOW64) | T1547.001 |
| Startup folders (with `.lnk` resolution) | T1547.001 |
| BootExecute | T1547.001 |
| Services and ServiceDlls | T1543.003 |
| Scheduled tasks | T1053.005 |
| Winlogon Shell/Userinit/Taskman | T1547.004 |
| IFEO Debugger, SilentProcessExit | T1546.012 |
| AppInit_DLLs | T1546.010 |
| AppCertDlls | T1546.009 |
| LSA packages | T1547.002 |
| Netsh helpers | T1546.007 |
| Print monitors | T1547.010 |
| COM hijacking (per-user InprocServer32 that redirects a machine class) | T1546.015 |
| WMI event subscriptions | T1546.003 |

Entries modified in the last 7 days that already carry a risk indicator are bumped one severity level.

## Integrity

| Check | Platform | Technique |
|---|---|---|
| `/etc/ld.so.preload` present | Linux | T1574.006 |
| Kernel taint (forced, out-of-tree, unsigned modules) | Linux | T1547.006 |
| Known rootkit/malware artefact paths (Reptile, Jynx, Kinsing, BPFDoor mutexes, …) | Linux | T1014 |
| Promiscuous network interface | Linux | T1040 |
| Test-signing / disabled driver signature enforcement | Windows | T1553.006 |
| Defender disabled by policy; broad or risky exclusions | Windows | T1562.001 |
| Hosts file redirecting security or update domains | Windows | T1562.001 |

## Known benign suppressions built in

These patterns were found during real-host validation and are excluded by design:

- crash-dump filter drivers (`dump_*.sys`);
- Chromium/Electron `--gpu-preferences` blobs;
- Windows' default `0.0.0.1 mssplus.mcafee.com` hosts entry;
- session-process PPID reuse;
- TCP sockets that are bound but not listening;
- common per-user app install locations.
