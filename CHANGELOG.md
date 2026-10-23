# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-10-23

### Added

**Cross-layer detection**
- **Cross-Layer Truth Analysis engine** (`panoptic-core`) for Linux and Windows.
- **Hidden processes:**
  - Linux: libc vs raw `getdents64` vs `tgkill` PID-space probe.
  - Windows: Toolhelp vs `EnumProcesses` vs `OpenProcess` probe.
  - Multi-pass confirmation guards against race conditions.
- **Hidden listeners:** kernel `bind()` probing, confirmed with `connect()` so that bound-only sockets are never mislabelled.
- **Unlinked kernel modules:** `/proc/modules` vs `/sys/module`; SCM running drivers vs `EnumDeviceDrivers`.

**Heuristics and checks**
- Persistence enumeration with 20+ mechanisms per OS, plus process, socket and integrity heuristics mapped to MITRE ATT&CK.

**Analyst workflow**
- Risk score, accepted risks (by finding ID or path pattern), and known-good baselines with drift detection.
- Scan history.
- Process suspend, resume and kill, guarded against PID reuse and critical processes.

**Integrations and automation**
- **AWS Security Hub export** in ASFF, with batching, stable IDs, EC2 resource mapping and partition awareness.
- **Scheduled scans** via Windows Task Scheduler or systemd user timers, using the bundled CLI sidecar.
- `panoptic-cli`: headless scanner with CI-friendly exit codes. Exports HTML, JSON, CSV, text and ASFF.

**Desktop app**
- Tauri v2 desktop app with guided onboarding and readiness checks.
- Opt-in detections and integrations.
- Setup guide, MITRE ATT&CK coverage matrix, and a command palette.
- Dark and light themes.
- **9 languages**, including right-to-left Arabic.
- Offline installers: MSI and NSIS with embedded WebView2; deb and AppImage.

**Project**
- Licensed under the **GNU Affero General Public License v3.0** (`AGPL-3.0-only`), with community documentation. The About screen and `panoptic-cli --help` show the AGPL's legal notices.

### Fixed (from real-host validation)
- Windows: non-elevated driver enumeration is no longer misreported, because kernel addresses are hidden by KASLR.
- Windows: crash-dump filter drivers (`dump_*.sys`) are no longer reported as missing from disk.
- Windows: per-user COM registrations of the same server are no longer reported as hijacks.
- Windows: session-manager parent PID reuse no longer produces false parent anomalies.
- Linux: scripts that only *mention* `/tmp` are no longer treated as executing from it.
- PowerShell `-ExecutionPolicy Bypass` on its own is now Low; it escalates only when combined with other indicators.
