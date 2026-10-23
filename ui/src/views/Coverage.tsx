import { useMemo } from 'react';
import { useI18n } from '../i18n';
import type { ScanReport } from '../types';

type Platform = 'L' | 'W';
interface Technique {
  id: string;
  name: string;
  platforms: Platform[];
}

// Every technique id here is emitted by a rule in crates/panoptic-core.
// Keep in sync when adding detections.
export const COVERAGE: { tactic: string; id: string; techniques: Technique[] }[] = [
  {
    tactic: 'Execution',
    id: 'TA0002',
    techniques: [
      { id: 'T1059', name: 'Command and Scripting Interpreter', platforms: ['L', 'W'] },
      { id: 'T1204.002', name: 'User Execution: Malicious File', platforms: ['W'] },
    ],
  },
  {
    tactic: 'Persistence',
    id: 'TA0003',
    techniques: [
      { id: 'T1053.002', name: 'Scheduled Task/Job: At', platforms: ['L'] },
      { id: 'T1053.003', name: 'Scheduled Task/Job: Cron', platforms: ['L'] },
      { id: 'T1053.005', name: 'Scheduled Task/Job: Scheduled Task', platforms: ['W'] },
      { id: 'T1543.002', name: 'Create or Modify System Process: Systemd Service', platforms: ['L'] },
      { id: 'T1543.003', name: 'Create or Modify System Process: Windows Service', platforms: ['W'] },
      { id: 'T1037.004', name: 'Boot or Logon Init Scripts: RC Scripts', platforms: ['L'] },
      { id: 'T1546.004', name: 'Event Triggered Execution: Unix Shell Configuration', platforms: ['L'] },
      { id: 'T1546.003', name: 'Event Triggered Execution: WMI Event Subscription', platforms: ['W'] },
      { id: 'T1546.007', name: 'Event Triggered Execution: Netsh Helper DLL', platforms: ['W'] },
      { id: 'T1546.009', name: 'Event Triggered Execution: AppCert DLLs', platforms: ['W'] },
      { id: 'T1546.010', name: 'Event Triggered Execution: AppInit DLLs', platforms: ['W'] },
      { id: 'T1546.012', name: 'Event Triggered Execution: IFEO Injection', platforms: ['W'] },
      { id: 'T1546.015', name: 'Event Triggered Execution: COM Hijacking', platforms: ['W'] },
      { id: 'T1546.017', name: 'Event Triggered Execution: Udev Rules', platforms: ['L'] },
      { id: 'T1547.001', name: 'Boot or Logon Autostart: Run Keys / Startup Folder', platforms: ['W'] },
      { id: 'T1547.002', name: 'Boot or Logon Autostart: Authentication Package', platforms: ['W'] },
      { id: 'T1547.004', name: 'Boot or Logon Autostart: Winlogon Helper DLL', platforms: ['W'] },
      { id: 'T1547.006', name: 'Boot or Logon Autostart: Kernel Modules and Extensions', platforms: ['L', 'W'] },
      { id: 'T1547.010', name: 'Boot or Logon Autostart: Port Monitors', platforms: ['W'] },
      { id: 'T1547.013', name: 'Boot or Logon Autostart: XDG Autostart Entries', platforms: ['L'] },
      { id: 'T1098.004', name: 'Account Manipulation: SSH Authorized Keys', platforms: ['L'] },
      { id: 'T1556.003', name: 'Modify Authentication Process: Pluggable Authentication Modules', platforms: ['L'] },
      { id: 'T1505.003', name: 'Server Software Component: Web Shell', platforms: ['W'] },
    ],
  },
  {
    tactic: 'Privilege Escalation',
    id: 'TA0004',
    techniques: [
      { id: 'T1055', name: 'Process Injection', platforms: ['L', 'W'] },
      { id: 'T1574.006', name: 'Hijack Execution Flow: Dynamic Linker Hijacking', platforms: ['L'] },
    ],
  },
  {
    tactic: 'Defense Evasion',
    id: 'TA0005',
    techniques: [
      { id: 'T1014', name: 'Rootkit', platforms: ['L', 'W'] },
      { id: 'T1036', name: 'Masquerading', platforms: ['L', 'W'] },
      { id: 'T1036.004', name: 'Masquerading: Masquerade Task or Service', platforms: ['L', 'W'] },
      { id: 'T1036.005', name: 'Masquerading: Match Legitimate Name or Location', platforms: ['L', 'W'] },
      { id: 'T1070.004', name: 'Indicator Removal: File Deletion', platforms: ['L', 'W'] },
      { id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools', platforms: ['W'] },
      { id: 'T1553.006', name: 'Subvert Trust Controls: Code Signing Policy Modification', platforms: ['W'] },
      { id: 'T1620', name: 'Reflective Code Loading', platforms: ['L'] },
    ],
  },
  {
    tactic: 'Credential Access',
    id: 'TA0006',
    techniques: [{ id: 'T1040', name: 'Network Sniffing', platforms: ['L'] }],
  },
  {
    tactic: 'Command and Control',
    id: 'TA0011',
    techniques: [
      { id: 'T1571', name: 'Non-Standard Port', platforms: ['L', 'W'] },
      { id: 'T1205.002', name: 'Traffic Signaling: Socket Filters', platforms: ['L'] },
    ],
  },
];

export function Coverage({ report }: { report: ScanReport | null }) {
  const { t } = useI18n();
  const detected = useMemo(() => new Set((report?.findings ?? []).filter((f) => !f.suppressed && f.mitre).map((f) => f.mitre!)), [report]);
  const total = COVERAGE.reduce((n, c) => n + c.techniques.length, 0);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold tracking-tight">{t('coverage.title')}</h2>
          <p className="mt-1 max-w-2xl text-[13px] text-muted">{t('coverage.subtitle')}</p>
        </div>
        <div className="flex items-center gap-4 text-xs text-muted">
          <span className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded bg-brand/15 ring-1 ring-brand/30" /> {t('coverage.covered')} · {t('coverage.techniques', { count: total })}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded bg-danger" /> {t('coverage.detected')} · {detected.size}
          </span>
        </div>
      </header>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {COVERAGE.map((c) => (
          <section key={c.id} className="card overflow-hidden">
            <div className="flex items-center justify-between border-b border-line bg-raised/50 px-4 py-3">
              <div>
                <div className="text-[13px] font-semibold">{c.tactic}</div>
                <div className="mono text-[11px] text-subtle">{c.id}</div>
              </div>
              <span className="chip bg-brand/10 text-brand">{c.techniques.length}</span>
            </div>
            <ul className="divide-y divide-line/60">
              {c.techniques.map((tech) => {
                const hit = detected.has(tech.id) || [...detected].some((d) => d.startsWith(`${tech.id}.`));
                return (
                  <li key={tech.id} className={`flex items-center gap-3 px-4 py-2.5 ${hit ? 'bg-danger/10' : ''}`}>
                    <span className={`mono w-[72px] shrink-0 text-[11px] ${hit ? 'font-bold text-danger' : 'text-brand'}`}>{tech.id}</span>
                    <span className="flex-1 text-[12.5px] leading-snug" lang="en">
                      {tech.name}
                    </span>
                    <span className="flex gap-1" title={t('coverage.platforms')}>
                      {tech.platforms.map((p) => (
                        <span key={p} className="kbd">
                          {p === 'L' ? 'Linux' : 'Win'}
                        </span>
                      ))}
                    </span>
                  </li>
                );
              })}
            </ul>
          </section>
        ))}
      </div>
      <p className="text-[11px] text-subtle">MITRE ATT&CK® is a registered trademark of The MITRE Corporation.</p>
    </div>
  );
}
