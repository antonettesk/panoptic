import type { MessageKey } from './i18n';
import type { Finding, FindingCategory, Severity } from './types';
import { SEVERITY_RANK } from './types';

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  return s < 60 ? `${s.toFixed(1)} s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

export function formatUptime(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

/** Token-based classes so severities read correctly in light and dark themes. */
export const SEVERITY_STYLE: Record<Severity, { badge: string; text: string; ring: string; soft: string; dot: string; bar: string }> = {
  critical: { badge: 'bg-danger text-white', text: 'text-danger', ring: 'ring-danger/40', soft: 'bg-danger/10', dot: 'bg-danger', bar: 'bg-danger' },
  high: { badge: 'bg-warn text-white', text: 'text-warn', ring: 'ring-warn/40', soft: 'bg-warn/10', dot: 'bg-warn', bar: 'bg-warn' },
  medium: { badge: 'bg-caution text-black', text: 'text-caution', ring: 'ring-caution/40', soft: 'bg-caution/10', dot: 'bg-caution', bar: 'bg-caution' },
  low: { badge: 'bg-info text-white', text: 'text-info', ring: 'ring-info/40', soft: 'bg-info/10', dot: 'bg-info', bar: 'bg-info' },
  info: { badge: 'bg-subtle/30 text-fg', text: 'text-muted', ring: 'ring-line', soft: 'bg-raised', dot: 'bg-subtle', bar: 'bg-subtle' },
};

export const severityKey = (s: Severity) => `sev.${s}` as MessageKey;
export const categoryKey = (c: FindingCategory) => `cat.${c}` as MessageKey;

export function riskLevel(score: number): { key: MessageKey; color: string; tone: 'danger' | 'warn' | 'caution' | 'ok' } {
  if (score >= 70) return { key: 'risk.compromised', color: 'rgb(var(--danger))', tone: 'danger' };
  if (score >= 40) return { key: 'risk.high', color: 'rgb(var(--warn))', tone: 'warn' };
  if (score > 0) return { key: 'risk.review', color: 'rgb(var(--caution))', tone: 'caution' };
  return { key: 'risk.clean', color: 'rgb(var(--ok))', tone: 'ok' };
}

/** Case-insensitive match of every whitespace-separated term against any field. */
export function matchesQuery(query: string, ...fields: (string | number | null | undefined)[]): boolean {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return true;
  const hay = fields.map((f) => (f == null ? '' : String(f).toLowerCase())).join('\u0000');
  return terms.every((t) => hay.includes(t));
}

export interface FindingFilter {
  severities: Set<Severity>;
  category: FindingCategory | 'all';
  query: string;
  showSuppressed: boolean;
}

export function filterFindings(findings: Finding[], f: FindingFilter): Finding[] {
  return findings.filter(
    (x) =>
      (f.showSuppressed || !x.suppressed) &&
      f.severities.has(x.severity) &&
      (f.category === 'all' || x.category === f.category) &&
      matchesQuery(f.query, x.title, x.description, x.path, x.pid, x.mitre, x.id, ...x.evidence),
  );
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[b] - SEVERITY_RANK[a];
}

export type SortDir = 'asc' | 'desc';
export function sortRows<T>(rows: T[], key: (r: T) => string | number, dir: SortDir): T[] {
  const m = dir === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => {
    const x = key(a);
    const y = key(b);
    if (typeof x === 'number' && typeof y === 'number') return (x - y) * m;
    return String(x).localeCompare(String(y), undefined, { numeric: true }) * m;
  });
}

export function mitreUrl(id: string): string {
  const [base, sub] = id.split('.');
  return `https://attack.mitre.org/techniques/${base}/${sub ?? ''}`;
}

export function isValidAccountId(v: string): boolean {
  return /^\d{12}$/.test(v);
}

export function isValidInstanceId(v: string): boolean {
  return v === '' || /^i-[0-9a-f]{8,17}$/.test(v);
}

export function loadPref<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(`panoptic:${key}`);
    return v ? { ...fallback, ...JSON.parse(v) } : fallback;
  } catch {
    return fallback;
  }
}

export function savePref(key: string, value: unknown): void {
  try {
    localStorage.setItem(`panoptic:${key}`, JSON.stringify(value));
  } catch {
    /* storage unavailable — preference simply isn't remembered */
  }
}
