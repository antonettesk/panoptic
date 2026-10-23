import { useEffect, useMemo, useState } from 'react';
import { ChevronRight, Eye, EyeOff, Pause, ShieldCheck, Skull } from 'lucide-react';
import type { Finding, FindingCategory, ProcessAction, ScanReport, Severity } from '../types';
import { SEVERITIES } from '../types';
import { useI18n } from '../i18n';
import { CopyButton, EmptyState, SearchBox, SeverityBadge } from '../components/ui';
import { SEVERITY_STYLE, categoryKey, filterFindings, loadPref, mitreUrl, savePref, severityKey } from '../util';

interface Props {
  report: ScanReport;
  focus?: string;
  onSuppress: (id: string, suppressed: boolean) => void;
  onProcessAction: (pid: number, action: ProcessAction) => void;
}

export function Findings({ report, focus, onSuppress, onProcessAction }: Props) {
  const { t } = useI18n();
  const saved = loadPref('findingFilter', { severities: ['critical', 'high', 'medium', 'low'] as Severity[], showSuppressed: false });
  const [severities, setSeverities] = useState<Set<Severity>>(new Set(saved.severities));
  const [category, setCategory] = useState<FindingCategory | 'all'>('all');
  const [query, setQuery] = useState('');
  const [showSuppressed, setShowSuppressed] = useState(saved.showSuppressed);
  const [open, setOpen] = useState<Set<string>>(new Set(focus ? [focus] : []));

  useEffect(() => savePref('findingFilter', { severities: [...severities], showSuppressed }), [severities, showSuppressed]);
  useEffect(() => {
    if (focus) {
      setOpen(new Set([focus]));
      requestAnimationFrame(() => document.getElementById(`f-${focus}`)?.scrollIntoView({ block: 'center', behavior: 'smooth' }));
    }
  }, [focus]);

  const categories = useMemo(() => [...new Set(report.findings.map((f) => f.category))].sort(), [report.findings]);
  const list = useMemo(() => filterFindings(report.findings, { severities, category, query, showSuppressed }), [report.findings, severities, category, query, showSuppressed]);
  const toggleSev = (s: Severity) =>
    setSeverities((prev) => {
      const n = new Set(prev);
      if (n.has(s)) n.delete(s);
      else n.add(s);
      return n;
    });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <SearchBox value={query} onChange={setQuery} placeholder={t('findings.search')} />
        <div className="flex flex-wrap gap-1.5">
          {SEVERITIES.map((s) => {
            const n = report.findings.filter((f) => f.severity === s && (showSuppressed || !f.suppressed)).length;
            const on = severities.has(s);
            return (
              <button key={s} onClick={() => toggleSev(s)} aria-pressed={on} className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition ${on ? `border-transparent ${SEVERITY_STYLE[s].soft} ${SEVERITY_STYLE[s].text}` : 'border-line text-subtle hover:text-fg'}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY_STYLE[s].dot}`} />
                {t(severityKey(s))} <span className="tabular-nums opacity-70">{n}</span>
              </button>
            );
          })}
        </div>
        <select className="input" value={category} onChange={(e) => setCategory(e.target.value as FindingCategory | 'all')} aria-label={t('findings.allCategories')}>
          <option value="all">{t('findings.allCategories')}</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {t(categoryKey(c))}
            </option>
          ))}
        </select>
        <label className="ms-auto flex cursor-pointer items-center gap-2 text-xs text-muted">
          <input type="checkbox" className="accent-[rgb(var(--brand))]" checked={showSuppressed} onChange={(e) => setShowSuppressed(e.target.checked)} />
          {t('findings.showSuppressed', { count: report.summary.suppressed })}
        </label>
      </div>

      {list.length === 0 ? (
        <EmptyState icon={<ShieldCheck size={22} className="text-ok" />} title={report.findings.length ? t('findings.noneMatch') : t('findings.none')}>
          {report.findings.length ? t('findings.noneMatchHint') : t('findings.noneHint')}
        </EmptyState>
      ) : (
        <div className="space-y-2">
          {list.map((f) => (
            <FindingCard
              key={f.id}
              f={f}
              open={open.has(f.id)}
              toggle={() =>
                setOpen((o) => {
                  const n = new Set(o);
                  if (n.has(f.id)) n.delete(f.id);
                  else n.add(f.id);
                  return n;
                })
              }
              onSuppress={onSuppress}
              onProcessAction={onProcessAction}
              processAlive={f.pid != null && report.processes.some((p) => p.pid === f.pid)}
            />
          ))}
          <p className="pt-2 text-center text-[11px] text-subtle">{t('findings.sourceNote')}</p>
        </div>
      )}
    </div>
  );
}

function FindingCard({ f, open, toggle, onSuppress, onProcessAction, processAlive }: { f: Finding; open: boolean; toggle: () => void; onSuppress: Props['onSuppress']; onProcessAction: Props['onProcessAction']; processAlive: boolean }) {
  const { t } = useI18n();
  const st = SEVERITY_STYLE[f.severity];
  return (
    <div id={`f-${f.id}`} className={`card overflow-hidden transition ${open ? `ring-1 ${st.ring}` : ''} ${f.suppressed ? 'opacity-60' : ''}`}>
      <button className="flex w-full items-center gap-3 px-4 py-3 text-start hover:bg-raised/40" onClick={toggle} aria-expanded={open}>
        <span className={`h-8 w-1 shrink-0 rounded-full ${st.bar}`} aria-hidden="true" />
        <ChevronRight size={15} className={`shrink-0 text-subtle transition rtl:-scale-x-100 ${open ? 'rotate-90 rtl:-rotate-90' : ''}`} />
        <SeverityBadge severity={f.severity} className="w-[74px] shrink-0 justify-center" />
        <span className="min-w-0 flex-1 truncate text-[13px] font-medium" lang="en">
          {f.title}
        </span>
        {f.suppressed && <span className="chip bg-raised text-muted">{t('findings.suppressedTag')}</span>}
        <span className="hidden shrink-0 text-[11px] text-subtle md:inline">{t(categoryKey(f.category))}</span>
        {f.mitre && <span className="mono hidden shrink-0 text-[11px] text-subtle lg:inline">{f.mitre}</span>}
      </button>
      {open && (
        <div className="space-y-4 border-t border-line bg-raised/30 px-6 py-5 text-[13px]">
          <p className="leading-relaxed" lang="en">
            {f.description}
          </p>
          <dl className="grid grid-cols-[100px_1fr] gap-x-4 gap-y-2 text-xs">
            {f.pid != null && (
              <>
                <dt className="text-muted">{t('findings.pid')}</dt>
                <dd className="mono">{f.pid}</dd>
              </>
            )}
            {f.path && (
              <>
                <dt className="text-muted">{t('findings.path')}</dt>
                <dd className="flex min-w-0 items-center gap-2">
                  <code className="mono break-all">{f.path}</code> <CopyButton text={f.path} />
                </dd>
              </>
            )}
            {f.mitre && (
              <>
                <dt className="text-muted">{t('findings.attack')}</dt>
                <dd className="mono">
                  {f.mitre} <span className="text-subtle">· {mitreUrl(f.mitre)}</span>
                </dd>
              </>
            )}
            <dt className="text-muted">{t('findings.id')}</dt>
            <dd className="flex items-center gap-2">
              <code className="mono text-muted">{f.id}</code> <CopyButton text={f.id} />
            </dd>
          </dl>
          {f.evidence.length > 0 && (
            <div>
              <div className="eyebrow mb-1.5">{t('findings.evidence')}</div>
              <ul className="space-y-1 rounded-lg border border-line bg-surface p-3" dir="ltr">
                {f.evidence.map((e, i) => (
                  <li key={i} className="mono break-all leading-relaxed text-fg/90">
                    <span className="text-subtle">› </span>
                    {e}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {f.recommendation && (
            <div className="rounded-lg border border-ok/25 bg-ok/5 p-3">
              <div className="eyebrow mb-1 text-ok">{t('findings.recommendation')}</div>
              <p className="leading-relaxed" lang="en">
                {f.recommendation}
              </p>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            {f.pid != null && processAlive && (
              <>
                <button className="btn-secondary btn-sm" onClick={() => onProcessAction(f.pid!, 'suspend')}>
                  <Pause size={13} /> {t('findings.suspend', { pid: f.pid })}
                </button>
                <button className="btn-danger btn-sm" onClick={() => onProcessAction(f.pid!, 'terminate')}>
                  <Skull size={13} /> {t('findings.kill', { pid: f.pid })}
                </button>
              </>
            )}
            <button className="btn-secondary btn-sm" onClick={() => onSuppress(f.id, !f.suppressed)}>
              {f.suppressed ? <Eye size={13} /> : <EyeOff size={13} />} {f.suppressed ? t('findings.unsuppress') : t('findings.suppress')}
            </button>
            <CopyButton text={JSON.stringify(f, null, 2)} label="JSON" />
          </div>
        </div>
      )}
    </div>
  );
}
