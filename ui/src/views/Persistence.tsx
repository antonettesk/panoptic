import { useMemo, useState } from 'react';
import { Anchor, ChevronRight } from 'lucide-react';
import type { PersistenceEntry, ScanReport } from '../types';
import { SEVERITY_RANK } from '../types';
import { useI18n } from '../i18n';
import { EmptyState, SearchBox, Segmented, SeverityBadge } from '../components/ui';
import { matchesQuery } from '../util';

type RiskFilter = 'risky' | 'all';

export function Persistence({ report }: { report: ScanReport }) {
  const { t } = useI18n();
  const risky = report.persistence.filter((p) => SEVERITY_RANK[p.risk_level] >= SEVERITY_RANK.low).length;
  const [risk, setRisk] = useState<RiskFilter>(risky ? 'risky' : 'all');
  const [mechanism, setMechanism] = useState('all');
  const [query, setQuery] = useState('');

  const mechanisms = useMemo(() => {
    const m = new Map<string, number>();
    report.persistence.forEach((p) => m.set(p.mechanism, (m.get(p.mechanism) ?? 0) + 1));
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [report.persistence]);

  const rows = useMemo(
    () =>
      report.persistence
        .filter((p) => (risk === 'all' || SEVERITY_RANK[p.risk_level] >= SEVERITY_RANK.low) && (mechanism === 'all' || p.mechanism === mechanism) && matchesQuery(query, p.location, p.command, p.target_path, p.mechanism, ...p.reasons))
        .sort((a, b) => SEVERITY_RANK[b.risk_level] - SEVERITY_RANK[a.risk_level] || a.location.localeCompare(b.location)),
    [report.persistence, risk, mechanism, query],
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <SearchBox value={query} onChange={setQuery} placeholder={t('persist.search')} />
        <Segmented<RiskFilter>
          value={risk}
          onChange={setRisk}
          options={[
            { value: 'risky', label: t('persist.risky'), count: risky },
            { value: 'all', label: t('persist.all'), count: report.persistence.length },
          ]}
        />
        <select className="input" value={mechanism} onChange={(e) => setMechanism(e.target.value)} aria-label={t('persist.allMechanisms')}>
          <option value="all">{t('persist.allMechanisms')}</option>
          {mechanisms.map(([m, n]) => (
            <option key={m} value={m}>
              {m} ({n})
            </option>
          ))}
        </select>
      </div>
      {rows.length === 0 ? (
        <EmptyState icon={<Anchor size={22} />} title={risk === 'risky' ? t('persist.none') : t('persist.noMatch')}>
          {risk === 'risky' ? t('persist.noneHint', { count: report.persistence.length }) : undefined}
        </EmptyState>
      ) : (
        <div className="card divide-y divide-line/60 overflow-hidden">
          {rows.slice(0, 2000).map((p, i) => (
            <Row key={`${p.location}-${i}`} p={p} />
          ))}
        </div>
      )}
    </div>
  );
}

function Row({ p }: { p: PersistenceEntry }) {
  const { t, formatDate } = useI18n();
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button className="flex w-full items-center gap-3 px-4 py-2.5 text-start hover:bg-raised/50" onClick={() => setOpen(!open)} aria-expanded={open}>
        <ChevronRight size={14} className={`shrink-0 text-subtle transition rtl:-scale-x-100 ${open ? 'rotate-90 rtl:-rotate-90' : ''}`} />
        <SeverityBadge severity={p.risk_level} className="w-[74px] shrink-0 justify-center" />
        <span className="mono w-40 shrink-0 truncate text-[11px] text-subtle">{p.mechanism}</span>
        <span className="mono min-w-0 flex-1 truncate text-xs" title={p.location} dir="ltr">
          {p.location}
        </span>
        <span className="mono hidden max-w-[38%] truncate text-[11px] text-subtle lg:inline" title={p.command} dir="ltr">
          {p.command}
        </span>
      </button>
      {open && (
        <dl className="grid grid-cols-[110px_1fr] gap-x-4 gap-y-2 bg-raised/30 px-6 py-4 text-xs">
          <dt className="text-muted">{t('persist.location')}</dt>
          <dd className="mono break-all" dir="ltr">
            {p.location}
          </dd>
          <dt className="text-muted">{t('persist.command')}</dt>
          <dd className="mono break-all" dir="ltr">
            {p.command || '—'}
          </dd>
          <dt className="text-muted">{t('persist.target')}</dt>
          <dd className="mono break-all" dir="ltr">
            {p.target_path || '—'}
          </dd>
          <dt className="text-muted">{t('persist.modified')}</dt>
          <dd>{formatDate(p.modified)}</dd>
          {p.reasons.length > 0 && (
            <>
              <dt className="text-muted">{t('persist.reasons')}</dt>
              <dd>
                <ul className="space-y-0.5 text-warn" lang="en">
                  {p.reasons.map((r, i) => (
                    <li key={i}>› {r}</li>
                  ))}
                </ul>
              </dd>
            </>
          )}
        </dl>
      )}
    </div>
  );
}
