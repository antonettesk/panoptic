import { useMemo, useState } from 'react';
import { Boxes } from 'lucide-react';
import type { ScanReport } from '../types';
import { useI18n } from '../i18n';
import { Banner, EmptyState, SearchBox, Segmented } from '../components/ui';
import { formatBytes, matchesQuery } from '../util';

type Filter = 'flagged' | 'all';

export function Kernel({ report }: { report: ScanReport }) {
  const { t } = useI18n();
  const flagged = report.modules.filter((m) => m.hidden || m.suspicious).length;
  const [filter, setFilter] = useState<Filter>(flagged ? 'flagged' : 'all');
  const [query, setQuery] = useState('');
  const stage = report.stages.find((s) => s.stage === 'modules');
  const rows = useMemo(() => report.modules.filter((m) => (filter === 'all' || m.hidden || m.suspicious) && matchesQuery(query, m.name, m.path, ...m.reasons)), [report.modules, filter, query]);

  return (
    <div className="space-y-4">
      {stage && !stage.ok && <Banner tone="warn">{t('kernel.notRun', { reason: stage.message ?? '' })}</Banner>}
      <div className="flex flex-wrap items-center gap-3">
        <SearchBox value={query} onChange={setQuery} placeholder={t('kernel.search')} />
        <Segmented<Filter>
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'flagged', label: t('proc.flagged'), count: flagged },
            { value: 'all', label: t('common.all'), count: report.modules.length },
          ]}
        />
      </div>
      {rows.length === 0 ? (
        <EmptyState icon={<Boxes size={22} />} title={filter === 'flagged' ? t('kernel.none') : t('kernel.empty')}>
          {filter === 'flagged' ? t('kernel.noneHint') : undefined}
        </EmptyState>
      ) : (
        <div className="card max-h-[calc(100vh-230px)] overflow-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              <tr>
                <th className="th">{t('col.module')}</th>
                <th className="th">{t('col.path')}</th>
                <th className="th text-end">{t('col.size')}</th>
                <th className="th">{t('col.primary')}</th>
                <th className="th">{t('col.corroborated')}</th>
                <th className="th">{t('col.assessment')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((m) => (
                <tr key={m.name + (m.path ?? '')} className={m.hidden ? 'bg-danger/10' : m.suspicious ? 'bg-warn/5' : 'hover:bg-raised/60'}>
                  <td className="td mono font-medium">{m.name}</td>
                  <td className="td mono max-w-[360px] truncate text-muted" title={m.path ?? ''} dir="ltr">
                    {m.path ?? '—'}
                  </td>
                  <td className="td text-end tabular-nums text-muted">{formatBytes(m.size)}</td>
                  <td className="td">{m.listed ? <span className="text-ok">✓</span> : <span className="chip bg-danger text-white">{t('kernel.missing')}</span>}</td>
                  <td className="td">{m.corroborated ? <span className="text-ok">✓</span> : <span className="text-warn">✕</span>}</td>
                  <td className="td">
                    {m.hidden ? (
                      <span className="chip animate-pulse bg-danger text-white">{t('kernel.unlinked')}</span>
                    ) : m.suspicious ? (
                      <span className="text-xs text-warn" lang="en">
                        {m.reasons[0]}
                      </span>
                    ) : (
                      <span className="text-subtle">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
