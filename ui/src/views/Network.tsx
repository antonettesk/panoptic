import { useMemo, useState } from 'react';
import { Network as NetIcon } from 'lucide-react';
import type { ScanReport, SocketInfo } from '../types';
import { useI18n } from '../i18n';
import { EmptyState, SearchBox, Segmented, SortTh } from '../components/ui';
import { matchesQuery, sortRows, type SortDir } from '../util';

type Filter = 'all' | 'listening' | 'established' | 'flagged';
type Key = 'proto' | 'local' | 'remote' | 'state' | 'pid' | 'proc';

export function Network({ report }: { report: ScanReport }) {
  const { t } = useI18n();
  const flagged = report.sockets.filter((s) => s.suspicious || s.hidden).length;
  const [filter, setFilter] = useState<Filter>(flagged ? 'flagged' : 'listening');
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<{ key: Key; dir: SortDir }>({ key: 'local', dir: 'asc' });

  const rows = useMemo(() => {
    const keyFn: Record<Key, (s: SocketInfo) => string | number> = {
      proto: (s) => s.protocol,
      local: (s) => s.local_port,
      remote: (s) => `${s.remote_address}:${s.remote_port}`,
      state: (s) => s.state,
      pid: (s) => s.pid ?? -1,
      proc: (s) => s.process_name ?? '',
    };
    const base = report.sockets.filter((s) => {
      const f =
        filter === 'all' ||
        (filter === 'listening' && (s.state === 'LISTEN' || ((s.protocol === 'udp' || s.protocol === 'udp6') && s.remote_port === 0))) ||
        (filter === 'established' && s.state === 'ESTABLISHED') ||
        (filter === 'flagged' && (s.suspicious || s.hidden));
      return f && matchesQuery(query, s.local_address, s.local_port, s.remote_address, s.remote_port, s.process_name, s.pid, s.state, s.protocol);
    });
    const sorted = sortRows(base, keyFn[sort.key], sort.dir);
    return [...sorted.filter((s) => s.hidden), ...sorted.filter((s) => !s.hidden && s.suspicious), ...sorted.filter((s) => !s.hidden && !s.suspicious)];
  }, [report.sockets, filter, query, sort]);

  const count = (pred: (s: SocketInfo) => boolean) => report.sockets.filter(pred).length;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <SearchBox value={query} onChange={setQuery} placeholder={t('net.search')} />
        <Segmented<Filter>
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'flagged', label: t('net.flagged'), count: flagged },
            { value: 'listening', label: t('net.listening'), count: count((s) => s.state === 'LISTEN') },
            { value: 'established', label: t('net.established'), count: count((s) => s.state === 'ESTABLISHED') },
            { value: 'all', label: t('common.all'), count: report.sockets.length },
          ]}
        />
      </div>
      {rows.length === 0 ? (
        <EmptyState icon={<NetIcon size={22} />} title={filter === 'flagged' ? t('net.none') : t('net.noMatch')}>
          {filter === 'flagged' ? t('net.noneHint') : undefined}
        </EmptyState>
      ) : (
        <div className="card max-h-[calc(100vh-230px)] overflow-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              <tr>
                <SortTh label={t('col.proto')} k="proto" sort={sort} setSort={setSort} />
                <SortTh label={t('col.local')} k="local" sort={sort} setSort={setSort} />
                <SortTh label={t('col.remote')} k="remote" sort={sort} setSort={setSort} />
                <SortTh label={t('col.state')} k="state" sort={sort} setSort={setSort} />
                <SortTh label={t('col.pid')} k="pid" sort={sort} setSort={setSort} />
                <SortTh label={t('col.process')} k="proc" sort={sort} setSort={setSort} />
                <th className="th">{t('col.assessment')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s, i) => (
                <tr key={i} className={s.hidden ? 'bg-danger/10' : s.suspicious ? 'bg-warn/5' : 'hover:bg-raised/60'}>
                  <td className="td">
                    <span className="chip bg-raised text-muted">{s.protocol}</span>
                  </td>
                  <td className="td mono tabular-nums" dir="ltr">
                    {s.local_address}:{s.local_port}
                  </td>
                  <td className="td mono tabular-nums text-muted" dir="ltr">
                    {s.remote_port ? `${s.remote_address}:${s.remote_port}` : '—'}
                  </td>
                  <td className="td mono text-xs">{s.state}</td>
                  <td className="td mono tabular-nums">{s.pid ?? '?'}</td>
                  <td className="td">{s.process_name ?? <span className="text-subtle">—</span>}</td>
                  <td className="td">
                    {s.hidden ? (
                      <span className="chip animate-pulse bg-danger text-white">{t('net.hidden')}</span>
                    ) : s.suspicious ? (
                      <span className="text-xs text-warn" title={s.reasons.join('\n')} lang="en">
                        {s.reasons[0]}
                        {s.reasons.length > 1 && ` (+${s.reasons.length - 1})`}
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
