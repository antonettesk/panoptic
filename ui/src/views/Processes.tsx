import { Fragment, useMemo, useState } from 'react';
import { Ghost, Pause, Play, Skull } from 'lucide-react';
import type { ProcessAction, ProcessInfo, ScanReport } from '../types';
import { useI18n } from '../i18n';
import { CopyButton, EmptyState, SearchBox, Segmented, SortTh, VisibilityDots } from '../components/ui';
import { formatBytes, matchesQuery, sortRows, type SortDir } from '../util';

type Key = 'pid' | 'name' | 'cpu' | 'mem' | 'user' | 'ppid';
type Filter = 'all' | 'flagged' | 'ghosts';
const LIMIT = 1500;

export function Processes({ report, onAction }: { report: ScanReport; onAction: (pid: number, a: ProcessAction) => void }) {
  const { t, formatDate } = useI18n();
  const ghosts = report.processes.filter((p) => p.is_discrepant).length;
  const flagged = report.processes.filter((p) => p.flags.length > 0 || p.is_discrepant).length;
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<Filter>(ghosts ? 'ghosts' : flagged ? 'flagged' : 'all');
  const [sort, setSort] = useState<{ key: Key; dir: SortDir }>({ key: 'cpu', dir: 'desc' });
  const [expanded, setExpanded] = useState<number | null>(null);

  const rows = useMemo(() => {
    const keyFn: Record<Key, (p: ProcessInfo) => string | number> = {
      pid: (p) => p.pid,
      ppid: (p) => p.ppid ?? -1,
      name: (p) => p.name.toLowerCase(),
      cpu: (p) => p.cpu_usage,
      mem: (p) => p.memory_bytes,
      user: (p) => p.user ?? '',
    };
    const base = report.processes.filter(
      (p) => (filter === 'all' || (filter === 'ghosts' ? p.is_discrepant : p.is_discrepant || p.flags.length > 0)) && matchesQuery(query, p.pid, p.name, p.path, p.cmdline, p.user, p.sha256),
    );
    const sorted = sortRows(base, keyFn[sort.key], sort.dir);
    return [...sorted.filter((p) => p.is_discrepant), ...sorted.filter((p) => !p.is_discrepant)];
  }, [report.processes, filter, query, sort]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <SearchBox value={query} onChange={setQuery} placeholder={t('proc.search')} />
        <Segmented<Filter>
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'all', label: t('common.all'), count: report.processes.length },
            { value: 'flagged', label: t('proc.flagged'), count: flagged },
            { value: 'ghosts', label: t('proc.ghosts'), count: ghosts },
          ]}
        />
        <span className="ms-auto text-[11px] text-subtle" dir="ltr">
          {t('proc.legend')}
        </span>
      </div>

      {rows.length === 0 ? (
        <EmptyState icon={<Ghost size={22} />} title={filter === 'ghosts' ? t('proc.noGhosts') : t('proc.noMatch')}>
          {filter === 'ghosts' ? t('proc.noGhostsHint') : undefined}
        </EmptyState>
      ) : (
        <div className="card max-h-[calc(100vh-230px)] overflow-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              <tr>
                <SortTh label={t('col.pid')} k="pid" sort={sort} setSort={setSort} />
                <SortTh label={t('col.ppid')} k="ppid" sort={sort} setSort={setSort} />
                <SortTh label={t('col.name')} k="name" sort={sort} setSort={setSort} />
                <th className="th">{t('col.path')}</th>
                <SortTh label={t('col.user')} k="user" sort={sort} setSort={setSort} />
                <SortTh label={t('col.cpu')} k="cpu" sort={sort} setSort={setSort} className="text-end" />
                <SortTh label={t('col.memory')} k="mem" sort={sort} setSort={setSort} className="text-end" />
                <th className="th">{t('col.layers')}</th>
                <th className="th">{t('col.status')}</th>
                <th className="th text-end">{t('col.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, LIMIT).map((p) => (
                <Fragment key={p.pid}>
                  <tr className={`cursor-pointer transition ${p.is_discrepant ? 'bg-danger/10 hover:bg-danger/15' : p.flags.length ? 'bg-warn/5 hover:bg-warn/10' : 'hover:bg-raised/60'}`} onClick={() => setExpanded(expanded === p.pid ? null : p.pid)}>
                    <td className="td mono tabular-nums">{p.pid}</td>
                    <td className="td mono tabular-nums text-subtle">{p.ppid ?? '—'}</td>
                    <td className="td font-medium">{p.name || <span className="text-subtle">&lt;unknown&gt;</span>}</td>
                    <td className="td mono max-w-[320px] truncate text-muted" title={p.path} dir="ltr">
                      {p.path || <span className="text-subtle">—</span>}
                    </td>
                    <td className="td text-muted">{p.user ?? '—'}</td>
                    <td className="td text-end tabular-nums">{p.cpu_usage.toFixed(1)}</td>
                    <td className="td text-end tabular-nums text-muted">{formatBytes(p.memory_bytes)}</td>
                    <td className="td">
                      <VisibilityDots v={p.visibility} ghost={p.is_discrepant} />
                    </td>
                    <td className="td">
                      {p.is_discrepant ? (
                        <span className="chip animate-pulse bg-danger text-white">{t('proc.ghost')}</span>
                      ) : p.flags.length ? (
                        <span className="chip bg-warn/15 text-warn">{t('proc.flaggedBadge')}</span>
                      ) : (
                        <span className="chip bg-ok/10 text-ok">{t('proc.verified')}</span>
                      )}
                    </td>
                    <td className="td text-end" onClick={(e) => e.stopPropagation()}>
                      <div className="inline-flex gap-1">
                        <IconBtn title={t('proc.suspend')} onClick={() => onAction(p.pid, 'suspend')} icon={<Pause size={13} />} />
                        <IconBtn title={t('proc.resume')} onClick={() => onAction(p.pid, 'resume')} icon={<Play size={13} />} />
                        <IconBtn title={t('proc.kill')} danger onClick={() => onAction(p.pid, 'terminate')} icon={<Skull size={13} />} />
                      </div>
                    </td>
                  </tr>
                  {expanded === p.pid && (
                    <tr className="bg-raised/40">
                      <td colSpan={10} className="td">
                        <dl className="grid grid-cols-[120px_1fr] gap-x-4 gap-y-2 py-1 text-xs">
                          <dt className="text-muted">{t('proc.cmdline')}</dt>
                          <dd className="mono break-all" dir="ltr">
                            {p.cmdline || '—'}
                          </dd>
                          <dt className="text-muted">{t('proc.started')}</dt>
                          <dd>{formatDate(p.start_time)}</dd>
                          {p.sha256 && (
                            <>
                              <dt className="text-muted">{t('proc.sha')}</dt>
                              <dd className="flex items-center gap-2">
                                <code className="mono break-all">{p.sha256}</code> <CopyButton text={p.sha256} />
                              </dd>
                            </>
                          )}
                          {p.path && (
                            <>
                              <dt className="text-muted">{t('col.path')}</dt>
                              <dd className="flex items-center gap-2" dir="ltr">
                                <code className="mono break-all">{p.path}</code> <CopyButton text={p.path} />
                              </dd>
                            </>
                          )}
                          {p.flags.length > 0 && (
                            <>
                              <dt className="text-muted">{t('proc.flags')}</dt>
                              <dd>
                                <ul className="space-y-0.5 text-warn" lang="en">
                                  {p.flags.map((f, i) => (
                                    <li key={i}>› {f}</li>
                                  ))}
                                </ul>
                              </dd>
                            </>
                          )}
                        </dl>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          {rows.length > LIMIT && <div className="p-3 text-center text-xs text-muted">{t('proc.limit', { limit: LIMIT, count: rows.length })}</div>}
        </div>
      )}
    </div>
  );
}

function IconBtn({ title, onClick, icon, danger }: { title: string; onClick: () => void; icon: React.ReactNode; danger?: boolean }) {
  return (
    <button title={title} aria-label={title} onClick={onClick} className={`rounded-md border p-1.5 transition ${danger ? 'border-danger/30 text-danger hover:bg-danger hover:text-white' : 'border-line text-muted hover:border-brand/40 hover:text-fg'}`}>
      {icon}
    </button>
  );
}
