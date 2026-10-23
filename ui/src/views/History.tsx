import { useEffect, useState } from 'react';
import { FolderOpen, History as HistoryIcon, Trash2 } from 'lucide-react';
import { api } from '../api';
import type { HistoryEntry } from '../types';
import { useI18n } from '../i18n';
import { EmptyState, Spinner, useConfirm, useToast } from '../components/ui';
import { formatDuration, riskLevel } from '../util';

export function History({ currentId, onLoad, refreshKey }: { currentId?: string; onLoad: (scanId: string) => void; refreshKey: number }) {
  const { t, formatDate, formatRelative } = useI18n();
  const [rows, setRows] = useState<HistoryEntry[] | null>(null);
  const toast = useToast();
  const confirm = useConfirm();

  const refresh = () =>
    api.history().then(setRows, (e) => {
      setRows([]);
      toast('error', t('history.loadFailed', { error: e.message }));
    });
  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshKey]);

  if (rows === null)
    return (
      <div className="flex items-center gap-2 p-6 text-[13px] text-muted">
        <Spinner /> {t('common.loading')}
      </div>
    );
  if (rows.length === 0)
    return (
      <EmptyState icon={<HistoryIcon size={22} />} title={t('history.empty')}>
        {t('history.emptyHint')}
      </EmptyState>
    );

  const trend = [...rows].reverse();
  const w = Math.max(1, trend.length - 1) * 48 + 24;

  return (
    <div className="space-y-5">
      <section className="card p-5">
        <div className="mb-3 text-[13px] font-semibold">{t('history.trend')}</div>
        <svg viewBox={`0 0 ${w} 100`} className="h-28 w-full" preserveAspectRatio="none" role="img" aria-label={t('history.trend')} style={{ direction: 'ltr' }}>
          <defs>
            <linearGradient id="trend-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="rgb(var(--brand))" stopOpacity="0.25" />
              <stop offset="1" stopColor="rgb(var(--brand))" stopOpacity="0" />
            </linearGradient>
          </defs>
          {[0, 40, 70].map((y) => (
            <line key={y} x1="0" x2={w} y1={92 - y * 0.85} y2={92 - y * 0.85} stroke="rgb(var(--line))" strokeDasharray="3 4" />
          ))}
          <polygon fill="url(#trend-fill)" points={`12,92 ${trend.map((r, i) => `${12 + i * 48},${92 - r.risk_score * 0.85}`).join(' ')} ${12 + (trend.length - 1) * 48},92`} />
          <polyline fill="none" stroke="rgb(var(--brand))" strokeWidth="2.5" strokeLinejoin="round" points={trend.map((r, i) => `${12 + i * 48},${92 - r.risk_score * 0.85}`).join(' ')} />
          {trend.map((r, i) => (
            <circle key={r.scan_id} cx={12 + i * 48} cy={92 - r.risk_score * 0.85} r="4" fill={riskLevel(r.risk_score).color} stroke="rgb(var(--surface))" strokeWidth="2">
              <title>
                {formatDate(r.started_at)}: {r.risk_score}
              </title>
            </circle>
          ))}
        </svg>
      </section>
      <div className="card overflow-auto">
        <table className="w-full border-collapse text-[13px]">
          <thead>
            <tr>
              <th className="th">{t('col.when')}</th>
              <th className="th">{t('col.risk')}</th>
              <th className="th">{t('col.counts')}</th>
              <th className="th">{t('col.hidden')}</th>
              <th className="th">{t('col.duration')}</th>
              <th className="th">{t('col.mode')}</th>
              <th className="th text-end">{t('col.actions')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const rl = riskLevel(r.risk_score);
              return (
                <tr key={r.scan_id} className={r.scan_id === currentId ? 'bg-brand/5' : 'hover:bg-raised/50'}>
                  <td className="td">
                    <div>{formatDate(r.started_at)}</div>
                    <div className="text-[11px] text-subtle">{formatRelative(r.started_at)}</div>
                  </td>
                  <td className="td">
                    <span className="font-semibold tabular-nums" style={{ color: rl.color }}>
                      {r.risk_score}
                    </span>{' '}
                    <span className="text-[11px] text-muted">{t(rl.key)}</span>
                  </td>
                  <td className="td mono tabular-nums">
                    {r.summary.critical} / {r.summary.high} / {r.summary.medium}
                  </td>
                  <td className="td mono tabular-nums">
                    {r.summary.hidden_processes} / {r.summary.hidden_sockets} / {r.summary.hidden_modules}
                  </td>
                  <td className="td mono text-muted">{formatDuration(r.duration_ms)}</td>
                  <td className="td text-muted">
                    {r.elevated ? t('history.elevated') : t('history.limited')}
                    {r.cancelled && <span className="ms-1 text-warn">({t('history.partial')})</span>}
                  </td>
                  <td className="td text-end">
                    <div className="inline-flex gap-1">
                      <button className="btn-secondary btn-sm" onClick={() => onLoad(r.scan_id)} disabled={r.scan_id === currentId}>
                        <FolderOpen size={13} /> {t('common.open')}
                      </button>
                      <button
                        className="btn-ghost btn-sm"
                        aria-label={t('common.delete')}
                        onClick={async () => {
                          if (await confirm({ title: t('history.deleteTitle'), body: t('history.deleteBody', { time: formatDate(r.started_at) }), confirmLabel: t('common.delete'), danger: true })) {
                            api.deleteReport(r.scan_id).then(refresh, (e) => toast('error', e.message));
                          }
                        }}
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
