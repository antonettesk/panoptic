import { ArrowUpRight, Boxes, CheckCircle2, Cpu, EyeOff, Network, Radar, ShieldCheck, Waypoints } from 'lucide-react';
import type { ScanReport, Severity } from '../types';
import { useI18n } from '../i18n';
import { Banner, RiskGauge, SeverityBadge, StatCard, StatusIcon } from '../components/ui';
import { SEVERITY_STYLE, categoryKey, formatDuration, formatUptime, severityKey } from '../util';
import type { Tab } from '../App';

export function Overview({ report, go }: { report: ScanReport; go: (tab: Tab, focus?: string) => void }) {
  const { t, formatDate, formatNumber } = useI18n();
  const s = report.summary;
  const active = report.findings.filter((f) => !f.suppressed);
  const top = active.slice(0, 7);
  const layers = {
    api: report.processes.filter((p) => p.visibility.api).length,
    syscall: report.processes.filter((p) => p.visibility.syscall).length,
    brute: report.processes.filter((p) => p.visibility.brute_force).length,
  };
  const sevCounts: [Severity, number][] = [
    ['critical', s.critical],
    ['high', s.high],
    ['medium', s.medium],
    ['low', s.low],
  ];
  const totalActive = sevCounts.reduce((n, [, c]) => n + c, 0);

  return (
    <div className="space-y-5">
      {report.cancelled && <Banner tone="warn">{t('overview.partial')}</Banner>}
      {!report.elevated && <Banner tone="info">{t('overview.limited')}</Banner>}

      <div className="grid gap-5 xl:grid-cols-[340px_1fr]">
        <section className="card flex flex-col items-center gap-5 p-6">
          <RiskGauge score={report.risk_score} />
          <div className="w-full">
            <div className="flex h-2 w-full overflow-hidden rounded-full bg-raised" aria-hidden="true">
              {totalActive > 0 && sevCounts.map(([sev, n]) => n > 0 && <div key={sev} className={SEVERITY_STYLE[sev].bar} style={{ width: `${(n / totalActive) * 100}%` }} />)}
            </div>
            <div className="mt-3 grid grid-cols-4 gap-2">
              {sevCounts.map(([sev, n]) => (
                <button key={sev} onClick={() => go('findings')} className="rounded-lg border border-line px-2 py-2 text-center transition hover:border-brand/40">
                  <div className="text-lg font-semibold tabular-nums">{formatNumber(n)}</div>
                  <div className={`text-[10.5px] font-medium ${SEVERITY_STYLE[sev].text}`}>{t(severityKey(sev))}</div>
                </button>
              ))}
            </div>
          </div>
          <div className="text-center text-xs text-muted">
            {report.host.hostname} · {formatDate(report.started_at)} · {formatDuration(report.duration_ms)}
          </div>
        </section>

        <div className="space-y-5">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatCard label={t('overview.hiddenProcesses')} value={formatNumber(s.hidden_processes)} tone={s.hidden_processes ? 'danger' : 'ok'} icon={<EyeOff size={16} />} onClick={() => go('processes')} />
            <StatCard label={t('overview.hiddenListeners')} value={formatNumber(s.hidden_sockets)} tone={s.hidden_sockets ? 'danger' : 'ok'} icon={<Waypoints size={16} />} onClick={() => go('network')} />
            <StatCard label={t('overview.hiddenModules')} value={formatNumber(s.hidden_modules)} tone={s.hidden_modules ? 'danger' : 'ok'} icon={<Boxes size={16} />} onClick={() => go('kernel')} />
            <StatCard label={t('overview.suppressed')} value={formatNumber(s.suppressed)} icon={<ShieldCheck size={16} />} onClick={() => go('findings')} />
          </div>

          <section className="card p-5">
            <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold">
              <Radar size={16} className="text-brand" /> {t('overview.matrix')}
            </h3>
            <div className="grid gap-3 md:grid-cols-3">
              <Layer icon={<Cpu size={15} />} title={t('layer.processes.title')} rows={[[t('overview.row.api'), layers.api], [t('overview.row.syscall'), layers.syscall], [t('overview.row.brute'), layers.brute]]} verdict={s.hidden_processes ? t('overview.verdict.procBad', { count: s.hidden_processes }) : t('overview.verdict.procOk')} bad={s.hidden_processes > 0} />
              <Layer icon={<Network size={15} />} title={t('layer.network.title')} rows={[[t('overview.row.table'), s.sockets - s.hidden_sockets], [t('overview.row.listening'), s.listening], [t('overview.row.unlisted'), s.hidden_sockets]]} verdict={s.hidden_sockets ? t('overview.verdict.netBad', { count: s.hidden_sockets }) : t('overview.verdict.netOk')} bad={s.hidden_sockets > 0} />
              <Layer icon={<Boxes size={15} />} title={t('layer.kernel.title')} rows={[[t('overview.row.modules'), s.modules - s.hidden_modules], [t('overview.row.autostart'), s.persistence_entries], [t('overview.row.unlinked'), s.hidden_modules]]} verdict={s.hidden_modules ? t('overview.verdict.modBad', { count: s.hidden_modules }) : t('overview.verdict.modOk')} bad={s.hidden_modules > 0} />
            </div>
          </section>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
        <section className="card overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
            <h3 className="text-[13px] font-semibold">{t('overview.priority')}</h3>
            <button className="inline-flex items-center gap-1 text-xs text-brand hover:underline" onClick={() => go('findings')}>
              {t('overview.viewAll', { count: active.length })} <ArrowUpRight size={13} className="rtl:-scale-x-100" />
            </button>
          </div>
          {top.length === 0 ? (
            <div className="flex items-center gap-3 p-6 text-[13px] text-ok">
              <CheckCircle2 size={18} /> {t('overview.noFindings')}
            </div>
          ) : (
            <ul className="divide-y divide-line/60">
              {top.map((f) => (
                <li key={f.id}>
                  <button onClick={() => go('findings', f.id)} className="flex w-full items-center gap-3 px-5 py-3 text-start transition hover:bg-raised/60">
                    <SeverityBadge severity={f.severity} className="w-[74px] justify-center" />
                    <span className="min-w-0 flex-1 truncate text-[13px]" lang="en">
                      {f.title}
                    </span>
                    <span className="hidden text-[11px] text-subtle md:inline">{t(categoryKey(f.category))}</span>
                    {f.mitre && <span className="mono hidden text-[11px] text-subtle lg:inline">{f.mitre}</span>}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card p-5">
          <h3 className="mb-4 text-[13px] font-semibold">{t('overview.stages')}</h3>
          <ul className="space-y-3">
            {report.stages.map((st) => (
              <li key={st.stage} className="flex items-start gap-2.5">
                <StatusIcon ok={st.ok} />
                <div className="min-w-0 flex-1">
                  <div className="flex justify-between text-[13px]">
                    <span className="capitalize" lang="en">
                      {st.stage}
                    </span>
                    <span className="mono text-subtle">{st.duration_ms ? formatDuration(st.duration_ms) : ''}</span>
                  </div>
                  {st.message && (
                    <div className={`text-xs ${st.ok ? 'text-muted' : 'text-danger'}`} lang="en">
                      {st.message}
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
          <dl className="mt-5 space-y-1.5 border-t border-line pt-4 text-xs">
            {[
              [t('overview.os'), report.host.os],
              [t('overview.kernel'), `${report.host.kernel_version} · ${report.host.arch}`],
              [t('overview.uptime'), formatUptime(report.host.uptime_secs)],
              [t('overview.engine'), `${report.engine} · v${report.tool_version}`],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between gap-3">
                <dt className="text-muted">{k}</dt>
                <dd className="truncate text-end" title={v}>
                  {v}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      </div>
    </div>
  );
}

function Layer({ icon, title, rows, verdict, bad }: { icon: React.ReactNode; title: string; rows: [string, number][]; verdict: string; bad: boolean }) {
  const { formatNumber } = useI18n();
  return (
    <div className={`rounded-xl border p-4 ${bad ? 'border-danger/40 bg-danger/5' : 'border-line bg-raised/40'}`}>
      <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold">
        <span className={bad ? 'text-danger' : 'text-brand'}>{icon}</span> {title}
      </div>
      <div className="space-y-1.5">
        {rows.map(([k, v]) => (
          <div key={k} className="flex justify-between gap-2 text-xs">
            <span className="text-muted">{k}</span>
            <span className="font-medium tabular-nums">{formatNumber(v)}</span>
          </div>
        ))}
      </div>
      <div className={`mt-3 flex items-center gap-1.5 text-xs font-semibold ${bad ? 'text-danger' : 'text-ok'}`}>{verdict}</div>
    </div>
  );
}
