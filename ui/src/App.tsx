import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  Anchor,
  BookOpen,
  Boxes,
  Command as CommandIcon,
  Download,
  Eye,
  Globe2,
  History as HistoryIcon,
  LayoutDashboard,
  Network as NetIcon,
  Settings as SettingsIcon,
  Shield,
  ShieldAlert,
  Square,
  SunMoon,
  Target,
  Zap,
} from 'lucide-react';
import { api, isTauri, onProgress, pickSavePath } from './api';
import { LANGUAGES, useI18n, type MessageKey } from './i18n';
import { useSettings } from './settings';
import type { ExportFormat, ProcessAction, Progress, ScanReport, SystemInfo } from './types';
import { CommandPalette, type Command } from './components/CommandPalette';
import { Logo, Spinner, useConfirm, useToast } from './components/ui';
import { Mark, PanopticonPattern, Wordmark } from './brand/Brand';
import { Overview } from './views/Overview';
import { Findings } from './views/Findings';
import { Processes } from './views/Processes';
import { Network } from './views/Network';
import { Persistence } from './views/Persistence';
import { Kernel } from './views/Kernel';
import { History } from './views/History';
import { Settings } from './views/Settings';
import { Coverage } from './views/Coverage';
import { Guide } from './views/Guide';
import { Onboarding } from './views/Onboarding';
import { riskLevel } from './util';

export type Tab = 'overview' | 'findings' | 'processes' | 'network' | 'persistence' | 'kernel' | 'coverage' | 'history' | 'guide' | 'settings';

const NEEDS_REPORT: Tab[] = ['overview', 'findings', 'processes', 'network', 'persistence', 'kernel'];

export default function App() {
  const { settings, loaded } = useSettings();
  const [forceOnboarding, setForceOnboarding] = useState(false);
  const [startAfterOnboarding, setStartAfterOnboarding] = useState(false);

  if (!loaded) {
    return (
      <div className="flex h-full items-center justify-center bg-bg">
        <div className="flex animate-fade-in flex-col items-center gap-5">
          <Logo size={64} scanning />
          <Wordmark size={18} />
        </div>
      </div>
    );
  }
  if (!settings.onboarding_completed || forceOnboarding) {
    return (
      <Onboarding
        onDone={(start) => {
          setForceOnboarding(false);
          setStartAfterOnboarding(start);
        }}
      />
    );
  }
  return <Shell autoStart={startAfterOnboarding} onRestartOnboarding={() => setForceOnboarding(true)} />;
}

function Shell({ autoStart, onRestartOnboarding }: { autoStart: boolean; onRestartOnboarding: () => void }) {
  const { t, formatDate } = useI18n();
  const { settings, update } = useSettings();
  const toast = useToast();
  const confirm = useConfirm();
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [tab, setTab] = useState<Tab>('overview');
  const [focus, setFocus] = useState<string | undefined>();
  const [historyKey, setHistoryKey] = useState(0);
  const [exportOpen, setExportOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const exportRef = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  const refreshInfo = useCallback(() => api.systemInfo().then(setInfo, (e) => toast('error', e.message)), [toast]);

  useEffect(() => {
    refreshInfo();
    let un: (() => void) | undefined;
    onProgress(setProgress).then((u) => (un = u));
    return () => un?.();
  }, [refreshInfo]);

  useEffect(() => {
    if (!exportOpen) return;
    const close = (e: MouseEvent) => !exportRef.current?.contains(e.target as Node) && setExportOpen(false);
    window.addEventListener('mousedown', close);
    return () => window.removeEventListener('mousedown', close);
  }, [exportOpen]);

  const offerBaseline = useCallback(
    async (r: ScanReport) => {
      if (!settings.baseline_after_first_scan || r.cancelled || r.summary.critical || r.summary.high || info?.has_baseline) return;
      const yes = await confirm({ title: t('baseline.offerTitle'), body: t('baseline.offerBody'), confirmLabel: t('baseline.save') });
      try {
        if (yes) {
          await api.saveBaseline();
          toast('ok', t('baseline.saved'));
          refreshInfo();
        }
        await update({ baseline_after_first_scan: false });
      } catch (e) {
        toast('error', (e as Error).message);
      }
    },
    [settings.baseline_after_first_scan, info?.has_baseline, confirm, t, toast, refreshInfo, update],
  );

  const runAudit = useCallback(
    async (quick = false) => {
      if (loading) return;
      setLoading(true);
      setProgress({ stage: 'start', percent: 0, message: t('scan.starting') });
      try {
        const opts = quick ? { ...settings.scan_options, brute_force_pids: false, port_probe: false, hash_evidence: false } : settings.scan_options;
        const result = await api.scan(opts);
        setReport(result);
        setFocus(undefined);
        setHistoryKey((k) => k + 1);
        if (result.cancelled) toast('info', t('scan.cancelled'));
        else if (result.summary.critical) toast('error', t('scan.critical', { count: result.summary.critical }));
        else toast('ok', t('scan.complete', { score: result.risk_score }));
        if (!quick) offerBaseline(result);
      } catch (err) {
        toast('error', t('scan.failed', { error: (err as Error).message }));
      } finally {
        setLoading(false);
        setProgress(null);
        refreshInfo();
      }
    },
    [loading, settings.scan_options, toast, t, refreshInfo, offerBaseline],
  );

  // Quick scan on launch if opted in (once per app start).
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    if (!autoStart && settings.auto_scan_on_launch) runAudit(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // First deep scan requested at the end of onboarding. The flag can arrive
  // after the first render (settings are saved before onDone fires).
  const autoStarted = useRef(false);
  useEffect(() => {
    if (autoStart && !autoStarted.current) {
      autoStarted.current = true;
      runAudit(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key === 'Enter') {
        e.preventDefault();
        runAudit(e.shiftKey);
      } else if (mod && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [runAudit]);

  const processAction = async (pid: number, action: ProcessAction) => {
    const p = report?.processes.find((x) => x.pid === pid);
    const name = p ? `${p.name || '<unknown>'} (PID ${pid})` : `PID ${pid}`;
    const keys = { terminate: 'kill', suspend: 'suspend', resume: 'resume' } as const;
    const k = keys[action];
    const ok = await confirm({ title: t(`action.${k}.title` as MessageKey, { name }), body: t(`action.${k}.body` as MessageKey), confirmLabel: t(`action.${k}.btn` as MessageKey), danger: action !== 'resume' });
    if (!ok) return;
    try {
      await api.processAction(action, pid, p?.start_time ?? 0);
      toast('ok', t('action.done', { name }));
      if (action === 'terminate') setReport((r) => (r ? { ...r, processes: r.processes.filter((x) => x.pid !== pid) } : r));
    } catch (err) {
      toast('error', t('action.failed', { error: (err as Error).message }));
    }
  };

  const suppress = async (id: string, suppressed: boolean) => {
    try {
      setReport(await api.setFindingSuppressed(id, suppressed));
    } catch (err) {
      toast('error', (err as Error).message);
    }
  };

  const scanIdForBackend = report && !report.scan_id.endsWith('-demo') ? report.scan_id : undefined;
  const doExport = async (format: ExportFormat | 'asff') => {
    setExportOpen(false);
    if (!report) return;
    const host = report.host.hostname || 'host';
    try {
      if (format === 'asff') {
        const path = await pickSavePath(`panoptic-asff-${host}-${report.scan_id}.json`, 'json', 'ASFF');
        if (!path) return;
        const files = await api.exportAsff(path, scanIdForBackend);
        toast('ok', t('export.asffSaved', { count: files.length }));
      } else {
        const path = await pickSavePath(`panoptic-${host}-${report.scan_id}.${format}`, format, format.toUpperCase());
        if (!path) return;
        const written = await api.exportReport(path, format, scanIdForBackend);
        toast('ok', t('export.saved', { path: written }));
      }
    } catch (err) {
      toast('error', t('export.failed', { error: (err as Error).message }));
    }
  };

  const go = (next: Tab, f?: string) => {
    setTab(next);
    setFocus(f);
  };

  const nav: { section: MessageKey; items: { id: Tab; icon: React.ReactNode; badge?: number; danger?: boolean }[] }[] = [
    {
      section: 'nav.section.investigate',
      items: [
        { id: 'overview', icon: <LayoutDashboard size={16} /> },
        { id: 'findings', icon: <AlertOctagon size={16} />, badge: report ? report.summary.critical + report.summary.high : undefined, danger: !!report?.summary.critical },
        { id: 'processes', icon: <Activity size={16} />, badge: report?.summary.hidden_processes || undefined, danger: true },
        { id: 'network', icon: <NetIcon size={16} />, badge: report?.summary.hidden_sockets || undefined, danger: true },
        { id: 'persistence', icon: <Anchor size={16} /> },
        { id: 'kernel', icon: <Boxes size={16} />, badge: report?.summary.hidden_modules || undefined, danger: true },
        { id: 'coverage', icon: <Target size={16} /> },
      ],
    },
    {
      section: 'nav.section.workspace',
      items: [
        { id: 'history', icon: <HistoryIcon size={16} /> },
        { id: 'guide', icon: <BookOpen size={16} /> },
        { id: 'settings', icon: <SettingsIcon size={16} /> },
      ],
    },
  ];

  const commands: Command[] = useMemo(
    () => [
      { id: 'scan-deep', label: t('scan.deep'), hint: 'Ctrl Enter', icon: <Eye size={15} />, run: () => runAudit(false) },
      { id: 'scan-quick', label: t('scan.quick'), hint: 'Ctrl Shift Enter', icon: <Zap size={15} />, run: () => runAudit(true) },
      ...nav.flatMap((s) => s.items).map((n) => ({ id: `go-${n.id}`, label: t('palette.goTo', { page: t(`nav.${n.id}` as MessageKey) }), icon: n.icon, run: () => go(n.id) })),
      ...(report ? (['html', 'json', 'csv', 'txt'] as ExportFormat[]).map((f) => ({ id: `export-${f}`, label: `${t('export.menu')}: ${t(`export.${f}` as MessageKey)}`, icon: <Download size={15} />, run: () => doExport(f) })) : []),
      { id: 'theme', label: t('palette.toggleTheme'), icon: <SunMoon size={15} />, run: () => update({ theme: document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark' }).catch(() => undefined) },
      ...LANGUAGES.map((l) => ({ id: `lang-${l.code}`, label: `${t('palette.language')}: ${l.native}`, hint: l.english, icon: <Globe2 size={15} />, run: () => update({ language: l.code }).catch(() => undefined) })),
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t, report, runAudit],
  );

  const level = report ? riskLevel(report.risk_score) : null;

  return (
    <div className="flex h-full">
      {/* Sidebar */}
      <aside className="flex w-60 shrink-0 flex-col border-e border-line bg-surface">
        <div className="flex items-center gap-3 px-5 py-5" title={loading ? t('scan.running') : undefined}>
          <Logo size={34} scanning={loading} />
          <Wordmark size={14} tagline={t('app.tagline')} />
        </div>
        <button onClick={() => setPaletteOpen(true)} className="mx-3 mb-3 flex items-center gap-2 rounded-lg border border-line bg-raised/60 px-3 py-2 text-xs text-subtle transition hover:border-brand/40 hover:text-fg">
          <CommandIcon size={13} /> <span className="flex-1 text-start">{t('palette.hint')}</span>
          <kbd className="kbd" dir="ltr">
            Ctrl K
          </kbd>
        </button>
        <nav className="flex-1 space-y-5 overflow-auto px-3 pb-3" aria-label="Main">
          {nav.map((s) => (
            <div key={s.section}>
              <div className="eyebrow mb-1.5 px-3">{t(s.section)}</div>
              <div className="space-y-0.5">
                {s.items.map((n) => (
                  <button
                    key={n.id}
                    onClick={() => go(n.id)}
                    aria-current={tab === n.id ? 'page' : undefined}
                    className={`group relative flex w-full items-center gap-3 rounded-lg px-3 py-2 text-[13px] transition ${tab === n.id ? 'bg-raised font-medium text-fg before:absolute before:inset-y-1.5 before:start-0 before:w-[3px] before:rounded-full before:bg-brand [&>svg]:text-brand' : 'text-muted hover:bg-raised/70 hover:text-fg'}`}
                  >
                    {n.icon}
                    <span className="flex-1 truncate text-start">{t(`nav.${n.id}` as MessageKey)}</span>
                    {n.badge ? <span className={`rounded-full px-1.5 py-px text-[10px] font-semibold tabular-nums ${n.danger ? 'bg-danger text-white' : 'bg-raised text-muted'}`}>{n.badge}</span> : null}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </nav>
        <div className="border-t border-line p-4 text-[11px]">
          {info ? (
            <>
              <div className="truncate font-medium text-fg" title={info.host.hostname}>
                {info.host.hostname}
              </div>
              <div className="truncate text-subtle" title={info.host.os}>
                {info.host.os}
              </div>
              <div className={`mt-2 inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 ${info.elevated ? 'bg-ok/10 text-ok' : 'bg-warn/10 text-warn'}`}>
                {info.elevated ? <Shield size={11} /> : <ShieldAlert size={11} />}
                {info.elevated ? t('priv.elevated') : t('priv.limited')}
              </div>
            </>
          ) : (
            <Spinner className="h-3.5 w-3.5 text-subtle" />
          )}
        </div>
      </aside>

      {/* Main */}
      <main className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-4 border-b border-line bg-surface/70 px-7 py-3.5 backdrop-blur">
          <div className="min-w-0">
            <h1 className="truncate text-[17px] font-semibold tracking-tight">{t(`nav.${tab}` as MessageKey)}</h1>
            <p className="truncate text-xs text-muted">
              {loading ? (
                t('scan.running')
              ) : report ? (
                <>
                  {t('scan.last', { time: formatDate(report.started_at) })} ·{' '}
                  <span className="font-medium" style={{ color: level!.color }}>
                    {report.risk_score}/100 {t(level!.key)}
                  </span>
                </>
              ) : (
                t('scan.idle')
              )}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {info && !info.elevated && (
              <button className="btn-secondary hidden text-warn lg:inline-flex" onClick={() => api.relaunchAsAdmin().catch((e) => toast('info', e.message))} title={info.platform === 'windows' ? undefined : t('priv.runRoot')}>
                <ShieldAlert size={14} /> {t('priv.relaunch')}
              </button>
            )}
            {report && (
              <div className="relative" ref={exportRef}>
                <button className="btn-secondary" onClick={() => setExportOpen((o) => !o)} aria-haspopup="menu" aria-expanded={exportOpen}>
                  <Download size={14} /> {t('export.menu')}
                </button>
                {exportOpen && (
                  <div role="menu" className="card absolute end-0 z-30 mt-1.5 w-60 animate-fade-in p-1.5 shadow-pop">
                    {(['html', 'json', 'csv', 'txt'] as ExportFormat[]).map((f) => (
                      <button key={f} role="menuitem" className="block w-full rounded-md px-3 py-2 text-start text-[13px] hover:bg-raised" onClick={() => doExport(f)}>
                        {t(`export.${f}` as MessageKey)}
                      </button>
                    ))}
                    <div className="my-1 border-t border-line" />
                    <button role="menuitem" disabled={!settings.aws} title={settings.aws ? undefined : t('export.asffDisabled')} className="block w-full rounded-md px-3 py-2 text-start text-[13px] hover:bg-raised disabled:cursor-not-allowed disabled:opacity-40" onClick={() => doExport('asff')}>
                      {t('export.asff')}
                    </button>
                  </div>
                )}
              </div>
            )}
            {loading ? (
              <button className="btn-secondary" onClick={() => api.cancelScan()}>
                <Square size={13} /> {t('scan.cancel')}
              </button>
            ) : (
              <button className="btn-secondary" onClick={() => runAudit(true)} title={t('scan.quickHint')}>
                <Zap size={14} /> {t('scan.quick')}
              </button>
            )}
            <button onClick={() => runAudit(false)} disabled={loading} className="btn-primary px-5">
              {loading ? <Spinner className="h-3.5 w-3.5" /> : <Eye size={15} />} {loading ? t('scan.running') : t('scan.deep')}
            </button>
          </div>
        </header>

        {loading && (
          <div className="border-b border-line bg-surface px-7 py-2.5" role="status" aria-live="polite">
            <div className="mb-1.5 flex justify-between text-xs text-muted">
              <span lang="en">{progress?.message ?? '…'}</span>
              <span className="tabular-nums">{progress?.percent ?? 0}%</span>
            </div>
            <div className="relative h-1.5 overflow-hidden rounded-full bg-raised">
              <div className="h-full rounded-full bg-gradient-to-r from-brand to-accent transition-all duration-500" style={{ width: `${Math.max(4, progress?.percent ?? 0)}%` }} />
              <div className="sweep absolute inset-y-0 w-1/4 bg-gradient-to-r from-transparent via-white/30 to-transparent" />
            </div>
          </div>
        )}

        {!isTauri && <div className="border-b border-info/30 bg-info/10 px-7 py-2 text-xs text-fg">{t('demo.banner')}</div>}

        <section className="flex-1 overflow-auto px-7 py-6">
          <div className="mx-auto max-w-[1440px]">
            {NEEDS_REPORT.includes(tab) && !report ? (
              <Welcome onScan={() => runAudit(false)} loading={loading} onHistory={() => go('history')} />
            ) : (
              <>
                {tab === 'overview' && report && <Overview report={report} go={go} />}
                {tab === 'findings' && report && <Findings report={report} focus={focus} onSuppress={suppress} onProcessAction={processAction} />}
                {tab === 'processes' && report && <Processes report={report} onAction={processAction} />}
                {tab === 'network' && report && <Network report={report} />}
                {tab === 'persistence' && report && <Persistence report={report} />}
                {tab === 'kernel' && report && <Kernel report={report} />}
                {tab === 'coverage' && <Coverage report={report} />}
                {tab === 'history' && (
                  <History
                    currentId={report?.scan_id}
                    refreshKey={historyKey}
                    onLoad={(id) =>
                      api.loadReport(id).then(
                        (r) => {
                          setReport(r);
                          go('overview');
                        },
                        (e) => toast('error', e.message),
                      )
                    }
                  />
                )}
                {tab === 'guide' && <Guide onRestartOnboarding={onRestartOnboarding} />}
                {tab === 'settings' && <Settings info={info} hasReport={!!report} onBaselineChanged={refreshInfo} onRestartOnboarding={onRestartOnboarding} />}
              </>
            )}
          </div>
        </section>
      </main>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} commands={commands} />
    </div>
  );
}

function Welcome({ onScan, loading, onHistory }: { onScan: () => void; loading: boolean; onHistory: () => void }) {
  const { t } = useI18n();
  return (
    <div className="relative mx-auto mt-6 max-w-3xl overflow-hidden rounded-3xl border border-line bg-surface px-8 pb-14 pt-12 text-center shadow-card">
      <PanopticonPattern className="absolute -top-[46%] start-1/2 w-[150%] -translate-x-1/2 rtl:translate-x-1/2" rings={7} spokes={36} />
      <div className="relative">
        <div className="relative mx-auto mb-7 w-fit">
          <div className="beacon-glow absolute -inset-10 rounded-full" />
          <Mark size={112} scanning={loading} />
        </div>
        <div className="eyebrow mb-3 text-brand">{t('app.tagline')}</div>
        <h2 className="text-4xl font-semibold tracking-tight">{t('welcome.title')}</h2>
        <p className="mx-auto mt-4 max-w-xl text-[14px] leading-relaxed text-muted">{t('welcome.body')}</p>
        <div className="mx-auto mt-8 grid max-w-2xl gap-3 text-start sm:grid-cols-3">
          {[
            ['layer.processes.title', 'layer.processes.desc', <Activity key="a" size={16} />],
            ['layer.network.title', 'layer.network.desc', <NetIcon key="n" size={16} />],
            ['layer.kernel.title', 'layer.kernel.desc', <Boxes key="b" size={16} />],
          ].map(([title, desc, icon]) => (
            <div key={title as string} className="rounded-xl border border-line bg-raised/40 p-4">
              <div className="mb-1.5 flex items-center gap-2 text-[13px] font-medium">
                <span className="text-brand">{icon}</span> {t(title as MessageKey)}
              </div>
              <div className="text-xs leading-relaxed text-muted">{t(desc as MessageKey)}</div>
            </div>
          ))}
        </div>
        <button className="btn-primary mt-10 px-7 py-3 text-[14px]" onClick={onScan} disabled={loading}>
          {loading ? <Spinner className="h-4 w-4" /> : <Eye size={17} />} {loading ? t('scan.running') : t('welcome.cta')}
        </button>
        <div className="mt-4 text-xs text-muted">
          <button className="text-brand hover:underline" onClick={onHistory}>
            {t('welcome.history')}
          </button>
        </div>
      </div>
    </div>
  );
}
