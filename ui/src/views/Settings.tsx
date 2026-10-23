import { useEffect, useState } from 'react';
import { Cloud, Globe2, Info, Plus, Radar, ShieldCheck, Timer, Trash2, Wrench } from 'lucide-react';
import { api } from '../api';
import { LANGUAGES, useI18n, type MessageKey } from '../i18n';
import { useSettings } from '../settings';
import type { ScheduleConfig, ScheduleStatus, Suppressions, SystemInfo } from '../types';
import { DEFAULT_OPTIONS } from '../types';
import { CopyButton, Logo, Spinner, Toggle, useConfirm, useToast } from '../components/ui';
import { Wordmark } from '../brand/Brand';
import { isValidAccountId, isValidInstanceId } from '../util';
import { AwsFields, DETECTIONS, ThemePicker, type AwsValue } from './Onboarding';

type SettingsTab = 'general' | 'scanning' | 'automation' | 'integrations' | 'baseline' | 'about';

interface Props {
  info: SystemInfo | null;
  hasReport: boolean;
  onBaselineChanged: () => void;
  onRestartOnboarding: () => void;
}

export function Settings({ info, hasReport, onBaselineChanged, onRestartOnboarding }: Props) {
  const { t } = useI18n();
  const [tab, setTab] = useState<SettingsTab>('general');
  const tabs: { id: SettingsTab; icon: React.ReactNode }[] = [
    { id: 'general', icon: <Globe2 size={15} /> },
    { id: 'scanning', icon: <Radar size={15} /> },
    { id: 'automation', icon: <Timer size={15} /> },
    { id: 'integrations', icon: <Cloud size={15} /> },
    { id: 'baseline', icon: <Wrench size={15} /> },
    { id: 'about', icon: <Info size={15} /> },
  ];
  return (
    <div className="grid max-w-5xl gap-6 md:grid-cols-[210px_1fr]">
      <nav className="flex gap-1 overflow-x-auto md:flex-col" aria-label={t('nav.settings')}>
        {tabs.map((x) => (
          <button key={x.id} onClick={() => setTab(x.id)} aria-current={tab === x.id ? 'page' : undefined} className={`flex shrink-0 items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] transition ${tab === x.id ? 'bg-surface font-medium text-fg shadow-sm ring-1 ring-line' : 'text-muted hover:bg-raised hover:text-fg'}`}>
            {x.icon} {t(`settings.tab.${x.id}` as MessageKey)}
          </button>
        ))}
      </nav>
      <div className="min-w-0 animate-fade-in" key={tab}>
        {tab === 'general' && <General />}
        {tab === 'scanning' && <Scanning />}
        {tab === 'automation' && <Automation elevated={info?.elevated ?? false} />}
        {tab === 'integrations' && <Integrations />}
        {tab === 'baseline' && <BaselineAndTuning info={info} hasReport={hasReport} onBaselineChanged={onBaselineChanged} />}
        {tab === 'about' && <About info={info} onRestartOnboarding={onRestartOnboarding} />}
      </div>
    </div>
  );
}

function Section({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return (
    <section className="card p-6">
      <h3 className="text-[15px] font-semibold">{title}</h3>
      {description && <p className="mt-1 text-[13px] leading-relaxed text-muted">{description}</p>}
      <div className="mt-5">{children}</div>
    </section>
  );
}

function useSave() {
  const { update } = useSettings();
  const { t } = useI18n();
  const toast = useToast();
  return (patch: Parameters<typeof update>[0], silent = true) =>
    update(patch).then(
      () => !silent && toast('ok', t('settings.saved')),
      (e) => toast('error', t('settings.saveFailed', { error: (e as Error).message })),
    );
}

function General() {
  const { t } = useI18n();
  const { settings } = useSettings();
  const save = useSave();
  return (
    <div className="space-y-5">
      <Section title={t('settings.tab.general')}>
        <div className="grid gap-5 sm:grid-cols-2">
          <div>
            <label className="label">{t('settings.language')}</label>
            <select className="input w-full" value={settings.language} onChange={(e) => save({ language: e.target.value })}>
              {LANGUAGES.map((l) => (
                <option key={l.code} value={l.code}>
                  {l.native}
                  {l.native !== l.english ? ` · ${l.english}` : ''}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label">{t('settings.theme')}</label>
            <ThemePicker value={settings.theme} onChange={(v) => save({ theme: v })} />
          </div>
        </div>
        <div className="mt-6 border-t border-line pt-5">
          <Toggle checked={settings.auto_scan_on_launch} onChange={(v) => save({ auto_scan_on_launch: v })} label={t('settings.autoScan')} />
        </div>
      </Section>
    </div>
  );
}

function Scanning() {
  const { t } = useI18n();
  const { settings } = useSettings();
  const save = useSave();
  const o = settings.scan_options;
  return (
    <Section title={t('settings.tab.scanning')} description={t('onboard.modules.body')}>
      <div className="divide-y divide-line">
        {DETECTIONS.map((d) => (
          <div key={d.key} className="py-4 first:pt-0">
            <Toggle checked={o[d.key] as boolean} onChange={(v) => save({ scan_options: { ...o, [d.key]: v } })} label={t(d.label)} description={t(d.help)} />
          </div>
        ))}
        <div className="flex flex-wrap items-center justify-between gap-4 py-4">
          <div>
            <div className="text-[13px] font-medium">{t('opt.rounds.label')}</div>
            <div className="text-xs text-muted">{t('opt.rounds.help')}</div>
          </div>
          <input type="number" min={1} max={10} className="input w-20 text-center" value={o.confirm_rounds} onChange={(e) => save({ scan_options: { ...o, confirm_rounds: Math.max(1, Math.min(10, Number(e.target.value) || 1)) } })} />
        </div>
      </div>
      <button className="btn-secondary mt-2" onClick={() => save({ scan_options: DEFAULT_OPTIONS }, false)}>
        {t('common.reset')}
      </button>
    </Section>
  );
}

function Automation({ elevated }: { elevated: boolean }) {
  const { t } = useI18n();
  const toast = useToast();
  const { settings } = useSettings();
  const save = useSave();
  const [cfg, setCfg] = useState<ScheduleConfig>(settings.schedule);
  const [status, setStatus] = useState<ScheduleStatus | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.scheduleStatus().then(setStatus, () => setStatus({ installed: false, detail: '' }));
  }, []);

  const apply = async () => {
    setBusy(true);
    try {
      const st = await api.setSchedule(cfg);
      setStatus(st);
      await save({ schedule: { ...cfg, enabled: st.installed } });
      toast('ok', t('schedule.applied'));
    } catch (e) {
      toast('error', (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section title={t('schedule.title')} description={t('schedule.help')}>
      <Toggle checked={cfg.enabled} onChange={(v) => setCfg({ ...cfg, enabled: v })} label={t('schedule.enable')} />
      {cfg.enabled && (
        <div className="mt-5 grid gap-4 sm:grid-cols-2">
          <div>
            <label className="label">{t('schedule.frequency')}</label>
            <select className="input w-full" value={cfg.frequency} onChange={(e) => setCfg({ ...cfg, frequency: e.target.value as ScheduleConfig['frequency'] })}>
              <option value="hourly">{t('freq.hourly')}</option>
              <option value="daily">{t('freq.daily')}</option>
              <option value="weekly">{t('freq.weekly')}</option>
            </select>
          </div>
          {cfg.frequency !== 'hourly' && (
            <div>
              <label className="label">{t('schedule.time')}</label>
              <input type="time" className="input w-full" value={cfg.time} onChange={(e) => setCfg({ ...cfg, time: e.target.value || '09:00' })} />
            </div>
          )}
        </div>
      )}
      {!elevated && <p className="mt-4 text-xs text-warn">{t('schedule.elevatedNote')}</p>}
      <div className="mt-6 flex flex-wrap items-center gap-4 border-t border-line pt-5">
        <button className="btn-primary" onClick={apply} disabled={busy}>
          {busy && <Spinner className="h-3.5 w-3.5" />} {t('schedule.apply')}
        </button>
        <span className="text-xs text-muted">{status ? t('schedule.status', { status: status.installed ? status.detail || '✓' : t('schedule.notInstalled') }) : t('common.loading')}</span>
      </div>
    </Section>
  );
}

function Integrations() {
  const { t } = useI18n();
  const { settings } = useSettings();
  const save = useSave();
  const toast = useToast();
  const [enabled, setEnabled] = useState(!!settings.aws);
  const [v, setV] = useState<AwsValue>({ account: settings.aws?.account_id ?? '', region: settings.aws?.region ?? 'us-east-1', instance: settings.aws?.instance_id ?? '' });
  const valid = !enabled || (isValidAccountId(v.account) && isValidInstanceId(v.instance));
  const cmd = 'aws securityhub batch-import-findings --findings file://panoptic-asff.json';
  return (
    <Section title={t('aws.title')} description={t('aws.help')}>
      <Toggle checked={enabled} onChange={setEnabled} label={t('aws.enable')} />
      {enabled && <AwsFields value={v} onChange={setV} />}
      <div className="mt-6 flex items-center gap-3 border-t border-line pt-5">
        <button
          className="btn-primary"
          disabled={!valid}
          onClick={() => save({ aws: enabled ? { account_id: v.account, region: v.region, instance_id: v.instance || null } : null }).then(() => toast('ok', t('aws.saved')))}
        >
          {t('aws.save')}
        </button>
      </div>
      <div className="mt-6 text-xs text-muted">{t('aws.howto')}</div>
      <div className="mt-1.5 flex items-center gap-2 rounded-lg border border-line bg-raised px-3 py-2" dir="ltr">
        <code className="mono flex-1 overflow-x-auto whitespace-nowrap">{cmd}</code>
        <CopyButton text={cmd} />
      </div>
    </Section>
  );
}

function BaselineAndTuning({ info, hasReport, onBaselineChanged }: { info: SystemInfo | null; hasReport: boolean; onBaselineChanged: () => void }) {
  const { t, formatDate } = useI18n();
  const toast = useToast();
  const confirm = useConfirm();
  const [sup, setSup] = useState<Suppressions | null>(null);
  const [pattern, setPattern] = useState('');

  useEffect(() => {
    api.getSuppressions().then(setSup, (e) => toast('error', e.message));
  }, [toast]);

  const saveSup = async (next: Suppressions) => {
    try {
      await api.setSuppressions(next);
      setSup(next);
      toast('ok', t('sup.saved'));
    } catch (e) {
      toast('error', (e as Error).message);
    }
  };

  return (
    <div className="space-y-5">
      <Section title={t('baseline.title')} description={t('baseline.help')}>
        <div className="mb-4 flex items-center gap-2 text-[13px]">
          <ShieldCheck size={15} className={info?.has_baseline ? 'text-ok' : 'text-subtle'} />
          {info?.has_baseline ? t('baseline.captured', { time: formatDate(info.baseline_created_at) }) : t('baseline.none')}
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            className="btn-primary"
            disabled={!hasReport}
            onClick={async () => {
              if (!(await confirm({ title: t('baseline.confirmTitle'), body: t('baseline.confirmBody'), confirmLabel: t('baseline.save') }))) return;
              api.saveBaseline().then(
                () => {
                  toast('ok', t('baseline.saved'));
                  onBaselineChanged();
                },
                (e) => toast('error', e.message),
              );
            }}
          >
            {t('baseline.save')}
          </button>
          <button
            className="btn-secondary"
            disabled={!info?.has_baseline}
            onClick={() =>
              api.clearBaseline().then(
                () => {
                  toast('ok', t('baseline.cleared'));
                  onBaselineChanged();
                },
                (e) => toast('error', e.message),
              )
            }
          >
            {t('baseline.clear')}
          </button>
        </div>
      </Section>

      <Section title={t('sup.title')}>
        {!sup ? (
          <Spinner />
        ) : (
          <div className="grid gap-6 lg:grid-cols-2">
            <div>
              <div className="text-[13px] font-medium">
                {t('sup.patterns')} <span className="text-subtle">({sup.path_patterns.length})</span>
              </div>
              <p className="mb-3 mt-0.5 text-xs text-muted">{t('sup.patternsHelp')}</p>
              <form
                className="mb-3 flex gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  const p = pattern.trim();
                  if (p.length < 3) return toast('error', t('sup.tooShort'));
                  if (!sup.path_patterns.includes(p)) saveSup({ ...sup, path_patterns: [...sup.path_patterns, p] });
                  setPattern('');
                }}
              >
                <input className="input mono flex-1" value={pattern} onChange={(e) => setPattern(e.target.value)} placeholder="\program files\vendor\" dir="ltr" />
                <button className="btn-secondary" type="submit">
                  <Plus size={14} /> {t('sup.add')}
                </button>
              </form>
              <ul className="space-y-1.5">
                {sup.path_patterns.map((p) => (
                  <li key={p} className="flex items-center justify-between rounded-lg border border-line px-3 py-1.5">
                    <code className="mono">{p}</code>
                    <button aria-label={t('common.delete')} className="text-subtle hover:text-danger" onClick={() => saveSup({ ...sup, path_patterns: sup.path_patterns.filter((x) => x !== p) })}>
                      <Trash2 size={13} />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="text-[13px] font-medium">
                {t('sup.ids')} <span className="text-subtle">({sup.finding_ids.length})</span>
              </div>
              <p className="mb-3 mt-0.5 text-xs text-muted">{t('sup.idsHelp')}</p>
              <ul className="max-h-64 space-y-1.5 overflow-auto">
                {sup.finding_ids.map((id) => (
                  <li key={id} className="flex items-center justify-between gap-2 rounded-lg border border-line px-3 py-1.5">
                    <code className="mono truncate">{id}</code>
                    <button aria-label={t('findings.unsuppress')} className="text-subtle hover:text-danger" onClick={() => saveSup({ ...sup, finding_ids: sup.finding_ids.filter((x) => x !== id) })}>
                      <Trash2 size={13} />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </Section>
    </div>
  );
}

function About({ info, onRestartOnboarding }: { info: SystemInfo | null; onRestartOnboarding: () => void }) {
  const { t } = useI18n();
  return (
    <Section title={t('about.title')}>
      <div className="flex items-center gap-4">
        <Logo size={56} />
        <div>
          <Wordmark size={18} />
          <div className="text-[13px] text-muted">{t('about.version', { version: info?.version ?? '—' })} · {info?.engine}</div>
        </div>
      </div>
      <div className="mt-6 space-y-3 text-[13px] leading-relaxed text-muted">
        <p className="font-medium text-fg">{t('about.license')}</p>
        <p className="rounded-lg border border-line bg-raised/50 p-3 text-xs">{t('about.legal')}</p>
        <p>{t('about.offline')}</p>
        <p>
          {t('about.dataDir')}: <code className="mono text-fg">{info?.data_dir ?? '—'}</code>
        </p>
      </div>
      <button className="btn-secondary mt-6" onClick={onRestartOnboarding}>
        {t('about.restartOnboarding')}
      </button>
    </Section>
  );
}
