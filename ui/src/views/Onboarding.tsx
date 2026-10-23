import { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, ArrowRight, Check, Cloud, Cpu, Eye, Globe2, Layers, Lock, Moon, Network, Radar, ShieldCheck, Sun, Timer, Monitor } from 'lucide-react';
import { api } from '../api';
import { LANGUAGES, useI18n, type MessageKey } from '../i18n';
import { useSettings } from '../settings';
import type { AppSettings, EnvCheck, ScanOptions, Theme } from '../types';
import { AWS_REGIONS } from '../types';
import { CheckRow, Logo, Toggle, useToast } from '../components/ui';
import { Mark, PanopticonPattern, Wordmark } from '../brand/Brand';
import { isValidAccountId, isValidInstanceId } from '../util';

type Draft = Pick<AppSettings, 'scan_options' | 'auto_scan_on_launch' | 'baseline_after_first_scan' | 'schedule'> & { awsEnabled: boolean; account: string; region: string; instance: string };

const STEPS: MessageKey[] = ['onboard.welcome.title', 'onboard.how.title', 'onboard.check.title', 'onboard.modules.title', 'onboard.integrations.title', 'onboard.ready.title'];

export function Onboarding({ onDone }: { onDone: (startScan: boolean) => void }) {
  const { t, dir } = useI18n();
  const { settings, update } = useSettings();
  const toast = useToast();
  const [step, setStep] = useState(0);
  const [checks, setChecks] = useState<EnvCheck[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState<Draft>({
    scan_options: settings.scan_options,
    auto_scan_on_launch: settings.auto_scan_on_launch,
    baseline_after_first_scan: settings.baseline_after_first_scan,
    schedule: settings.schedule,
    awsEnabled: !!settings.aws,
    account: settings.aws?.account_id ?? '',
    region: settings.aws?.region ?? 'us-east-1',
    instance: settings.aws?.instance_id ?? '',
  });

  useEffect(() => {
    if (step === 2 && !checks) api.environmentChecks().then(setChecks, (e) => toast('error', e.message));
  }, [step, checks, toast]);

  const awsValid = !draft.awsEnabled || (isValidAccountId(draft.account) && isValidInstanceId(draft.instance));
  const canNext = step !== 4 || awsValid;
  const elevated = checks?.find((c) => c.id === 'elevation')?.ok ?? true;

  const setOpt = (k: keyof ScanOptions, v: boolean) => setDraft((d) => ({ ...d, scan_options: { ...d.scan_options, [k]: v } }));

  const finish = async (startScan: boolean) => {
    setBusy(true);
    try {
      await update({
        onboarding_completed: true,
        scan_options: draft.scan_options,
        auto_scan_on_launch: draft.auto_scan_on_launch,
        baseline_after_first_scan: draft.baseline_after_first_scan,
        schedule: draft.schedule,
        aws: draft.awsEnabled ? { account_id: draft.account, region: draft.region, instance_id: draft.instance || null } : null,
      });
      if (draft.schedule.enabled) {
        try {
          await api.setSchedule(draft.schedule);
        } catch (e) {
          toast('error', (e as Error).message);
        }
      }
      onDone(startScan);
    } catch (e) {
      toast('error', t('settings.saveFailed', { error: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  };

  const enabledDetections = useMemo(() => (['brute_force_pids', 'port_probe', 'persistence', 'kernel_modules', 'hash_evidence'] as const).filter((k) => draft.scan_options[k]).length, [draft.scan_options]);
  const Arrow = dir === 'rtl' ? ArrowLeft : ArrowRight;
  const Back = dir === 'rtl' ? ArrowRight : ArrowLeft;

  return (
    <div className="flex h-full bg-bg">
      {/* Brand rail */}
      {/* The rail is always "ink", the brand's signature surface, in both themes. */}
      <aside data-theme="dark" className="relative hidden w-[340px] shrink-0 flex-col overflow-hidden border-e border-line bg-bg p-8 text-fg lg:flex">
        <PanopticonPattern className="absolute -bottom-[38%] -start-[45%] w-[190%]" rings={8} spokes={36} />
        <div className="beacon-glow pointer-events-none absolute -end-28 -top-28 h-80 w-80 rounded-full" />
        <div className="relative flex items-center gap-3">
          <Logo size={38} />
          <Wordmark size={16} tagline={t('app.tagline')} />
        </div>
        <ol className="relative mt-12 space-y-1">
          {STEPS.map((k, i) => (
            <li key={k}>
              <button
                disabled={i > step}
                onClick={() => i < step && setStep(i)}
                className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-start text-[13px] transition ${i === step ? 'bg-raised font-medium text-fg' : i < step ? 'text-muted hover:text-fg' : 'text-subtle'}`}
              >
                <span className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold ${i < step ? 'bg-brand text-brand-fg' : i === step ? 'border-2 border-brand text-brand' : 'border border-line'}`}>
                  {i < step ? <Check size={12} /> : i + 1}
                </span>
                {t(k)}
              </button>
            </li>
          ))}
        </ol>
        <div className="relative mt-auto flex items-center gap-2 text-xs text-muted">
          <Lock size={13} /> {t('onboard.welcome.privacy')}
        </div>
      </aside>

      {/* Content */}
      <main className="flex min-w-0 flex-1 flex-col">
        <div className="flex-1 overflow-auto px-6 py-10 sm:px-12">
          <div key={step} className="mx-auto max-w-2xl animate-fade-in">
            <div className="eyebrow mb-3">{t('onboard.step', { n: step + 1, total: STEPS.length })}</div>

            {step === 0 && (
              <>
                <div className="mb-6 lg:hidden">
                  <Logo size={48} />
                </div>
                <h1 className="text-3xl font-semibold tracking-tight">{t('onboard.welcome.title')}</h1>
                <p className="mt-3 text-[15px] leading-relaxed text-muted">{t('onboard.welcome.body')}</p>
                <div className="mt-8 grid gap-5 sm:grid-cols-2">
                  <div>
                    <label className="label flex items-center gap-1.5">
                      <Globe2 size={13} /> {t('settings.language')}
                    </label>
                    <select className="input w-full" value={settings.language} onChange={(e) => update({ language: e.target.value }).catch(() => undefined)}>
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
                    <ThemePicker value={settings.theme} onChange={(v) => update({ theme: v }).catch(() => undefined)} />
                  </div>
                </div>
              </>
            )}

            {step === 1 && (
              <>
                <h1 className="text-3xl font-semibold tracking-tight">{t('onboard.how.title')}</h1>
                <p className="mt-3 text-[15px] leading-relaxed text-muted">{t('onboard.how.body')}</p>
                <div className="mt-8 grid gap-3">
                  {[
                    { icon: <Cpu size={18} />, title: 'layer.processes.title', desc: 'layer.processes.desc' },
                    { icon: <Network size={18} />, title: 'layer.network.title', desc: 'layer.network.desc' },
                    { icon: <Layers size={18} />, title: 'layer.kernel.title', desc: 'layer.kernel.desc' },
                  ].map((l) => (
                    <div key={l.title} className="card flex items-start gap-4 p-4">
                      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand/10 text-brand">{l.icon}</span>
                      <div>
                        <div className="font-medium">{t(l.title as MessageKey)}</div>
                        <div className="text-[13px] text-muted">{t(l.desc as MessageKey)}</div>
                      </div>
                    </div>
                  ))}
                </div>
                <p className="mt-6 flex items-center gap-2 text-[13px] text-muted">
                  <ShieldCheck size={15} className="text-ok" /> {t('onboard.how.verdicts')}
                </p>
              </>
            )}

            {step === 2 && (
              <>
                <h1 className="text-3xl font-semibold tracking-tight">{t('onboard.check.title')}</h1>
                <p className="mt-3 text-[15px] leading-relaxed text-muted">{t('onboard.check.body')}</p>
                <div className="mt-8 grid gap-2.5">
                  {(['elevation', 'engine', 'storage', 'cli', 'scheduler'] as const).map((id) => {
                    const c = checks?.find((x) => x.id === id);
                    return <CheckRow key={id} pending={!checks} ok={c?.ok ?? false} label={t(`check.${id}` as MessageKey)} detail={c?.detail ?? t('common.loading')} />;
                  })}
                </div>
                {checks && !elevated && (
                  <div className="mt-5 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-warn/30 bg-warn/10 p-4 text-[13px]">
                    <span className="flex-1">{t('onboard.check.limitedNote')}</span>
                    <button className="btn-secondary" onClick={() => api.relaunchAsAdmin().catch((e) => toast('info', e.message))}>
                      <ShieldCheck size={14} /> {t('priv.relaunch')}
                    </button>
                  </div>
                )}
              </>
            )}

            {step === 3 && (
              <>
                <h1 className="text-3xl font-semibold tracking-tight">{t('onboard.modules.title')}</h1>
                <p className="mt-3 text-[15px] leading-relaxed text-muted">{t('onboard.modules.body')}</p>
                <div className="card mt-8 divide-y divide-line">
                  {DETECTIONS.map((d) => (
                    <div key={d.key} className="p-4">
                      <Toggle
                        checked={draft.scan_options[d.key] as boolean}
                        onChange={(v) => setOpt(d.key, v)}
                        label={t(d.label)}
                        description={t(d.help)}
                        badge={d.recommended ? <span className="chip bg-brand/10 text-brand">{t('common.recommended')}</span> : undefined}
                      />
                    </div>
                  ))}
                </div>
              </>
            )}

            {step === 4 && (
              <>
                <h1 className="text-3xl font-semibold tracking-tight">{t('onboard.integrations.title')}</h1>
                <p className="mt-3 text-[15px] leading-relaxed text-muted">{t('onboard.integrations.body')}</p>
                <div className="mt-8 space-y-4">
                  <div className="card p-5">
                    <div className="mb-4 flex items-center gap-2 font-medium">
                      <Timer size={16} className="text-brand" /> {t('schedule.title')}
                    </div>
                    <Toggle checked={draft.schedule.enabled} onChange={(v) => setDraft((d) => ({ ...d, schedule: { ...d.schedule, enabled: v } }))} label={t('schedule.enable')} description={t('schedule.help')} />
                    {draft.schedule.enabled && (
                      <div className="mt-4 grid gap-3 sm:grid-cols-2">
                        <div>
                          <label className="label">{t('schedule.frequency')}</label>
                          <select className="input w-full" value={draft.schedule.frequency} onChange={(e) => setDraft((d) => ({ ...d, schedule: { ...d.schedule, frequency: e.target.value as Draft['schedule']['frequency'] } }))}>
                            <option value="hourly">{t('freq.hourly')}</option>
                            <option value="daily">{t('freq.daily')}</option>
                            <option value="weekly">{t('freq.weekly')}</option>
                          </select>
                        </div>
                        {draft.schedule.frequency !== 'hourly' && (
                          <div>
                            <label className="label">{t('schedule.time')}</label>
                            <input type="time" className="input w-full" value={draft.schedule.time} onChange={(e) => setDraft((d) => ({ ...d, schedule: { ...d.schedule, time: e.target.value || '09:00' } }))} />
                          </div>
                        )}
                        {!elevated && <p className="text-xs text-warn sm:col-span-2">{t('schedule.elevatedNote')}</p>}
                      </div>
                    )}
                  </div>

                  <div className="card p-5">
                    <div className="mb-4 flex items-center gap-2 font-medium">
                      <Cloud size={16} className="text-brand" /> {t('aws.title')}
                    </div>
                    <Toggle checked={draft.awsEnabled} onChange={(v) => setDraft((d) => ({ ...d, awsEnabled: v }))} label={t('aws.enable')} description={t('aws.help')} />
                    {draft.awsEnabled && <AwsFields value={draft} onChange={(v) => setDraft((d) => ({ ...d, ...v }))} />}
                  </div>

                  <div className="card space-y-4 p-5">
                    <Toggle checked={draft.auto_scan_on_launch} onChange={(v) => setDraft((d) => ({ ...d, auto_scan_on_launch: v }))} label={t('settings.autoScan')} />
                    <Toggle checked={draft.baseline_after_first_scan} onChange={(v) => setDraft((d) => ({ ...d, baseline_after_first_scan: v }))} label={t('onboard.int.baseline')} />
                  </div>
                </div>
              </>
            )}

            {step === 5 && (
              <>
                <div className="relative mb-6 w-fit">
                  <div className="beacon-glow absolute -inset-6 rounded-full" />
                  <Mark size={84} />
                </div>
                <h1 className="text-3xl font-semibold tracking-tight">{t('onboard.ready.title')}</h1>
                <p className="mt-3 text-[15px] leading-relaxed text-muted">{t('onboard.ready.body')}</p>
                <dl className="card mt-8 divide-y divide-line text-[13px]">
                  <Summary icon={<Radar size={15} />} label={t('onboard.summary.detections')} value={`${enabledDetections} / 5`} />
                  <Summary icon={<Timer size={15} />} label={t('onboard.summary.schedule')} value={draft.schedule.enabled ? `${t(`freq.${draft.schedule.frequency}` as MessageKey)}${draft.schedule.frequency !== 'hourly' ? ` · ${draft.schedule.time}` : ''}` : t('common.off')} />
                  <Summary icon={<Cloud size={15} />} label={t('onboard.summary.aws')} value={draft.awsEnabled ? `${draft.account} · ${draft.region}` : t('common.off')} />
                  <Summary icon={<Globe2 size={15} />} label={t('settings.language')} value={LANGUAGES.find((l) => l.code === settings.language)?.native ?? settings.language} />
                </dl>
              </>
            )}
          </div>
        </div>

        {/* Footer nav */}
        <footer className="border-t border-line bg-surface/80 px-6 py-4 backdrop-blur sm:px-12">
          <div className="mx-auto flex max-w-2xl items-center gap-3">
            {step > 0 && (
              <button className="btn-ghost" onClick={() => setStep(step - 1)} disabled={busy}>
                <Back size={15} /> {t('common.back')}
              </button>
            )}
            <div className="flex-1" />
            {step < STEPS.length - 1 ? (
              <>
                {step >= 3 && (
                  <button className="btn-ghost" disabled={!canNext} onClick={() => setStep(STEPS.length - 1)}>
                    {t('common.skip')}
                  </button>
                )}
                <button className="btn-primary min-w-[140px]" disabled={!canNext} onClick={() => setStep(step + 1)}>
                  {t('common.next')} <Arrow size={15} />
                </button>
              </>
            ) : (
              <>
                <button className="btn-secondary" disabled={busy} onClick={() => finish(false)}>
                  {t('onboard.ready.later')}
                </button>
                <button className="btn-primary" disabled={busy} onClick={() => finish(true)}>
                  <Eye size={15} /> {t('onboard.ready.start')}
                </button>
              </>
            )}
          </div>
        </footer>
      </main>
    </div>
  );
}

export const DETECTIONS: { key: keyof ScanOptions; label: MessageKey; help: MessageKey; recommended?: boolean }[] = [
  { key: 'brute_force_pids', label: 'opt.brute.label', help: 'opt.brute.help', recommended: true },
  { key: 'port_probe', label: 'opt.ports.label', help: 'opt.ports.help', recommended: true },
  { key: 'persistence', label: 'opt.persistence.label', help: 'opt.persistence.help', recommended: true },
  { key: 'kernel_modules', label: 'opt.modules.label', help: 'opt.modules.help', recommended: true },
  { key: 'hash_evidence', label: 'opt.hash.label', help: 'opt.hash.help' },
];

export function ThemePicker({ value, onChange }: { value: Theme; onChange: (t: Theme) => void }) {
  const { t } = useI18n();
  const opts: { v: Theme; icon: React.ReactNode }[] = [
    { v: 'system', icon: <Monitor size={14} /> },
    { v: 'dark', icon: <Moon size={14} /> },
    { v: 'light', icon: <Sun size={14} /> },
  ];
  return (
    <div className="grid grid-cols-3 gap-1 rounded-lg border border-line bg-raised p-1" role="radiogroup">
      {opts.map((o) => (
        <button key={o.v} role="radio" aria-checked={value === o.v} onClick={() => onChange(o.v)} className={`flex items-center justify-center gap-1.5 rounded-md py-1.5 text-xs font-medium transition ${value === o.v ? 'bg-surface text-fg shadow-sm' : 'text-muted hover:text-fg'}`}>
          {o.icon} {t(`theme.${o.v}` as MessageKey)}
        </button>
      ))}
    </div>
  );
}

export interface AwsValue {
  account: string;
  region: string;
  instance: string;
}

export function AwsFields({ value: draft, onChange }: { value: AwsValue; onChange: (v: AwsValue) => void }) {
  const { t } = useI18n();
  const setDraft = (fn: (d: AwsValue) => AwsValue) => onChange(fn(draft));
  const accountBad = draft.account !== '' && !isValidAccountId(draft.account);
  const instanceBad = !isValidInstanceId(draft.instance);
  return (
    <div className="mt-4 grid gap-3 sm:grid-cols-3">
      <div>
        <label className="label">{t('aws.account')}</label>
        <input className={`input mono w-full ${accountBad ? 'border-danger' : ''}`} inputMode="numeric" maxLength={12} placeholder="123456789012" value={draft.account} onChange={(e) => setDraft((d) => ({ ...d, account: e.target.value.replace(/\D/g, '') }))} aria-invalid={accountBad} />
      </div>
      <div>
        <label className="label">{t('aws.region')}</label>
        <select className="input mono w-full" value={draft.region} onChange={(e) => setDraft((d) => ({ ...d, region: e.target.value }))}>
          {AWS_REGIONS.map((r) => (
            <option key={r}>{r}</option>
          ))}
        </select>
      </div>
      <div>
        <label className="label">
          {t('aws.instance')} <span className="text-subtle">· {t('common.optional')}</span>
        </label>
        <input className={`input mono w-full ${instanceBad ? 'border-danger' : ''}`} placeholder="i-0abc…" value={draft.instance} onChange={(e) => setDraft((d) => ({ ...d, instance: e.target.value.trim() }))} aria-invalid={instanceBad} />
      </div>
    </div>
  );
}

function Summary({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-3 px-4 py-3">
      <span className="text-subtle">{icon}</span>
      <dt className="flex-1 text-muted">{label}</dt>
      <dd className="mono font-medium">{value}</dd>
    </div>
  );
}
