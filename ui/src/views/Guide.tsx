import { BookOpen, Cloud, Keyboard, LifeBuoy, RotateCcw, Terminal } from 'lucide-react';
import { useI18n, type MessageKey } from '../i18n';
import { CopyButton } from '../components/ui';

const CLI = [
  { cmd: 'panoptic-cli scan --html report.html --json report.json', note: 'Full scan with reports' },
  { cmd: 'panoptic-cli scan --save-baseline baseline.json', note: 'Capture a known-good baseline' },
  { cmd: 'panoptic-cli scan --baseline baseline.json --fail-on high --quiet', note: 'CI / cron gate (exit 1 on High+)' },
  { cmd: 'panoptic-cli scan --asff asff.json --aws-account 123456789012 --aws-region us-east-1', note: 'AWS Security Hub export' },
  { cmd: 'panoptic-cli suspend <pid> --start-time <epoch>', note: 'Freeze a process for forensics' },
];

export function Guide({ onRestartOnboarding }: { onRestartOnboarding: () => void }) {
  const { t } = useI18n();
  const mod = navigator.platform?.toLowerCase().includes('mac') ? '⌘' : 'Ctrl';
  const steps = [1, 2, 3, 4, 5, 6];

  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
            <BookOpen size={20} className="text-brand" /> {t('guide.title')}
          </h2>
          <p className="mt-1 text-[13px] text-muted">{t('guide.subtitle')}</p>
        </div>
        <button className="btn-secondary" onClick={onRestartOnboarding}>
          <RotateCcw size={14} /> {t('about.restartOnboarding')}
        </button>
      </header>

      <ol className="relative space-y-4 border-s border-line ps-6">
        {steps.map((n) => (
          <li key={n} className="relative">
            <span className="absolute -start-[33px] top-1 flex h-[18px] w-[18px] items-center justify-center rounded-full bg-brand text-[10px] font-bold text-brand-fg">{n}</span>
            <div className="card p-5">
              <h3 className="font-semibold">{t(`guide.s${n}.title` as MessageKey)}</h3>
              <p className="mt-1.5 text-[13px] leading-relaxed text-muted">{t(`guide.s${n}.body` as MessageKey)}</p>
            </div>
          </li>
        ))}
      </ol>

      <section className="card p-5">
        <h3 className="mb-3 flex items-center gap-2 font-semibold">
          <Terminal size={16} className="text-brand" /> {t('guide.cli.title')}
        </h3>
        <div className="space-y-2" dir="ltr">
          {CLI.map((c) => (
            <div key={c.cmd} className="flex items-center gap-3 rounded-lg border border-line bg-raised px-3 py-2">
              <code className="mono flex-1 overflow-x-auto whitespace-nowrap text-fg">{c.cmd}</code>
              <span className="hidden text-[11px] text-subtle md:inline">{c.note}</span>
              <CopyButton text={c.cmd} />
            </div>
          ))}
        </div>
      </section>

      <section className="card p-5">
        <h3 className="mb-3 flex items-center gap-2 font-semibold">
          <Cloud size={16} className="text-brand" /> {t('aws.title')}
        </h3>
        <p className="mb-3 text-[13px] leading-relaxed text-muted">{t('aws.help')}</p>
        <div className="text-xs text-muted">{t('aws.howto')}</div>
        <div className="mt-1.5 flex items-center gap-3 rounded-lg border border-line bg-raised px-3 py-2" dir="ltr">
          <code className="mono flex-1 overflow-x-auto whitespace-nowrap">aws securityhub batch-import-findings --findings file://panoptic-asff.json</code>
          <CopyButton text="aws securityhub batch-import-findings --findings file://panoptic-asff.json" />
        </div>
      </section>

      <div className="grid gap-4 md:grid-cols-2">
        <section className="card p-5">
          <h3 className="mb-3 flex items-center gap-2 font-semibold">
            <Keyboard size={16} className="text-brand" /> {t('guide.shortcuts.title')}
          </h3>
          <dl className="space-y-2.5 text-[13px]">
            {[
              [`${mod} K`, 'guide.shortcut.palette'],
              [`${mod} Enter`, 'guide.shortcut.deep'],
              [`${mod} Shift Enter`, 'guide.shortcut.quick'],
            ].map(([k, label]) => (
              <div key={k} className="flex items-center justify-between">
                <dt className="text-muted">{t(label as MessageKey)}</dt>
                <dd className="flex gap-1" dir="ltr">
                  {k.split(' ').map((p) => (
                    <kbd key={p} className="kbd">
                      {p}
                    </kbd>
                  ))}
                </dd>
              </div>
            ))}
          </dl>
        </section>
        <section className="card p-5">
          <h3 className="mb-3 flex items-center gap-2 font-semibold">
            <LifeBuoy size={16} className="text-brand" /> {t('guide.faq.title')}
          </h3>
          <div className="space-y-2">
            {[1, 2, 3].map((n) => (
              <details key={n} className="group rounded-lg border border-line px-3 py-2 open:bg-raised/50">
                <summary className="cursor-pointer list-none text-[13px] font-medium marker:hidden">{t(`guide.faq.q${n}` as MessageKey)}</summary>
                <p className="mt-2 text-[13px] leading-relaxed text-muted">{t(`guide.faq.a${n}` as MessageKey)}</p>
              </details>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
