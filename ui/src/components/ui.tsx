import React, { createContext, useCallback, useContext, useEffect, useId, useRef, useState } from 'react';
import { AlertTriangle, Check, CheckCircle2, ChevronDown, ChevronUp, Copy, Info, Search, X, XCircle } from 'lucide-react';
import { translate, useI18n } from '../i18n';
import type { Severity } from '../types';
import { SEVERITY_STYLE, riskLevel, severityKey, type SortDir } from '../util';
import { CellGauge, Mark } from '../brand/Brand';

// ---------------------------------------------------------------- brand

/** App-icon style mark (ink tile). See brand/Brand.tsx for the full system. */
export function Logo({ size = 28, scanning = false }: { size?: number; scanning?: boolean }) {
  return <Mark size={size} tile scanning={scanning} />;
}

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    if (!this.state.error) return this.props.children;
    const lang = document.documentElement.lang || 'en';
    return (
      <div className="flex h-full items-center justify-center bg-bg p-8">
        <div className="card max-w-xl p-6">
          <h1 className="mb-2 text-lg font-semibold text-danger">{translate(lang, 'error.title')}</h1>
          <pre className="mono mb-4 whitespace-pre-wrap text-muted">{this.state.error.message}</pre>
          <button className="btn-primary" onClick={() => this.setState({ error: null })}>
            {translate(lang, 'error.recover')}
          </button>
        </div>
      </div>
    );
  }
}

// ---------------------------------------------------------------- primitives

export function SeverityBadge({ severity, className = '' }: { severity: Severity; className?: string }) {
  const { t } = useI18n();
  return <span className={`chip ${SEVERITY_STYLE[severity].badge} ${className}`}>{t(severityKey(severity))}</span>;
}

export function SeverityDot({ severity }: { severity: Severity }) {
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${SEVERITY_STYLE[severity].dot}`} aria-hidden="true" />;
}

export function Spinner({ className = 'h-4 w-4' }: { className?: string }) {
  return <span className={`inline-block animate-spin rounded-full border-2 border-current border-t-transparent ${className}`} role="status" aria-label="loading" />;
}

/** Risk score drawn as the brand mark: lit cells = risk. */
export function RiskGauge({ score, size = 196 }: { score: number; size?: number }) {
  const { t } = useI18n();
  const level = riskLevel(score);
  return <CellGauge score={score} color={level.color} label={t(level.key)} size={size} />;
}

export function StatCard({ label, value, tone = 'default', icon, onClick }: { label: string; value: React.ReactNode; tone?: 'default' | 'danger' | 'ok'; icon?: React.ReactNode; onClick?: () => void }) {
  const toneClass = { default: 'text-fg', danger: 'text-danger', ok: 'text-ok' }[tone];
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag onClick={onClick} className={`card group p-4 text-start ${onClick ? 'transition hover:-translate-y-0.5 hover:border-brand/40' : ''}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted">{label}</span>
        <span className="text-subtle group-hover:text-brand">{icon}</span>
      </div>
      <div className={`mt-2 text-3xl font-semibold tabular-nums tracking-tight ${toneClass}`}>{value}</div>
    </Tag>
  );
}

export function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <label className="relative block min-w-[260px] flex-1 sm:max-w-sm">
      <Search size={14} className="pointer-events-none absolute start-3 top-1/2 -translate-y-1/2 text-subtle" />
      <input className="input w-full ps-9 pe-8" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} aria-label={placeholder} />
      {value && (
        <button className="absolute end-2.5 top-1/2 -translate-y-1/2 text-subtle hover:text-fg" onClick={() => onChange('')} aria-label="Clear">
          <X size={13} />
        </button>
      )}
    </label>
  );
}

export function SortTh<K extends string>({ label, k, sort, setSort, className = '' }: { label: string; k: K; sort: { key: K; dir: SortDir }; setSort: (s: { key: K; dir: SortDir }) => void; className?: string }) {
  const active = sort.key === k;
  return (
    <th className={`th cursor-pointer hover:text-fg ${className}`} onClick={() => setSort({ key: k, dir: active && sort.dir === 'asc' ? 'desc' : 'asc' })} aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <span className="inline-flex items-center gap-1">
        {label}
        {active && (sort.dir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
      </span>
    </th>
  );
}

export function Segmented<T extends string>({ value, onChange, options }: { value: T; onChange: (v: T) => void; options: { value: T; label: string; count?: number }[] }) {
  return (
    <div className="inline-flex rounded-lg border border-line bg-raised p-0.5" role="tablist">
      {options.map((o) => (
        <button
          key={o.value}
          role="tab"
          aria-selected={value === o.value}
          onClick={() => onChange(o.value)}
          className={`rounded-md px-3 py-1.5 text-xs font-medium transition ${value === o.value ? 'bg-surface text-fg shadow-sm' : 'text-muted hover:text-fg'}`}
        >
          {o.label}
          {o.count !== undefined && <span className={`ms-1.5 tabular-nums ${value === o.value ? 'text-brand' : 'text-subtle'}`}>{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Toggle({ checked, onChange, label, description, badge, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; description?: string; badge?: React.ReactNode; disabled?: boolean }) {
  const id = useId();
  return (
    <div className={`flex items-start justify-between gap-4 ${disabled ? 'opacity-50' : ''}`}>
      <label htmlFor={id} className="cursor-pointer">
        <span id={`${id}-l`} className="flex items-center gap-2 text-[13px] font-medium text-fg">
          {label} {badge}
        </span>
        {description && (
          <span id={`${id}-d`} className="mt-0.5 block text-xs leading-relaxed text-muted">
            {description}
          </span>
        )}
      </label>
      <button
        id={id}
        role="switch"
        aria-label={label}
        aria-labelledby={`${id}-l`}
        aria-describedby={description ? `${id}-d` : undefined}
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative mt-0.5 inline-flex h-5 w-9 shrink-0 items-center rounded-full transition ${checked ? 'bg-brand' : 'bg-line'}`}
      >
        <span className={`inline-block h-4 w-4 rounded-full bg-white shadow transition ${checked ? 'translate-x-[18px] rtl:-translate-x-[18px]' : 'translate-x-0.5 rtl:-translate-x-0.5'}`} />
      </button>
    </div>
  );
}

export function EmptyState({ icon, title, children }: { icon?: React.ReactNode; title: string; children?: React.ReactNode }) {
  return (
    <div className="card-flat flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      {icon && <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-raised text-muted">{icon}</div>}
      <div className="text-sm font-semibold">{title}</div>
      {children && <div className="max-w-md text-xs leading-relaxed text-muted">{children}</div>}
    </div>
  );
}

export function Banner({ tone, children, action }: { tone: 'warn' | 'info' | 'danger'; children: React.ReactNode; action?: React.ReactNode }) {
  const cls = { warn: 'border-warn/30 bg-warn/10 text-fg', info: 'border-info/30 bg-info/10 text-fg', danger: 'border-danger/30 bg-danger/10 text-fg' }[tone];
  const Icon = tone === 'info' ? Info : AlertTriangle;
  const iconCls = { warn: 'text-warn', info: 'text-info', danger: 'text-danger' }[tone];
  return (
    <div className={`flex items-start gap-3 rounded-xl border px-4 py-3 text-[13px] ${cls}`}>
      <Icon size={16} className={`mt-0.5 shrink-0 ${iconCls}`} />
      <div className="flex-1 leading-relaxed">{children}</div>
      {action}
    </div>
  );
}

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const { t } = useI18n();
  const [done, setDone] = useState(false);
  return (
    <button
      className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] text-subtle hover:bg-raised hover:text-fg"
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* clipboard unavailable */
        }
      }}
      title={t('common.copy')}
    >
      {done ? <Check size={11} className="text-ok" /> : <Copy size={11} />} {done ? t('common.copied') : (label ?? t('common.copy'))}
    </button>
  );
}

export function VisibilityDots({ v, ghost }: { v: { api: boolean; syscall: boolean; brute_force: boolean }; ghost: boolean }) {
  const { t } = useI18n();
  const dot = (on: boolean, l: string, name: string) => (
    <span
      title={`${name}: ${on ? t('proc.visible') : t('proc.notVisible')}`}
      className={`inline-flex h-5 w-5 items-center justify-center rounded-md font-mono text-[10px] font-bold ${on ? 'bg-ok/15 text-ok' : ghost ? 'bg-danger text-white' : 'bg-raised text-subtle'}`}
    >
      {l}
    </span>
  );
  return (
    <span className="inline-flex gap-1" style={{ direction: 'ltr' }}>
      {dot(v.api, 'A', t('proc.layerApi'))}
      {dot(v.syscall, 'S', t('proc.layerSyscall'))}
      {dot(v.brute_force, 'B', t('proc.layerBrute'))}
    </span>
  );
}

export function CheckRow({ ok, label, detail, pending }: { ok: boolean; label: string; detail: string; pending?: boolean }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-line bg-surface px-3.5 py-3">
      {pending ? <Spinner className="mt-0.5 h-4 w-4 text-brand" /> : ok ? <CheckCircle2 size={17} className="mt-0.5 shrink-0 text-ok" /> : <AlertTriangle size={17} className="mt-0.5 shrink-0 text-warn" />}
      <div className="min-w-0">
        <div className="text-[13px] font-medium">{label}</div>
        <div className="truncate text-xs text-muted" title={detail}>
          {detail}
        </div>
      </div>
    </div>
  );
}

export function StatusIcon({ ok }: { ok: boolean }) {
  return ok ? <CheckCircle2 size={14} className="shrink-0 text-ok" /> : <XCircle size={14} className="shrink-0 text-danger" />;
}

// ---------------------------------------------------------------- confirm dialog

export interface ConfirmOptions {
  title: string;
  body: React.ReactNode;
  confirmLabel: string;
  danger?: boolean;
}

const ConfirmCtx = createContext<(o: ConfirmOptions) => Promise<boolean>>(async () => false);
export const useConfirm = () => useContext(ConfirmCtx);

export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const { t } = useI18n();
  const [opts, setOpts] = useState<ConfirmOptions | null>(null);
  const resolver = useRef<(v: boolean) => void>();
  const confirm = useCallback((o: ConfirmOptions) => {
    setOpts(o);
    return new Promise<boolean>((res) => (resolver.current = res));
  }, []);
  const close = (v: boolean) => {
    resolver.current?.(v);
    setOpts(null);
  };
  useEffect(() => {
    if (!opts) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && close(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [opts]);
  return (
    <ConfirmCtx.Provider value={confirm}>
      {children}
      {opts && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm" onClick={() => close(false)}>
          <div role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" className="card w-full max-w-md animate-fade-in p-6 shadow-pop" onClick={(e) => e.stopPropagation()}>
            <div className="mb-3 flex items-center gap-3">
              {opts.danger && (
                <span className="flex h-9 w-9 items-center justify-center rounded-full bg-danger/10">
                  <AlertTriangle size={17} className="text-danger" />
                </span>
              )}
              <h2 id="confirm-title" className="text-base font-semibold">
                {opts.title}
              </h2>
            </div>
            <div className="mb-6 text-[13px] leading-relaxed text-muted">{opts.body}</div>
            <div className="flex justify-end gap-2">
              <button className="btn-secondary" onClick={() => close(false)}>
                {t('common.cancel')}
              </button>
              <button autoFocus className={opts.danger ? 'btn-danger' : 'btn-primary'} onClick={() => close(true)}>
                {opts.confirmLabel}
              </button>
            </div>
          </div>
        </div>
      )}
    </ConfirmCtx.Provider>
  );
}

// ---------------------------------------------------------------- toasts

interface Toast {
  id: number;
  kind: 'ok' | 'error' | 'info';
  text: string;
}
const ToastCtx = createContext<(kind: Toast['kind'], text: string) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const { t } = useI18n();
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((kind: Toast['kind'], text: string) => {
    const id = Date.now() + Math.random();
    setToasts((x) => [...x.slice(-3), { id, kind, text }]);
    setTimeout(() => setToasts((x) => x.filter((y) => y.id !== id)), kind === 'error' ? 8000 : 4000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-5 end-5 z-50 flex w-[380px] max-w-[calc(100vw-2.5rem)] flex-col gap-2" aria-live="polite">
        {toasts.map((x) => (
          <div key={x.id} className="card pointer-events-auto flex animate-fade-in items-start gap-3 p-3.5 text-[13px] shadow-pop">
            {x.kind === 'error' ? <XCircle size={16} className="mt-0.5 shrink-0 text-danger" /> : x.kind === 'ok' ? <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-ok" /> : <Info size={16} className="mt-0.5 shrink-0 text-info" />}
            <span className="flex-1 break-words leading-relaxed">{x.text}</span>
            <button onClick={() => setToasts((y) => y.filter((z) => z.id !== x.id))} className="text-subtle hover:text-fg" aria-label={t('common.dismiss')}>
              <X size={13} />
            </button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}
