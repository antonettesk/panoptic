import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from 'react';
import en, { type MessageKey, type Messages } from './locales/en';
import es from './locales/es';
import fr from './locales/fr';
import de from './locales/de';
import ptBR from './locales/pt-BR';
import ja from './locales/ja';
import zhCN from './locales/zh-CN';
import ar from './locales/ar';
import hi from './locales/hi';

export type { MessageKey };

export interface Language {
  code: string;
  /** Name in its own language, so people can always find theirs. */
  native: string;
  english: string;
  dir: 'ltr' | 'rtl';
}

export const LANGUAGES: Language[] = [
  { code: 'en', native: 'English', english: 'English', dir: 'ltr' },
  { code: 'es', native: 'Español', english: 'Spanish', dir: 'ltr' },
  { code: 'fr', native: 'Français', english: 'French', dir: 'ltr' },
  { code: 'de', native: 'Deutsch', english: 'German', dir: 'ltr' },
  { code: 'pt-BR', native: 'Português (Brasil)', english: 'Portuguese (Brazil)', dir: 'ltr' },
  { code: 'ja', native: '日本語', english: 'Japanese', dir: 'ltr' },
  { code: 'zh-CN', native: '简体中文', english: 'Chinese (Simplified)', dir: 'ltr' },
  { code: 'ar', native: 'العربية', english: 'Arabic', dir: 'rtl' },
  { code: 'hi', native: 'हिन्दी', english: 'Hindi', dir: 'ltr' },
];

export const CATALOGS: Record<string, Partial<Messages>> = { en, es, fr, de, 'pt-BR': ptBR, ja, 'zh-CN': zhCN, ar, hi };

/** Best supported match for a BCP-47 tag (`pt-PT` → `pt-BR`, `zh-TW` → `zh-CN`). */
export function resolveLanguage(tag: string | undefined | null): string {
  if (!tag) return 'en';
  if (CATALOGS[tag]) return tag;
  const base = tag.toLowerCase().split('-')[0];
  return LANGUAGES.find((l) => l.code.toLowerCase().split('-')[0] === base)?.code ?? 'en';
}

export function detectLanguage(): string {
  const prefs = typeof navigator !== 'undefined' ? [...(navigator.languages ?? []), navigator.language] : [];
  for (const p of prefs) {
    const r = resolveLanguage(p);
    if (r !== 'en' || p?.toLowerCase().startsWith('en')) return r;
  }
  return 'en';
}

export function translate(lang: string, key: MessageKey, vars?: Record<string, string | number>): string {
  const raw = CATALOGS[lang]?.[key] ?? en[key] ?? key;
  if (!vars) return raw;
  return raw.replace(/\{(\w+)\}/g, (_, k) => (vars[k] !== undefined ? String(vars[k]) : `{${k}}`));
}

interface I18n {
  lang: string;
  dir: 'ltr' | 'rtl';
  t: (key: MessageKey, vars?: Record<string, string | number>) => string;
  formatDate: (epochSecs: number | null | undefined, style?: 'short' | 'long') => string;
  formatNumber: (n: number, opts?: Intl.NumberFormatOptions) => string;
  formatRelative: (epochSecs: number) => string;
}

const Ctx = createContext<I18n | null>(null);

export function I18nProvider({ lang, children }: { lang: string; children: ReactNode }) {
  const code = resolveLanguage(lang);
  const dir = LANGUAGES.find((l) => l.code === code)?.dir ?? 'ltr';

  useEffect(() => {
    document.documentElement.lang = code;
    document.documentElement.dir = dir;
  }, [code, dir]);

  const t = useCallback((key: MessageKey, vars?: Record<string, string | number>) => translate(code, key, vars), [code]);
  const value = useMemo<I18n>(() => {
    const dateFmt = { short: new Intl.DateTimeFormat(code, { dateStyle: 'medium', timeStyle: 'short' }), long: new Intl.DateTimeFormat(code, { dateStyle: 'full', timeStyle: 'medium' }) };
    const rel = new Intl.RelativeTimeFormat(code, { numeric: 'auto' });
    return {
      lang: code,
      dir,
      t,
      formatDate: (s, style = 'short') => (s ? dateFmt[style].format(new Date(s * 1000)) : '—'),
      formatNumber: (n, opts) => new Intl.NumberFormat(code, opts).format(n),
      formatRelative: (s) => {
        const d = s - Date.now() / 1000;
        const abs = Math.abs(d);
        if (abs < 60) return rel.format(Math.round(d), 'second');
        if (abs < 3600) return rel.format(Math.round(d / 60), 'minute');
        if (abs < 86400) return rel.format(Math.round(d / 3600), 'hour');
        return rel.format(Math.round(d / 86400), 'day');
      },
    };
  }, [code, dir, t]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useI18n(): I18n {
  const v = useContext(Ctx);
  if (!v) throw new Error('useI18n must be used inside I18nProvider');
  return v;
}
