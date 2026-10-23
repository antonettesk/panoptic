import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { api } from './api';
import { detectLanguage } from './i18n';
import type { AppSettings, Theme } from './types';
import { DEFAULT_SETTINGS } from './types';

interface SettingsCtx {
  settings: AppSettings;
  loaded: boolean;
  /** Persisted, validated update. Rejects with a readable error. */
  update: (patch: Partial<AppSettings>) => Promise<AppSettings>;
  warning: string | null;
}

const Ctx = createContext<SettingsCtx | null>(null);

function resolveTheme(theme: Theme): 'dark' | 'light' {
  if (theme !== 'system') return theme;
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

export function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = resolveTheme(theme);
}

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<AppSettings>(() => ({ ...DEFAULT_SETTINGS, language: detectLanguage() }));
  const [loaded, setLoaded] = useState(false);
  const [warning, setWarning] = useState<string | null>(null);
  const latest = useRef(settings);
  latest.current = settings;

  useEffect(() => {
    api
      .getSettings()
      .then(({ settings: s, warning: w }) => {
        // First launch: adopt the OS language instead of the stored default.
        setSettings(s.onboarding_completed ? s : { ...s, language: detectLanguage() });
        setWarning(w);
      })
      .catch((e) => setWarning(String(e?.message ?? e)))
      .finally(() => setLoaded(true));
  }, []);

  useEffect(() => {
    applyTheme(settings.theme);
    if (settings.theme !== 'system') return;
    const mq = window.matchMedia?.('(prefers-color-scheme: light)');
    const onChange = () => applyTheme('system');
    mq?.addEventListener?.('change', onChange);
    return () => mq?.removeEventListener?.('change', onChange);
  }, [settings.theme]);

  const update = useCallback(async (patch: Partial<AppSettings>) => {
    const prev = latest.current;
    const next = { ...prev, ...patch };
    setSettings(next); // optimistic so toggles feel instant
    try {
      const saved = await api.saveSettings(next);
      setSettings(saved);
      return saved;
    } catch (e) {
      setSettings(prev); // backend rejected it: show the truth again
      throw e;
    }
  }, []);

  return <Ctx.Provider value={{ settings, loaded, update, warning }}>{children}</Ctx.Provider>;
}

export function useSettings(): SettingsCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error('useSettings must be used inside SettingsProvider');
  return v;
}
