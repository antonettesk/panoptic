import { describe, expect, it } from 'vitest';
import en from './locales/en';
import { CATALOGS, LANGUAGES, resolveLanguage, translate } from './index';

const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

describe('i18n catalogs', () => {
  const keys = Object.keys(en);

  it('every language listed has a catalog and vice versa', () => {
    expect(LANGUAGES.map((l) => l.code).sort()).toEqual(Object.keys(CATALOGS).sort());
  });

  for (const lang of LANGUAGES.map((l) => l.code)) {
    it(`${lang} is complete, non-empty and keeps placeholders`, () => {
      const cat = CATALOGS[lang] as Record<string, string>;
      const missing = keys.filter((k) => !cat[k]?.trim());
      expect(missing, `missing in ${lang}`).toEqual([]);
      const extra = Object.keys(cat).filter((k) => !(k in en));
      expect(extra, `unknown keys in ${lang}`).toEqual([]);
      for (const k of keys) {
        expect(placeholders(cat[k]), `${lang}:${k}`).toEqual(placeholders((en as Record<string, string>)[k]));
      }
    });
  }

  it('resolves regional tags', () => {
    expect(resolveLanguage('pt-PT')).toBe('pt-BR');
    expect(resolveLanguage('zh-TW')).toBe('zh-CN');
    expect(resolveLanguage('es-MX')).toBe('es');
    expect(resolveLanguage('xx')).toBe('en');
    expect(resolveLanguage(undefined)).toBe('en');
  });

  it('interpolates and falls back', () => {
    expect(translate('de', 'scan.complete', { score: 42 })).toContain('42/100');
    expect(translate('ar', 'nav.findings')).toBe('النتائج');
    expect(translate('nope', 'nav.findings')).toBe('Findings');
  });
});
