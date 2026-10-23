import { describe, expect, it } from 'vitest';
import { filterFindings, formatBytes, isValidAccountId, isValidInstanceId, matchesQuery, mitreUrl, riskLevel, sortRows } from './util';
import type { Finding } from './types';

const f = (over: Partial<Finding>): Finding => ({
  id: 'x', category: 'persistence', severity: 'high', title: 't', description: '', evidence: [], pid: null, path: null,
  mitre: null, recommendation: '', suppressed: false, ...over,
});

describe('util', () => {
  it('formats bytes', () => {
    expect(formatBytes(0)).toBe('—');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(5 * 1024 ** 3)).toBe('5.0 GB');
  });

  it('matches multi-term queries across fields', () => {
    expect(matchesQuery('', 'a')).toBe(true);
    expect(matchesQuery('cron tmp', '/etc/cron.d/x', '/tmp/payload')).toBe(true);
    expect(matchesQuery('cron ssh', '/etc/cron.d/x')).toBe(false);
    expect(matchesQuery('1337', 'proc', 1337)).toBe(true);
  });

  it('filters findings', () => {
    const list = [f({ id: '1', severity: 'critical', title: 'ghost' }), f({ id: '2', severity: 'low' }), f({ id: '3', suppressed: true })];
    const base = { severities: new Set(['critical', 'high'] as const), category: 'all' as const, query: '', showSuppressed: false };
    expect(filterFindings(list, base).map((x) => x.id)).toEqual(['1']);
    expect(filterFindings(list, { ...base, showSuppressed: true }).map((x) => x.id)).toEqual(['1', '3']);
    expect(filterFindings(list, { ...base, query: 'ghost' }).map((x) => x.id)).toEqual(['1']);
  });

  it('maps risk levels', () => {
    expect(riskLevel(0).key).toBe('risk.clean');
    expect(riskLevel(45).key).toBe('risk.high');
    expect(riskLevel(75).key).toBe('risk.compromised');
  });

  it('sorts numerically and textually', () => {
    expect(sortRows([3, 10, 2], (x) => x, 'asc')).toEqual([2, 3, 10]);
    expect(sortRows(['b10', 'b9'], (x) => x, 'asc')).toEqual(['b9', 'b10']);
  });

  it('builds MITRE urls', () => {
    expect(mitreUrl('T1014')).toBe('https://attack.mitre.org/techniques/T1014/');
    expect(mitreUrl('T1574.006')).toBe('https://attack.mitre.org/techniques/T1574/006');
  });

  it('validates AWS identifiers like the backend', () => {
    expect(isValidAccountId('123456789012')).toBe(true);
    expect(isValidAccountId('12345')).toBe(false);
    expect(isValidInstanceId('')).toBe(true);
    expect(isValidInstanceId('i-0abc1234def567890')).toBe(true);
    expect(isValidInstanceId('abc')).toBe(false);
  });
});
