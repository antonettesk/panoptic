import type {
  AppSettings,
  EnvCheck,
  ExportFormat,
  HistoryEntry,
  ProcessAction,
  Progress,
  ScanOptions,
  ScanReport,
  ScheduleConfig,
  ScheduleStatus,
  Suppressions,
  SystemInfo,
} from './types';
import { mockBackend } from './mock';

/** True inside the Tauri webview; false in a plain browser (demo mode). */
export const isTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri) return mockBackend<T>(cmd, args);
  const { invoke } = await import('@tauri-apps/api/core');
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    throw new Error(typeof e === 'string' ? e : e instanceof Error ? e.message : JSON.stringify(e));
  }
}

export const api = {
  systemInfo: () => call<SystemInfo>('get_system_info'),
  scan: (options: ScanOptions) => call<ScanReport>('scan_system', { options }),
  cancelScan: () => call<boolean>('cancel_scan'),
  processAction: (action: ProcessAction, pid: number, startTime: number) => {
    const cmd = action === 'terminate' ? 'terminate_process' : action === 'suspend' ? 'suspend_process' : 'resume_process';
    return call<void>(cmd, { pid, startTime: startTime || null });
  },
  exportReport: (path: string, format: ExportFormat, scanId?: string) => call<string>('export_report', { path, format, scanId: scanId ?? null }),
  exportAsff: (path: string, scanId?: string) => call<string[]>('export_asff', { path, scanId: scanId ?? null, minSeverity: 'low' }),
  history: () => call<HistoryEntry[]>('get_history'),
  loadReport: (scanId: string) => call<ScanReport>('load_report', { scanId }),
  deleteReport: (scanId: string) => call<void>('delete_report', { scanId }),
  saveBaseline: () => call<number>('save_baseline'),
  clearBaseline: () => call<void>('clear_baseline'),
  getSuppressions: () => call<Suppressions>('get_suppressions'),
  setSuppressions: (suppressions: Suppressions) => call<void>('set_suppressions', { suppressions }),
  setFindingSuppressed: (findingId: string, suppressed: boolean) => call<ScanReport>('set_finding_suppressed', { findingId, suppressed }),
  relaunchAsAdmin: () => call<void>('relaunch_as_admin'),
  getSettings: () => call<{ settings: AppSettings; warning: string | null }>('get_settings'),
  saveSettings: (settings: AppSettings) => call<AppSettings>('save_settings', { settings }),
  environmentChecks: () => call<EnvCheck[]>('environment_checks'),
  scheduleStatus: () => call<ScheduleStatus>('schedule_status'),
  setSchedule: (config: ScheduleConfig) => call<ScheduleStatus>('set_schedule', { config }),
};

export async function onProgress(cb: (p: Progress) => void): Promise<() => void> {
  if (!isTauri) {
    const handler = (e: Event) => cb((e as CustomEvent<Progress>).detail);
    window.addEventListener('panoptic-mock-progress', handler);
    return () => window.removeEventListener('panoptic-mock-progress', handler);
  }
  const { listen } = await import('@tauri-apps/api/event');
  return listen<Progress>('scan-progress', (e) => cb(e.payload));
}

/** Ask the user where to save; returns null if they cancel. */
export async function pickSavePath(defaultName: string, ext: string, label: string): Promise<string | null> {
  if (!isTauri) return `~/Downloads/${defaultName}`;
  const { save } = await import('@tauri-apps/plugin-dialog');
  return save({ defaultPath: defaultName, filters: [{ name: label, extensions: [ext] }] });
}
