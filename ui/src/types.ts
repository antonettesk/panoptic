// Mirrors crates/panoptic-core/src/model.rs. Keep in sync.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export type Protocol = 'tcp' | 'tcp6' | 'udp' | 'udp6' | 'raw' | 'packet';

export type FindingCategory =
  | 'hidden-process'
  | 'process-anomaly'
  | 'hidden-socket'
  | 'suspicious-socket'
  | 'persistence'
  | 'hidden-module'
  | 'kernel-integrity'
  | 'loader-hijack'
  | 'baseline-drift';

export interface Visibility {
  api: boolean;
  syscall: boolean;
  brute_force: boolean;
}

export interface ProcessInfo {
  pid: number;
  ppid: number | null;
  name: string;
  path: string;
  cmdline: string;
  user: string | null;
  cpu_usage: number;
  memory_bytes: number;
  start_time: number;
  is_discrepant: boolean;
  visibility: Visibility;
  flags: string[];
  sha256: string | null;
}

export interface SocketInfo {
  local_address: string;
  local_port: number;
  remote_address: string;
  remote_port: number;
  protocol: Protocol;
  state: string;
  pid: number | null;
  process_name: string | null;
  suspicious: boolean;
  hidden: boolean;
  reasons: string[];
}

export interface PersistenceEntry {
  mechanism: string;
  location: string;
  target_path: string;
  command: string;
  risk_level: Severity;
  reasons: string[];
  modified: number | null;
}

export interface KernelModule {
  name: string;
  path: string | null;
  size: number;
  listed: boolean;
  corroborated: boolean;
  hidden: boolean;
  suspicious: boolean;
  reasons: string[];
}

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  evidence: string[];
  pid: number | null;
  path: string | null;
  mitre: string | null;
  recommendation: string;
  suppressed: boolean;
}

export interface HostInfo {
  hostname: string;
  os: string;
  os_version: string;
  kernel_version: string;
  arch: string;
  uptime_secs: number;
}

export interface ScanSummary {
  processes: number;
  hidden_processes: number;
  sockets: number;
  listening: number;
  hidden_sockets: number;
  persistence_entries: number;
  modules: number;
  hidden_modules: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  suppressed: number;
}

export interface StageStatus {
  stage: string;
  ok: boolean;
  duration_ms: number;
  message: string | null;
}

export interface ScanReport {
  scan_id: string;
  tool_version: string;
  started_at: number;
  duration_ms: number;
  engine: string;
  elevated: boolean;
  host: HostInfo;
  risk_score: number;
  summary: ScanSummary;
  findings: Finding[];
  processes: ProcessInfo[];
  sockets: SocketInfo[];
  persistence: PersistenceEntry[];
  modules: KernelModule[];
  stages: StageStatus[];
  cancelled: boolean;
}

export interface ScanOptions {
  brute_force_pids: boolean;
  port_probe: boolean;
  persistence: boolean;
  kernel_modules: boolean;
  hash_evidence: boolean;
  confirm_rounds: number;
}

export const DEFAULT_OPTIONS: ScanOptions = {
  brute_force_pids: true,
  port_probe: true,
  persistence: true,
  kernel_modules: true,
  hash_evidence: true,
  confirm_rounds: 3,
};

export interface Progress {
  stage: string;
  percent: number;
  message: string;
}

export interface SystemInfo {
  host: HostInfo;
  elevated: boolean;
  engine: string;
  version: string;
  platform: string;
  data_dir: string;
  has_baseline: boolean;
  baseline_created_at: number | null;
  scanning: boolean;
}

export interface HistoryEntry {
  scan_id: string;
  started_at: number;
  duration_ms: number;
  risk_score: number;
  elevated: boolean;
  cancelled: boolean;
  summary: ScanSummary;
}

export interface Suppressions {
  finding_ids: string[];
  path_patterns: string[];
}

export type ProcessAction = 'terminate' | 'suspend' | 'resume';
export type ExportFormat = 'json' | 'html' | 'csv' | 'txt';

export type Theme = 'system' | 'dark' | 'light';
export type Frequency = 'hourly' | 'daily' | 'weekly';

export interface ScheduleConfig {
  enabled: boolean;
  frequency: Frequency;
  time: string;
}

export interface ScheduleStatus {
  installed: boolean;
  detail: string;
}

export interface AsffTarget {
  account_id: string;
  region: string;
  instance_id: string | null;
}

export interface AppSettings {
  version: number;
  onboarding_completed: boolean;
  language: string;
  theme: Theme;
  scan_options: ScanOptions;
  auto_scan_on_launch: boolean;
  baseline_after_first_scan: boolean;
  aws: AsffTarget | null;
  schedule: ScheduleConfig;
}

export const DEFAULT_SETTINGS: AppSettings = {
  version: 1,
  onboarding_completed: false,
  language: 'en',
  theme: 'system',
  scan_options: DEFAULT_OPTIONS,
  auto_scan_on_launch: false,
  baseline_after_first_scan: true,
  aws: null,
  schedule: { enabled: false, frequency: 'daily', time: '09:00' },
};

export interface EnvCheck {
  id: 'elevation' | 'engine' | 'storage' | 'cli' | 'scheduler';
  ok: boolean;
  detail: string;
}

export const AWS_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'sa-east-1',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-central-2', 'eu-north-1', 'eu-south-1',
  'me-south-1', 'me-central-1', 'il-central-1', 'af-south-1',
  'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-east-1',
  'us-gov-west-1', 'us-gov-east-1', 'cn-north-1', 'cn-northwest-1',
];
