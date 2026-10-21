/**
 * Typed client for the Blindspot backend API.
 * BASE is /api (proxied to http://localhost:8000 in dev). No invented endpoints.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface ScanSummary {
  scan_id: string;
  package_name: string | null;
  app_name: string | null;
  status: string;
  created_at: string;
  counts: SeverityCounts;
}

export interface StageInfo {
  name: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
}

export interface ScanProgress {
  stage: string | null;
  percent: number | null;
  stages: StageInfo[];
  checks_run: number;
  findings_so_far: number;
  elapsed_s: number;
}

export interface ScanMetadata {
  package_name: string | null;
  app_name: string | null;
  version_name: string | null;
  version_code: string | null;
  sha256: string | null;
  min_sdk: number | string | null;
  target_sdk: number | string | null;
}

export interface ScanDetail {
  scan_id: string;
  status: string;
  progress: ScanProgress;
  metadata: ScanMetadata;
  counts: SeverityCounts;
  limitations: string[];
  ai: { status: string; model: string | null };
  scan_config?: { enable_ai_review: boolean; ai_model: string; disabled_rules: string[] };
  errors: string[];
}

export interface Finding {
  finding_id: string;
  title: string;
  severity: Severity;
  confidence: string | null;
  validation_status: string | null;
  rule_id: string | null;
  category: string | null;
  owasp: string[];
  cwe: string[];
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  snippet: string | null;
  description: string | null;
  impact: string | null;
  remediation: string | null;
  engine: string | null;
  rule_version: string | null;
  review_status: string | null;
  review_note: string | null;
  provenance: Array<Record<string, unknown>> | null;
}

export interface FindingsResponse {
  findings: Finding[];
  total: number;
}

export interface AiVerdict {
  verdict: 'true_positive' | 'false_positive' | 'uncertain';
  reasoning: string;
  model: string;
}

export interface AiFix {
  fixed_code: string;
  explanation: string;
  caveats: string;
  model: string;
}

export interface RuleInfo {
  id: string;
  title: string;
  description: string | null;
  category: string | null;
  default_severity: Severity | null;
  owasp: string[];
  cwe: string[];
  enabled_by_default: boolean;
  version: string | null;
}

export interface OllamaStatus {
  available: boolean;
  models: string[];
}

export interface SystemStatus {
  tools: {
    jadx: boolean;
    apktool: boolean;
    mobsfscan: boolean;
    androguard: boolean;
    ollama: OllamaStatus;
  };
  pdf?: { available: boolean; hint: string };
  limits: {
    max_upload_mb: number;
    max_extract_mb: number;
    scan_timeout_s: number;
  };
}

export interface ScanEvent {
  ts: string | null;
  level: string;
  source: string;
  message: string;
}

export interface ScanConfig {
  enable_ai_review: boolean;
  ai_model: string | null;
  disabled_rules: string[];
}

export type ReviewStatus = 'confirmed' | 'rejected' | 'accepted_risk' | 'needs_review';

export interface FindingsQuery {
  severity?: Severity[];
  q?: string;
  owasp?: string;
  engine?: string;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function extractErrorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === 'object') {
    const b = body as Record<string, unknown>;
    if (typeof b.detail === 'string') return b.detail;
    if (typeof b.message === 'string') return b.message;
    if (typeof b.error === 'string') return b.error;
  }
  return fallback;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, init);
  } catch {
    throw new ApiError(0, 'Backend unreachable. Is the Blindspot API running at http://localhost:8000?');
  }
  if (!res.ok) {
    let msg = `Request failed (HTTP ${res.status})`;
    try {
      const body: unknown = await res.json();
      msg = extractErrorMessage(body, msg);
    } catch {
      /* keep fallback */
    }
    throw new ApiError(res.status, msg);
  }
  if (res.status === 204) return undefined as unknown as T;
  return (await res.json()) as T;
}

export const api = {
  systemStatus(): Promise<SystemStatus> {
    return request<SystemStatus>('/system/status');
  },

  /** Lightweight reachability probe - no Ollama ping, safe to poll often. */
  health(): Promise<{ status: string }> {
    return request<{ status: string }>('/health');
  },

  listScans(): Promise<ScanSummary[]> {
    return request<ScanSummary[]>('/scans');
  },

  getScan(scanId: string): Promise<ScanDetail> {
    return request<ScanDetail>(`/scans/${encodeURIComponent(scanId)}`);
  },

  createScan(file: File, config: ScanConfig): Promise<{ scan_id: string; status: string }> {
    const form = new FormData();
    form.append('file', file, file.name);
    form.append('config', JSON.stringify(config));
    return request<{ scan_id: string; status: string }>('/scans', { method: 'POST', body: form });
  },

  cancelScan(scanId: string): Promise<{ status: string }> {
    return request<{ status: string }>(`/scans/${encodeURIComponent(scanId)}/cancel`, { method: 'POST' });
  },

  deleteScan(scanId: string): Promise<Record<string, never>> {
    return request<Record<string, never>>(`/scans/${encodeURIComponent(scanId)}`, { method: 'DELETE' });
  },

  listFindings(scanId: string, q: FindingsQuery = {}): Promise<FindingsResponse> {
    const params = new URLSearchParams();
    for (const s of q.severity ?? []) params.append('severity', s);
    if (q.q) params.set('q', q.q);
    if (q.owasp) params.set('owasp', q.owasp);
    if (q.engine) params.set('engine', q.engine);
    const suffix = params.toString();
    return request<FindingsResponse>(
      `/scans/${encodeURIComponent(scanId)}/findings${suffix ? `?${suffix}` : ''}`,
    );
  },

  updateFinding(
    scanId: string,
    findingId: string,
    patch: { review_status: ReviewStatus; note: string },
  ): Promise<Finding> {
    return request<Finding>(`/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    });
  },

  aiVerify(
    scanId: string,
    findingId: string,
  ): Promise<Finding & { ai_verdict?: AiVerdict; error?: string }> {
    return request<Finding & { ai_verdict?: AiVerdict; error?: string }>(
      `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/ai-verify`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
    );
  },

  aiFix(
    scanId: string,
    findingId: string,
  ): Promise<Finding & { ai_fix?: AiFix; error?: string }> {
    return request<Finding & { ai_fix?: AiFix; error?: string }>(
      `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/ai-fix`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
    );
  },

  listRules(): Promise<RuleInfo[]> {
    return request<RuleInfo[]>('/rules');
  },

  reportUrl(scanId: string, kind: 'html' | 'pdf' | 'json'): string {
    return `/api/scans/${encodeURIComponent(scanId)}/report.${kind}`;
  },

  getScanLog(scanId: string): Promise<{ scan_id: string; events: ScanEvent[] }> {
    return request<{ scan_id: string; events: ScanEvent[] }>(
      `/scans/${encodeURIComponent(scanId)}/log`
    );
  },

  eventsUrl(scanId: string): string {
    return `/api/scans/${encodeURIComponent(scanId)}/events`;
  },
};

/** Render "-" for missing values (never invent data). */
export function dash(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === '') return '-';
  return String(value);
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '-';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

export function formatElapsed(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds) || totalSeconds < 0) return '-';
  const s = Math.floor(totalSeconds);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m ${sec}s`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}
