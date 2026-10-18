import { Link, Navigate, useParams } from 'react-router-dom';
import { api, dash, formatElapsed, type Finding, type ScanDetail, type SeverityCounts } from '../api';
import { useFetch } from '../hooks/useFetch';
import {
  Card,
  CardHeader,
  EmptyState,
  ErrorBox,
  LoadingSpinner,
  Mono,
  PageHeader,
  SeverityBadge,
  SEVERITY_ORDER,
  StatusPill,
} from '../components/ui';

const OWASP_CATEGORIES: { code: string; name: string }[] = [
  { code: 'M1', name: 'Improper Credential Usage' },
  { code: 'M2', name: 'Inadequate Supply Chain Security' },
  { code: 'M3', name: 'Insecure Authentication/Authorization' },
  { code: 'M4', name: 'Insufficient Input/Output Validation' },
  { code: 'M5', name: 'Insecure Communication' },
  { code: 'M6', name: 'Inadequate Privacy Controls' },
  { code: 'M7', name: 'Insufficient Binary Protections' },
  { code: 'M8', name: 'Security Misconfiguration' },
  { code: 'M9', name: 'Insecure Data Storage' },
  { code: 'M10', name: 'Insufficient Cryptography' },
];

function owaspCode(entry: string): string | null {
  const m = entry.match(/^(M\d{1,2})\b/);
  return m ? m[1] : null;
}

function distribution(findings: Finding[]): Map<string, number> {
  const map = new Map<string, number>();
  for (const f of findings) {
    for (const o of f.owasp ?? []) {
      const code = owaspCode(o);
      if (code) map.set(code, (map.get(code) ?? 0) + 1);
    }
  }
  return map;
}

const countCardStyles: Record<keyof SeverityCounts, string> = {
  critical: 'bg-[#ffe9e7]/50 dark:bg-[#ff8a8e]/[0.06]',
  high: 'bg-[#ffefe2]/50 dark:bg-[#ffb37a]/[0.06]',
  medium: 'bg-[#fff4dd]/50 dark:bg-[#ffd37a]/[0.06]',
  low: 'bg-[#e5f1ff]/50 dark:bg-[#7cc0ff]/[0.06]',
  informational: '',
};

const countTextStyles: Record<keyof SeverityCounts, string> = {
  critical: 'text-[#b3261e] dark:text-[#ff8a8e]',
  high: 'text-[#b3541e] dark:text-[#ffb37a]',
  medium: 'text-[#8a5a00] dark:text-[#ffd37a]',
  low: 'text-[#0b57d0] dark:text-[#7cc0ff]',
  informational: 'text-[#6e6e73] dark:text-[#98989f]',
};

function MetaRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2">
      <dt className="shrink-0 text-sm text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="min-w-0 text-right text-sm font-medium text-slate-900 dark:text-slate-100">
        {mono ? (
          <Mono className="break-all text-slate-900 dark:text-slate-100" >{value}</Mono>
        ) : (
          value
        )}
      </dd>
    </div>
  );
}

export default function OverviewPage() {
  const { scanId } = useParams<{ scanId: string }>();

  const scan = useFetch(() => api.getScan(scanId ?? ''), [scanId]);
  const findings = useFetch(() => api.listFindings(scanId ?? ''), [scanId]);
  const scanLog = useFetch(() => api.getScanLog(scanId ?? ''), [scanId]);
  const sysStatus = useFetch(() => api.systemStatus(), []);

  if (scan.loading) {
    return (
      <div>
        <PageHeader title="Assessment overview" />
        <LoadingSpinner label="Loading assessment…" />
      </div>
    );
  }
  if (scan.error || !scan.data) {
    return (
      <div>
        <PageHeader title="Assessment overview" />
        <ErrorBox message={scan.error ?? 'Scan not found'} onRetry={scan.retry} />
      </div>
    );
  }

  const d: ScanDetail = scan.data;
  // A running scan has no finished overview - send the user to the live view.
  if (d.status === 'running') {
    return <Navigate to={`/scans/${scanId}/live`} replace />;
  }
  const m = d.metadata;
  const dist = findings.data ? distribution(findings.data.findings) : new Map<string, number>();
  const maxDist = Math.max(1, ...Array.from(dist.values()));
  const total = SEVERITY_ORDER.reduce((a, s) => a + (d.counts[s] ?? 0), 0);
  const stages = d.progress.stages ?? [];
  const completedStages = stages.filter((s) => ['completed', 'done', 'success', 'passed'].includes(s.status.toLowerCase())).length;

  const exports = (
    <>
      <a
        href={api.reportUrl(d.scan_id, 'html')}
        className="inline-flex items-center justify-center rounded-full bg-black/[0.05] px-5 py-2.5 text-[15px] font-medium text-[#1d1d1f] transition-all duration-150 hover:bg-black/[0.08] active:scale-[0.98] dark:bg-white/[0.1] dark:text-white dark:hover:bg-white/[0.14]"
      >
        HTML report
      </a>
      {sysStatus.data?.pdf && !sysStatus.data.pdf.available ? (
        <span
          title={sysStatus.data.pdf.hint}
          className="inline-flex cursor-not-allowed items-center justify-center rounded-full bg-black/[0.03] px-5 py-2.5 text-[15px] font-medium text-[#aeaeb2] dark:bg-white/[0.04]"
        >
          PDF report (unavailable)
        </span>
      ) : (
        <a
          href={api.reportUrl(d.scan_id, 'pdf')}
          className="inline-flex items-center justify-center rounded-full bg-black/[0.05] px-5 py-2.5 text-[15px] font-medium text-[#1d1d1f] transition-all duration-150 hover:bg-black/[0.08] active:scale-[0.98] dark:bg-white/[0.1] dark:text-white dark:hover:bg-white/[0.14]"
        >
          PDF report
        </a>
      )}
      <a
        href={api.reportUrl(d.scan_id, 'json')}
        className="inline-flex items-center justify-center rounded-full bg-black/[0.05] px-5 py-2.5 text-[15px] font-medium text-[#1d1d1f] transition-all duration-150 hover:bg-black/[0.08] active:scale-[0.98] dark:bg-white/[0.1] dark:text-white dark:hover:bg-white/[0.14]"
      >
        JSON
      </a>
    </>
  );
  const pdfHint = sysStatus.data?.pdf && !sysStatus.data.pdf.available ? sysStatus.data.pdf.hint : null;

  return (
    <div>
      <PageHeader
        title={m.app_name || m.package_name || 'Assessment overview'}
        subtitle={m.package_name ? `${m.package_name}${m.version_name ? ` · v${m.version_name}` : ''}` : `Scan ${d.scan_id}`}
        actions={
          <>
            <StatusPill status={d.status} />
            <Link
              to={`/scans/${d.scan_id}/findings`}
              className="inline-flex items-center justify-center rounded-full bg-[#0071e3] px-5 py-2.5 text-[15px] font-medium text-white shadow-[0_1px_2px_rgba(0,0,0,0.12)] transition-all duration-150 hover:bg-[#0077ed] active:scale-[0.98]"
            >
              View findings
            </Link>
            <Link
              to={`/scans/${d.scan_id}/ai-findings`}
              className="inline-flex items-center justify-center rounded-full border border-slate-300 px-5 py-2.5 text-[15px] font-medium text-slate-700 transition-all duration-150 hover:bg-slate-100 active:scale-[0.98] dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800"
            >
              AI findings
            </Link>
            {exports}
          </>
        }
      />

      {/* Severity counts */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        {SEVERITY_ORDER.map((s) => (
          <Card key={s} className={countCardStyles[s]}>
            <div className="px-5 py-4">
              <p className={`text-[34px] font-semibold tracking-tight ${countTextStyles[s]}`}>{d.counts[s] ?? 0}</p>
              <div className="mt-1.5">
                <SeverityBadge severity={s} size="sm" />
              </div>
            </div>
          </Card>
        ))}
        <Card>
          <div className="px-5 py-4">
            <p className="text-[34px] font-semibold tracking-tight text-[#1d1d1f] dark:text-white">{total}</p>
            <p className="mt-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              Total findings
            </p>
          </div>
        </Card>
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {/* Metadata */}
          <Card>
            <CardHeader title="Package metadata" subtitle="Extracted from the actual APK." />
            <dl className="divide-y divide-slate-100 px-5 py-2 dark:divide-slate-800">
              <MetaRow label="Package name" value={dash(m.package_name)} mono />
              <MetaRow label="Application name" value={dash(m.app_name)} />
              <MetaRow label="Version name" value={dash(m.version_name)} mono />
              <MetaRow label="Version code" value={dash(m.version_code)} mono />
              <MetaRow label="SHA-256" value={dash(m.sha256)} mono />
              <MetaRow label="Min SDK" value={dash(m.min_sdk)} mono />
              <MetaRow label="Target SDK" value={dash(m.target_sdk)} mono />
              <MetaRow label="Checks executed" value={String(d.progress.checks_run ?? 0)} mono />
              <MetaRow
                label="Stages completed"
                value={stages.length ? `${completedStages} of ${stages.length}` : '-'}
                mono
              />
              <MetaRow label="Elapsed" value={formatElapsed(d.progress.elapsed_s)} mono />
            </dl>
          </Card>

          {/* OWASP distribution */}
          <Card>
            <CardHeader
              title="OWASP Mobile Top 10 (2024) distribution"
              subtitle="Findings can map to more than one category."
            />
            <div className="space-y-3 p-5">
              {findings.loading && <LoadingSpinner label="Loading findings…" />}
              {findings.error && <ErrorBox message={findings.error} onRetry={findings.retry} />}
              {findings.data &&
                OWASP_CATEGORIES.map((c) => {
                  const n = dist.get(c.code) ?? 0;
                  return (
                    <div key={c.code} className="flex items-center gap-3">
                      <span className="w-10 shrink-0 font-mono text-xs font-bold text-slate-700 dark:text-slate-300">
                        {c.code}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-baseline justify-between gap-2">
                          <span className="truncate text-xs text-slate-600 dark:text-slate-400">{c.name}</span>
                          <span className="font-mono text-xs font-semibold text-slate-800 dark:text-slate-200">{n}</span>
                        </div>
                        <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
                          <div
                            className="h-full rounded-full bg-slate-600 dark:bg-slate-400"
                            style={{ width: `${(n / maxDist) * 100}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  );
                })}
            </div>
          </Card>

          {/* Limitations & errors */}
          <Card>
            <CardHeader title="Coverage, limitations & errors" subtitle="Read before trusting the result." />
            <div className="space-y-4 p-5">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  Limitations
                </p>
                {(d.limitations ?? []).length === 0 ? (
                  <p className="mt-1.5 text-sm text-slate-500 dark:text-slate-400">None reported.</p>
                ) : (
                  <ul className="mt-1.5 list-disc space-y-1 pl-5 text-sm text-slate-700 dark:text-slate-300">
                    {d.limitations.map((l, i) => (
                      <li key={i}>{l}</li>
                    ))}
                  </ul>
                )}
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  Tool errors
                </p>
                {(d.errors ?? []).length === 0 ? (
                  <p className="mt-1.5 text-sm text-slate-500 dark:text-slate-400">No tool errors reported.</p>
                ) : (
                  <ul className="mt-1.5 space-y-1.5">
                    {d.errors.map((e, i) => (
                      <li
                        key={i}
                        className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300"
                      >
                        {e}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              {pdfHint && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                    PDF export
                  </p>
                  <p className="mt-1.5 text-sm text-slate-600 dark:text-slate-300">{pdfHint}</p>
                </div>
              )}
            </div>
          </Card>

          {/* Scan log - what ran, what broke */}
          <Card>
            <CardHeader title="Scan log" subtitle="Timestamped engine activity - for troubleshooting." />
            <div className="p-5">
              {scanLog.loading ? (
                <p className="text-sm text-slate-500 dark:text-slate-400">Loading scan log…</p>
              ) : (scanLog.data?.events ?? []).length === 0 ? (
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  No log entries yet - the log fills in while the scan runs.
                </p>
              ) : (
                <ul className="max-h-80 space-y-1.5 overflow-y-auto font-mono text-xs leading-relaxed">
                  {(scanLog.data?.events ?? []).map((e, i) => (
                    <li key={i} className="flex gap-2">
                      <span className="shrink-0 text-slate-400 dark:text-slate-500">
                        {e.ts ? new Date(e.ts).toLocaleTimeString() : '-'}
                      </span>
                      <span
                        className={
                          e.level === 'error'
                            ? 'shrink-0 font-semibold text-red-500'
                            : e.level === 'warn'
                              ? 'shrink-0 font-semibold text-amber-500'
                              : 'shrink-0 text-slate-400 dark:text-slate-500'
                        }
                      >
                        [{e.source}]
                      </span>
                      <span className="break-words text-slate-600 dark:text-slate-300">{e.message}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Card>
        </div>

        <div className="space-y-6">
          {/* AI review status */}
          <Card>
            <CardHeader title="AI review" />
            <div className="p-5">
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500 dark:text-slate-400">Status</dt>
                  <dd className="font-medium capitalize text-slate-900 dark:text-slate-100">
                    {dash(d.ai?.status).replace(/_/g, ' ')}
                  </dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500 dark:text-slate-400">Model</dt>
                  <dd className="font-mono text-[13px] text-slate-900 dark:text-slate-100">{dash(d.ai?.model)}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500 dark:text-slate-400">Requested</dt>
                  <dd className="font-medium text-slate-900 dark:text-slate-100">
                    {d.scan_config ? (d.scan_config.enable_ai_review ? `yes (${d.scan_config.ai_model || 'auto'})` : 'no') : '-'}
                  </dd>
                </div>
              </dl>
              <p className="mt-3 text-xs leading-relaxed text-slate-500 dark:text-slate-400">
                AI findings are hypotheses until corroborated - they are never auto-confirmed. Review each one in the
                findings explorer.
              </p>
            </div>
          </Card>

          {/* Top findings preview */}
          <Card>
            <CardHeader
              title="Highest severity findings"
              action={
                <Link
                  to={`/scans/${d.scan_id}/findings`}
                  className="text-xs font-semibold text-slate-600 underline hover:text-slate-900 dark:text-slate-300 dark:hover:text-white"
                >
                  Open explorer
                </Link>
              }
            />
            <div className="p-5">
              {findings.loading && <LoadingSpinner label="Loading…" />}
              {findings.error && <p className="text-sm text-red-600 dark:text-red-400">{findings.error}</p>}
              {findings.data && findings.data.findings.length === 0 && (
                <EmptyState title="No findings" hint="The scan reported no findings." />
              )}
              {findings.data && findings.data.findings.length > 0 && (
                <ul className="space-y-2.5">
                  {[...findings.data.findings]
                    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
                    .slice(0, 5)
                    .map((f) => (
                      <li key={f.finding_id} className="flex items-start justify-between gap-3">
                        <Link
                          to={`/scans/${d.scan_id}/findings`}
                          className="min-w-0 text-sm font-medium text-slate-800 hover:underline dark:text-slate-200"
                        >
                          <span className="block truncate">{f.title}</span>
                          <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{f.rule_id ?? '-'}</span>
                        </Link>
                        <SeverityBadge severity={f.severity} size="sm" />
                      </li>
                    ))}
                </ul>
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
