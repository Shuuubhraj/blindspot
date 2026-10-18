import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, formatDateTime, type ScanSummary } from '../api';
import { useFetch } from '../hooks/useFetch';
import { Card, EmptyState, ErrorBox, LoadingSpinner, Mono, PageHeader, SEVERITY_ORDER, SeverityBadge, StatusPill } from '../components/ui';

export default function HistoryPage() {
  const scans = useFetch(() => api.listScans(), []);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const deleteScan = async (s: ScanSummary) => {
    const label = s.package_name ?? s.scan_id;
    if (!window.confirm(`Delete scan of ${label}? This removes all findings, evidence, and reports.`)) return;
    setDeleting(s.scan_id);
    setDeleteError(null);
    try {
      await api.deleteScan(s.scan_id);
      scans.retry();
    } catch (e) {
      setDeleteError(e instanceof Error ? e.message : 'Failed to delete scan');
    } finally {
      setDeleting(null);
    }
  };

  const sorted = [...(scans.data ?? [])].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  );

  return (
    <div>
      <PageHeader
        title="Scan history"
        subtitle="Prior assessments. Reopen a report, export it, or delete stored scan data."
        actions={
          <Link
            to="/"
            className="inline-flex items-center justify-center rounded-full bg-[#0071e3] px-5 py-2.5 text-[15px] font-medium text-white shadow-[0_1px_2px_rgba(0,0,0,0.12)] transition-all duration-150 hover:bg-[#0077ed] active:scale-[0.98]"
          >
            New scan
          </Link>
        }
      />

      {deleteError && (
        <div className="mb-4 rounded-xl border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950/50 dark:text-red-300">
          {deleteError}
        </div>
      )}

      {scans.loading && <LoadingSpinner label="Loading scan history…" />}
      {scans.error && <ErrorBox message={scans.error} onRetry={scans.retry} />}
      {scans.data && sorted.length === 0 && (
        <EmptyState title="No scans yet" hint="Upload an APK to run your first assessment." />
      )}

      {scans.data && sorted.length > 0 && (
        <Card className="overflow-hidden">
          <div className="slim-scroll overflow-x-auto">
            <table className="w-full min-w-[860px] text-left text-sm">
              <thead>
                <tr className="border-b border-black/[0.06] text-[12px] font-medium text-[#6e6e73] dark:border-white/[0.08] dark:text-[#98989f]">
                  <th className="px-6 py-3.5 font-medium">Package / app</th>
                  <th className="px-6 py-3.5 font-medium">Status</th>
                  <th className="px-6 py-3.5 font-medium">Findings</th>
                  <th className="px-6 py-3.5 font-medium">Created</th>
                  <th className="px-6 py-3.5 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-black/[0.05] dark:divide-white/[0.06]">
                {sorted.map((s) => (
                  <tr key={s.scan_id} className="transition-colors duration-150 hover:bg-black/[0.02] dark:hover:bg-white/[0.03]">
                    <td className="px-6 py-4">
                      <Link
                        to={`/scans/${s.scan_id}${s.status === 'running' ? '/live' : ''}`}
                        className="font-medium text-slate-900 hover:underline dark:text-slate-100"
                      >
                        {s.app_name || s.package_name || 'Unknown package'}
                      </Link>
                      {s.package_name && s.app_name && (
                        <p className="mt-0.5 font-mono text-xs text-slate-500 dark:text-slate-400">{s.package_name}</p>
                      )}
                      <p className="mt-0.5 font-mono text-[11px] text-slate-400 dark:text-slate-500">
                        {s.scan_id.slice(0, 8)}…
                      </p>
                    </td>
                    <td className="px-6 py-4">
                      <StatusPill status={s.status} />
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1">
                        {SEVERITY_ORDER.map((sev) => {
                          const n = s.counts?.[sev] ?? 0;
                          return n > 0 ? (
                            <span
                              key={sev}
                              title={`${sev}: ${n}`}
                              className="inline-flex items-center gap-1 rounded-full bg-black/[0.04] px-2 py-0.5 font-mono text-[11px] font-semibold text-[#424245] dark:bg-white/[0.06] dark:text-[#aeaeb2]"
                            >
                              <SeverityBadge severity={sev} size="sm" />
                              <span className="sr-only">{sev}</span>
                              {n}
                            </span>
                          ) : null;
                        })}
                        {SEVERITY_ORDER.every((sev) => (s.counts?.[sev] ?? 0) === 0) && (
                          <span className="text-xs text-slate-400">0</span>
                        )}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-5 py-3.5 text-slate-600 dark:text-slate-300">
                      {formatDateTime(s.created_at)}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Link
                          to={`/scans/${s.scan_id}${s.status === 'running' ? '/live' : ''}`}
                          className="rounded-full border border-black/[0.1] px-3.5 py-1.5 text-[13px] font-medium text-[#424245] transition-all duration-150 hover:bg-black/[0.04] dark:border-white/[0.12] dark:text-[#aeaeb2] dark:hover:bg-white/[0.06]"
                        >
                          {s.status === 'running' ? 'View live' : 'Open'}
                        </Link>
                        <Link
                          to={`/scans/${s.scan_id}/findings`}
                          className="rounded-full border border-black/[0.1] px-3.5 py-1.5 text-[13px] font-medium text-[#424245] transition-all duration-150 hover:bg-black/[0.04] dark:border-white/[0.12] dark:text-[#aeaeb2] dark:hover:bg-white/[0.06]"
                        >
                          Findings
                        </Link>
                        <a
                          href={api.reportUrl(s.scan_id, 'html')}
                          className="rounded-full border border-black/[0.1] px-3.5 py-1.5 text-[13px] font-medium text-[#424245] transition-all duration-150 hover:bg-black/[0.04] dark:border-white/[0.12] dark:text-[#aeaeb2] dark:hover:bg-white/[0.06]"
                        >
                          HTML
                        </a>
                        <a
                          href={api.reportUrl(s.scan_id, 'pdf')}
                          className="rounded-full border border-black/[0.1] px-3.5 py-1.5 text-[13px] font-medium text-[#424245] transition-all duration-150 hover:bg-black/[0.04] dark:border-white/[0.12] dark:text-[#aeaeb2] dark:hover:bg-white/[0.06]"
                        >
                          PDF
                        </a>
                        <a
                          href={api.reportUrl(s.scan_id, 'json')}
                          className="rounded-full border border-black/[0.1] px-3.5 py-1.5 text-[13px] font-medium text-[#424245] transition-all duration-150 hover:bg-black/[0.04] dark:border-white/[0.12] dark:text-[#aeaeb2] dark:hover:bg-white/[0.06]"
                        >
                          JSON
                        </a>
                        <button
                          onClick={() => deleteScan(s)}
                          disabled={deleting === s.scan_id}
                          className="rounded-full border border-[#d92d20]/25 px-3.5 py-1.5 text-[13px] font-medium text-[#b3261e] transition-all duration-150 hover:bg-[#d92d20]/[0.07] disabled:opacity-40 dark:border-[#ff8a8e]/25 dark:text-[#ff8a8e] dark:hover:bg-[#ff8a8e]/[0.08]"
                        >
                          {deleting === s.scan_id ? 'Deleting…' : 'Delete'}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <p className="mt-4 flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
        <Mono className="text-slate-500 dark:text-slate-400">scan_id</Mono> shown truncated; full IDs are used in URLs.
      </p>
    </div>
  );
}
