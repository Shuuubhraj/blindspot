import { useMemo, useState } from 'react';
import { api, dash } from '../api';
import { useFetch } from '../hooks/useFetch';
import { Card, EmptyState, ErrorBox, LoadingSpinner, Mono, PageHeader, SeverityBadge } from '../components/ui';

export default function RulesPage() {
  const rules = useFetch(() => api.listRules(), []);
  const [q, setQ] = useState('');
  const [category, setCategory] = useState('all');

  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const r of rules.data ?? []) if (r.category) set.add(r.category);
    return Array.from(set).sort();
  }, [rules.data]);

  const visible = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (rules.data ?? []).filter((r) => {
      if (category !== 'all' && r.category !== category) return false;
      if (!needle) return true;
      return (
        r.id.toLowerCase().includes(needle) ||
        r.title.toLowerCase().includes(needle) ||
        (r.description ?? '').toLowerCase().includes(needle)
      );
    });
  }, [rules.data, q, category]);

  return (
    <div>
      <PageHeader
        title="Rule library"
        subtitle={
          rules.data
            ? `${visible.length} of ${rules.data.length} security checks`
            : 'Every check the assessment engine can run.'
        }
      />

      <Card className="mb-5">
        <div className="flex flex-col gap-3 p-5 sm:flex-row">
          <input
            type="text"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by rule ID, title, or description…"
            className="flex-1 rounded-xl border border-black/[0.12] bg-white px-4 py-2.5 text-[14px] text-[#1d1d1f] placeholder:text-[#aeaeb2] transition-all duration-150 focus:border-[#0071e3] focus:outline-none focus:ring-4 focus:ring-[#0071e3]/15 dark:border-white/[0.16] dark:bg-[#1c1c1e] dark:text-white dark:focus:border-[#2997ff] dark:focus:ring-[#2997ff]/20"
          />
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="rounded-xl border border-black/[0.12] bg-white px-3.5 py-2.5 text-[14px] text-[#1d1d1f] transition-all duration-150 focus:border-[#0071e3] focus:outline-none focus:ring-4 focus:ring-[#0071e3]/15 dark:border-white/[0.16] dark:bg-[#1c1c1e] dark:text-white dark:focus:border-[#2997ff] dark:focus:ring-[#2997ff]/20 sm:w-56"
          >
            <option value="all">All categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>
      </Card>

      {rules.loading && <LoadingSpinner label="Loading rules…" />}
      {rules.error && <ErrorBox message={rules.error} onRetry={rules.retry} />}
      {rules.data && visible.length === 0 && (
        <EmptyState title="No rules match" hint="Try a different search or category." />
      )}

      {rules.data && visible.length > 0 && (
        <Card className="overflow-hidden">
          <div className="slim-scroll overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead>
                <tr className="border-b border-black/[0.06] text-[12px] font-medium text-[#6e6e73] dark:border-white/[0.08] dark:text-[#98989f]">
                  <th className="px-5 py-3 font-semibold">Rule ID</th>
                  <th className="px-5 py-3 font-semibold">Title</th>
                  <th className="px-5 py-3 font-semibold">Category</th>
                  <th className="px-5 py-3 font-semibold">Default severity</th>
                  <th className="px-5 py-3 font-semibold">OWASP</th>
                  <th className="px-5 py-3 font-semibold">Version</th>
                  <th className="px-5 py-3 font-semibold">Enabled</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {visible.map((r) => (
                  <tr key={r.id} className="align-top hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="whitespace-nowrap px-5 py-3.5">
                      <Mono className="font-semibold text-slate-800 dark:text-slate-200">{r.id}</Mono>
                    </td>
                    <td className="px-5 py-3.5">
                      <p className="font-medium text-slate-900 dark:text-slate-100">{r.title}</p>
                      {r.description && (
                        <p className="mt-1 max-w-xl text-xs leading-relaxed text-slate-500 dark:text-slate-400">
                          {r.description}
                        </p>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-5 py-3.5 text-slate-600 dark:text-slate-300">
                      {dash(r.category)}
                    </td>
                    <td className="px-5 py-3.5">
                      {r.default_severity ? <SeverityBadge severity={r.default_severity} size="sm" /> : <span className="text-slate-400">-</span>}
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="flex max-w-[220px] flex-wrap gap-1">
                        {(r.owasp ?? []).map((o) => (
                          <span key={o} className="rounded bg-violet-100 px-1.5 py-0.5 font-mono text-[11px] font-semibold text-violet-800 dark:bg-violet-950 dark:text-violet-300">
                            {o}
                          </span>
                        ))}
                        {(r.owasp ?? []).length === 0 && <span className="text-xs text-slate-400">-</span>}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-5 py-3.5 font-mono text-xs text-slate-600 dark:text-slate-300">
                      {dash(r.version)}
                    </td>
                    <td className="px-5 py-3.5">
                      <span
                        className={`inline-flex rounded-full px-2 py-0.5 text-[11px] font-semibold ${
                          r.enabled_by_default
                            ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                            : 'bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
                        }`}
                      >
                        {r.enabled_by_default ? 'Yes' : 'No'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
