import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api, dash, type AiFix, type AiVerdict, type Finding, type ReviewStatus, type Severity } from '../api';
import { useFetch } from '../hooks/useFetch';
import {
  Card,
  ConfidencePill,
  EmptyState,
  ErrorBox,
  LoadingSpinner,
  Mono,
  PageHeader,
  SeverityBadge,
  SEVERITY_ORDER,
} from '../components/ui';

const CONFIDENCE_RANK: Record<string, number> = { high: 0, medium: 1, low: 2 };
const OWASP_OPTIONS = ['M1', 'M2', 'M3', 'M4', 'M5', 'M6', 'M7', 'M8', 'M9', 'M10'];

const REVIEW_META: { value: ReviewStatus; label: string; pill: string }[] = [
  { value: 'confirmed', label: 'Confirmed', pill: 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800' },
  { value: 'rejected', label: 'Rejected', pill: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950 dark:text-red-300 dark:border-red-800' },
  { value: 'accepted_risk', label: 'Accepted risk', pill: 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800' },
  { value: 'needs_review', label: 'Needs review', pill: 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-800' },
];

function ReviewPill({ status }: { status: string | null | undefined }) {
  const meta = REVIEW_META.find((r) => r.value === status);
  if (!meta)
    return (
      <span className="inline-flex items-center rounded-full border border-slate-300 bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
        Needs triage
      </span>
    );
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${meta.pill}`}>
      {meta.label}
    </span>
  );
}

function copyText(text: string, done: (msg: string) => void) {
  const finish = () => done('Copied to clipboard');
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).then(finish, () => done('Copy failed'));
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      finish();
    } catch {
      done('Copy failed');
    }
    document.body.removeChild(ta);
  }
}

function CodeViewer({ snippet, lineStart }: { snippet: string; lineStart: number | null }) {
  const lines = snippet.replace(/\n$/, '').split('\n');
  return (
    <pre className="slim-scroll overflow-x-auto rounded-xl border border-black/[0.06] bg-black/[0.02] p-0 text-[12.5px] leading-6 dark:border-white/[0.08] dark:bg-black">
      <code className="block min-w-max">
        {lines.map((ln, i) => (
          <span key={i} className="flex hover:bg-slate-100 dark:hover:bg-slate-800/60">
            {lineStart !== null && (
              <span className="w-14 shrink-0 select-none border-r border-slate-200 pr-3 text-right text-slate-400 dark:border-slate-700 dark:text-slate-600">
                {lineStart + i}
              </span>
            )}
            <span className="whitespace-pre px-4 font-mono text-slate-800 dark:text-slate-200">{ln || ' '}</span>
          </span>
        ))}
      </code>
    </pre>
  );
}

function FindingDetail({
  finding,
  onReviewed,
  notify,
}: {
  finding: Finding;
  onReviewed: (f: Finding) => void;
  notify: (msg: string) => void;
}) {
  const { scanId } = useParams<{ scanId: string }>();
  const [note, setNote] = useState(finding.review_note ?? '');
  const [saving, setSaving] = useState<ReviewStatus | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [aiBusy, setAiBusy] = useState<'verify' | 'fix' | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const lastVerify = [...(finding.provenance ?? [])].reverse().find((p) => p.action === 'verify');
  const lastFix = [...(finding.provenance ?? [])].reverse().find((p) => p.action === 'fix');
  const [verdict, setVerdict] = useState<AiVerdict | null>(
    lastVerify && typeof lastVerify.verdict === 'string'
      ? { verdict: lastVerify.verdict as AiVerdict['verdict'], reasoning: String(lastVerify.reasoning ?? ''), model: String(lastVerify.model ?? '') }
      : null,
  );
  const [aiFix, setAiFix] = useState<AiFix | null>(
    lastFix && typeof lastFix.fixed_code === 'string'
      ? { fixed_code: String(lastFix.fixed_code ?? ''), explanation: String(lastFix.explanation ?? ''), caveats: String(lastFix.caveats ?? ''), model: String(lastFix.model ?? '') }
      : null,
  );

  const setReview = async (status: ReviewStatus) => {
    if (!scanId || saving) return;
    setSaving(status);
    setSaveError(null);
    try {
      const updated = await api.updateFinding(scanId, finding.finding_id, { review_status: status, note });
      onReviewed(updated);
      notify(`Marked as ${REVIEW_META.find((r) => r.value === status)?.label ?? status}`);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Failed to save review');
    } finally {
      setSaving(null);
    }
  };

  const evidenceText = [
    finding.file_path ? `File: ${finding.file_path}` : null,
    finding.line_start !== null && finding.line_start !== undefined
      ? `Lines: ${finding.line_start}${finding.line_end ? `-${finding.line_end}` : ''}`
      : null,
    finding.snippet ?? null,
  ]
    .filter((x) => x !== null)
    .join('\n');

  const field = (label: string, value: string | null | undefined) =>
    value ? (
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</p>
        <p className="mt-1 whitespace-pre-wrap text-sm leading-relaxed text-slate-800 dark:text-slate-200">{value}</p>
      </div>
    ) : null;

  return (
    <div className="border-t border-slate-200 bg-slate-50/60 px-5 py-5 dark:border-slate-800 dark:bg-slate-900/60">
      <div className="grid gap-6 lg:grid-cols-2">
        <div className="space-y-4">
          {field('Description', finding.description)}
          {field('Security impact', finding.impact)}
          {field('Remediation', finding.remediation)}
        </div>
        <div className="space-y-4">
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Evidence</p>
              {evidenceText && (
                <button
                  onClick={() => copyText(evidenceText, notify)}
                  className="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs font-medium text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
                >
                  Copy evidence
                </button>
              )}
            </div>
            {(finding.file_path || finding.line_start !== null) && (
              <p className="mb-1.5 font-mono text-xs text-slate-600 dark:text-slate-400">
                {dash(finding.file_path)}
                {finding.line_start !== null && finding.line_start !== undefined
                  ? `:${finding.line_start}${finding.line_end ? `-${finding.line_end}` : ''}`
                  : ''}
              </p>
            )}
            {finding.snippet ? (
              <CodeViewer snippet={finding.snippet} lineStart={finding.line_start} />
            ) : (
              <p className="text-sm text-slate-500 dark:text-slate-400">
                No source snippet - see the artifact reference above.
              </p>
            )}
          </div>

          <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs">
            <span className="text-slate-500 dark:text-slate-400">
              Category: <span className="font-medium text-slate-700 dark:text-slate-300">{dash(finding.category)}</span>
            </span>
            <span className="text-slate-500 dark:text-slate-400">
              Rule: <Mono>{dash(finding.rule_id)}</Mono>
              {finding.rule_version ? <span className="text-slate-400"> v{finding.rule_version}</span> : null}
            </span>
            <span className="text-slate-500 dark:text-slate-400">
              Engine: <span className="font-medium text-slate-700 dark:text-slate-300">{dash(finding.engine)}</span>
            </span>
            <span className="text-slate-500 dark:text-slate-400">
              Validation: <span className="font-medium text-slate-700 dark:text-slate-300">{dash(finding.validation_status)}</span>
            </span>
          </div>

          <div className="flex flex-wrap gap-1.5">
            {(finding.owasp ?? []).map((o) => (
              <span key={o} className="rounded-md bg-violet-100 px-2 py-0.5 font-mono text-[11px] font-semibold text-violet-800 dark:bg-violet-950 dark:text-violet-300">
                {o}
              </span>
            ))}
            {(finding.cwe ?? []).map((c) => (
              <span key={c} className="rounded-md bg-slate-200 px-2 py-0.5 font-mono text-[11px] font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                {c}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Review controls */}
      <div className="mt-5 rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800/50">
        <div className="flex flex-wrap items-center gap-2">
          <p className="mr-1 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Assessor review</p>
          <ReviewPill status={finding.review_status} />
          <div className="ml-auto flex flex-wrap gap-2">
            {finding.remediation && (
              <button
                onClick={() => copyText(finding.remediation ?? '', notify)}
                className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-100 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-700"
              >
                Copy remediation
              </button>
            )}
            {REVIEW_META.map((r) => (
              <button
                key={r.value}
                onClick={() => setReview(r.value)}
                disabled={saving !== null}
                className={`rounded-lg border px-2.5 py-1.5 text-xs font-semibold disabled:opacity-40 ${r.pill}`}
              >
                {saving === r.value ? 'Saving…' : r.label}
              </button>
            ))}
          </div>
        </div>
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          rows={2}
          placeholder="Reviewer note - recorded with your decision (optional)"
          className="mt-3 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
        />
        {finding.review_note && finding.review_status && (
          <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
            Saved note: <span className="italic">{finding.review_note}</span>
          </p>
        )}
        {saveError && <p className="mt-2 text-xs font-medium text-red-600 dark:text-red-400">{saveError}</p>}
      </div>

      {/* On-demand AI */}
      <div className="mt-5 rounded-lg border border-violet-200 bg-violet-50/60 p-4 dark:border-violet-900 dark:bg-violet-950/40">
        <div className="flex flex-wrap items-center gap-2">
          <p className="mr-1 text-xs font-semibold uppercase tracking-wide text-violet-700 dark:text-violet-300">AI assistant</p>
          {verdict && (
            <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${
              verdict.verdict === 'true_positive'
                ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                : verdict.verdict === 'false_positive'
                  ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300'
                  : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
            }`}>
              {verdict.verdict === 'true_positive' ? 'AI: true positive'
                : verdict.verdict === 'false_positive' ? 'AI: false positive'
                  : 'AI: uncertain'}
            </span>
          )}
          <div className="ml-auto flex flex-wrap gap-2">
            <button
              onClick={async () => {
                if (!scanId || aiBusy) return;
                setAiBusy('verify'); setAiError(null);
                try {
                  const res = await api.aiVerify(scanId, finding.finding_id);
                  if (res.error) setAiError(res.error);
                  else {
                    if (res.ai_verdict) setVerdict(res.ai_verdict);
                    onReviewed(res);
                    notify('AI verification complete');
                  }
                } catch (e) {
                  setAiError(e instanceof Error ? e.message : 'AI verify failed');
                } finally { setAiBusy(null); }
              }}
              disabled={aiBusy !== null}
              className="rounded-lg border border-violet-300 bg-white px-2.5 py-1.5 text-xs font-semibold text-violet-700 hover:bg-violet-100 disabled:opacity-40 dark:border-violet-700 dark:bg-slate-800 dark:text-violet-300 dark:hover:bg-violet-900/50"
            >
              {aiBusy === 'verify' ? 'Verifying…' : 'AI verify'}
            </button>
            <button
              onClick={async () => {
                if (!scanId || aiBusy) return;
                setAiBusy('fix'); setAiError(null);
                try {
                  const res = await api.aiFix(scanId, finding.finding_id);
                  if (res.error) setAiError(res.error);
                  else {
                    if (res.ai_fix) setAiFix(res.ai_fix);
                    onReviewed(res);
                    notify('AI fix generated');
                  }
                } catch (e) {
                  setAiError(e instanceof Error ? e.message : 'AI fix failed');
                } finally { setAiBusy(null); }
              }}
              disabled={aiBusy !== null}
              className="rounded-lg border border-violet-300 bg-white px-2.5 py-1.5 text-xs font-semibold text-violet-700 hover:bg-violet-100 disabled:opacity-40 dark:border-violet-700 dark:bg-slate-800 dark:text-violet-300 dark:hover:bg-violet-900/50"
            >
              {aiBusy === 'fix' ? 'Writing fix…' : 'AI fix'}
            </button>
          </div>
        </div>
        <p className="mt-2 text-xs text-violet-600/80 dark:text-violet-300/70">
          Runs the On-device model on this finding only. Verify asks for a true/false-positive verdict; Fix writes a minimal secure code patch.
        </p>
        {verdict && (
          <div className="mt-3 rounded-md bg-white/70 p-3 text-sm dark:bg-slate-900/60">
            <p className="whitespace-pre-wrap leading-relaxed text-slate-800 dark:text-slate-200">{verdict.reasoning}</p>
            <p className="mt-1.5 font-mono text-[11px] text-slate-400">model: {verdict.model}</p>
          </div>
        )}
        {aiFix && (
          <div className="mt-3 space-y-2">
            <div className="rounded-md bg-slate-900 p-3">
              <div className="mb-1.5 flex items-center justify-between">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">Suggested fix</p>
                <button
                  onClick={() => copyText(aiFix.fixed_code, notify)}
                  className="rounded-md border border-slate-700 px-2 py-1 text-xs font-medium text-slate-300 hover:bg-slate-800"
                >
                  Copy fix
                </button>
              </div>
              <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-xs leading-relaxed text-slate-100">{aiFix.fixed_code}</pre>
            </div>
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-800 dark:text-slate-200">{aiFix.explanation}</p>
            {aiFix.caveats && (
              <p className="text-xs text-amber-700 dark:text-amber-300">Caveats: {aiFix.caveats}</p>
            )}
          </div>
        )}
        {aiError && <p className="mt-2 text-xs font-medium text-red-600 dark:text-red-400">{aiError}</p>}
      </div>
    </div>
  );
}

export default function FindingsPage() {
  const { scanId } = useParams<{ scanId: string }>();

  const [severitySel, setSeveritySel] = useState<Severity[]>([]);
  const [q, setQ] = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');
  const [owaspSel, setOwaspSel] = useState('all');
  const [engineSel, setEngineSel] = useState('all');
  const [confidenceSel, setConfidenceSel] = useState('all');
  const [reviewSel, setReviewSel] = useState('all');
  const [sortKey, setSortKey] = useState<'severity' | 'confidence'>('severity');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [overrides, setOverrides] = useState<Record<string, Finding>>({});
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    const id = window.setTimeout(() => setDebouncedQ(q.trim()), 400);
    return () => window.clearTimeout(id);
  }, [q]);

  useEffect(() => {
    if (!toast) return;
    const id = window.setTimeout(() => setToast(null), 2500);
    return () => window.clearTimeout(id);
  }, [toast]);

  const serverOwasp = /^M\d{1,2}$/.test(owaspSel) ? owaspSel : undefined;

  const res = useFetch(
    () =>
      api.listFindings(scanId ?? '', {
        severity: severitySel,
        q: debouncedQ || undefined,
        owasp: serverOwasp,
        engine: engineSel === 'all' ? undefined : engineSel,
      }),
    [scanId, severitySel, debouncedQ, serverOwasp, engineSel],
  );

  const engines = useMemo(() => {
    const set = new Set<string>();
    for (const f of res.data?.findings ?? []) if (f.engine) set.add(f.engine);
    return Array.from(set).sort();
  }, [res.data]);

  const confidences = useMemo(() => {
    const set = new Set<string>();
    for (const f of res.data?.findings ?? []) if (f.confidence) set.add(f.confidence);
    return Array.from(set).sort();
  }, [res.data]);

  const visible = useMemo(() => {
    const merged = (res.data?.findings ?? []).map((f) => overrides[f.finding_id] ?? f);
    const filtered = merged.filter((f) => {
      if (confidenceSel !== 'all' && (f.confidence ?? '').toLowerCase() !== confidenceSel.toLowerCase()) return false;
      if (reviewSel === 'triage' && f.review_status) return false;
      if (reviewSel !== 'all' && reviewSel !== 'triage' && f.review_status !== reviewSel) return false;
      if (owaspSel === 'unmapped' && (f.owasp ?? []).length > 0) return false;
      return true;
    });
    const rank = (f: Finding) => CONFIDENCE_RANK[(f.confidence ?? '').toLowerCase()] ?? 99;
    filtered.sort((a, b) => {
      if (sortKey === 'severity') {
        const d = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
        return d !== 0 ? d : rank(a) - rank(b);
      }
      const d = rank(a) - rank(b);
      return d !== 0 ? d : SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    });
    return filtered;
  }, [res.data, overrides, confidenceSel, reviewSel, owaspSel, sortKey]);

  const toggleSeverity = (s: Severity) =>
    setSeveritySel((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]));

  const toggleExpanded = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const onReviewed = (f: Finding) => setOverrides((prev) => ({ ...prev, [f.finding_id]: f }));

  const activeFilterCount =
    severitySel.length +
    (debouncedQ ? 1 : 0) +
    (owaspSel !== 'all' ? 1 : 0) +
    (engineSel !== 'all' ? 1 : 0) +
    (confidenceSel !== 'all' ? 1 : 0) +
    (reviewSel !== 'all' ? 1 : 0);

  const resetFilters = () => {
    setSeveritySel([]);
    setQ('');
    setOwaspSel('all');
    setEngineSel('all');
    setConfidenceSel('all');
    setReviewSel('all');
  };

  return (
    <div>
      <PageHeader
        title="Findings explorer"
        subtitle={
          res.data
            ? `Showing ${visible.length} of ${res.data.total} findings`
            : 'Search and filter assessment findings.'
        }
        actions={
          <div className="flex items-center gap-3">
            <Link
              to={`/scans/${scanId}/ai-findings`}
              className="inline-flex items-center justify-center rounded-full border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 transition-all duration-150 hover:bg-slate-100 active:scale-[0.98] dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800"
            >
              AI findings
            </Link>
            <label className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
            Sort by
            <select
              value={sortKey}
              onChange={(e) => setSortKey(e.target.value as 'severity' | 'confidence')}
              className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-slate-800 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            >
              <option value="severity">Severity</option>
              <option value="confidence">Confidence</option>
            </select>
          </label>
          </div>
        }
      />

      {/* Filters */}
      <Card className="mb-5">
        <div className="space-y-4 p-5">
          <div>
            <input
              type="text"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search title, file path, rule ID, or code snippet…"
              className="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Severity</span>
            {SEVERITY_ORDER.map((s) => {
              const on = severitySel.includes(s);
              return (
                <button
                  key={s}
                  onClick={() => toggleSeverity(s)}
                  className={`rounded-full border px-3 py-1 text-xs font-semibold capitalize transition-colors ${
                    on
                      ? 'border-transparent bg-[#0071e3] text-white dark:bg-[#2997ff]'
                      : 'border-black/[0.1] bg-white text-[#424245] hover:bg-black/[0.04] dark:border-white/[0.12] dark:bg-white/[0.04] dark:text-[#aeaeb2] dark:hover:bg-white/[0.08]'
                  }`}
                >
                  {s}
                </button>
              );
            })}
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <label className="block">
              <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">OWASP</span>
              <select
                value={owaspSel}
                onChange={(e) => setOwaspSel(e.target.value)}
                className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-sm text-slate-800 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
              >
                <option value="all">All</option>
                {OWASP_OPTIONS.map((o) => (
                  <option key={o} value={o}>{o}</option>
                ))}
                <option value="unmapped">Unmapped</option>
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Engine</span>
              <select
                value={engineSel}
                onChange={(e) => setEngineSel(e.target.value)}
                className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-sm text-slate-800 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
              >
                <option value="all">All</option>
                {engines.map((e) => (
                  <option key={e} value={e}>{e}</option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Confidence</span>
              <select
                value={confidenceSel}
                onChange={(e) => setConfidenceSel(e.target.value)}
                className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-sm capitalize text-slate-800 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
              >
                <option value="all">All</option>
                {confidences.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Review status</span>
              <select
                value={reviewSel}
                onChange={(e) => setReviewSel(e.target.value)}
                className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-2 text-sm text-slate-800 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
              >
                <option value="all">All</option>
                <option value="triage">Needs triage</option>
                <option value="confirmed">Confirmed</option>
                <option value="rejected">Rejected</option>
                <option value="accepted_risk">Accepted risk</option>
                <option value="needs_review">Needs review</option>
              </select>
            </label>
          </div>
          {activeFilterCount > 0 && (
            <button onClick={resetFilters} className="text-xs font-semibold text-slate-600 underline hover:text-slate-900 dark:text-slate-300 dark:hover:text-white">
              Clear all filters ({activeFilterCount})
            </button>
          )}
        </div>
      </Card>

      {toast && (
        <div className="fixed bottom-6 right-6 z-30 rounded-full bg-[#1d1d1f]/90 px-5 py-2.5 text-[14px] font-medium text-white shadow-[0_4px_16px_rgba(0,0,0,0.18)] backdrop-blur dark:bg-white/90 dark:text-black">
          {toast}
        </div>
      )}

      {res.loading && <LoadingSpinner label="Loading findings…" />}
      {res.error && <ErrorBox message={res.error} onRetry={res.retry} />}
      {res.data && visible.length === 0 && (
        <EmptyState
          title="No findings match"
          hint={activeFilterCount > 0 ? 'Try widening or clearing the filters.' : 'This scan reported no findings.'}
        />
      )}

      {res.data && visible.length > 0 && (
        <div className="space-y-3">
          {visible.map((f) => {
            const open = expanded.has(f.finding_id);
            return (
              <Card key={f.finding_id} className="overflow-hidden">
                <button
                  onClick={() => toggleExpanded(f.finding_id)}
                  className="flex w-full items-center gap-3.5 px-6 py-4 text-left transition-colors duration-150 hover:bg-black/[0.02] dark:hover:bg-white/[0.03]"
                >
                  <svg
                    className={`h-4 w-4 shrink-0 text-[#aeaeb2] transition-transform duration-200 ${open ? 'rotate-90' : ''}`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={2}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                  </svg>
                  <SeverityBadge severity={f.severity} size="sm" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[15px] font-medium text-[#1d1d1f] dark:text-white">{f.title}</p>
                    <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[13px] text-[#6e6e73] dark:text-[#98989f]">
                      {f.rule_id && <Mono className="text-slate-500 dark:text-slate-400">{f.rule_id}</Mono>}
                      {f.category && <span>{f.category}</span>}
                      {f.file_path && <Mono className="truncate text-slate-500 dark:text-slate-400">{f.file_path}</Mono>}
                    </p>
                  </div>
                  <div className="hidden shrink-0 items-center gap-2 sm:flex">
                    <ConfidencePill confidence={f.confidence} />
                    <ReviewPill status={f.review_status} />
                  </div>
                </button>
                {open && (
                  <FindingDetail finding={f} onReviewed={onReviewed} notify={setToast} />
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
