import { useMemo } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api, type Finding } from '../api';
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
} from '../components/ui';

export function isAiFinding(f: Finding): boolean {
  if (f.engine === 'ai') return true;
  if (f.validation_status && f.validation_status.startsWith('ai-')) return true;
  try {
    const prov = (f as unknown as { provenance?: { engine?: string }[] }).provenance;
    if (Array.isArray(prov) && prov.some((p) => p.engine === 'ai')) return true;
  } catch {
    /* ignore */
  }
  return false;
}

function validationPill(status: string | null | undefined) {
  const s = (status ?? '').toLowerCase();
  if (s === 'ai-corroborated')
    return 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800';
  if (s === 'ai-evidence-supported')
    return 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-800';
  return 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800';
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </p>
      <div className="mt-1.5">{children}</div>
    </div>
  );
}

function AiFindingCard({ finding, index }: { finding: Finding; index: number }) {
  const location =
    finding.file_path +
    (finding.line_start !== null && finding.line_start !== undefined
      ? `:${finding.line_start}${finding.line_end ? `-${finding.line_end}` : ''}`
      : '');
  return (
    <Card className="overflow-hidden">
      <div className="border-b border-slate-200 bg-slate-50/70 px-5 py-4 dark:border-slate-800 dark:bg-slate-900/70">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-slate-400 dark:text-slate-500">{index + 1}</span>
          <SeverityBadge severity={finding.severity} size="sm" />
          <h3 className="text-[16px] font-semibold tracking-tight text-slate-900 dark:text-white">
            {finding.title}
          </h3>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <span
            className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${validationPill(finding.validation_status)}`}
          >
            {finding.validation_status ?? 'ai'}
          </span>
          <ConfidencePill confidence={finding.confidence} />
          {finding.owasp?.map((o) => (
            <span
              key={o}
              className="inline-flex items-center rounded-full bg-slate-200/70 px-2.5 py-0.5 text-xs font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-300"
            >
              {o}
            </span>
          ))}
          {finding.cwe?.map((c) => (
            <Mono key={c}>{c}</Mono>
          ))}
        </div>
      </div>
      <div className="space-y-5 px-5 py-5">
        {finding.description && (
          <Section label="The finding">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-800 dark:text-slate-200">
              {finding.description}
            </p>
          </Section>
        )}
        {(finding.file_path || finding.snippet) && (
          <Section label="Proof of concept">
            {finding.file_path && (
              <p className="mb-2 font-mono text-xs text-slate-600 dark:text-slate-400">{location}</p>
            )}
            {finding.snippet ? (
              <pre className="slim-scroll overflow-x-auto rounded-xl border border-slate-200 bg-slate-950 p-4 font-mono text-xs leading-relaxed text-slate-100 dark:border-slate-800">
                {finding.snippet}
              </pre>
            ) : (
              <p className="text-sm text-slate-500 dark:text-slate-400">
                No source snippet captured for this finding.
              </p>
            )}
          </Section>
        )}
        {finding.impact && (
          <Section label="Impact">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-800 dark:text-slate-200">
              {finding.impact}
            </p>
          </Section>
        )}
        {finding.remediation && (
          <Section label="Remediation">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-800 dark:text-slate-200">
              {finding.remediation}
            </p>
          </Section>
        )}
      </div>
    </Card>
  );
}

export default function AiFindings() {
  const { scanId } = useParams<{ scanId: string }>();
  const res = useFetch(() => api.listFindings(scanId ?? ''), [scanId]);
  const aiSummary = useFetch(() => api.getScan(scanId ?? ''), [scanId]);

  const aiFindings = useMemo(() => {
    if (!res.data) return [];
    return res.data.findings.filter(isAiFinding);
  }, [res.data]);

  const model = aiSummary.data?.ai?.model ?? null;

  return (
    <div>
      <PageHeader
        title="AI Findings"
        subtitle={
          model
            ? `Second opinion by ${model} - ${aiFindings.length} finding${aiFindings.length === 1 ? '' : 's'}`
            : 'Local AI second opinion for this scan.'
        }
        actions={
          <Link
            to={`/scans/${scanId}/findings`}
            className="inline-flex items-center justify-center rounded-full border border-slate-300 px-5 py-2.5 text-[15px] font-medium text-slate-700 transition-all duration-150 hover:bg-slate-100 active:scale-[0.98] dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800"
          >
            All findings
          </Link>
        }
      />

      <div className="mb-5 rounded-2xl border border-blue-200/70 bg-blue-50/70 px-5 py-4 text-sm leading-relaxed text-blue-900 dark:border-blue-900/50 dark:bg-blue-950/40 dark:text-blue-200">
        AI findings are <strong>hypotheses, never confirmed results</strong>. Every proposal is
        validated against real code locations before it is kept; findings the static engines
        independently confirm are marked <Mono>ai-corroborated</Mono>. AI output never overrides a
        static-engine result. Review each one manually before acting on it.
      </div>

      {res.loading && <LoadingSpinner label="Loading AI findings…" />}
      {res.error && <ErrorBox message={res.error} onRetry={res.retry} />}
      {res.data && aiFindings.length === 0 && (
        <EmptyState
          title="No AI findings"
          hint={
            ['completed', 'failed', 'cancelled'].includes(aiSummary.data?.ai?.status ?? '')
              ? 'The AI review ran but proposed no findings that survived validation for this scan.'
              : 'AI review was not run for this scan. Enable it in the scan configuration to get a local on-device second opinion.'
          }
        />
      )}
      {aiFindings.length > 0 && (
        <div className="space-y-5">
          {aiFindings.map((f, i) => (
            <AiFindingCard key={f.finding_id} finding={f} index={i} />
          ))}
        </div>
      )}
    </div>
  );
}
