import { Fragment, useEffect, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api, formatElapsed, type ScanDetail, type StageInfo } from '../api';
import { useScanEvents, type ProgressEventData } from '../hooks/useScanEvents';
import { Card, CardHeader, DestructiveButton, ErrorBox, LoadingSpinner, PageHeader, StatusPill } from '../components/ui';

type StageKind = 'completed' | 'running' | 'failed' | 'skipped' | 'pending';

interface FeedEntry {
  id: number;
  t: number;
  text: string;
  hot?: boolean;
}

// "AI reviewed 5/12: Foo.java - 5 finding(s) accepted so far" -> 5
function aiAcceptedCount(text: string): number | null {
  const m = text.match(/(\d+)\s*finding\(s\)\s*accepted/i);
  return m ? parseInt(m[1], 10) : null;
}

function stageKind(status: string): StageKind {
  const s = status.toLowerCase();
  if (['completed', 'done', 'success', 'passed'].includes(s)) return 'completed';
  if (['running', 'in_progress', 'active'].includes(s)) return 'running';
  if (['failed', 'error'].includes(s)) return 'failed';
  if (['skipped', 'cancelled', 'canceled'].includes(s)) return 'skipped';
  return 'pending';
}

const STAGE_DISPLAY: Record<string, string> = {
  mobsfscan: 'MobSFScan',
};

function stageLabel(name: string): string {
  return STAGE_DISPLAY[name] ?? name.replace(/_/g, ' ');
}

function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '-';
  return `${(ms / 1000).toFixed(1)}s`;
}

/** Status disc for a pipeline node. The running node breathes quietly -
    one calm animation, in the Apple spirit of restraint. */
function StageDisc({ kind, index }: { kind: StageKind; index: number }) {
  if (kind === 'running') {
    return (
      <span className="relative flex h-10 w-10 items-center justify-center">
        <span className="animate-breathe relative flex h-10 w-10 items-center justify-center rounded-full bg-[#0071e3] text-white">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
        </span>
      </span>
    );
  }
  if (kind === 'completed') {
    return (
      <span className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500 text-white shadow-[0_0_14px_rgba(16,185,129,0.4)]">
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
      </span>
    );
  }
  if (kind === 'failed') {
    return (
      <span className="flex h-10 w-10 items-center justify-center rounded-full bg-red-500 text-white shadow-[0_0_14px_rgba(239,68,68,0.4)]">
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </span>
    );
  }
  if (kind === 'skipped') {
    return (
      <span className="flex h-10 w-10 items-center justify-center rounded-full bg-amber-400 text-white">
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14" />
        </svg>
      </span>
    );
  }
  return (
    <span className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-200 text-xs font-bold text-slate-500 dark:bg-slate-700 dark:text-slate-400">
      {index + 1}
    </span>
  );
}

function StageConnector({ state }: { state: 'full' | 'active' | 'idle' }) {
  return (
    <div className="relative mt-5 h-0.5 w-6 shrink-0 overflow-hidden rounded-full bg-black/[0.08] dark:bg-white/[0.1] sm:w-10">
      {state === 'full' && (
        <div className="absolute inset-0 bg-[#30a46c]" />
      )}
      {state === 'active' && (
        <div className="animate-indeterminate absolute inset-y-0 rounded-full bg-[#0071e3]/70" />
      )}
    </div>
  );
}

export default function LiveScanPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  const [detail, setDetail] = useState<ScanDetail | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [live, setLive] = useState<ProgressEventData | null>(null);
  const [streamError, setStreamError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [tick, setTick] = useState(0);
  const [feed, setFeed] = useState<FeedEntry[]>([]);
  const mountedAt = useRef(Date.now());
  const feedId = useRef(0);
  const feedScrollRef = useRef<HTMLDivElement>(null);
  // Tracks the highest AI "accepted" count seen so far; a higher count means
  // the AI just found something new - those entries get highlighted.
  const maxAccepted = useRef(0);

  const markHot = (text: string): boolean => {
    const n = aiAcceptedCount(text);
    if (n === null) return false;
    const hot = n > maxAccepted.current;
    if (n > maxAccepted.current) maxAccepted.current = n;
    return hot;
  };

  const fetchDetail = async () => {
    if (!scanId) return;
    try {
      const d = await api.getScan(scanId);
      setDetail(d);
      const terminal = ['completed', 'failed', 'cancelled', 'canceled'];
      if (terminal.includes(d.status.toLowerCase())) {
        navigate(`/scans/${scanId}`, { replace: true });
      }
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : 'Failed to load scan');
    }
  };

  useEffect(() => {
    fetchDetail();
    // Backfill the feed from the persisted scan log: navigating away and back
    // mid-scan used to wipe the feed. Oldest entries first, cap at 30.
    if (scanId) {
      api.getScanLog(scanId).then((log) => {
        const entries: FeedEntry[] = (log.events || []).map((e) => ({
          id: feedId.current++,
          t: e.ts ? new Date(e.ts).getTime() : Date.now(),
          text: e.message,
          hot: markHot(e.message),
        }));
        setFeed(entries.slice(-30));
      }).catch(() => {});
    }
    const id = window.setInterval(() => setTick(Math.floor((Date.now() - mountedAt.current) / 1000)), 1000);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  useScanEvents(scanId, {
    onProgress: (d) => {
      setLive(d);
      if (d.message) {
        const text = d.message;
        setFeed((prev) => {
          if (prev.length > 0 && prev[prev.length - 1].text === text) return prev;
          const next = [...prev, { id: feedId.current++, t: Date.now(), text, hot: markHot(text) }];
          return next.slice(-30);
        });
      }
      // Refresh stage list + warnings; events are server-paced so this is cheap.
      fetchDetail().catch(() => {});
    },
    onDone: () => {
      if (scanId) navigate(`/scans/${scanId}`, { replace: true });
    },
    onError: (d) => setStreamError(d.message),
  });

  // Auto-scroll the feed to the bottom on new entries, unless the user has
  // scrolled up to read earlier output.
  useEffect(() => {
    const el = feedScrollRef.current;
    if (!el) return;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 120) {
      el.scrollTop = el.scrollHeight;
    }
  }, [feed]);

  const cancelScan = async () => {
    if (!scanId || cancelling) return;
    if (!window.confirm('Cancel this scan? Partial results will be kept.')) return;
    setCancelling(true);
    try {
      await api.cancelScan(scanId);
      navigate(`/scans/${scanId}`, { replace: true });
    } catch (e) {
      setStreamError(e instanceof Error ? e.message : 'Failed to cancel scan');
      setCancelling(false);
    }
  };

  if (loadError && !detail) {
    return (
      <div>
        <PageHeader title="Live scan" />
        <ErrorBox message={loadError} onRetry={fetchDetail} />
      </div>
    );
  }

  if (!detail) {
    return (
      <div>
        <PageHeader title="Live scan" />
        <LoadingSpinner label="Connecting to scan…" />
      </div>
    );
  }

  const percent = live?.percent ?? detail.progress.percent;
  const stages: StageInfo[] = detail.progress.stages ?? [];
  const activeIdx = stages.findIndex((s) => stageKind(s.status) === 'running');
  const stageName =
    live?.stage ?? (activeIdx >= 0 ? stages[activeIdx].name : null) ?? detail.progress.stage;
  const liveMessage =
    live?.message ?? (detail.progress as { message?: string | null }).message ?? null;
  const checksRun = live?.checks_run ?? detail.progress.checks_run ?? 0;
  const findingsSoFar = live?.findings_so_far ?? detail.progress.findings_so_far ?? 0;
  const baseElapsed = live?.elapsed_s ?? detail.progress.elapsed_s ?? 0;
  const elapsed = Math.max(baseElapsed, tick);
  const completedCount = stages.filter((s) => stageKind(s.status) === 'completed').length;
  const anyRunning = activeIdx >= 0;
  const percentText =
    percent === null || percent === undefined ? 'working…' : `${Math.round(percent)}%`;
  const errors = detail.errors ?? [];

  return (
    <div className="flex flex-col gap-4 lg:h-[calc(100vh-10rem)] lg:overflow-hidden">
      {/* Row 1 - compact header */}
      <div className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-2">
        <div className="min-w-0">
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-50">
            Scan in progress
          </h1>
          <p
            className="truncate font-mono text-xs text-slate-500 dark:text-slate-400"
            title={detail.metadata.package_name ?? detail.scan_id}
          >
            {detail.metadata.package_name ?? `Scan ${detail.scan_id}`}
          </p>
        </div>
        <StatusPill status={detail.status} />
        <span className="inline-flex items-center gap-1.5 font-mono text-sm text-slate-600 dark:text-slate-300">
          <svg
            className="h-4 w-4 text-slate-400 dark:text-slate-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          {formatElapsed(elapsed)}
        </span>
        <div className="ml-auto">
          <DestructiveButton onClick={cancelScan} disabled={cancelling}>
            {cancelling ? 'Cancelling…' : 'Cancel scan'}
          </DestructiveButton>
        </div>
      </div>

      {streamError && (
        <div className="shrink-0 rounded-xl border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950/50 dark:text-red-300">
          Scan stream reported an error: {streamError}
        </div>
      )}

      {/* Row 2 - horizontal pipeline stepper */}
      <Card className="shrink-0 p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <p className="text-xs font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400">
            Pipeline
          </p>
          <p className="font-mono text-xs text-slate-500 dark:text-slate-400">
            {stages.length > 0 ? `${completedCount} of ${stages.length} complete` : 'starting…'}
          </p>
        </div>
        {stages.length === 0 ? (
          <p className="py-2 text-center text-sm text-slate-500 dark:text-slate-400">
            No stage information yet - the pipeline is starting.
          </p>
        ) : (
          <div className="slim-scroll overflow-x-auto pb-1">
            <div className="flex min-w-max items-start">
              {stages.map((s, i) => {
                const kind = stageKind(s.status);
                const connState =
                  kind === 'completed' ? 'full' : kind === 'running' ? 'active' : 'idle';
                const isActive = i === activeIdx;
                return (
                  <Fragment key={`${s.name}-${i}`}>
                    <div className="flex w-20 shrink-0 flex-col items-center gap-1.5">
                      <StageDisc kind={kind} index={i} />
                      <p
                        className={`w-full truncate text-center text-[11px] font-medium ${
                          isActive
                            ? 'text-[#0071e3] dark:text-[#2997ff]'
                            : 'text-[#424245] dark:text-[#aeaeb2]'
                        }`}
                        title={stageLabel(s.name)}
                      >
                        {stageLabel(s.name)}
                      </p>
                      <p className="font-mono text-[10px] text-slate-400 dark:text-slate-500">
                        {formatDuration(s.duration_ms)}
                      </p>
                    </div>
                    {i < stages.length - 1 && <StageConnector state={connState} />}
                  </Fragment>
                );
              })}
            </div>
          </div>
        )}
        {anyRunning && (
          <div className="relative mt-3 h-1 overflow-hidden rounded-full bg-black/[0.06] dark:bg-white/[0.08]">
            <div className="animate-shimmer absolute inset-y-0 w-1/3 bg-gradient-to-r from-transparent via-[#0071e3]/50 to-transparent" />
          </div>
        )}
      </Card>

      {/* Row 3 - now happening + behind the scenes */}
      <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-5">
        {/* Left: now happening */}
        <Card className="flex min-h-0 min-w-0 flex-col overflow-hidden lg:col-span-3">
          <CardHeader
            title="Now happening"
            subtitle="Live engine status"
            action={
              <span className="inline-flex items-center gap-2">
                <span className="animate-breathe h-2.5 w-2.5 rounded-full bg-[#0071e3]" />
                <span className="font-mono text-sm text-slate-600 dark:text-slate-300">
                  {percentText}
                </span>
              </span>
            }
          />
          <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-hidden p-4">
            <div className="min-w-0">
              <p className="truncate text-base font-bold text-slate-900 dark:text-slate-100" title={stageName ?? undefined}>
                {stageName ? stageLabel(stageName) : 'Starting…'}
              </p>
              {liveMessage && (
                <p
                  className="mt-1 truncate text-sm text-slate-500 dark:text-slate-400"
                  title={liveMessage}
                >
                  {liveMessage}
                </p>
              )}
            </div>
            <div className="relative h-2.5 shrink-0 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
              {percent === null || percent === undefined ? (
                <div className="animate-indeterminate h-full rounded-full bg-blue-500" />
              ) : (
                <>
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-500"
                    style={{ width: `${Math.min(100, Math.max(0, percent))}%` }}
                  />
                  <div className="animate-shimmer pointer-events-none absolute inset-y-0 w-1/2 bg-gradient-to-r from-transparent via-white/30 to-transparent" />
                </>
              )}
            </div>
            <div className="grid shrink-0 grid-cols-3 gap-3 text-center">
              <div className="rounded-lg bg-slate-50 px-3 py-2 dark:bg-slate-800/60">
                <p className="text-lg font-bold text-slate-900 dark:text-slate-100">{checksRun}</p>
                <p className="text-xs text-slate-500 dark:text-slate-400">checks run</p>
              </div>
              <div className="rounded-lg bg-slate-50 px-3 py-2 dark:bg-slate-800/60">
                <p className="text-lg font-bold text-slate-900 dark:text-slate-100">{findingsSoFar}</p>
                <p className="text-xs text-slate-500 dark:text-slate-400">findings so far</p>
              </div>
              <div className="rounded-lg bg-slate-50 px-3 py-2 dark:bg-slate-800/60">
                <p className="font-mono text-lg font-bold text-slate-900 dark:text-slate-100">
                  {formatElapsed(elapsed)}
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">elapsed</p>
              </div>
            </div>
            {errors.length > 0 && (
              <details className="shrink-0 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2 dark:border-amber-900 dark:bg-amber-950/40">
                <summary className="cursor-pointer list-none text-xs font-semibold uppercase tracking-wide text-amber-700 dark:text-amber-300">
                  Warnings & errors ({errors.length})
                </summary>
                <ul className="slim-scroll mt-1.5 max-h-20 space-y-1 overflow-y-auto">
                  {errors.map((e, i) => (
                    <li key={i} className="text-xs text-amber-800 dark:text-amber-300">
                      {e}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        </Card>

        {/* Right: behind the scenes */}
        <Card className="flex min-h-0 min-w-0 flex-col overflow-hidden lg:col-span-2">
          <CardHeader
            title="Behind the scenes"
            subtitle="Real-time engine activity"
            action={
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" title="Live" />
            }
          />
          <div
            ref={feedScrollRef}
            className="slim-scroll max-h-80 min-h-0 flex-1 space-y-1.5 overflow-y-auto p-5 font-mono text-xs leading-relaxed lg:max-h-none"
          >
            {feed.length === 0 ? (
              <p className="font-sans text-sm text-slate-500 dark:text-slate-400">
                Waiting for the engine to report in…
              </p>
            ) : (
              feed.map((f) => (
                <div
                  key={f.id}
                  className={
                    f.hot
                      ? 'animate-feed-in -mx-2 flex gap-2 rounded-lg bg-emerald-500/10 px-2 py-1 font-semibold text-emerald-700 dark:text-emerald-300'
                      : 'animate-feed-in flex gap-2 text-slate-600 dark:text-slate-300'
                  }
                >
                  <span className="shrink-0 text-slate-400 dark:text-slate-500">
                    {new Date(f.t).toLocaleTimeString()}
                  </span>
                  <span className="break-words">{f.text}</span>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
