import { api } from '../api';
import { useFetch } from '../hooks/useFetch';
import { Card, CardHeader, ErrorBox, LoadingSpinner, Mono, PageHeader } from '../components/ui';

const TOOL_INFO: { key: string; name: string; role: string; install: string }[] = [
  { key: 'jadx', name: 'JADX', role: 'Decompiles DEX to Java/Kotlin source for code review.', install: 'Download a release from github.com/skylot/jadx and put jadx on your PATH.' },
  { key: 'apktool', name: 'Apktool', role: 'Decodes the manifest, resources, and smali.', install: 'See apktool.org/docs/install - requires Java.' },
  { key: 'mobsfscan', name: 'MobSFScan', role: 'Established mobile static-analysis rule set.', install: 'pip install mobsfscan' },
  { key: 'androguard', name: 'Androguard', role: 'APK parsing, metadata, and manifest analysis.', install: 'pip install androguard' },
];

function StatusBadge({ ok }: { ok: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
        ok
          ? 'border-emerald-300 bg-emerald-100 text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
          : 'border-slate-300 bg-slate-100 text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400'
      }`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${ok ? 'bg-emerald-500' : 'bg-slate-400'}`} />
      {ok ? 'Available' : 'Missing'}
    </span>
  );
}

export default function SystemPage() {
  const sys = useFetch(() => api.systemStatus(), []);
  const data = sys.data;

  return (
    <div>
      <PageHeader title="System status" subtitle="Tool readiness, resource limits, and local AI setup." />

      {sys.loading && <LoadingSpinner label="Checking system status…" />}
      {sys.error && <ErrorBox message={sys.error} onRetry={sys.retry} />}

      {data && (
        <>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {TOOL_INFO.map((t) => {
              const ok = Boolean((data.tools as unknown as Record<string, unknown>)[t.key]);
              return (
                <Card key={t.key}>
                  <div className="p-5">
                    <div className="flex items-center justify-between gap-3">
                      <h3 className="font-mono text-sm font-bold text-slate-900 dark:text-slate-100">{t.name}</h3>
                      <StatusBadge ok={ok} />
                    </div>
                    <p className="mt-2 text-sm leading-relaxed text-slate-600 dark:text-slate-300">{t.role}</p>
                    {!ok && (
                      <p className="mt-2 rounded-xl bg-black/[0.03] px-3.5 py-2.5 text-[13px] leading-relaxed text-[#424245] dark:bg-white/[0.04] dark:text-[#aeaeb2]">
                        {t.install}
                      </p>
                    )}
                  </div>
                </Card>
              );
            })}

            {/* Ollama */}
            <Card>
              <div className="p-5">
                <div className="flex items-center justify-between gap-3">
                  <h3 className="font-mono text-sm font-bold text-slate-900 dark:text-slate-100">Ollama</h3>
                  <StatusBadge ok={data.tools.ollama.available} />
                </div>
                <p className="mt-2 text-sm leading-relaxed text-slate-600 dark:text-slate-300">
                  Local AI code review. Never required, never a cloud fallback.
                </p>
                {data.tools.ollama.available ? (
                  data.tools.ollama.models.length > 0 ? (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {data.tools.ollama.models.map((m) => (
                        <Mono key={m} className="rounded bg-slate-100 px-2 py-0.5 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                          {m}
                        </Mono>
                      ))}
                    </div>
                  ) : (
                    <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                      Ollama is running but no models are installed.
                    </p>
                  )
                ) : (
                  <p className="mt-2 rounded-xl bg-black/[0.03] px-3.5 py-2.5 text-[13px] leading-relaxed text-[#424245] dark:bg-white/[0.04] dark:text-[#aeaeb2]">
                    Install from ollama.com, then pull a code-capable model.
                  </p>
                )}
              </div>
            </Card>
          </div>

          {/* Limits */}
          <Card className="mt-6">
            <CardHeader title="Resource limits" subtitle="Configured on the backend; enforced per scan." />
            <div className="grid grid-cols-1 gap-4 p-5 sm:grid-cols-3">
              <div className="rounded-2xl bg-black/[0.02] px-5 py-4 dark:bg-white/[0.03]">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Max upload</p>
                <p className="mt-1 font-mono text-lg font-bold text-slate-900 dark:text-slate-100">{data.limits.max_upload_mb} MB</p>
              </div>
              <div className="rounded-2xl bg-black/[0.02] px-5 py-4 dark:bg-white/[0.03]">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Max extraction</p>
                <p className="mt-1 font-mono text-lg font-bold text-slate-900 dark:text-slate-100">{data.limits.max_extract_mb} MB</p>
              </div>
              <div className="rounded-2xl bg-black/[0.02] px-5 py-4 dark:bg-white/[0.03]">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Scan timeout</p>
                <p className="mt-1 font-mono text-lg font-bold text-slate-900 dark:text-slate-100">{data.limits.scan_timeout_s}s</p>
              </div>
            </div>
          </Card>

          {/* Model setup */}
          <Card className="mt-6">
            <CardHeader title="Local model setup" subtitle="Optional - scans run fully without AI review." />
            <div className="space-y-4 p-5 text-sm leading-relaxed text-slate-600 dark:text-slate-300">
              <p>
                Blindspot uses <Mono>Ollama</Mono> running on this machine. No model is ever downloaded silently, and
                there is no cloud AI fallback - if Ollama is unavailable the scan simply continues with deterministic
                analysis only.
              </p>
              <div>
                <p className="font-semibold text-slate-800 dark:text-slate-100">1. Install Ollama</p>
                <p className="mt-1">
                  Download from <Mono>ollama.com</Mono> and start the service (it listens on localhost by default).
                </p>
              </div>
              <div>
                <p className="font-semibold text-slate-800 dark:text-slate-100">2. Pull a code-capable model</p>
                <pre className="slim-scroll mt-1.5 overflow-x-auto rounded-xl border border-black/[0.06] bg-black/[0.02] p-3.5 font-mono text-[13px] text-[#1d1d1f] dark:border-white/[0.08] dark:bg-black dark:text-[#f5f5f7]">
                  ollama pull qwen2.5-coder:7b
                </pre>
                <p className="mt-1.5">
                  A quantized 3B–7B code model is a good starting point. Roughly: 3B needs ~4&nbsp;GB RAM, 7B needs
                  ~8&nbsp;GB RAM. Larger models improve review quality but slow the scan.
                </p>
              </div>
              <div>
                <p className="font-semibold text-slate-800 dark:text-slate-100">3. Select it in Blindspot</p>
                <p className="mt-1">
                  Enter the model name (e.g. <Mono>qwen2.5-coder:7b</Mono>) in the scan configuration on the upload
                  screen, or leave it blank to use the backend default.
                </p>
              </div>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
