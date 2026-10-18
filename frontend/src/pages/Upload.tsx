import { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, formatBytes, type ScanConfig } from '../api';
import { useFetch } from '../hooks/useFetch';
import { Card, CardHeader, ErrorBox, LoadingSpinner, PageHeader, PrimaryButton, ToolDot } from '../components/ui';

export default function UploadPage() {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [file, setFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [enableAI, setEnableAI] = useState(true);
  const [aiModel, setAiModel] = useState('');
  const [disabledRulesCsv, setDisabledRulesCsv] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const sys = useFetch(() => api.systemStatus(), []);
  const maxUploadMb = sys.data?.limits.max_upload_mb;
  const ollamaModels = sys.data?.tools.ollama.models ?? [];
  const ollamaAvailable = sys.data?.tools.ollama.available ?? false;

  const pickFile = (f: File | null) => {
    setSubmitError(null);
    if (!f) {
      setFile(null);
      return;
    }
    if (maxUploadMb && f.size > maxUploadMb * 1024 * 1024) {
      setSubmitError(
        `File is ${formatBytes(f.size)} - exceeds the configured upload limit of ${maxUploadMb} MB.`,
      );
      setFile(null);
      return;
    }
    setFile(f);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const f = e.dataTransfer.files?.[0] ?? null;
    pickFile(f);
  };

  const startScan = async () => {
    if (!file || submitting) return;
    setSubmitting(true);
    setSubmitError(null);
    const config: ScanConfig = {
      enable_ai_review: enableAI,
      ai_model: aiModel.trim() ? aiModel.trim() : null,
      disabled_rules: disabledRulesCsv
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0),
    };
    try {
      const res = await api.createScan(file, config);
      navigate(`/scans/${res.scan_id}/live`);
    } catch (e) {
      setSubmitError(e instanceof Error ? e.message : 'Upload failed');
      setSubmitting(false);
    }
  };

  const notApk = file && !file.name.toLowerCase().endsWith('.apk');

  return (
    <div>
      <PageHeader
        title="New security assessment"
        subtitle="Upload an Android APK to run a fully automated static security assessment."
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {/* Drop zone */}
          <Card>
            <CardHeader title="APK upload" subtitle="Drag and drop a file, or browse your machine." />
            <div className="p-5">
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragActive(true);
                }}
                onDragLeave={() => setDragActive(false)}
                onDrop={onDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`cursor-pointer rounded-2xl border-2 border-dashed px-6 py-14 text-center transition-all duration-200 ${
                  dragActive
                    ? 'border-[#0071e3] bg-[#0071e3]/[0.06] dark:border-[#2997ff] dark:bg-[#2997ff]/[0.08]'
                    : 'border-black/[0.12] hover:border-black/[0.22] hover:bg-black/[0.02] dark:border-white/[0.16] dark:hover:border-white/[0.28] dark:hover:bg-white/[0.03]'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".apk,application/vnd.android.package-archive"
                  className="hidden"
                  onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
                />
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-800">
                  <svg className="h-6 w-6 text-slate-500 dark:text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                  </svg>
                </div>
                <p className="mt-4 text-sm font-semibold text-slate-800 dark:text-slate-200">
                  Drop your APK here, or <span className="underline">browse files</span>
                </p>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  .apk only{maxUploadMb ? ` · max ${maxUploadMb} MB` : ''} · SHA-256 is computed on upload
                </p>
              </div>

              {file && (
                <div className="mt-4 rounded-2xl border border-black/[0.06] bg-black/[0.02] px-5 py-4 dark:border-white/[0.08] dark:bg-white/[0.04]">
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="truncate font-mono text-sm font-medium text-slate-900 dark:text-slate-100">{file.name}</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400">{formatBytes(file.size)}</p>
                    </div>
                    <button
                      onClick={() => pickFile(null)}
                      className="rounded-full px-3 py-1.5 text-[13px] font-medium text-[#6e6e73] transition-colors hover:bg-black/[0.06] hover:text-[#1d1d1f] dark:text-[#98989f] dark:hover:bg-white/[0.08] dark:hover:text-white"
                    >
                      Remove
                    </button>
                  </div>
                  {notApk && (
                    <p className="mt-2 text-xs font-medium text-amber-600 dark:text-amber-400">
                      This file does not have a .apk extension. The backend validates the archive signature on upload and
                      will reject it if it is not a valid APK.
                    </p>
                  )}
                </div>
              )}

              {submitError && (
                <div className="mt-4 rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950/50 dark:text-red-300">
                  {submitError}
                </div>
              )}

              <PrimaryButton onClick={startScan} disabled={!file || submitting} className="mt-6 w-full !py-3.5 !text-[16px]">
                {submitting ? 'Uploading…' : 'Start Security Assessment'}
              </PrimaryButton>
            </div>
          </Card>

          {/* Scan configuration */}
          <Card>
            <CardHeader title="Scan configuration" subtitle="Optional. Defaults are safe for a first run." />
            <div className="space-y-5 p-5">
              <label className="flex cursor-pointer items-start gap-3">
                <input
                  type="checkbox"
                  checked={enableAI}
                  onChange={(e) => setEnableAI(e.target.checked)}
                  className="mt-1 h-[18px] w-[18px] rounded-md accent-[#0071e3]"
                />
                <span>
                  <span className="block text-sm font-medium text-slate-800 dark:text-slate-200">Enable local AI code review</span>
                  <span className="block text-xs text-slate-500 dark:text-slate-400">
                    Uses Ollama on this machine only. The scan continues without AI review if no model is available.
                  </span>
                </span>
              </label>

              <div>
                <label htmlFor="ai-model" className="block text-sm font-medium text-slate-800 dark:text-slate-200">
                  AI model name
                </label>
                <input
                  id="ai-model"
                  type="text"
                  value={aiModel}
                  onChange={(e) => setAiModel(e.target.value)}
                  placeholder="e.g. qwen2.5-coder:7b (blank = backend default)"
                  list="ollama-models"
                  className="mt-1.5 w-full rounded-xl border border-black/[0.12] bg-white px-4 py-2.5 font-mono text-[14px] text-[#1d1d1f] placeholder:text-[#aeaeb2] transition-all duration-150 focus:border-[#0071e3] focus:outline-none focus:ring-4 focus:ring-[#0071e3]/15 dark:border-white/[0.16] dark:bg-[#1c1c1e] dark:text-white dark:focus:border-[#2997ff] dark:focus:ring-[#2997ff]/20"
                />
                <datalist id="ollama-models">
                  {ollamaModels.map((m) => (
                    <option key={m} value={m} />
                  ))}
                </datalist>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  {ollamaAvailable
                    ? ollamaModels.length > 0
                      ? `${ollamaModels.length} local model${ollamaModels.length === 1 ? '' : 's'} detected.`
                      : 'Ollama is running but no models are installed yet.'
                    : 'Ollama is not currently available - install it to enable AI review.'}
                </p>
              </div>

              <div>
                <label htmlFor="disabled-rules" className="block text-sm font-medium text-slate-800 dark:text-slate-200">
                  Disabled rule IDs <span className="font-normal text-slate-500">(optional, comma-separated)</span>
                </label>
                <input
                  id="disabled-rules"
                  type="text"
                  value={disabledRulesCsv}
                  onChange={(e) => setDisabledRulesCsv(e.target.value)}
                  placeholder="e.g. MAN-001, CRY-014"
                  className="mt-1.5 w-full rounded-xl border border-black/[0.12] bg-white px-4 py-2.5 font-mono text-[14px] text-[#1d1d1f] placeholder:text-[#aeaeb2] transition-all duration-150 focus:border-[#0071e3] focus:outline-none focus:ring-4 focus:ring-[#0071e3]/15 dark:border-white/[0.16] dark:bg-[#1c1c1e] dark:text-white dark:focus:border-[#2997ff] dark:focus:ring-[#2997ff]/20"
                />
              </div>
            </div>
          </Card>
        </div>

        <div className="space-y-6">
          {/* Dependency readiness */}
          <Card>
            <CardHeader title="Dependency readiness" subtitle="Live status from the backend." />
            <div className="space-y-2.5 p-5">
              {sys.loading && <LoadingSpinner label="Checking tools…" />}
              {sys.error && <ErrorBox message={sys.error} onRetry={sys.retry} />}
              {sys.data && (
                <>
                  <ToolDot ok={sys.data.tools.jadx} label="JADX" />
                  <ToolDot ok={sys.data.tools.apktool} label="Apktool" />
                  <ToolDot ok={sys.data.tools.mobsfscan} label="MobSFScan" />
                  <ToolDot ok={sys.data.tools.androguard} label="Androguard" />
                  <ToolDot ok={sys.data.tools.ollama.available} label="Ollama (local AI)" />
                  <p className="pt-1 text-xs text-slate-500 dark:text-slate-400">
                    Missing tools are reported per-stage during the scan and reduce coverage - the scan still runs with
                    what is available.
                  </p>
                </>
              )}
            </div>
          </Card>

          {/* Privacy notice */}
          <Card>
            <CardHeader title="Privacy" />
            <div className="p-5 text-sm leading-relaxed text-slate-600 dark:text-slate-300">
              <p>
                <span className="font-semibold text-slate-800 dark:text-slate-100">APKs never leave this machine.</span>{' '}
                Upload, extraction, decompilation, and AI inference all run locally. No external uploads, no cloud AI
                fallback, no telemetry.
              </p>
              <p className="mt-2">
                Uploaded packages are treated as untrusted input and analyzed in isolated per-scan workspaces. APKs are
                never executed on the host.
              </p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
