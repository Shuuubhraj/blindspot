import type { ReactNode } from 'react';
import type { Severity } from '../api';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];

const severityBadgeStyles: Record<Severity, string> = {
  critical:
    'bg-[#ffe9e7] text-[#b3261e] dark:bg-[#3a1416] dark:text-[#ff8a8e]',
  high: 'bg-[#ffefe2] text-[#b3541e] dark:bg-[#3a1f10] dark:text-[#ffb37a]',
  medium: 'bg-[#fff4dd] text-[#8a5a00] dark:bg-[#3a2c0e] dark:text-[#ffd37a]',
  low: 'bg-[#e5f1ff] text-[#0b57d0] dark:bg-[#10283f] dark:text-[#7cc0ff]',
  informational:
    'bg-black/[0.05] text-[#424245] dark:bg-white/[0.08] dark:text-[#aeaeb2]',
};

const severityDotStyles: Record<Severity, string> = {
  critical: 'bg-[#d92d20]',
  high: 'bg-[#ec4a0a]',
  medium: 'bg-[#e6a817]',
  low: 'bg-[#0b57d0]',
  informational: 'bg-[#8e8e93]',
};

export function severityLabel(s: Severity): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function SeverityBadge({ severity, size = 'md' }: { severity: Severity; size?: 'sm' | 'md' }) {
  const pad = size === 'sm' ? 'px-2 py-px text-[11px]' : 'px-2.5 py-0.5 text-xs';
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-semibold tracking-wide ${pad} ${severityBadgeStyles[severity]}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${severityDotStyles[severity]}`} />
      {severityLabel(severity)}
    </span>
  );
}

const confidenceStyles: Record<string, string> = {
  high: 'bg-[#e6f4ea] text-[#137333] dark:bg-emerald-950 dark:text-emerald-300',
  medium: 'bg-[#fff4dd] text-[#8a5a00] dark:bg-[#3a2c0e] dark:text-[#ffd37a]',
  low: 'bg-black/[0.05] text-[#6e6e73] dark:bg-white/[0.08] dark:text-[#98989f]',
};

export function ConfidencePill({ confidence }: { confidence: string | null | undefined }) {
  if (!confidence) return <span className="text-[#aeaeb2]">-</span>;
  const key = confidence.toLowerCase();
  const style =
    confidenceStyles[key] ??
    'bg-black/[0.05] text-[#424245] dark:bg-white/[0.08] dark:text-[#aeaeb2]';
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${style}`}
    >
      {confidence}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const s = status.toLowerCase();
  let style = 'bg-black/[0.05] text-[#424245] dark:bg-white/[0.08] dark:text-[#aeaeb2]';
  if (s === 'completed' || s === 'done' || s === 'success')
    style = 'bg-[#e6f4ea] text-[#137333] dark:bg-emerald-950 dark:text-emerald-300';
  else if (s === 'running' || s === 'in_progress' || s === 'scanning')
    style = 'bg-[#e5f1ff] text-[#0b57d0] dark:bg-[#10283f] dark:text-[#7cc0ff]';
  else if (s === 'failed' || s === 'error')
    style = 'bg-[#ffe9e7] text-[#b3261e] dark:bg-[#3a1416] dark:text-[#ff8a8e]';
  else if (s === 'cancelled' || s === 'canceled')
    style = 'bg-[#fff4dd] text-[#8a5a00] dark:bg-[#3a2c0e] dark:text-[#ffd37a]';
  else if (s === 'queued' || s === 'pending')
    style = 'bg-[#f0e9ff] text-[#5e3fb3] dark:bg-violet-950 dark:text-violet-300';
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium capitalize transition-colors duration-150 ${style}`}
    >
      {status.replace(/_/g, ' ')}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Buttons - Apple-like: calm, pill-ish, precise states                */
/* ------------------------------------------------------------------ */

type ButtonProps = {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  className?: string;
  type?: 'button' | 'submit';
};

const btnBase =
  'inline-flex items-center justify-center gap-2 rounded-full px-5 py-2.5 text-[15px] font-medium transition-all duration-150 select-none active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40 disabled:active:scale-100 focus-visible:outline-2';

export function PrimaryButton({ children, onClick, disabled, className = '', type = 'button' }: ButtonProps) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`${btnBase} bg-[#0071e3] text-white shadow-[0_1px_2px_rgba(0,0,0,0.12)] hover:bg-[#0077ed] ${className}`}
    >
      {children}
    </button>
  );
}

export function SecondaryButton({ children, onClick, disabled, className = '' }: ButtonProps) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`${btnBase} bg-black/[0.05] text-[#1d1d1f] hover:bg-black/[0.08] dark:bg-white/[0.1] dark:text-white dark:hover:bg-white/[0.14] ${className}`}
    >
      {children}
    </button>
  );
}

export function DestructiveButton({ children, onClick, disabled, className = '' }: ButtonProps) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`${btnBase} bg-[#d92d20]/10 text-[#b3261e] hover:bg-[#d92d20]/15 dark:bg-[#ff8a8e]/10 dark:text-[#ff8a8e] dark:hover:bg-[#ff8a8e]/15 ${className}`}
    >
      {children}
    </button>
  );
}

/* ------------------------------------------------------------------ */

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={`rounded-2xl border border-black/[0.06] bg-white shadow-[0_1px_3px_rgba(0,0,0,0.04)] dark:border-white/[0.08] dark:bg-[#1c1c1e] dark:shadow-none ${className}`}
    >
      {children}
    </div>
  );
}

export function CardHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-black/[0.06] px-6 py-4 dark:border-white/[0.08]">
      <div>
        <h2 className="text-[17px] font-semibold tracking-tight text-[#1d1d1f] dark:text-white">{title}</h2>
        {subtitle && <p className="mt-0.5 text-[13px] text-[#6e6e73] dark:text-[#98989f]">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-7 flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 className="text-[28px] font-semibold tracking-tight text-[#1d1d1f] dark:text-white">{title}</h1>
        {subtitle && <p className="mt-1.5 text-[15px] text-[#6e6e73] dark:text-[#98989f]">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2.5">{actions}</div>}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="rounded-2xl border border-dashed border-black/[0.12] bg-white/60 px-6 py-14 text-center dark:border-white/[0.14] dark:bg-white/[0.02]">
      <p className="text-[15px] font-medium text-[#1d1d1f] dark:text-white">{title}</p>
      {hint && <p className="mx-auto mt-1.5 max-w-sm text-[13px] leading-relaxed text-[#6e6e73] dark:text-[#98989f]">{hint}</p>}
    </div>
  );
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="rounded-2xl border border-[#d92d20]/20 bg-[#ffe9e7]/60 px-6 py-8 text-center dark:border-[#ff8a8e]/20 dark:bg-[#ff8a8e]/[0.06]">
      <p className="text-[15px] font-semibold text-[#b3261e] dark:text-[#ff8a8e]">Something went wrong</p>
      <p className="mx-auto mt-1.5 max-w-xl text-[13px] leading-relaxed text-[#b3261e]/80 dark:text-[#ff8a8e]/80">{message}</p>
      {onRetry && (
        <div className="mt-5">
          <SecondaryButton onClick={onRetry}>Retry</SecondaryButton>
        </div>
      )}
    </div>
  );
}

export function LoadingSpinner({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 px-6 py-14 text-[13px] text-[#6e6e73] dark:text-[#98989f]">
      <span className="inline-block h-5 w-5 animate-spin rounded-full border-2 border-black/[0.12] border-t-[#0071e3] dark:border-white/[0.15] dark:border-t-[#2997ff]" />
      {label}
    </div>
  );
}

export function ToolDot({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className="flex items-center gap-2.5 text-[14px]">
      <span
        className={`h-2 w-2 rounded-full transition-colors duration-200 ${ok ? 'bg-[#30a46c]' : 'bg-black/[0.15] dark:bg-white/[0.2]'}`}
        title={ok ? 'Available' : 'Not available'}
      />
      <span className="text-[#1d1d1f] dark:text-white">{label}</span>
      <span className={`text-[13px] ${ok ? 'text-[#137333] dark:text-emerald-400' : 'text-[#aeaeb2]'}`}>
        {ok ? 'ready' : 'missing'}
      </span>
    </span>
  );
}

export function Mono({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <span className={`font-mono text-[13px] ${className}`}>{children}</span>;
}
