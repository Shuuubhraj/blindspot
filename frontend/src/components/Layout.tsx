import { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { api } from '../api';
import { ThemeToggle } from './theme';

const NAV = [
  { to: '/', label: 'New Scan', end: true },
  { to: '/history', label: 'Scan History', end: false },
  { to: '/rules', label: 'Rule Library', end: false },
  { to: '/system', label: 'System', end: false },
];

function Logo() {
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-[#1d1d1f] text-white shadow-[0_2px_8px_rgba(0,0,0,0.12)] dark:bg-white dark:text-black">
        <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z"
          />
          <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
      </div>
      <div className="leading-tight">
        <p className="text-[17px] font-semibold tracking-tight text-[#1d1d1f] dark:text-white">Blindspot</p>
        <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-[#6e6e73] dark:text-[#98989f]">
          Security Console
        </p>
      </div>
    </div>
  );
}

export default function Layout() {
  const [backendOk, setBackendOk] = useState<boolean | null>(null);
  const failStreak = useRef(0);
  const checkId = useRef(0);

  const checkBackend = (isInitial = false) => {
    // Don't blank the indicator on every poll - a slow/hung check must not
    // wedge the UI in "checking…". The 10s race guarantees resolution.
    // NOTE: uses /api/health, NOT /api/system/status - the latter pings
    // Ollama, which can be slow while a model is generating, causing false
    // "unreachable" banners mid-scan.
    if (isInitial) {
      setBackendOk(null);
      failStreak.current = 0;
    }
    const id = ++checkId.current;
    const timeout = new Promise<never>((_, reject) =>
      window.setTimeout(() => reject(new Error('backend check timed out')), 10000)
    );
    Promise.race([api.health(), timeout])
      .then(() => {
        if (id !== checkId.current) return; // stale check, ignore
        failStreak.current = 0;
        setBackendOk(true);
      })
      .catch(() => {
        if (id !== checkId.current) return; // stale check, ignore
        failStreak.current += 1;
        // A single failed poll is usually a blip, not an outage: while the
        // AI model is generating, Ollama can pin every CPU core and starve
        // the API thread past the 10s timeout even though the backend is
        // fine. Only raise the banner after consecutive failures.
        if (failStreak.current >= 3) setBackendOk(false);
      });
  };

  useEffect(() => {
    checkBackend(true);
    const id = window.setInterval(() => checkBackend(false), 30000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <div className="flex min-h-full">
      {/* Sidebar */}
      <aside className="hidden w-64 shrink-0 flex-col border-r border-black/[0.06] bg-white/80 backdrop-blur-xl dark:border-white/[0.08] dark:bg-black/80 md:flex">
        <div className="px-6 pb-5 pt-7">
          <Logo />
          <p className="mt-2.5 text-[13px] text-[#6e6e73] dark:text-[#98989f]">Find what others miss.</p>
        </div>
        <nav className="flex-1 space-y-1 px-3.5 py-2">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `block rounded-[10px] px-3.5 py-2.5 text-[15px] transition-all duration-150 ${
                  isActive
                    ? 'bg-black/[0.05] font-semibold text-[#1d1d1f] dark:bg-white/[0.1] dark:text-white'
                    : 'font-normal text-[#424245] hover:bg-black/[0.03] dark:text-[#aeaeb2] dark:hover:bg-white/[0.06]'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="px-6 py-5 text-[13px] leading-relaxed text-[#6e6e73] dark:text-[#98989f]">
          <p className="font-semibold text-[#1d1d1f] dark:text-[#f5f5f7]">Local-first</p>
          <p className="mt-1">APKs never leave this machine. Analysis runs locally.</p>
        </div>
      </aside>

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 border-b border-black/[0.06] bg-[#f5f5f7]/80 backdrop-blur-xl dark:border-white/[0.08] dark:bg-black/80">
          <div className="flex items-center justify-between gap-3 px-4 py-3 sm:px-6">
            <div className="md:hidden">
              <Logo />
            </div>
            <nav className="flex items-center gap-1 md:hidden">
              {NAV.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    `rounded-[10px] px-3 py-2 text-[13px] transition-all duration-150 ${
                      isActive
                        ? 'bg-black/[0.05] font-semibold text-[#1d1d1f] dark:bg-white/[0.1] dark:text-white'
                        : 'text-[#424245] dark:text-[#aeaeb2]'
                    }`
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>
            <div className="ml-auto flex items-center gap-3">
              <span
                className="hidden items-center gap-2 text-xs font-medium sm:inline-flex"
                title={backendOk === false ? 'Backend unreachable' : backendOk ? 'Backend connected' : 'Checking backend…'}
              >
                <span className="flex h-2.5 w-2.5">
                  <span
                    className={`inline-flex h-2.5 w-2.5 rounded-full transition-colors duration-300 ${
                      backendOk === null ? 'bg-amber-400' : backendOk ? 'bg-emerald-500' : 'bg-red-500'
                    }`}
                  />
                </span>
                <span className="text-slate-500 dark:text-slate-400">
                  {backendOk === null ? 'checking backend…' : backendOk ? 'backend connected' : 'backend unreachable'}
                </span>
              </span>
              <ThemeToggle />
            </div>
          </div>
          {backendOk === false && (
            <div className="border-t border-red-200 bg-red-50 px-4 py-2.5 dark:border-red-900 dark:bg-red-950/60 sm:px-6">
              <div className="flex flex-wrap items-center gap-3 text-sm">
                <p className="font-medium text-red-800 dark:text-red-300">
                  Backend unreachable at <span className="font-mono">http://localhost:8000</span>. Start the Blindspot API
                  server, then retry.
                </p>
                <button
                  onClick={() => checkBackend(true)}
                  className="rounded-lg border border-red-300 bg-white px-3 py-1 text-xs font-semibold text-red-700 hover:bg-red-100 dark:border-red-700 dark:bg-red-900 dark:text-red-200 dark:hover:bg-red-800"
                >
                  Retry
                </button>
              </div>
            </div>
          )}
        </header>

        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>

        <footer className="px-6 py-5 text-center text-[13px] text-[#6e6e73] dark:text-[#98989f]">
          Blindspot Security Console - local-first Android APK security assessment
          <span className="mx-2 text-[#aeaeb2]">·</span>
          made by{' '}
          <a
            href="https://github.com/shuuubhraj"
            target="_blank"
            rel="noreferrer"
            className="font-medium text-[#424245] underline decoration-[#aeaeb2] decoration-dotted underline-offset-4 transition-colors hover:text-[#0071e3] dark:text-[#aeaeb2] dark:hover:text-[#2997ff]"
          >
            @shuuubhraj
          </a>
        </footer>
      </div>
    </div>
  );
}
