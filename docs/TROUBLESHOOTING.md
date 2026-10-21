# Troubleshooting

## Real quirks discovered during development

### 1. mobsfscan silently skips paths containing "fixtures" / "spec" / ".git"

mobsfscan (via libsast) has a default `IGNORE_PATHS = {'__MACOSX', 'fixtures', 'spec', '.git', '.svn'}` and skips **any file whose path contains one of these substrings** (`mobsfscan` → `libsast` `validate_file`). This is upstream default behavior and cannot be overridden via its config file (user config only *adds* ignore paths).

**Impact:** during development, scanning sources under `backend/tests/fixtures/vuln_app` produced 0 mobsfscan matches while the same files scanned fine from a neutral directory.

**Guidance:** keep test/demo sources in neutrally-named directories when validating mobsfscan coverage. In production this rarely bites - decompiled output lives under `workspaces/<scan_id>/jadx`.

### 2. CLI needed `trust_env=False` on its httpx client

`httpx.Client` reads proxy environment variables by default. In sandboxed/CI environments `HTTP(S)_PROXY` may be set to values httpx cannot parse (e.g. socket paths), which breaks even plain `http://127.0.0.1:8000` calls with `InvalidURL: Invalid port`. The CLI talks to localhost, so `blindspot/cli.py` builds its client with `trust_env=False` - system proxies are never consulted.

### 3. "unable to open database file" on first run

The SQLAlchemy engine is created at import time; if the SQLite parent directory didn't exist yet, the first run failed with `unable to open database file`. Fixed in `core/db.py`, which now creates the parent directory before the engine is built (and `Settings.ensure_dirs()` covers workspace/upload dirs).

## Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| `422 not a ZIP archive` on upload | not an APK / corrupted file | verify the file; APKs are ZIP archives |
| `413 upload exceeds 200 MB` | file too large | raise `BLINDSPOT_MAX_UPLOAD_MB` |
| Scan shows "jadx not installed" limitation | JADX absent | install from https://github.com/skylot/jadx; decompilation-gated engines stay silent until then |
| Scan shows "apktool not installed" | apktool absent | install from https://apktool.org |
| AI review skipped | Ollama not running | `ollama serve` + `ollama pull <model>`; see `docs/MODEL_SETUP.md` |
| PDF export fails | missing system font libs | install libpango (`scripts/install-deps.sh` handles it) |
| Port 8000 in use | another server running | `blindspot serve --port 8001` (+ `BLINDSPOT_URL=http://127.0.0.1:8001` for the CLI) |
| Stale frontend | serving old `frontend/dist` | `cd frontend && npm run build` |

### 4. semgrep was removed in v5
`pip install semgrep` fails on Windows by design (`Exception: Semgrep does not support Windows yet`, semgrep/semgrep#1330), so the semgrep adapter was removed entirely in v5. The pipeline's third-party stage now runs **MobSFScan only** (its own semantic-grep rules degrade gracefully when no semgrep binary is present). The 200 custom Blindspot rules are unaffected.

### 5. PDF reports (v4+: ReportLab, zero setup)
Since v4.0, PDF reports are generated with **ReportLab** (pure Python, no system libraries). PDF export works out of the box on Windows, Linux, and macOS - no MSYS2/Pango/GTK setup needed. Each finding starts on its own page.
